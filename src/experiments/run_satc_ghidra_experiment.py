#!/usr/bin/env python3
"""Run a content-bound SaTC Ghidra to TSDS ingestion experiment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.satc_source_snapshot import validate_snapshot


SCHEMA = "tsds-satc-ghidra-ingestion-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_identity(path: Path, base: Path | None = None) -> dict[str, Any]:
    resolved = path.resolve()
    try:
        label = resolved.relative_to(base.resolve()).as_posix() if base else str(resolved)
    except ValueError:
        label = str(resolved)
    return {
        "path": label,
        "size": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }


def command_version(command: list[str]) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            check=False,
        )
        return {"command": command, "returncode": proc.returncode, "output": proc.stdout.strip()}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"command": command, "error": f"{type(exc).__name__}:{exc}"}


def python_environment_identity(python: Path) -> dict[str, Any]:
    """Capture the interpreter and installed-package identity for replay.

    The front-end runner can execute from a dedicated compatibility virtual
    environment while TSDS uses its analysis virtual environment.  A Python
    version alone is therefore not sufficient to diagnose an ingestion drift.
    ``pip freeze --all`` is captured as structured evidence and hashed so an
    artifact consumer can compare environments without relying on a mutable
    package index.
    """

    packages = command_version([str(python), "-m", "pip", "freeze", "--all"])
    output = str(packages.get("output") or "")
    packages["output_sha256"] = hashlib.sha256(output.encode("utf-8")).hexdigest()
    return {
        "version": command_version([str(python), "--version"]),
        "packages": packages,
    }


def run_stage(
    name: str,
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
    log_dir: Path,
    resource_path: Path | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    effective = list(command)
    if resource_path is not None and Path("/usr/bin/time").is_file():
        effective = ["/usr/bin/time", "-v", "-o", str(resource_path)] + effective
    started = time.perf_counter()
    try:
        child_environment = {
            **os.environ,
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            "PYTHONHASHSEED": "0",
        }
        if environment:
            child_environment.update(environment)
        proc = subprocess.run(
            effective,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
            env=child_environment,
        )
        output = proc.stdout
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", "replace")
        output = partial + "\nSTAGE_TIMEOUT\n"
        returncode = 124
    except OSError as exc:
        output = f"STAGE_LAUNCH_ERROR:{exc}\n"
        returncode = 127
    log_path = log_dir / f"{name}.log"
    log_path.write_text(output, encoding="utf-8", errors="replace")
    return {
        "name": name,
        "command": command,
        "effective_command": effective,
        "returncode": returncode,
        "elapsed_sec": round(time.perf_counter() - started, 4),
        "log": str(log_path),
        "resource_log": str(resource_path) if resource_path and resource_path.is_file() else None,
    }


def artifact_identities(out_dir: Path) -> list[dict[str, Any]]:
    return [
        file_identity(path, out_dir)
        for path in sorted(out_dir.rglob("*"))
        if path.is_file() and path.name != "experiment_manifest.json"
    ]


def build_commands(args: argparse.Namespace, out_dir: Path) -> dict[str, list[str]]:
    satc_main = args.satc_root / "src" / "headless" / "main.py"
    script = args.satc_root / "src" / "headless" / "ref2sink_cmdi.py"
    raw_output = out_dir / "satc_ref2sink_cmdi.result"
    project_dir = out_dir / "ghidra_project"
    closures = out_dir / "satc_tsds_closures.json"
    wrapped_ghidra_command = [
            str(args.frontend_python),
            str(satc_main),
            "--ghidra-path",
            str(args.ghidra_root),
            "--binary",
            str(args.binary),
            "--script",
            str(script),
            "--project-dir",
            str(project_dir),
            "--infile",
            str(args.keywords_file),
            "--outfile",
            str(raw_output),
            "--reset",
        ]
    if args.ghidra_analysis_timeout_per_file is None:
        ghidra_command = wrapped_ghidra_command
    else:
        # SaTC's small headless wrapper does not expose Ghidra's documented
        # per-file analysis timeout.  Invoke the same official postscript
        # directly when a bounded front-end workload is requested; SaTC source
        # and script identities remain bound in the manifest.
        ghidra_command = [
            str(args.ghidra_root / "support" / "analyzeHeadless"),
            str(project_dir),
            f"tsds_satc_{args.binary.name}",
            "-analysisTimeoutPerFile",
            str(args.ghidra_analysis_timeout_per_file),
            "-postscript",
            str(script),
            str(args.keywords_file),
            str(raw_output),
            "-scriptPath",
            str(script.parent),
            "-import",
            str(args.binary),
        ]
    commands = {
        "ghidra": ghidra_command,
        "convert": [
            str(args.tsds_python),
            str(args.converter),
            str(raw_output),
            "--input-format",
            "ghidra",
            "--binary",
            str(args.binary),
            "--output",
            str(closures),
        ],
        "candidate_contract": [
            str(args.tsds_python),
            str(PROJECT_ROOT / "experiments" / "audit_candidate_contract.py"),
            "--input",
            str(closures),
            "--out-dir",
            str(out_dir / "candidate_contract"),
            "--require-valid",
        ],
    }
    if args.run_tsds:
        results = out_dir / "tsds.results.jsonl"
        command = [
            str(args.tsds_python),
            str(args.evaluator),
            str(args.binary),
            str(closures),
            "--engine-timeout",
            str(args.engine_timeout),
            "--closure-timeout",
            str(args.closure_timeout),
            "--subprocess-timeout",
            str(args.subprocess_timeout),
            "--subprocess-memory-limit-mib",
            str(args.memory_limit_mib),
            "--summary-json",
            str(out_dir / "tsds_summary.json"),
            "--results-jsonl",
            str(results),
            "--report-file",
            str(out_dir / "tsds_report.md"),
            "--report-max-records",
            "0",
            "--no-evidence-cache",
        ]
        if args.max_closures is not None:
            command.extend(["--max-closures", str(args.max_closures)])
        commands["tsds"] = command
        commands["evidence_contract"] = [
            str(args.tsds_python),
            str(PROJECT_ROOT / "experiments" / "audit_evidence_contract.py"),
            "--input-dir",
            str(out_dir),
            "--out-dir",
            str(out_dir / "evidence_contract"),
            "--fail-on-contract-issues",
        ]
        commands["vector_integrity"] = [
            str(args.tsds_python),
            str(PROJECT_ROOT / "experiments" / "audit_vector_decision_integrity.py"),
            "--input-dir",
            str(out_dir),
            "--out-dir",
            str(out_dir / "vector_integrity"),
            "--fail-on-issues",
        ]
        commands["ledger_schema"] = [
            str(args.tsds_python),
            str(PROJECT_ROOT / "experiments" / "audit_ledger_schema.py"),
            "--input-dir",
            str(out_dir),
            "--out-dir",
            str(out_dir / "ledger_schema"),
            "--fail-on-issues",
        ]
    return commands


def keyword_provenance_path(args: argparse.Namespace) -> Path | None:
    """Resolve the optional legacy or generic keyword provenance argument."""

    supplied = [
        path
        for path in (
            getattr(args, "keyword_extraction_manifest", None),
            getattr(args, "keyword_provenance_manifest", None),
        )
        if path is not None
    ]
    if len(supplied) > 1:
        raise ValueError(
            "provide only one of --keyword-extraction-manifest and "
            "--keyword-provenance-manifest"
        )
    return supplied[0] if supplied else None


def validate_keyword_provenance(path: Path, keywords_file: Path) -> str:
    """Require a provenance manifest to bind the exact consumed keyword file."""

    try:
        provenance = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unreadable keyword provenance manifest: {exc}") from exc
    output_key_by_schema = {
        "tsds-satc-keyword-extraction-v1": "keyword_output",
        "tsds-satc-keyword-slice-v1": "slice_output",
    }
    schema = provenance.get("schema")
    output_key = output_key_by_schema.get(schema)
    if output_key is None:
        raise ValueError("keyword provenance manifest has an unexpected schema")
    if provenance.get("success") is not True:
        raise ValueError("keyword provenance manifest is not successful")
    if schema == "tsds-satc-keyword-extraction-v1" and (
        (provenance.get("environment") or {}).get("js_parser_environment_bound")
        is not True
    ):
        raise ValueError("keyword extraction manifest does not bind the JavaScript parser environment")
    if schema == "tsds-satc-keyword-slice-v1" and provenance.get(
        "parent_js_parser_environment_bound"
    ) is not True:
        raise ValueError("keyword slice manifest does not bind its JavaScript parser parent environment")
    output = provenance.get(output_key) or {}
    if output.get("size") != keywords_file.stat().st_size:
        raise ValueError("keyword provenance manifest size does not bind keywords file")
    if output.get("sha256") != sha256_file(keywords_file):
        raise ValueError("keyword provenance manifest hash does not bind keywords file")
    return str(schema)


def java_stage_environment(java_home: Path | None) -> dict[str, str] | None:
    """Return an explicit JDK environment for legacy Ghidra launch scripts."""

    if java_home is None:
        return None
    resolved = java_home.resolve()
    inherited_path = os.environ.get("PATH", "")
    return {
        "JAVA_HOME": str(resolved),
        "PATH": str(resolved / "bin") + os.pathsep + inherited_path,
    }


def prepare_direct_ghidra_project(args: argparse.Namespace, out_dir: Path) -> Path | None:
    """Mirror SaTC's project-directory setup for direct Ghidra execution."""

    if args.ghidra_analysis_timeout_per_file is None:
        return None
    project_dir = out_dir / "ghidra_project"
    project_dir.mkdir(parents=True, exist_ok=True)
    return project_dir


def validate_inputs(args: argparse.Namespace) -> dict[str, Path]:
    source_snapshot = getattr(args, "satc_source_snapshot", None)
    paths = {
        "binary": args.binary,
        "keywords": args.keywords_file,
        "satc_main": args.satc_root / "src" / "headless" / "main.py",
        "satc_script": args.satc_root / "src" / "headless" / "ref2sink_cmdi.py",
        "ghidra_headless": args.ghidra_root / "support" / "analyzeHeadless",
        "converter": args.converter,
        "candidate_contract_audit": PROJECT_ROOT / "experiments" / "audit_candidate_contract.py",
        "tsds_python": args.tsds_python,
    }
    if args.run_tsds:
        paths["evaluator"] = args.evaluator
        paths["evidence_contract_audit"] = PROJECT_ROOT / "experiments" / "audit_evidence_contract.py"
        paths["vector_integrity_audit"] = PROJECT_ROOT / "experiments" / "audit_vector_decision_integrity.py"
        paths["ledger_schema_audit"] = PROJECT_ROOT / "experiments" / "audit_ledger_schema.py"
    # A source archive is optional because a developer checkout may already be
    # content-addressed by its Git revision.  When SaTC is deployed from an
    # offline bundle, however, the checkout normally has no ``.git`` metadata;
    # binding the bundle closes that provenance gap without treating a version
    # string as a substitute for source identity.
    if args.satc_archive is not None:
        paths["satc_archive"] = args.satc_archive
    if source_snapshot is not None:
        paths["satc_source_snapshot"] = source_snapshot
    provenance_path = keyword_provenance_path(args)
    if provenance_path is not None:
        paths["keyword_provenance_manifest"] = provenance_path
    if args.java_home is not None:
        paths["java_binary"] = args.java_home / "bin" / "java"
        paths["java_compiler"] = args.java_home / "bin" / "javac"
        java_release = args.java_home / "release"
        if java_release.is_file():
            paths["java_release"] = java_release
    ghidra_properties = args.ghidra_root / "Ghidra" / "application.properties"
    if ghidra_properties.is_file():
        paths["ghidra_application_properties"] = ghidra_properties
    missing = [f"{name}:{path}" for name, path in paths.items() if not path.is_file()]
    if missing:
        raise ValueError("missing experiment input(s): " + ", ".join(missing))
    if provenance_path is not None:
        validate_keyword_provenance(provenance_path, args.keywords_file)
    if source_snapshot is not None:
        validate_snapshot(source_snapshot, args.satc_root)
    return paths


def run_experiment(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    logs = out_dir / "logs"
    logs.mkdir()
    prepare_direct_ghidra_project(args, out_dir)
    inputs = validate_inputs(args)
    identities = {name: file_identity(path) for name, path in inputs.items()}
    commands = build_commands(args, out_dir)
    stages = [
        run_stage(
            "01_satc_ghidra",
            commands["ghidra"],
            cwd=args.satc_root,
            timeout=args.ghidra_timeout_sec,
            log_dir=logs,
            resource_path=out_dir / "satc_ghidra.resource.txt",
            environment=java_stage_environment(args.java_home),
        )
    ]
    raw_output = out_dir / "satc_ref2sink_cmdi.result"
    if stages[-1]["returncode"] == 0 and raw_output.is_file():
        stages.append(
            run_stage(
                "02_convert",
                commands["convert"],
                cwd=PROJECT_ROOT,
                timeout=300,
                log_dir=logs,
            )
        )
    else:
        stages.append({"name": "02_convert", "command": commands["convert"], "returncode": 125, "blocked_by": ["01_satc_ghidra"]})
    closures_path = out_dir / "satc_tsds_closures.json"
    closure_count = 0
    if closures_path.is_file():
        closure_doc = json.loads(closures_path.read_text(encoding="utf-8"))
        closure_count = len(closure_doc.get("closures") or [])
    if stages[-1]["returncode"] == 0 and closure_count:
        stages.append(
            run_stage(
                "03_candidate_contract",
                commands["candidate_contract"],
                cwd=PROJECT_ROOT,
                timeout=300,
                log_dir=logs,
            )
        )
    else:
        stages.append(
            {
                "name": "03_candidate_contract",
                "command": commands["candidate_contract"],
                "returncode": 125,
                "blocked_by": ["02_convert"],
            }
        )
    if args.run_tsds:
        if stages[-1]["returncode"] == 0 and closure_count:
            stages.append(
                run_stage(
                    "04_tsds",
                    commands["tsds"],
                    cwd=PROJECT_ROOT,
                    timeout=args.tsds_timeout_sec,
                    log_dir=logs,
                    resource_path=out_dir / "tsds.resource.txt",
                )
            )
        else:
            stages.append({"name": "04_tsds", "command": commands["tsds"], "returncode": 125, "blocked_by": ["03_candidate_contract"]})
        if stages[-1]["returncode"] == 0:
            for name, command in (
                ("05_evidence_contract", commands["evidence_contract"]),
                ("06_vector_integrity", commands["vector_integrity"]),
                ("07_ledger_schema", commands["ledger_schema"]),
            ):
                stages.append(
                    run_stage(name, command, cwd=PROJECT_ROOT, timeout=300, log_dir=logs)
                )
        else:
            for name, command in (
                ("05_evidence_contract", commands["evidence_contract"]),
                ("06_vector_integrity", commands["vector_integrity"]),
                ("07_ledger_schema", commands["ledger_schema"]),
            ):
                stages.append(
                    {
                        "name": name,
                        "command": command,
                        "returncode": 125,
                        "blocked_by": ["04_tsds"],
                    }
                )
    tsds_counts: dict[str, Any] = {}
    summary_path = out_dir / "tsds_summary.json"
    if summary_path.is_file():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        tsds_counts = {
            "unique_pairs_analyzed": summary.get("unique_pairs_analyzed"),
            "verdicts": (summary.get("evidence_contract_ledger") or {}).get("verdicts") or {},
        }
    tsds_audits: dict[str, Any] = {}
    candidate_contract_path = (
        out_dir / "candidate_contract" / "candidate_contract_audit.json"
    )
    if candidate_contract_path.is_file():
        tsds_audits["candidate_contract"] = json.loads(
            candidate_contract_path.read_text(encoding="utf-8")
        )
    if args.run_tsds:
        for name, path in (
            ("evidence_contract", out_dir / "evidence_contract" / "evidence_contract_audit.json"),
            ("vector_integrity", out_dir / "vector_integrity" / "vector_decision_integrity_audit.json"),
            ("ledger_schema", out_dir / "ledger_schema" / "ledger_schema_audit.json"),
        ):
            if path.is_file():
                tsds_audits[name] = json.loads(path.read_text(encoding="utf-8"))
    success = bool(
        stages
        and all(stage.get("returncode") == 0 for stage in stages)
        and closure_count > 0
        and (not args.run_tsds or bool(tsds_counts))
    )
    manifest = {
        "schema": SCHEMA,
        "success": success,
        "comparison_mode": "native_frontend_ingestion",
        "claim_boundary": (
            "This experiment establishes SaTC-to-TSDS ingestion, candidate "
            "coverage, and TSDS ledger-class outcomes. Without independently "
            "frozen labels it does not establish accuracy or SOTA superiority."
        ),
        "inputs": identities,
        "environment": {
            "java": command_version(["java", "-version"]),
            "frontend_python": python_environment_identity(args.frontend_python),
            "tsds_python": python_environment_identity(args.tsds_python),
        },
        "configuration": {
            "max_closures": args.max_closures,
            "memory_limit_mib": args.memory_limit_mib,
            "evidence_cache": "disabled",
            "satc_archive_bound": args.satc_archive is not None,
            "satc_source_snapshot_bound": getattr(args, "satc_source_snapshot", None) is not None,
            "keyword_provenance_manifest_bound": keyword_provenance_path(args) is not None,
            "java_home_bound": args.java_home is not None,
            "ghidra_execution_mode": (
                "direct_ghidra_official_satc_postscript"
                if args.ghidra_analysis_timeout_per_file is not None
                else "satc_headless_wrapper"
            ),
            "ghidra_analysis_timeout_per_file": args.ghidra_analysis_timeout_per_file,
        },
        "stages": stages,
        "satc_candidates": closure_count,
        "tsds": tsds_counts,
        "tsds_audits": tsds_audits,
    }
    manifest["artifacts"] = artifact_identities(out_dir)
    (out_dir / "experiment_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--satc-root", type=Path, required=True)
    parser.add_argument("--ghidra-root", type=Path, required=True)
    parser.add_argument(
        "--java-home",
        type=Path,
        help=(
            "Explicit JDK home for legacy Ghidra launchers. When supplied, "
            "its java binary and release metadata are content-bound."
        ),
    )
    parser.add_argument(
        "--satc-archive",
        type=Path,
        help=(
            "Optional immutable SaTC source/dependency archive. Required for "
            "content provenance when the deployed SaTC tree has no Git metadata."
        ),
    )
    parser.add_argument(
        "--satc-source-snapshot",
        type=Path,
        help="Optional validated tsds-satc-source-snapshot-v1 manifest for full front-end provenance.",
    )
    parser.add_argument(
        "--keyword-extraction-manifest",
        type=Path,
        help=(
            "Optional successful tsds-satc-keyword-extraction-v1 manifest. "
            "When supplied, its output hash and size must bind --keywords-file."
        ),
    )
    parser.add_argument(
        "--keyword-provenance-manifest",
        type=Path,
        help=(
            "Optional generic successful keyword provenance manifest. Supports "
            "tsds-satc-keyword-extraction-v1 and tsds-satc-keyword-slice-v1."
        ),
    )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--keywords-file", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--frontend-python", type=Path, default=Path(sys.executable))
    parser.add_argument("--tsds-python", type=Path, default=Path(sys.executable))
    parser.add_argument("--converter", type=Path, default=PROJECT_ROOT / "experiments" / "convert_satc_to_tsds.py")
    parser.add_argument("--evaluator", type=Path, default=PROJECT_ROOT / "Taint_demo" / "sanitizer_demo" / "advanced_sanitizer_evaluator.py")
    parser.add_argument("--run-tsds", action="store_true")
    parser.add_argument("--max-closures", type=int)
    parser.add_argument("--memory-limit-mib", type=int, default=8192)
    parser.add_argument("--engine-timeout", type=int, default=45)
    parser.add_argument("--closure-timeout", type=int, default=90)
    parser.add_argument("--subprocess-timeout", type=int, default=150)
    parser.add_argument("--ghidra-timeout-sec", type=int, default=7200)
    parser.add_argument(
        "--ghidra-analysis-timeout-per-file",
        type=int,
        help=(
            "When set, invoke Ghidra directly with its documented "
            "-analysisTimeoutPerFile option and the official SaTC postscript."
        ),
    )
    parser.add_argument("--tsds-timeout-sec", type=int, default=7200)
    args = parser.parse_args()
    try:
        manifest = run_experiment(args)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"success": manifest["success"], "satc_candidates": manifest["satc_candidates"], "tsds": manifest["tsds"]}, indent=2, sort_keys=True))
    return 0 if manifest["success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
