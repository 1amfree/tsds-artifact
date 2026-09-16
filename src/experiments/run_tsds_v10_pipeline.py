#!/usr/bin/env python3
"""Run the reproducible TSDS v10 campaign and acceptance gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any


REPRODUCIBILITY_SOURCES = (
    "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py",
    "advanced_sanitizer_evaluator.py",
    "experiments/run_full_firmware_campaign.py",
    "experiments/run_tsds_v10_pipeline.py",
    "experiments/audit_evidence_contract.py",
    "experiments/audit_shell_witness_syntax.py",
    "experiments/run_threat_matrix_boundary_suite.py",
    "experiments/export_v10_paper_tables.py",
    "experiments/verify_v10_artifact_manifest.py",
    "experiments/run_busybox_shell_vector_calibration.py",
    "experiments/run_negative_confirmation.py",
    "experiments/audit_campaign_conservation.py",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_identity(path: Path, base: Path) -> dict[str, Any]:
    resolved = path.resolve()
    try:
        name = str(resolved.relative_to(base.resolve()))
    except ValueError:
        name = str(resolved)
    return {
        "path": name,
        "size": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }


def load_campaign_targets(root: Path) -> list[dict[str, str]]:
    """Load TARGETS without relying on the caller's PYTHONPATH."""
    import importlib.util

    campaign_script = root / "experiments" / "run_full_firmware_campaign.py"
    spec = importlib.util.spec_from_file_location("tsds_campaign_manifest", campaign_script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load campaign definition: {campaign_script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return list(module.TARGETS)


def query_python_environment(python: Path, cwd: Path) -> dict[str, Any]:
    code = r'''
import hashlib, importlib.metadata as md, json, platform, sys
packages = {}
for name in ("angr", "claripy", "unicorn", "z3-solver"):
    try:
        packages[name] = md.version(name)
    except md.PackageNotFoundError:
        packages[name] = None
dependency_versions = {}
for dist in md.distributions():
    name = dist.metadata.get("Name")
    if name:
        dependency_versions[name.lower()] = str(dist.version)
dependency_lock = sorted(dependency_versions.items())
dependency_payload = json.dumps(
    dependency_lock, separators=(",", ":"), ensure_ascii=True
).encode("utf-8")
print(json.dumps({
    "executable": sys.executable,
    "python": platform.python_version(),
    "implementation": platform.python_implementation(),
    "packages": packages,
    "dependency_lock": dependency_lock,
    "dependency_lock_sha256": hashlib.sha256(dependency_payload).hexdigest(),
}, sort_keys=True))
'''
    proc = subprocess.run(
        [str(python), "-c", code],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode:
        return {
            "query_returncode": proc.returncode,
            "query_stderr": proc.stderr.strip(),
        }
    return json.loads(proc.stdout)


def query_host_environment() -> dict[str, Any]:
    """Return stable host fields needed to interpret performance results."""

    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpu_count": os.cpu_count(),
        "byteorder": sys.byteorder,
    }


def build_reproducibility_manifest(root: Path, python: Path) -> dict[str, Any]:
    source_files = [root / rel for rel in REPRODUCIBILITY_SOURCES]
    missing_sources = [str(path) for path in source_files if not path.is_file()]
    targets = load_campaign_targets(root)
    inputs = []
    missing_inputs = []
    for target in targets:
        row: dict[str, Any] = {"target": target["name"], "label": target["label"]}
        for kind in ("binary", "mango"):
            path = root / target[kind]
            if path.is_file():
                row[kind] = file_identity(path, root)
            else:
                missing_inputs.append(str(path))
        inputs.append(row)
    return {
        "schema": "tsds-reproducibility-v1",
        "host": query_host_environment(),
        "python_environment": query_python_environment(python, root),
        "source_files": [file_identity(path, root) for path in source_files if path.is_file()],
        "campaign_inputs": inputs,
        "missing_sources": missing_sources,
        "missing_inputs": missing_inputs,
    }


def artifact_identities(out_dir: Path) -> list[dict[str, Any]]:
    return [
        file_identity(path, out_dir)
        for path in sorted(out_dir.rglob("*"))
        if path.is_file() and path.name != "pipeline_manifest.json"
    ]


def prepare_fresh_output_dir(out_dir: Path) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise RuntimeError(f"refusing to reuse non-empty pipeline directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)


def run_stage(
    name: str,
    command: list[str],
    cwd: Path,
    timeout: int,
    log_dir: Path,
) -> dict[str, Any]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = proc.stdout
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", "replace")
        output = partial + "\nPIPELINE_STAGE_TIMEOUT"
        returncode = 124
    except OSError as exc:
        output = f"PIPELINE_STAGE_LAUNCH_ERROR: {exc}\n"
        returncode = 127
    log_path = log_dir / f"{name}.log"
    log_path.write_text(output, encoding="utf-8", errors="replace")
    return {
        "name": name,
        "command": command,
        "returncode": returncode,
        "elapsed_sec": round(time.perf_counter() - start, 4),
        "log": str(log_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("/home/ubuntu/work/sanitizer"),
    )
    parser.add_argument(
        "--python",
        type=Path,
        default=Path(
            "/home/ubuntu/work/sanitizer/operation-mango-public/.venv/bin/python"
        ),
    )
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--max-closures", type=int, default=None)
    parser.add_argument("--target-timeout", type=int, default=7200)
    parser.add_argument("--skip-busybox-calibration", action="store_true")
    parser.add_argument("--run-negative-confirmation", action="store_true")
    parser.add_argument("--negative-max-records", type=int, default=0)
    args = parser.parse_args()

    args.root = args.root.resolve()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = (
        args.out_dir.resolve()
        if args.out_dir
        else args.root / "experiment_reports" / f"tsds_v10_pipeline_{stamp}"
    )
    try:
        prepare_fresh_output_dir(out_dir)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    logs = out_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    campaign = out_dir / "campaign"
    stages: list[dict[str, Any]] = []

    campaign_command = [
        str(args.python),
        "experiments/run_full_firmware_campaign.py",
        "--root",
        str(args.root),
        "--out-dir",
        str(campaign),
        "--target-timeout",
        str(args.target_timeout),
    ]
    if args.max_closures is not None:
        campaign_command.extend(["--max-closures", str(args.max_closures)])
    stages.append(
        run_stage(
            "01_full_campaign",
            campaign_command,
            args.root,
            max(args.target_timeout * 8 + 600, 1800),
            logs,
        )
    )

    mandatory = [
        (
            "02_campaign_conservation",
            [
                str(args.python),
                "experiments/audit_campaign_conservation.py",
                "--campaign-dir",
                str(campaign),
                "--out-dir",
                str(out_dir / "campaign_conservation"),
                "--expected-targets",
                "8",
                "--require-resource-metrics",
                "--fail-on-issues",
            ],
            900,
        ),
        (
            "02_evidence_contract",
            [
                str(args.python),
                "experiments/audit_evidence_contract.py",
                "--input-dir",
                str(campaign),
                "--out-dir",
                str(out_dir / "evidence_contract"),
                "--fail-on-contract-issues",
            ],
            900,
        ),
        (
            "03_shell_witness_syntax",
            [
                str(args.python),
                "experiments/audit_shell_witness_syntax.py",
                "--input-dir",
                str(campaign),
                "--out-dir",
                str(out_dir / "shell_witness_syntax"),
                "--fail-on-invalid-minimal",
            ],
            900,
        ),
        (
            "04_threat_matrix_boundary",
            [
                str(args.python),
                "experiments/run_threat_matrix_boundary_suite.py",
                "--out-dir",
                str(out_dir / "threat_matrix_boundary"),
            ],
            900,
        ),
        (
            "05_paper_tables",
            [
                str(args.python),
                "experiments/export_v10_paper_tables.py",
                "--campaign-dir",
                str(campaign),
                "--out-dir",
                str(out_dir / "paper_tables"),
                "--contract-audit",
                str(out_dir / "evidence_contract" / "evidence_contract_audit.json"),
                "--syntax-audit",
                str(out_dir / "shell_witness_syntax" / "shell_witness_syntax_summary.json"),
            ],
            900,
        ),
    ]
    if stages[0]["returncode"] == 0:
        for name, command, timeout in mandatory:
            stages.append(run_stage(name, command, args.root, timeout, logs))

    if not args.skip_busybox_calibration:
        stages.append(
            run_stage(
                "06_busybox_calibration",
                [
                    str(args.python),
                    "experiments/run_busybox_shell_vector_calibration.py",
                    "--workspace",
                    str(args.root),
                    "--out-dir",
                    str(out_dir / "busybox_calibration"),
                ],
                args.root,
                1800,
                logs,
            )
        )

    if args.run_negative_confirmation and stages[0]["returncode"] == 0:
        command = [
            str(args.python),
            "experiments/run_negative_confirmation.py",
            "--root",
            str(args.root),
            "--campaign-dir",
            str(campaign),
            "--out-dir",
            str(out_dir / "negative_confirmation"),
        ]
        if args.negative_max_records:
            command.extend(
                ["--max-records", str(args.negative_max_records)]
            )
        stages.append(
            run_stage(
                "07_negative_confirmation",
                command,
                args.root,
                max(args.target_timeout * 8, 1800),
                logs,
            )
        )

    success = all(stage["returncode"] == 0 for stage in stages)
    reproducibility = build_reproducibility_manifest(args.root, args.python)
    manifest = {
        "schema": "tsds-v10-pipeline-v2",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(args.root),
        "out_dir": str(out_dir),
        "invocation": sys.argv,
        "success": success,
        "stages": stages,
        "reproducibility": reproducibility,
        "artifacts": artifact_identities(out_dir),
    }
    (out_dir / "pipeline_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "success": success,
                "manifest": str(out_dir / "pipeline_manifest.json"),
                "stages": [
                    {"name": stage["name"], "returncode": stage["returncode"]}
                    for stage in stages
                ],
                "artifact_files": len(manifest["artifacts"]),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if success else 2


if __name__ == "__main__":
    raise SystemExit(main())
