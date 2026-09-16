#!/usr/bin/env python3
"""Promote an accepted TSDS campaign through the v18/v7 evidence extension.

The campaign ledgers remain read-only.  All new outputs are derived in a fresh
directory from a content-addressed source snapshot and the accepted pipeline
manifest, avoiding a costly re-execution of the already frozen symbolic run.
"""

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

from experiments.run_tsds_v18_pipeline import (  # noqa: E402
    ADDITIONAL_REPRODUCIBILITY_SOURCES,
    PIPELINE_SCHEMA,
    V18_ARTIFACT_SOURCE_SET,
)


EXTENSION_SCHEMA = "tsds-v18-evidence-extension-v7"


def preserve_python_executable(path: Path) -> Path:
    """Make a path absolute without dereferencing a virtual-environment symlink."""

    return Path(os.path.abspath(os.fspath(path)))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_accepted_run(run: Path) -> dict[str, Any]:
    manifest_path = run / "pipeline_manifest.json"
    if not manifest_path.is_file():
        raise ValueError("accepted run has no pipeline_manifest.json")
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    if document.get("success") is not True:
        raise ValueError("input pipeline manifest is not successful")
    campaign = run / "campaign"
    repeatability = run / "repeatability_consensus/repeatability_records.csv"
    repeatability_summary = run / "repeatability_consensus/repeatability_summary.json"
    ledgers = sorted(campaign.glob("*.results.jsonl"))
    if not ledgers or not repeatability.is_file() or not repeatability_summary.is_file():
        raise ValueError("input run lacks campaign or repeatability evidence")
    artifacts = {
        str(row.get("path") or "").replace("\\", "/"): row
        for row in document.get("artifacts") or []
    }
    issues = []
    for path in ledgers:
        suffix = "campaign/" + path.name
        matches = [row for name, row in artifacts.items() if name.endswith(suffix)]
        if len(matches) != 1 or matches[0].get("sha256") != sha256_file(path):
            issues.append(f"campaign_binding_failed:{path.name}")
    if issues:
        raise ValueError(";".join(issues))
    records = 0
    residuals = 0
    for path in ledgers:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records += 1
                residuals += int(json.loads(line).get("verdict") == "RESIDUAL")
    return {
        "manifest": manifest_path,
        "manifest_schema": document.get("schema"),
        "manifest_sha256": sha256_file(manifest_path),
        "campaign": campaign,
        "repeatability": repeatability,
        "repeatability_summary": repeatability_summary,
        "targets": len(ledgers),
        "records": records,
        "residuals": residuals,
    }


def snapshot_sources(source_root: Path, destination: Path) -> list[dict[str, Any]]:
    rows = []
    source_set = tuple(
        sorted(set(V18_ARTIFACT_SOURCE_SET) | set(ADDITIONAL_REPRODUCIBILITY_SOURCES))
    )
    for relative in source_set:
        source = source_root / Path(relative)
        if not source.is_file():
            raise ValueError(f"snapshot source missing: {relative}")
        target = destination / Path(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        rows.append(
            {
                "path": relative,
                "size": target.stat().st_size,
                "sha256": sha256_file(target),
            }
        )
    return rows


def build_stage_commands(
    python: Path,
    source: Path,
    run: Path,
    out: Path,
    facts: dict[str, Any],
    *,
    seed: int,
    calibration_limit: int,
    audit_per_stratum: int,
) -> list[tuple[str, list[str], int]]:
    experiments = source / "experiments"
    return [
        (
            "01_source_snapshot_self_test",
            [
                str(python), str(experiments / "run_source_snapshot_self_test.py"),
                "--source-root", str(source),
                "--out-dir", str(out / "source_snapshot_self_test"),
                "--python", str(python),
                "--timeout", "1200",
            ],
            1500,
        ),
        (
            "02_evidence_certificates_v2",
            [
                str(python), str(experiments / "build_evidence_certificates.py"),
                "--input-dir", str(facts["campaign"]),
                "--out-dir", str(out / "evidence_certificates_v2"),
                "--fail-on-issues",
            ],
            900,
        ),
        (
            "03_independent_certificate_verifier",
            [
                str(python), str(experiments / "verify_evidence_certificates.py"),
                "--certificates", str(out / "evidence_certificates_v2/evidence_certificates.jsonl"),
                "--source-dir", str(facts["campaign"]),
                "--shell", "/bin/bash", "--shell", "/bin/dash",
                "--out-dir", str(out / "independent_certificate_verifier"),
                "--fail-on-issues",
            ],
            900,
        ),
        (
            "04_residual_root_causes",
            [
                str(python), str(experiments / "audit_residual_root_causes.py"),
                "--campaign", str(facts["campaign"]),
                "--pipeline-manifest", str(facts["manifest"]),
                "--expected-residuals", str(facts["residuals"]),
                "--out-dir", str(out / "residual_root_causes"),
                "--require-complete",
            ],
            900,
        ),
        (
            "05_performance_diagnostics",
            [
                str(python), str(experiments / "audit_performance_diagnostics.py"),
                "--campaign", str(facts["campaign"]),
                "--expected-records", str(facts["records"]),
                "--out-dir", str(out / "performance_diagnostics"),
                "--require-complete",
            ],
            900,
        ),
        (
            "06_shell_matrix_profiles",
            [
                str(python), str(experiments / "audit_shell_dialect_profiles.py"),
                "--input-dir", str(facts["campaign"]),
                "--out-dir", str(out / "shell_matrix_profiles"),
                "--fail-on-sat-issues",
            ],
            900,
        ),
        (
            "07_external_calibration_pack",
            [
                str(python), str(experiments / "build_exploitability_calibration_pack.py"),
                "--campaign", str(facts["campaign"]),
                "--repeatability-records", str(facts["repeatability"]),
                "--pipeline-manifest", str(facts["manifest"]),
                "--limit", str(calibration_limit), "--seed", str(seed),
                "--require-repeatability", "--require-pipeline-binding",
                "--out-dir", str(out / "external_calibration_pack"),
            ],
            900,
        ),
        (
            "08_blinded_ground_truth_sample",
            [
                str(python), str(experiments / "build_blinded_ground_truth_sample.py"),
                "--campaign-dir", str(facts["campaign"]),
                "--repeatability-records", str(facts["repeatability"]),
                "--pipeline-manifest", str(facts["manifest"]),
                "--per-stratum", str(audit_per_stratum), "--seed", str(seed),
                "--out-dir", str(out / "blinded_ground_truth_sample"),
            ],
            900,
        ),
        (
            "09_satc_fixture_conversion",
            [
                str(python), str(experiments / "convert_satc_to_tsds.py"),
                str(experiments / "fixtures/satc_sample.csv"),
                "--input-format", "csv", "--output", str(out / "candidate_adapter/satc_closures.json"),
            ],
            300,
        ),
        (
            "10_candidate_contract",
            [
                str(python), str(experiments / "audit_candidate_contract.py"),
                "--input", str(out / "candidate_adapter/satc_closures.json"),
                "--out-dir", str(out / "candidate_contract"), "--require-valid",
            ],
            300,
        ),
        (
            "11_reproduction_sbom",
            [
                str(python), str(experiments / "generate_reproduction_sbom.py"),
                "--source-root", str(source),
                "--out-dir", str(out / "reproduction_sbom"),
                "--source-date-epoch", "0",
            ],
            900,
        ),
        (
            "12_paper_tables",
            [
                str(python), str(experiments / "export_paper_tables.py"),
                "--campaign-dir", str(facts["campaign"]),
                "--out-dir", str(out / "paper_tables"),
                "--repeatability-audit", str(facts["repeatability_summary"]),
            ],
            900,
        ),
    ]


def run_stage(
    name: str, command: list[str], timeout: int, cwd: Path, logs: Path
) -> dict[str, Any]:
    started = time.monotonic()
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        returncode = result.returncode
        output = result.stdout
    except subprocess.TimeoutExpired as exc:
        returncode = 124
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        output = partial + "\nSTAGE_TIMEOUT\n"
    (logs / f"{name}.log").write_text(output, encoding="utf-8")
    return {
        "name": name,
        "command": command,
        "returncode": returncode,
        "elapsed_sec": round(time.monotonic() - started, 4),
        "log": f"logs/{name}.log",
        "environment": {
            "PYTHONDONTWRITEBYTECODE": environment["PYTHONDONTWRITEBYTECODE"],
            "PYTHONHASHSEED": environment["PYTHONHASHSEED"],
        },
    }


def artifact_identities(root: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_file() and path.name != "extension_manifest.json":
            rows.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--accepted-run", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--seed", type=int, default=20260714)
    parser.add_argument("--calibration-limit", type=int, default=16)
    parser.add_argument("--audit-per-stratum", type=int, default=8)
    parser.add_argument("--require-success", action="store_true")
    args = parser.parse_args()
    run = args.accepted_run.resolve()
    out = args.out_dir.resolve()
    if out.exists() and any(out.iterdir()):
        print(f"output directory is non-empty: {out}", file=sys.stderr)
        return 3
    out.mkdir(parents=True, exist_ok=True)
    logs = out / "logs"
    logs.mkdir()
    try:
        facts = verify_accepted_run(run)
        source = out / "source_snapshot"
        source_rows = snapshot_sources(args.source_root.resolve(), source)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 4
    stages = []
    for name, command, timeout in build_stage_commands(
        preserve_python_executable(args.python), source, run, out, facts,
        seed=args.seed,
        calibration_limit=args.calibration_limit,
        audit_per_stratum=args.audit_per_stratum,
    ):
        stage = run_stage(name, command, timeout, args.source_root.resolve(), logs)
        stages.append(stage)
        if stage["returncode"] != 0:
            break
    success = len(stages) == 12 and all(stage["returncode"] == 0 for stage in stages)
    manifest = {
        "schema": EXTENSION_SCHEMA,
        "full_pipeline_schema": PIPELINE_SCHEMA,
        "success": success,
        "input": {
            "accepted_run": str(run),
            "pipeline_schema": facts["manifest_schema"],
            "pipeline_manifest_sha256": facts["manifest_sha256"],
            "targets": facts["targets"],
            "records": facts["records"],
            "residuals": facts["residuals"],
        },
        "source_snapshot_files": len(source_rows),
        "source_snapshot": source_rows,
        "stages": stages,
        "artifacts": artifact_identities(out),
    }
    (out / "extension_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "schema": EXTENSION_SCHEMA,
        "success": success,
        "stages": len(stages),
        "artifacts": len(manifest["artifacts"]),
        "records": facts["records"],
    }, indent=2, sort_keys=True))
    return 2 if args.require_success and not success else 0


if __name__ == "__main__":
    raise SystemExit(main())
