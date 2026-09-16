#!/usr/bin/env python3
"""Verify the content-addressed TSDS v10 pipeline manifest.

The verifier checks source code, firmware/candidate inputs, and generated
artifacts against the SHA-256 identities recorded by the pipeline. It is a
bit-level reproducibility check, independent of any vulnerability claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_entry(entry: dict[str, Any], base: Path, category: str) -> dict[str, Any]:
    declared = Path(str(entry["path"]))
    path = declared if declared.is_absolute() else base / declared
    row = {
        "category": category,
        "path": str(path),
        "expected_sha256": entry.get("sha256"),
        "actual_sha256": None,
        "expected_size": entry.get("size"),
        "actual_size": None,
        "outcome": "ok",
    }
    if not path.is_file():
        row["outcome"] = "missing"
        return row
    row["actual_size"] = path.stat().st_size
    row["actual_sha256"] = sha256_file(path)
    if row["actual_size"] != row["expected_size"]:
        row["outcome"] = "size_mismatch"
    if row["actual_sha256"] != row["expected_sha256"]:
        row["outcome"] = "sha256_mismatch" if row["outcome"] == "ok" else "size_and_sha256_mismatch"
    return row


def verify_manifest(
    manifest_path: Path,
    root_override: Path | None = None,
    out_override: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    root = (root_override or Path(manifest["root"])).resolve()
    out_dir = (out_override or Path(manifest["out_dir"])).resolve()
    reproducibility = manifest.get("reproducibility") or {}
    pipeline_schema = str(manifest.get("schema") or "")
    run_lock_required = pipeline_schema.startswith("tsds-v17-")
    invocation = [str(value) for value in manifest.get("invocation") or []]
    repeatability_lock_required = (
        pipeline_schema == "tsds-v17-pipeline-v5"
        and "--require-sink-semantic-repeatability" in invocation
    )
    exclusive_run_lock = manifest.get("exclusive_run_lock") or {}
    exclusive_run_lock_valid = (
        pipeline_schema != "tsds-v17-pipeline-v5"
        or (
            exclusive_run_lock.get("schema") == "tsds-exclusive-run-lock-v1"
            and str(exclusive_run_lock.get("mode") or "").endswith(
                "exclusive_nonblocking"
            )
            and isinstance(exclusive_run_lock.get("pid"), int)
            and bool(exclusive_run_lock.get("path"))
        )
    )
    execution_root_raw = str(reproducibility.get("source_execution_root") or "")
    execution_snapshot_declared = bool(execution_root_raw)
    source_base = root
    source_execution_root_valid = True
    if execution_root_raw:
        declared_root = Path(execution_root_raw)
        if declared_root.is_absolute() or ".." in declared_root.parts:
            source_execution_root_valid = False
        else:
            source_base = (out_dir / declared_root).resolve()
            if out_dir not in source_base.parents and source_base != out_dir:
                source_execution_root_valid = False
                source_base = root
    rows: list[dict[str, Any]] = []
    python_executable = reproducibility.get("python_executable")
    if python_executable:
        rows.append(verify_entry(python_executable, root, "python_executable"))
    for entry in reproducibility.get("source_files") or []:
        rows.append(verify_entry(entry, source_base, "execution_source"))
    repeatability = reproducibility.get("repeatability_baseline") or {}
    repeatability_execution_path = str(repeatability.get("execution_path") or "")
    repeatability_snapshot_declared = bool(
        repeatability_execution_path and repeatability.get("files")
    )
    repeatability_snapshot_valid = True
    repeatability_base = out_dir
    if repeatability_snapshot_declared:
        declared = Path(repeatability_execution_path)
        if declared.is_absolute() or ".." in declared.parts:
            repeatability_snapshot_valid = False
        else:
            repeatability_base = (out_dir / declared).resolve()
            if out_dir not in repeatability_base.parents:
                repeatability_snapshot_valid = False
        declared_files = repeatability.get("files") or []
        payload = json.dumps(
            declared_files, sort_keys=True, separators=(",", ":")
        ).encode()
        if hashlib.sha256(payload).hexdigest() != repeatability.get(
            "aggregate_sha256"
        ):
            repeatability_snapshot_valid = False
        if repeatability_snapshot_valid:
            for entry in declared_files:
                rows.append(
                    verify_entry(
                        entry,
                        repeatability_base,
                        "repeatability_baseline_snapshot",
                    )
                )
    for target in reproducibility.get("campaign_inputs") or []:
        for kind in ("binary", "mango"):
            if target.get(kind):
                row = verify_entry(target[kind], root, f"input:{target.get('target')}:{kind}")
                rows.append(row)
    calibration = reproducibility.get("resource_calibration")
    if calibration:
        calibration_execution_path = str(
            reproducibility.get("resource_calibration_execution_path") or ""
        )
        calibration_base = root
        calibration_entry = calibration
        if calibration_execution_path:
            declared = Path(calibration_execution_path)
            if not declared.is_absolute() and ".." not in declared.parts:
                calibration_base = out_dir
                calibration_entry = dict(calibration)
                calibration_entry["path"] = calibration_execution_path
        rows.append(
            verify_entry(
                calibration_entry, calibration_base, "resource_calibration"
            )
        )
    for entry in manifest.get("artifacts") or []:
        rows.append(verify_entry(entry, out_dir, "artifact"))
    outcomes: dict[str, int] = {}
    for row in rows:
        outcomes[row["outcome"]] = outcomes.get(row["outcome"], 0) + 1
    pipeline_success = manifest.get("success")
    identity_drift = manifest.get("identity_drift") or {}
    run_identity_stable = (
        identity_drift.get("stable") is True
        and execution_snapshot_declared
        and source_execution_root_valid
        and exclusive_run_lock_valid
        if run_lock_required
        else identity_drift.get("stable") is not False
    )
    pipeline_accepted = pipeline_success is not False
    summary = {
        "schema": "tsds-artifact-manifest-verification-v1",
        "claim_boundary": (
            "This verifies bit-level identity of declared artifacts. It does not "
            "independently validate analyzer semantics or device exploitability."
        ),
        "manifest": str(manifest_path),
        "root": str(root),
        "out_dir": str(out_dir),
        "checked": len(rows),
        "outcomes": outcomes,
        "pipeline_schema": pipeline_schema,
        "pipeline_accepted": pipeline_accepted,
        "run_lock_required": run_lock_required,
        "repeatability_lock_required": repeatability_lock_required,
        "exclusive_run_lock_valid": exclusive_run_lock_valid,
        "repeatability_snapshot_declared": repeatability_snapshot_declared,
        "repeatability_snapshot_valid": repeatability_snapshot_valid,
        "execution_snapshot_declared": execution_snapshot_declared,
        "source_execution_root": str(source_base),
        "source_execution_root_valid": source_execution_root_valid,
        "run_identity_stable": run_identity_stable,
        "verified": (
            all(row["outcome"] == "ok" for row in rows)
            and pipeline_accepted
            and run_identity_stable
            and (not repeatability_lock_required or repeatability_snapshot_declared)
            and repeatability_snapshot_valid
        ),
    }
    return rows, summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--root-override", type=Path)
    parser.add_argument("--artifact-root-override", type=Path)
    parser.add_argument("--fail-on-mismatch", action="store_true")
    args = parser.parse_args()
    rows, summary = verify_manifest(
        args.manifest, args.root_override, args.artifact_root_override
    )
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "artifact_manifest_verification.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.out_dir / "artifact_manifest_verification.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
    )
    (args.out_dir / "README.md").write_text(
        "# TSDS artifact-manifest verification\n\n"
        f"Checked: **{summary['checked']}**; verified: **{summary['verified']}**.\n\n"
        + summary["claim_boundary"] + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["verified"] or not args.fail_on_mismatch else 2


if __name__ == "__main__":
    raise SystemExit(main())
