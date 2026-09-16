#!/usr/bin/env python3
"""Reconcile the historical V20 ledger with its retained release inputs.

This is a read-only provenance audit.  It checks that the eight raw campaign
JSONL files, the campaign configuration, and the aggregate referenced by the
V20 release fetch manifest are present and byte-identical.  It then compares
raw JSONL row counts and aggregate counters with the independently recomputed
matrix-profile audit.  The audit does not re-run symbolic execution, validate
solver semantics, establish source realizability, or claim exploitability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA = "tsds-historical-v20-source-reconciliation-v1"
CLAIM_BOUNDARY = (
    "This audit checks release-file integrity and accounting reconciliation only. "
    "It does not validate solver semantics, source realizability, exhaustive "
    "path coverage, or device exploitability."
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl_count(path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected JSON object")
            count += 1
    return count


def fetch_entries(fetch_manifest: dict[str, Any], release_key: str) -> dict[str, dict[str, Any]]:
    downloads = fetch_manifest.get("downloads")
    if not isinstance(downloads, dict) or release_key not in downloads:
        raise ValueError(f"fetch manifest does not contain release {release_key!r}")
    entries = downloads[release_key]
    if not isinstance(entries, list):
        raise ValueError(f"fetch manifest release {release_key!r} is not a list")
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("path"):
            raise ValueError("fetch manifest contains an invalid file entry")
        path = str(entry["path"])
        if path in result:
            raise ValueError(f"duplicate fetch-manifest path: {path}")
        result[path] = entry
    return result


def compare_release_file(
    path: Path, relative_path: str, entries: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    entry = entries.get(relative_path)
    actual_hash = sha256_file(path) if path.is_file() else None
    actual_size = path.stat().st_size if path.is_file() else None
    expected_hash = str(entry.get("sha256")) if entry else None
    expected_size = int(entry["size"]) if entry and entry.get("size") is not None else None
    return {
        "path": relative_path,
        "exists": path.is_file(),
        "actual_sha256": actual_hash,
        "expected_sha256": expected_hash,
        "sha256_match": bool(actual_hash and expected_hash and actual_hash == expected_hash),
        "actual_size": actual_size,
        "expected_size": expected_size,
        "size_match": bool(actual_size is not None and expected_size is not None and actual_size == expected_size),
        "manifest_entry_present": entry is not None,
    }


def reconcile(
    campaign_dir: Path,
    fetch_manifest_path: Path,
    matrix_audit_path: Path,
    aggregate_path: Path,
    release_key: str = "tsds_v20_accepted_repeat_20260718_r7",
) -> dict[str, Any]:
    fetch_manifest = load_json(fetch_manifest_path)
    matrix_audit = load_json(matrix_audit_path)
    aggregate = load_json(aggregate_path)
    entries = fetch_entries(fetch_manifest, release_key)

    result_paths = sorted(campaign_dir.glob("*.results.jsonl"))
    raw_counts = {
        path.stem.removesuffix(".results"): load_jsonl_count(path)
        for path in result_paths
    }
    required_paths = [
        f"campaign/{path.name}" for path in result_paths
    ] + ["campaign/campaign_configuration.json", "campaign/full_campaign_aggregate.json"]
    release_files = [
        compare_release_file(campaign_dir / path.removeprefix("campaign/"), path, entries)
        if path.startswith("campaign/")
        else {"path": path, "exists": False}
        for path in required_paths
    ]

    aggregate_targets = aggregate.get("targets")
    if not isinstance(aggregate_targets, list):
        raise ValueError("campaign aggregate has no target list")
    aggregate_by_target = {
        str(item.get("target")): item
        for item in aggregate_targets
        if isinstance(item, dict) and item.get("target")
    }
    aggregate_rows = {
        target: int(item.get("evaluated") or 0)
        for target, item in aggregate_by_target.items()
    }
    aggregate_checks = {
        "target_names_match": sorted(raw_counts) == sorted(aggregate_rows),
        "target_row_counts_match": raw_counts == aggregate_rows,
        "evaluated_sum": sum(aggregate_rows.values()),
        "vector_sat_sum": sum(int(item.get("vector_sat") or 0) for item in aggregate_by_target.values()),
        "matrix_unsat_sum": sum(int(item.get("matrix_unsat") or 0) for item in aggregate_by_target.values()),
        "no_taint_sink_sum": sum(int(item.get("no_taint_sink") or 0) for item in aggregate_by_target.values()),
        "contract_residual_sum": sum(int(item.get("contract_residual") or 0) for item in aggregate_by_target.values()),
        "static_source_inference_sum": sum(int(item.get("static_source_inference") or 0) for item in aggregate_by_target.values()),
        "static_warning_reduction_sum": sum(int(item.get("static_warning_reduction") or 0) for item in aggregate_by_target.values()),
    }
    expected_aggregate = {
        "evaluated_sum": 518,
        "vector_sat_sum": 85,
        "matrix_unsat_sum": 3,
        "no_taint_sink_sum": 58,
        "contract_residual_sum": 237,
        "static_source_inference_sum": 15,
        "static_warning_reduction_sum": 120,
    }
    aggregate_checks["expected_counters_match"] = all(
        aggregate_checks[key] == value for key, value in expected_aggregate.items()
    )

    matrix_checks = {
        "record_count_matches_raw": matrix_audit.get("record_count") == sum(raw_counts.values()),
        "target_count_matches_raw": matrix_audit.get("target_count") == len(raw_counts),
        "target_record_counts_match_raw": matrix_audit.get("target_record_counts") == raw_counts,
        "matrix_profile_count": matrix_audit.get("matrix_profile_count"),
        "matrix_cell_count": matrix_audit.get("matrix_cell_count"),
        "matrix_profile_count_expected": matrix_audit.get("matrix_profile_count") == 102,
        "matrix_cell_count_expected": matrix_audit.get("matrix_cell_count") == 1122,
        "matrix_audit_valid": matrix_audit.get("valid") is True and not matrix_audit.get("issues"),
    }
    file_checks_pass = all(
        item["exists"]
        and item["manifest_entry_present"]
        and item["sha256_match"]
        and item["size_match"]
        for item in release_files
    )
    issues: list[str] = []
    if len(result_paths) != 8:
        issues.append("result_file_count_not_8")
    if not file_checks_pass:
        issues.append("release_file_integrity_mismatch")
    if not aggregate_checks["target_names_match"]:
        issues.append("aggregate_target_names_mismatch")
    if not aggregate_checks["target_row_counts_match"]:
        issues.append("aggregate_target_row_counts_mismatch")
    if not aggregate_checks["expected_counters_match"]:
        issues.append("aggregate_counter_mismatch")
    if not matrix_checks["record_count_matches_raw"] or not matrix_checks["target_record_counts_match_raw"]:
        issues.append("matrix_audit_raw_count_mismatch")
    if not matrix_checks["matrix_profile_count_expected"] or not matrix_checks["matrix_cell_count_expected"]:
        issues.append("matrix_denominator_mismatch")
    if not matrix_checks["matrix_audit_valid"]:
        issues.append("matrix_audit_invalid")

    return {
        "schema": SCHEMA,
        "claim_boundary": CLAIM_BOUNDARY,
        "release_key": release_key,
        "campaign_dir": str(campaign_dir),
        "input_hashes": {
            "fetch_manifest": sha256_file(fetch_manifest_path),
            "matrix_audit": sha256_file(matrix_audit_path),
            "aggregate": sha256_file(aggregate_path),
        },
        "raw_result_files": len(result_paths),
        "raw_record_counts": raw_counts,
        "raw_record_total": sum(raw_counts.values()),
        "release_file_checks": release_files,
        "file_integrity_pass": file_checks_pass,
        "aggregate_checks": aggregate_checks,
        "expected_aggregate_counters": expected_aggregate,
        "matrix_checks": matrix_checks,
        "issues": sorted(set(issues)),
        "valid": not issues,
    }


def write_outputs(out_dir: Path, report: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "source_reconciliation.json"
    summary_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Historical V20 source reconciliation",
        "",
        f"Valid: **{report['valid']}**",
        f"Raw result files: **{report['raw_result_files']}**",
        f"Raw records: **{report['raw_record_total']}**",
        f"Release-file integrity: **{report['file_integrity_pass']}**",
        f"Matrix denominator: **{report['matrix_checks']['matrix_profile_count']} profiles / {report['matrix_checks']['matrix_cell_count']} cells**",
        "",
        CLAIM_BOUNDARY,
        "",
        "The release-file checks cover the eight raw `*.results.jsonl` files, the campaign configuration, and the campaign aggregate. Historical V20 accounting is separate from the current query-export ledger.",
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out_dir / "SHA256SUMS").write_text(
        f"{sha256_file(summary_path)}  source_reconciliation.json\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--fetch-manifest", type=Path, required=True)
    parser.add_argument("--matrix-audit", type=Path, required=True)
    parser.add_argument("--aggregate", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = reconcile(
            args.campaign_dir.resolve(),
            args.fetch_manifest.resolve(),
            args.matrix_audit.resolve(),
            args.aggregate.resolve(),
        )
        write_outputs(args.out_dir.resolve(), report)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"V20_SOURCE_RECONCILIATION_ERROR: {exc}")
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
