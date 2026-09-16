#!/usr/bin/env python3
"""Audit whether the frozen V20 result files serialize multi-state evidence.

This is an evidence-only schema audit.  It distinguishes an unavailable
serialized field from an empty multi-state collection and therefore cannot
establish First-Ready coverage for the historical run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from pathlib import Path
from typing import Any


MULTI_STATE_FIELDS = (
    "multi_state_audit",
    "multi_state_selection",
    "primary_selection",
    "profiles",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def audit_campaign(campaign_dir: Path, expected_targets: int | None = None) -> dict[str, Any]:
    paths = sorted(campaign_dir.glob("*.results.jsonl"))
    issues: list[str] = []
    if expected_targets is not None and len(paths) != expected_targets:
        issues.append("target_file_count_mismatch")
    if not paths:
        issues.append("no_result_files")

    rows = 0
    sink_reached = 0
    malformed_rows = 0
    field_presence = {field: 0 for field in MULTI_STATE_FIELDS}
    vector_lengths: dict[str, int] = {}
    active_states: list[int] = []
    files: list[dict[str, Any]] = []

    for path in paths:
        file_rows = 0
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            issues.append(f"file_unreadable:{path.name}")
            continue
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                malformed_rows += 1
                issues.append(f"malformed_json:{path.name}:{line_number}")
                continue
            if not isinstance(value, dict):
                malformed_rows += 1
                issues.append(f"row_not_object:{path.name}:{line_number}")
                continue
            rows += 1
            file_rows += 1
            if value.get("sink_reached_observed") is True:
                sink_reached += 1
            for field in MULTI_STATE_FIELDS:
                if field in value:
                    field_presence[field] += 1
            vector_decisions = value.get("vector_decisions")
            if isinstance(vector_decisions, list):
                key = str(len(vector_decisions))
                vector_lengths[key] = vector_lengths.get(key, 0) + 1
            active_state_count = _int(value.get("engine_exit_active_states"))
            if active_state_count is not None:
                active_states.append(active_state_count)
        try:
            digest = sha256_file(path)
            size = path.stat().st_size
        except OSError:
            digest = None
            size = None
        files.append(
            {
                "name": path.name,
                "bytes": size,
                "rows": file_rows,
                "sha256": digest,
            }
        )

    vector_rows = sum(vector_lengths.values())
    vector_length_ok = vector_rows == 0 or (
        len(vector_lengths) == 1 and vector_lengths.get("11") == vector_rows
    )
    if not vector_length_ok:
        issues.append("vector_decision_lengths_not_11")

    active_summary: dict[str, Any] = {
        "records_with_value": len(active_states),
        "missing_records": rows - len(active_states),
        "zero": sum(value == 0 for value in active_states),
        "one": sum(value == 1 for value in active_states),
        "more_than_one": sum(value > 1 for value in active_states),
        "median": statistics.median(active_states) if active_states else None,
        "max": max(active_states) if active_states else None,
        "interpretation": (
            "engine_exit_active_states is worker-termination metadata; it is not "
            "a count of accepted sink captures or a proof of exhaustive coverage"
        ),
    }
    multi_state_serialized = any(field_presence.values())
    result = {
        "schema": "tsds-historical-v20-multistate-schema-audit-v1",
        "campaign_dir": str(campaign_dir),
        "result_file_count": len(paths),
        "record_count": rows,
        "sink_reached_observed_true": sink_reached,
        "malformed_rows": malformed_rows,
        "file_inventory": files,
        "field_presence": field_presence,
        "vector_decision_lengths": vector_lengths,
        "vector_decision_rows": vector_rows,
        "engine_exit_active_states": active_summary,
        "serialized_multistate_selection_available": multi_state_serialized,
        "selection_coverage_auditable_from_v20_files": False,
        "claim_boundary": (
            "The frozen V20 JSONL files are auditable for their recorded fields, "
            "but they do not serialize multi-state profiles or First-Ready "
            "selection metadata. This report therefore does not infer empty "
            "coverage, reconstruct missing sink states, or establish solver, "
            "source-realizability, firmware-precision, or exploitability claims."
        ),
        "issues": sorted(set(issues)),
        "valid": not issues and not multi_state_serialized,
    }
    return result


def write_outputs(out_dir: Path, result: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "schema_audit.json"
    summary_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Historical V20 multi-state schema audit",
        "",
        f"Valid: **{result['valid']}**",
        f"Result files: **{result['result_file_count']}**",
        f"Records: **{result['record_count']}**",
        f"Rows with serialized multi-state fields: **{sum(result['field_presence'].values())}**",
        f"Rows with complete 11-entry vector decisions: **{result['vector_decision_lengths'].get('11', 0)}**",
        "",
        "The frozen V20 files do not contain serialized multi-state profiles or First-Ready selection metadata.",
        "The active-state cardinality field is diagnostic metadata, not exhaustive sink-state coverage.",
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    digest = hashlib.sha256(summary_path.read_bytes()).hexdigest()
    (out_dir / "SHA256SUMS").write_text(f"{digest}  schema_audit.json\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--expected-targets", type=int, default=None)
    args = parser.parse_args()
    try:
        result = audit_campaign(args.campaign_dir.resolve(), args.expected_targets)
        write_outputs(args.out_dir.resolve(), result)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"HISTORICAL_V20_SCHEMA_AUDIT_ERROR: {exc}")
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
