#!/usr/bin/env python3
"""Audit the final-C-string boundary of historical conditioned records.

The historical V20 release contains reconstructed templates and broad taint
offsets, but not serialized source-to-sink links.  This read-only audit keeps
those facts separate: it checks snapshot metadata and reports whether the
recorded offset set stays inside the visible C string.  It never infers a link
from a template, prefix, or offset list.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tsds.reconciliation_link import reconciliation_link_admission  # noqa: E402


SCHEMA = "tsds-historical-v20-conditioned-snapshot-boundary-audit-v1"
DEFAULT_INPUT = Path(
    "experiment_reports/tsds_v20_release_20260718_r7_v8/"
    "tsds_v20_accepted_repeat_20260718_r7/campaign"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _offsets(value: Any) -> list[int]:
    if not isinstance(value, list):
        return []
    result: list[int] = []
    for item in value:
        parsed = _integer(item)
        if parsed is not None and parsed >= 0:
            result.append(parsed)
    return sorted(set(result))


def is_conditioned(record: dict[str, Any]) -> bool:
    return (
        record.get("evidence_provenance") == "SINK_RECONCILED"
        or record.get("analysis_recovery") == "static_dynamic_taint_reconciliation"
        or record.get("verdict") == "CT_SAT"
    )


def analyze_record(
    record: dict[str, Any],
    *,
    target: str = "",
    line: int | None = None,
) -> dict[str, Any]:
    terminator = _integer(record.get("sink_snapshot_terminator_offset"))
    capture_length = _integer(record.get("sink_snapshot_capture_length"))
    controlled = _offsets(record.get("controlled_offsets") or record.get("tainted_offsets"))
    issues: list[str] = []
    if record.get("sink_snapshot_cstring_complete") is not True:
        issues.append("incomplete_sink_snapshot")
    if terminator is None or terminator < 0:
        issues.append("terminator_offset_missing_or_invalid")
    if capture_length is None or terminator is None or capture_length != terminator + 1:
        issues.append("capture_length_not_terminator_plus_one")
    if not record.get("recovered_sink_template"):
        issues.append("recovered_template_missing")
    if not record.get("recovered_source_prefix"):
        issues.append("recovered_source_prefix_missing")
    if (_integer(record.get("recovery_path_constraint_count")) or 0) <= 0:
        issues.append("recovery_path_constraints_missing")
    if record.get("matrix_reconciled_constrained") is not True:
        issues.append("matrix_reconciliation_flag_missing")

    outside = (
        [offset for offset in controlled if terminator is not None and offset >= terminator]
        if terminator is not None
        else list(controlled)
    )
    inside = (
        [offset for offset in controlled if terminator is not None and offset < terminator]
        if terminator is not None
        else []
    )
    source_after_terminator = _offsets(record.get("source_after_terminator_offsets"))
    if source_after_terminator:
        issues.append("source_after_terminator_metadata_present")
    admission = reconciliation_link_admission(
        record.get("reconciliation_link"), record=record
    )
    if outside:
        boundary_status = "outside_final_cstring"
    elif inside:
        boundary_status = "inside_final_cstring"
    else:
        boundary_status = "no_controlled_offsets"
    return {
        "target": target,
        "line": line,
        "closure_idx": record.get("closure_idx"),
        "verdict": record.get("verdict"),
        "status": record.get("status"),
        "evidence_provenance": record.get("evidence_provenance"),
        "analysis_recovery": record.get("analysis_recovery"),
        "sink_snapshot_cstring_complete": record.get("sink_snapshot_cstring_complete"),
        "capture_length": capture_length,
        "terminator_offset": terminator,
        "controlled_offset_count": len(controlled),
        "inside_final_cstring_count": len(inside),
        "outside_final_cstring_count": len(outside),
        "source_after_terminator_count": len(source_after_terminator),
        "recovered_template_present": bool(record.get("recovered_sink_template")),
        "recovered_source_prefix_present": bool(record.get("recovered_source_prefix")),
        "recovery_path_constraint_count": _integer(
            record.get("recovery_path_constraint_count")
        ),
        "matrix_reconciled_constrained": record.get("matrix_reconciled_constrained"),
        "reconciliation_link_present": isinstance(
            record.get("reconciliation_link"), dict
        ),
        "reconciliation_link_admitted": bool(admission.get("admitted")),
        "reconciliation_link_issues": list(admission.get("issues") or []),
        "boundary_status": boundary_status,
        "issues": sorted(set(issues)),
    }


def iter_records(campaign: Path) -> Iterable[tuple[str, int, dict[str, Any]]]:
    for path in sorted(campaign.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1
        ):
            if not line.strip():
                continue
            record = json.loads(line)
            if isinstance(record, dict) and is_conditioned(record):
                yield target, line_number, record


def audit(campaign: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = [
        analyze_record(record, target=target, line=line)
        for target, line, record in iter_records(campaign)
    ]
    if not rows:
        raise ValueError("no conditioned records found")
    metadata_issues = [row for row in rows if row["issues"]]
    summary = {
        "schema": SCHEMA,
        "input_campaign": str(campaign),
        "input_configuration_sha256": sha256_file(campaign / "campaign_configuration.json")
        if (campaign / "campaign_configuration.json").is_file()
        else None,
        "records": len(rows),
        "complete_snapshots": sum(
            row["sink_snapshot_cstring_complete"] is True for row in rows
        ),
        "terminator_capture_consistent": sum(
            "capture_length_not_terminator_plus_one" not in row["issues"]
            for row in rows
        ),
        "recovered_template_records": sum(
            row["recovered_template_present"] for row in rows
        ),
        "recovered_source_prefix_records": sum(
            row["recovered_source_prefix_present"] for row in rows
        ),
        "positive_recovery_constraint_records": sum(
            (row["recovery_path_constraint_count"] or 0) > 0 for row in rows
        ),
        "matrix_reconciled_records": sum(
            row["matrix_reconciled_constrained"] is True for row in rows
        ),
        "records_with_offsets_inside_final_cstring": sum(
            row["inside_final_cstring_count"] > 0 for row in rows
        ),
        "records_with_offsets_outside_final_cstring": sum(
            row["outside_final_cstring_count"] > 0 for row in rows
        ),
        "records_with_source_after_terminator": sum(
            row["source_after_terminator_count"] > 0 for row in rows
        ),
        "reconciliation_links_present": sum(
            row["reconciliation_link_present"] for row in rows
        ),
        "reconciliation_links_admitted": sum(
            row["reconciliation_link_admitted"] for row in rows
        ),
        "metadata_issue_records": len(metadata_issues),
        "metadata_issues": sorted(
            {issue for row in rows for issue in row["issues"]}
        ),
        "valid": not metadata_issues,
        "claim_boundary": (
            "This audit checks historical conditioned snapshot metadata and the "
            "visible final-C-string boundary. It does not infer a source link "
            "from a reconstructed template, prefix, taint interval, or matrix "
            "result; it does not prove historical solver semantics or exploitability."
        ),
    }
    return rows, summary


def write_outputs(out_dir: Path, rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "conditioned_snapshot_boundary.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "README.md").write_text(
        "# Historical conditioned snapshot-boundary audit\n\n"
        + summary["claim_boundary"]
        + "\n\n"
        + f"- Conditioned records: `{summary['records']}`.\n"
        + f"- Complete snapshots: `{summary['complete_snapshots']}`; terminator/capture agreement: `{summary['terminator_capture_consistent']}`.\n"
        + f"- Rows with offsets inside the visible C string: `{summary['records_with_offsets_inside_final_cstring']}`; rows with offsets at/after the terminator: `{summary['records_with_offsets_outside_final_cstring']}`.\n"
        + f"- Serialized reconciliation links present/admitted: `{summary['reconciliation_links_present']}/{summary['reconciliation_links_admitted']}`.\n"
        + "- No source link was inferred and no shell was executed.\n",
        encoding="utf-8",
    )
    digest_lines = []
    for path in sorted(out_dir.iterdir()):
        if path.name != "SHA256SUMS" and path.is_file():
            digest_lines.append(f"{sha256_file(path)}  {path.name}")
    (out_dir / "SHA256SUMS").write_text("\n".join(digest_lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    rows, summary = audit(args.input_dir.resolve())
    write_outputs(args.out_dir.resolve(), rows, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
