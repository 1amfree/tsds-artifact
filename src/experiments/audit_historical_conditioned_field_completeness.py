#!/usr/bin/env python3
"""Audit the fields available for historical conditioned source replay.

The historical V20 ledger contains reconstructed templates and recovery
metadata, but it may not contain the serialized source variables, transform
chain, or per-byte source-to-sink map required by the current reconciliation
link contract.  This read-only audit records that distinction explicitly.  It
never synthesizes a link and never promotes a historical result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from tsds.reconciliation_link import reconciliation_link_admission


SCHEMA = "tsds-historical-conditioned-field-completeness-audit-v1"
DEFAULT_CAMPAIGN = Path(
    "experiment_reports/tsds_v20_release_20260718_r7_v8"
    "/tsds_v20_accepted_repeat_20260718_r7/campaign"
)
DEFAULT_OUTPUT = Path(
    "paper_work/iceccs_historical_conditioned_field_completeness_20260916"
)

LINK_FIELDS = (
    "reconciliation_link",
    "source_variables",
    "source_variable_sha256",
    "transform_chain",
    "transform_chain_sha256",
    "source_to_sink",
    "source_to_sink_sha256",
    "program_sha256",
    "sink_snapshot_sha256",
    "input_contract",
    "sink_cstring",
    "link_sha256",
)

TRACE_FIELDS = (
    "trace_nodes",
    "trace_len",
    "trace_summary",
    "byte_provenance_graph_sha256",
    "byte_provenance_node_count",
    "byte_provenance_edge_count",
    "byte_provenance_source_node_count",
    "byte_provenance_controlled_offsets",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def offsets(value: Any) -> list[int]:
    if not isinstance(value, (list, tuple)):
        return []
    result: list[int] = []
    for item in value:
        parsed = integer(item)
        if parsed is not None:
            result.append(parsed)
    return sorted(set(result))


def conditioned(record: dict[str, Any]) -> bool:
    return bool(
        record.get("evidence_provenance") == "SINK_RECONCILED"
        or record.get("analysis_recovery") == "static_dynamic_taint_reconciliation"
        or record.get("verdict") == "CT_SAT"
    )


def records(campaign: Path) -> Iterable[tuple[str, int, dict[str, Any]]]:
    for path in sorted(campaign.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            if not line.strip():
                continue
            value = json.loads(line)
            if isinstance(value, dict) and conditioned(value):
                yield target, line_number, value


def field_present(value: Any) -> bool:
    return value not in (None, "", [], {})


def audit_row(target: str, line_number: int, record: dict[str, Any]) -> dict[str, Any]:
    present_link_fields = [
        field for field in LINK_FIELDS if field_present(record.get(field))
    ]
    link = record.get("reconciliation_link")
    admission = reconciliation_link_admission(link, record=record)

    terminator = integer(record.get("sink_snapshot_terminator_offset"))
    capture_length = integer(record.get("sink_snapshot_capture_length"))
    complete = record.get("sink_snapshot_cstring_complete") is True
    boundary_consistent = (
        terminator is not None
        and capture_length is not None
        and capture_length == terminator + 1
    )
    controlled = offsets(record.get("controlled_offsets"))
    if not controlled:
        controlled = offsets(record.get("tainted_offsets"))
    inside = [item for item in controlled if terminator is not None and item < terminator]
    outside = [item for item in controlled if terminator is not None and item >= terminator]
    after_terminator_metadata = offsets(record.get("source_after_terminator_offsets"))

    trace = record.get("trace_nodes")
    trace_has_byte_map = any(
        field_present(record.get(field))
        for field in ("source_to_sink", "byte_origin_map", "origin_map", "source_byte_mapping")
    )
    issues: list[str] = []
    if present_link_fields:
        issues.append("record_contains_partial_link_fields")
    if not isinstance(link, dict):
        issues.append("serialized_reconciliation_link_absent")
    if not complete:
        issues.append("final_cstring_not_marked_complete")
    if not boundary_consistent:
        issues.append("capture_terminator_boundary_inconsistent")
    if outside:
        issues.append("controlled_offsets_reach_or_cross_terminator")
    if not trace_has_byte_map:
        issues.append("trace_has_no_serialized_per_byte_mapping")

    return {
        "target": target,
        "line_number": line_number,
        "closure_idx": record.get("closure_idx"),
        "source_addr": record.get("source_addr"),
        "sink_addr": record.get("sink_addr"),
        "status": record.get("status"),
        "verdict": record.get("verdict"),
        "evidence_provenance": record.get("evidence_provenance"),
        "analysis_recovery": record.get("analysis_recovery"),
        "recovery_constraint_mode": record.get("recovery_constraint_mode"),
        "recovery_path_constraint_count": integer(
            record.get("recovery_path_constraint_count")
        ),
        "recovered_template_present": field_present(
            record.get("recovered_sink_template")
        ),
        "recovered_prefix_present": field_present(
            record.get("recovered_source_prefix")
        ),
        "trace_nodes_present": field_present(trace),
        "trace_node_count": len(trace) if isinstance(trace, list) else 0,
        "trace_has_serialized_per_byte_mapping": trace_has_byte_map,
        "link_fields_present": present_link_fields,
        "link_field_count": len(present_link_fields),
        "reconciliation_link_present": isinstance(link, dict),
        "reconciliation_link_admitted": bool(admission.get("admitted")),
        "reconciliation_link_issues": list(admission.get("issues") or []),
        "sink_snapshot_cstring_complete": complete,
        "sink_snapshot_terminator_offset": terminator,
        "sink_snapshot_capture_length": capture_length,
        "sink_snapshot_boundary_consistent": boundary_consistent,
        "controlled_offset_count": len(controlled),
        "controlled_offsets_inside_final_cstring": len(inside),
        "controlled_offsets_at_or_after_terminator": len(outside),
        "source_after_terminator_metadata_count": len(after_terminator_metadata),
        "issues": sorted(set(issues)),
        "claim_boundary": (
            "Historical conditioned template metadata only; no source-realizability "
            "or firmware exploitability claim."
        ),
    }


def audit(campaign: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = [audit_row(*item) for item in records(campaign)]
    if not rows:
        raise ValueError("no conditioned records found")
    issue_counts = Counter(
        issue for row in rows for issue in row.get("issues", [])
    )
    summary = {
        "schema": SCHEMA,
        "input_campaign": str(campaign.resolve()),
        "input_campaign_sha256": sha256_file(campaign / "campaign_configuration.json")
        if (campaign / "campaign_configuration.json").is_file()
        else None,
        "records": len(rows),
        "positive_records": sum(row["status"] == "vulnerable" for row in rows),
        "residual_records": sum(row["status"] == "residual" for row in rows),
        "serialized_link_records": sum(row["reconciliation_link_present"] for row in rows),
        "admitted_link_records": sum(row["reconciliation_link_admitted"] for row in rows),
        "records_with_any_link_field": sum(bool(row["link_fields_present"]) for row in rows),
        "records_with_complete_link_field_set": sum(
            set(row["link_fields_present"]) == set(LINK_FIELDS) for row in rows
        ),
        "records_with_source_to_sink_mapping": sum(
            "source_to_sink" in row["link_fields_present"] for row in rows
        ),
        "records_with_transform_chain": sum(
            "transform_chain" in row["link_fields_present"] for row in rows
        ),
        "records_with_source_variables": sum(
            "source_variables" in row["link_fields_present"] for row in rows
        ),
        "trace_nodes_present": sum(row["trace_nodes_present"] for row in rows),
        "trace_mappings_present": sum(
            row["trace_has_serialized_per_byte_mapping"] for row in rows
        ),
        "recovery_constraint_records": sum(
            (row["recovery_path_constraint_count"] or 0) > 0 for row in rows
        ),
        "complete_snapshots": sum(row["sink_snapshot_cstring_complete"] for row in rows),
        "terminator_capture_consistent": sum(
            row["sink_snapshot_boundary_consistent"] for row in rows
        ),
        "records_with_offsets_inside_final_cstring": sum(
            row["controlled_offsets_inside_final_cstring"] > 0 for row in rows
        ),
        "records_with_offsets_at_or_after_terminator": sum(
            row["controlled_offsets_at_or_after_terminator"] > 0 for row in rows
        ),
        "records_with_source_after_terminator_metadata": sum(
            row["source_after_terminator_metadata_count"] > 0 for row in rows
        ),
        "issue_counts": dict(sorted(issue_counts.items())),
        "all_checks_pass": all(
            row["sink_snapshot_cstring_complete"]
            and row["sink_snapshot_boundary_consistent"]
            and not row["reconciliation_link_admitted"]
            for row in rows
        ),
        "no_links_synthesized": True,
        "claim_boundary": (
            "This read-only audit distinguishes historical reconstructed-template "
            "metadata from the serialized fields required for source-to-sink replay. "
            "It does not infer missing links, prove solver semantics, establish "
            "firmware ground truth, or establish device-level exploitability."
        ),
    }
    return rows, summary


def write_outputs(output: Path, rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    summary_path = output / "summary.json"
    rows_path = output / "field_completeness.jsonl"
    readme_path = output / "README.md"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    rows_path.write_text(
        "".join(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    readme_path.write_text(
        "# Historical conditioned field-completeness audit\n\n"
        + summary["claim_boundary"]
        + "\n\n"
        + f"- Conditioned records: `{summary['records']}` (`{summary['positive_records']}` vulnerable, `{summary['residual_records']}` residual).\n"
        + f"- Serialized links present/admitted: `{summary['serialized_link_records']}/{summary['admitted_link_records']}`.\n"
        + f"- Complete C-string snapshots and consistent boundaries: `{summary['complete_snapshots']}/{summary['terminator_capture_consistent']}`.\n"
        + f"- Records with a serialized source-to-sink map: `{summary['records_with_source_to_sink_mapping']}`.\n"
        + f"- Records with offsets at or after the terminator: `{summary['records_with_offsets_at_or_after_terminator']}`.\n"
        + "- No link was synthesized and no shell was executed.\n",
        encoding="utf-8",
    )
    sums = []
    for path in (summary_path, rows_path, readme_path):
        sums.append(f"{sha256_file(path)}  {path.name}")
    (output / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, default=DEFAULT_CAMPAIGN)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    rows, summary = audit(args.campaign.resolve())
    write_outputs(args.out_dir.resolve(), rows, summary)
    print(json.dumps(summary, ensure_ascii=True, indent=2, sort_keys=True))
    return 0 if summary["all_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
