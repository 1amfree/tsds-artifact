#!/usr/bin/env python3
"""Audit TSDS campaign records against the paper's sink-evidence contract.

The audit is deliberately read-only. It does not rewrite campaign ledgers or
change reported verdicts. Instead, it separates directly observed sink-byte
evidence from dynamic reconciliation, static inference, and residual records,
then reports where the current aggregate label is stronger than its fields.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


DEFAULT_INPUT = Path(
    "experiment_reports/full_firmware_campaign_current_tsds_20260627"
)
DEFAULT_OUTPUT = Path("experiment_reports/evidence_contract_audit_current")

SINK_REACHED_STOPS = {
    "sink_callsite_in_block",
    "sink_address",
    "post_sink_delay_slot",
    "sink_capture_final",
    "sink_capture",
    "target_sink_reached",
}
STATIC_POSITIVE_RECOVERY = {
    "static_sink_template_fallback",
    "static_direct_source_fallback",
}
DYNAMIC_RECONCILIATION = {
    "static_dynamic_taint_reconciliation",
}
ADMISSIBLE_SHELL_SINK_SEMANTICS = {
    "shell_command",
    "shell_format_wrapper",
}
ADMISSIBLE_SINK_BINDING_TRUST = {
    "direct_abi_arg0",
    "rendered_format_wrapper",
}
RESIDUAL_STATUSES = {
    "unreachable",
    "timeout",
    "crashed",
    "eval_error",
    "state_error",
    "invalid_closure",
    "empty_trace",
}


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def sink_was_reached(record: dict[str, Any]) -> bool:
    """Return whether the ledger contains an observed target-sink reach."""
    if record.get("memoized"):
        return False
    if bool(record.get("sink_reached_observed")):
        return True
    if _as_int(record.get("no_taint_reaches")) > 0:
        return True
    if str(record.get("engine_stop_reason") or "") in SINK_REACHED_STOPS:
        return True
    # path_control_class is a derived reporting field. Historical ledgers also
    # assign direct_no_taint_evidence to static fixed-template shortcuts, so it
    # cannot independently establish that symbolic execution reached the sink.
    return False


def controlled_byte_count(record: dict[str, Any]) -> int:
    count = _as_int(record.get("tainted_byte_count"))
    if count:
        return count
    offsets = record.get("tainted_offsets") or record.get("controlled_offsets") or []
    return len(offsets) if isinstance(offsets, list) else 0


def _conditioned_tier(record: dict[str, Any], tier: str) -> str:
    conditioning = str(record.get("evidence_conditioning") or "unconditioned")
    if conditioning != "unconditioned":
        return f"{conditioning}_{tier}"
    return tier


def classify_evidence_tier(record: dict[str, Any]) -> str:
    """Classify a record by provenance, independently of its current label."""
    status = str(record.get("status") or "")
    recovery = str(record.get("analysis_recovery") or "")
    reached = sink_was_reached(record)
    controlled = controlled_byte_count(record)
    provenance = str(record.get("evidence_provenance") or "")
    tier = "other"

    if provenance == "SINK_RECONCILED":
        if status == "conditioned_feasibility":
            tier = "conditioned_template_feasibility"
        else:
            tier = "sink_reached_reconciliation" if status == "vulnerable" else "reconciled_residual"
    elif provenance == "STATIC_SOURCE_INFERENCE":
        tier = "static_source_slot_inference"
    elif provenance == "STATIC_WARNING_REDUCTION":
        tier = "static_warning_reduction"
    elif provenance == "RESIDUAL":
        tier = "residual"
    elif provenance == "DIRECT_SINK_BYTE":
        if status == "vulnerable":
            tier = "direct_prefix_sv_sat" if record.get("sink_snapshot_cstring_complete") is False else "direct_sv_sat"
        elif status == "filtered":
            tier = "direct_modeled_vector_filtered"
        elif status == "no_taint_sink":
            tier = "dynamic_nms"
        else:
            tier = "direct_sink_residual"
    elif status == "vulnerable":
        if recovery in STATIC_POSITIVE_RECOVERY or not reached:
            tier = "static_source_slot_inference"
        elif recovery in DYNAMIC_RECONCILIATION:
            tier = "sink_reached_reconciliation"
        elif reached and controlled > 0:
            tier = "direct_sv_sat"
        else:
            tier = "invalid_positive"
    elif status == "filtered":
        tier = "direct_modeled_vector_filtered" if reached and controlled > 0 else "invalid_filtered"
    elif status == "no_taint_sink":
        tier = "dynamic_nms" if reached else "static_warning_reduction"
    elif status in RESIDUAL_STATUSES:
        tier = "residual"
    elif status == "static_candidate":
        tier = "candidate_only"
    return _conditioned_tier(record, tier)


def contract_issues(record: dict[str, Any]) -> list[str]:
    """Return current-label invariants that are not supported by ledger fields."""
    if record.get("contract_violations"):
        return list(record.get("contract_violations") or [])
    status = str(record.get("status") or "")
    reached = sink_was_reached(record)
    controlled = controlled_byte_count(record)
    sink_semantics = str(record.get("sink_semantics") or "")
    binding_trust = str(record.get("sink_argument_binding_trust") or "")
    sink_name_source = str(record.get("sink_function_name_source") or "")
    analysis_version = str(record.get("analysis_version") or "")
    snapshot_complete = record.get("sink_snapshot_cstring_complete")
    issues: list[str] = []

    if status in {"vulnerable", "conditioned_feasibility", "filtered", "no_taint_sink"}:
        if (
            sink_semantics
            and sink_semantics not in ADMISSIBLE_SHELL_SINK_SEMANTICS
        ):
            issues.append("claim_without_admissible_shell_sink_semantics")
        if (
            binding_trust
            and binding_trust not in ADMISSIBLE_SINK_BINDING_TRUST
        ):
            issues.append("claim_without_admissible_sink_argument_binding")
        strict_sink_provenance = bool(
            re.match(
                r"^\d{4}-\d{2}-\d{2}-evidence-contract-v(?:1[5-9]|[2-9][0-9])-",
                analysis_version,
            )
        )
        if strict_sink_provenance and not sink_name_source:
            issues.append("claim_without_sink_name_provenance")
        if strict_sink_provenance and not sink_semantics:
            issues.append("claim_without_shell_sink_semantics")
        if strict_sink_provenance and not binding_trust:
            issues.append("claim_without_sink_argument_binding")
        if status in {"filtered", "no_taint_sink"} and snapshot_complete is False:
            issues.append("negative_claim_from_incomplete_sink_snapshot")

    if status == "vulnerable":
        if not reached:
            issues.append("positive_without_observed_sink_reach")
        if controlled <= 0:
            issues.append("positive_without_observed_controlled_offsets")
        if record.get("matrix_fast_static_reconciliation"):
            issues.append("positive_from_unconstrained_recovery_matrix")
        minimal = record.get("minimal_bypass_vector") or {}
        if not (
            minimal.get("grammar_complete")
            and (minimal.get("witness") or minimal.get("poc"))
        ):
            issues.append("positive_without_minimal_witness")
        if not minimal.get("parser_calibration"):
            issues.append("positive_without_parser_calibration")

    if status == "conditioned_feasibility":
        if provenance != "SINK_RECONCILED":
            issues.append("conditioned_without_reconciliation_provenance")
        if record.get("primary_aggregate_eligible") is True:
            issues.append("conditioned_claim_marked_primary")
        if not sink_was_reached(record):
            issues.append("conditioned_without_observed_sink_reach")

    if status == "filtered":
        if not reached:
            issues.append("filtered_without_observed_sink_reach")
        if controlled <= 0:
            issues.append("filtered_without_observed_controlled_offsets")
        if _as_int(record.get("inconclusive_vectors")) > 0:
            issues.append("filtered_with_inconclusive_vectors")

    if status == "no_taint_sink" and not reached:
        issues.append("nms_without_observed_sink_reach")
    conditioning = str(record.get("evidence_conditioning") or "unconditioned")
    if conditioning != "unconditioned" and record.get("primary_aggregate_eligible"):
        issues.append("conditioned_claim_marked_primary")
        if conditioning == "fixture_conditioned":
            issues.append("fixture_conditioned_claim_marked_primary")

    return issues


def iter_campaign_records(input_dir: Path) -> Iterable[dict[str, Any]]:
    files = sorted(input_dir.glob("*.results.jsonl"))
    if not files:
        raise FileNotFoundError(f"no *.results.jsonl files found under {input_dir}")
    for path in files:
        target = path.name.removesuffix(".results.jsonl")
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                record = json.loads(line)
                record["_audit_target"] = target
                record["_audit_source"] = str(path)
                record["_audit_line"] = line_no
                yield record


def audit_records(records: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    tier_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    recovery_counts: Counter[str] = Counter()
    issue_counts: Counter[str] = Counter()

    for record in records:
        tier = classify_evidence_tier(record)
        issues = contract_issues(record)
        status = str(record.get("status") or "unknown")
        recovery = str(record.get("analysis_recovery") or "direct_or_none")
        tier_counts[tier] += 1
        status_counts[status] += 1
        recovery_counts[recovery] += 1
        issue_counts.update(issues)
        rows.append(
            {
                "target": record.get("_audit_target"),
                "closure_idx": record.get("closure_idx"),
                "status": status,
                "evidence_tier": tier,
                "sink_reached": sink_was_reached(record),
                "controlled_bytes": controlled_byte_count(record),
                "sat_vectors": _as_int(record.get("vulnerable_vectors")),
                "unsat_vectors": _as_int(record.get("secure_vectors")),
                "sink_semantics": record.get("sink_semantics") or "",
                "binding_trust": record.get("sink_argument_binding_trust") or "",
                "captured_sink_function_name": record.get(
                    "captured_sink_function_name"
                ) or "",
                "sink_function_name_source": record.get(
                    "sink_function_name_source"
                ) or "",
                "snapshot_cstring_complete": record.get(
                    "sink_snapshot_cstring_complete"
                ),
                "evidence_conditioning": record.get("evidence_conditioning") or "unconditioned",
                "primary_aggregate_eligible": record.get("primary_aggregate_eligible"),
                "recovery": recovery,
                "stop_reason": record.get("engine_stop_reason") or "",
                "issues": ";".join(issues),
            }
        )

    summary = {
        "schema": "tsds-evidence-contract-audit-v1",
        "records": len(rows),
        "evidence_tiers": dict(sorted(tier_counts.items())),
        "current_statuses": dict(sorted(status_counts.items())),
        "recovery_modes": dict(sorted(recovery_counts.items())),
        "contract_issue_counts": dict(sorted(issue_counts.items())),
        "records_with_contract_issues": sum(1 for row in rows if row["issues"]),
        "claim_boundary": (
            "This is a provenance and invariant audit of existing analyzer ledgers; "
            "it does not establish device-level exploitability."
        ),
    }
    return rows, summary


def write_outputs(out_dir: Path, rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "evidence_contract_audit.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    fields = list(rows[0]) if rows else []
    with (out_dir / "evidence_contract_records.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# TSDS evidence-contract audit",
        "",
        summary["claim_boundary"],
        "",
        f"- Records: `{summary['records']}`",
        f"- Records with current-label issues: `{summary['records_with_contract_issues']}`",
        "",
        "## Evidence tiers",
        "",
        "| Tier | Records |",
        "|---|---:|",
    ]
    for name, count in summary["evidence_tiers"].items():
        lines.append(f"| `{name}` | {count} |")
    lines.extend(["", "## Contract issues", "", "| Issue | Records |", "|---|---:|"])
    for name, count in summary["contract_issue_counts"].items():
        lines.append(f"| `{name}` | {count} |")
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--fail-on-contract-issues",
        action="store_true",
        help="return exit code 2 when current aggregate labels violate an invariant",
    )
    args = parser.parse_args()

    rows, summary = audit_records(iter_campaign_records(args.input_dir))
    write_outputs(args.out_dir, rows, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    if args.fail_on_contract_issues and summary["records_with_contract_issues"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
