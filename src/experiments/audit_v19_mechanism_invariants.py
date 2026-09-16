#!/usr/bin/env python3
"""Audit P0/P1/P2 ledger invariants independently of the TSDS evaluator."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "tsds-v19-mechanism-invariant-audit-v1"
SINK_VERDICTS = {"VECTOR_SAT", "MATRIX_UNSAT", "NO_MODELED_SOURCE"}
CONTROLLED_VERDICTS = {"VECTOR_SAT", "MATRIX_UNSAT"}
SCHEDULER_SCHEMAS = {
    "tsds-evidence-aware-scheduler-v1",
    "tsds-evidence-aware-scheduler-v2",
    "tsds-evidence-aware-scheduler-v3",
}


def normalized_offsets(values: Iterable[Any]) -> list[int]:
    return sorted(
        {
            int(value)
            for value in values
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        }
    )


def load_configuration(campaign: Path) -> dict[str, Any]:
    path = campaign / "campaign_configuration.json"
    if not path.is_file():
        raise ValueError(f"missing campaign configuration: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("campaign configuration is not an object")
    return value


def iter_records(campaign: Path):
    found = False
    for path in sorted(campaign.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            found = True
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError(f"record is not an object: {path}:{line_number}")
            yield target, line_number, record
    if not found:
        raise ValueError(f"no campaign records found: {campaign}")


def _integer(record: dict[str, Any], key: str) -> int:
    try:
        return int(record.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def _positive_reason_count(value: Any) -> int:
    if not isinstance(value, dict):
        return 0
    total = 0
    for reason, count in value.items():
        if not isinstance(reason, str) or not reason:
            continue
        try:
            amount = int(count or 0)
        except (TypeError, ValueError):
            continue
        total += max(0, amount)
    return total


def record_issues(record: dict[str, Any], arguments: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    verdict = str(record.get("verdict") or "")
    provenance = str(record.get("evidence_provenance") or "")
    static_reduction = verdict == "STATIC_WARNING_REDUCTION" or provenance == "STATIC_WARNING_REDUCTION"
    scheduler_enabled = not bool(arguments.get("no_evidence_aware_scheduler"))
    corridor_enabled = not bool(arguments.get("no_sink_corridor"))
    projection_enabled = not bool(arguments.get("no_source_projected_constraints"))
    byte_provenance_enabled = not bool(arguments.get("no_byte_provenance"))
    plugins_enabled = not bool(arguments.get("no_sink_semantic_plugins"))
    expected_backend = str(arguments.get("execution_backend") or "forkserver")

    if record.get("evidence_contract_valid") is not True:
        issues.append("evidence_contract_invalid")
    conditioning = str(record.get("evidence_conditioning") or "unconditioned")
    summary_events = record.get("summary_runtime_events") or []
    summary_origins = {
        str(item.get("origin") or "")
        for item in summary_events
        if isinstance(item, dict) and item.get("origin")
    }
    if summary_events:
        expected_conditioning = (
            "refinement_conditioned"
            if "residual_cegar" in summary_origins
            else "summary_conditioned"
        )
        if expected_conditioning not in conditioning:
            issues.append("executed_summary_without_matching_conditioning")
        if record.get("primary_aggregate_eligible") is not False:
            issues.append("executed_summary_marked_primary")
        if "residual_cegar" in summary_origins and not record.get(
            "evidence_refinement_bundle_sha256"
        ):
            issues.append("refinement_conditioning_without_bundle_digest")
    if conditioning != "unconditioned" and record.get(
        "primary_aggregate_eligible"
    ) is not False:
        issues.append("conditioned_record_marked_primary")
    if not static_reduction:
        if str(record.get("execution_backend") or "") != expected_backend:
            issues.append("execution_backend_mismatch")
        if scheduler_enabled:
            if record.get("engine_scheduler_schema") not in SCHEDULER_SCHEMAS:
                issues.append("enabled_scheduler_ledger_missing")
        elif record.get("engine_scheduler_schema"):
            issues.append("disabled_scheduler_emitted_ledger")
        if corridor_enabled and not isinstance(record.get("engine_sink_corridor"), dict):
            issues.append("enabled_sink_corridor_ledger_missing")
        if not corridor_enabled and record.get("engine_sink_corridor"):
            issues.append("disabled_sink_corridor_emitted_ledger")

        if record.get("engine_scheduler_schema") == (
            "tsds-evidence-aware-scheduler-v3"
        ):
            suppressions = _integer(
                record, "engine_source_liveness_stop_suppressions"
            )
            reason_count = _positive_reason_count(
                record.get("engine_source_liveness_stop_suppression_reasons")
            )
            if suppressions and not reason_count:
                issues.append("liveness_suppression_reasons_missing")
            elif reason_count and reason_count < suppressions:
                issues.append("liveness_suppression_reason_count_underflow")

    if verdict in CONTROLLED_VERDICTS:
        decisions = record.get("vector_decisions") or record.get("threat_matrix_decisions") or []
        if not decisions:
            issues.append("controlled_verdict_without_vector_decisions")
        if projection_enabled:
            full_constraints = _integer(record, "matrix_projection_full_constraints")
            selected_constraints = _integer(record, "matrix_projection_selected_constraints")
            if full_constraints <= 0 or selected_constraints <= 0:
                issues.append("enabled_projection_accounting_missing")
            if selected_constraints > full_constraints:
                issues.append("projection_selected_exceeds_full")
            if verdict == "VECTOR_SAT" and _integer(
                record, "matrix_projection_full_validations"
            ) <= 0:
                issues.append("projected_sat_without_full_validation")
            if verdict == "MATRIX_UNSAT" and _integer(
                record, "matrix_projection_unsat_shortcuts"
            ) <= 0:
                issues.append("matrix_unsat_without_projected_shortcut")
        elif any(
            _integer(record, key)
            for key in (
                "matrix_projection_full_constraints",
                "matrix_projection_selected_constraints",
                "matrix_projection_unsat_shortcuts",
                "matrix_projection_full_validations",
            )
        ):
            issues.append("disabled_projection_emitted_accounting")

        if byte_provenance_enabled:
            digest = str(record.get("byte_provenance_graph_sha256") or "")
            if len(digest) != 64:
                issues.append("enabled_byte_provenance_digest_missing")
            if _integer(record, "byte_provenance_node_count") <= 0:
                issues.append("enabled_byte_provenance_nodes_missing")
            controlled = normalized_offsets(record.get("controlled_offsets") or [])
            graph_controlled = normalized_offsets(
                record.get("byte_provenance_controlled_offsets") or []
            )
            if not set(controlled).issubset(graph_controlled):
                issues.append("byte_provenance_active_offsets_not_covered")
            boundary_only = sorted(set(graph_controlled) - set(controlled))
            terminator = record.get("matrix_snapshot_terminator_offset")
            allowed_boundary = (
                [int(terminator)]
                if record.get("matrix_snapshot_cstring_complete") is True
                and isinstance(terminator, int)
                and not isinstance(terminator, bool)
                else []
            )
            if boundary_only and boundary_only != allowed_boundary:
                issues.append("byte_provenance_nonboundary_lineage_offset")
        elif record.get("byte_provenance_graph_sha256"):
            issues.append("disabled_byte_provenance_emitted_graph")

    if verdict in SINK_VERDICTS:
        if plugins_enabled:
            if not record.get("sink_semantic_plugin"):
                issues.append("enabled_sink_semantic_plugin_missing")
            if not isinstance(record.get("sink_semantic_contract"), dict):
                issues.append("enabled_sink_semantic_contract_missing")
        elif record.get("sink_semantic_plugin") or record.get("sink_semantic_contract"):
            issues.append("disabled_sink_semantic_plugin_emitted_contract")

    refinement = record.get("online_refinement") or {}
    rounds = refinement.get("rounds") or []
    if int(arguments.get("online_refinement_rounds") or 0) == 0 and rounds:
        issues.append("disabled_online_refinement_emitted_rounds")
    if len(rounds) > int(arguments.get("online_refinement_rounds") or 0):
        issues.append("online_refinement_round_budget_exceeded")
    candidate_limit = int(arguments.get("online_refinement_candidates") or 0)
    if any(len(item.get("candidate_ids") or []) > candidate_limit for item in rounds):
        issues.append("online_refinement_candidate_budget_exceeded")

    expected_limit = int(arguments.get("subprocess_memory_limit_mib") or 0)
    if _integer(record, "subprocess_memory_limit_mib") != expected_limit:
        issues.append("subprocess_memory_limit_mismatch")
    return sorted(set(issues))


def audit_campaign(campaign: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    configuration = load_configuration(campaign)
    arguments = configuration.get("arguments") or {}
    rows = []
    issue_counts: Counter[str] = Counter()
    verdicts: Counter[str] = Counter()
    versions: Counter[str] = Counter()
    structural_static_reductions = 0
    for target, line_number, record in iter_records(campaign):
        issues = record_issues(record, arguments)
        issue_counts.update(issues)
        verdict = str(record.get("verdict") or "UNKNOWN")
        verdicts[verdict] += 1
        versions[str(record.get("analysis_version") or "missing")] += 1
        if verdict == "STATIC_WARNING_REDUCTION" and not record.get("engine_scheduler_schema"):
            structural_static_reductions += 1
        rows.append(
            {
                "target": target,
                "line_number": line_number,
                "closure_idx": record.get("closure_idx"),
                "verdict": verdict,
                "analysis_version": record.get("analysis_version"),
                "issues": ";".join(issues),
            }
        )
    summary = {
        "schema": SCHEMA,
        "campaign": str(campaign),
        "records": len(rows),
        "records_with_issues": sum(bool(row["issues"]) for row in rows),
        "issue_counts": dict(sorted(issue_counts.items())),
        "verdicts": dict(sorted(verdicts.items())),
        "analysis_versions": dict(sorted(versions.items())),
        "static_reductions_without_dynamic_scheduler": structural_static_reductions,
        "configuration_arguments": arguments,
        "valid": bool(rows) and not issue_counts,
        "claim_boundary": (
            "This audit checks serialized P0/P1/P2 mechanism invariants and resource "
            "configuration; it does not independently solve path constraints."
        ),
    }
    return rows, summary


def write_outputs(out_dir: Path, rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "v19_mechanism_invariant_audit.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (out_dir / "v19_mechanism_invariant_records.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "README.md").write_text(
        "# TSDS v19 mechanism-invariant audit\n\n"
        f"Valid: **{summary['valid']}**; records: **{summary['records']}**; "
        f"records with issues: **{summary['records_with_issues']}**.\n\n"
        + summary["claim_boundary"]
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--fail-on-issues", action="store_true")
    args = parser.parse_args()
    try:
        rows, summary = audit_campaign(args.campaign.resolve())
        write_outputs(args.out_dir.resolve(), rows, summary)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"V19_MECHANISM_AUDIT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.fail_on_issues and not summary["valid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
