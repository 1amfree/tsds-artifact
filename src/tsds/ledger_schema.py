"""Versioned structural validation for TSDS JSONL ledger records."""

from __future__ import annotations

import re
from typing import Any, Mapping


LEDGER_SCHEMA = "tsds-ledger-schema-v1"

BASE_REQUIRED = (
    "status",
    "analysis_version",
    "evidence_contract_schema",
    "evidence_contract_valid",
    "evidence_provenance",
    "verdict",
    "admissible_claim",
    "closure_idx",
)
CLAIM_STATUSES = frozenset({"vulnerable", "conditioned_feasibility", "filtered", "no_taint_sink"})


def _has(record: Mapping[str, Any], key: str) -> bool:
    return key in record and record.get(key) not in (None, "")


def validate_ledger_record(record: Mapping[str, Any]) -> list[str]:
    """Return structural violations; semantic proofs remain certificate work."""

    record = record or {}
    issues: list[str] = []
    for field in BASE_REQUIRED:
        if not _has(record, field):
            issues.append(f"missing_{field}")
    version = str(record.get("analysis_version") or "")
    status = str(record.get("status") or "")
    if re.match(
        r"^\d{4}-\d{2}-\d{2}-evidence-contract-v(?:1[6-9]|[2-9][0-9])-", version
    ):
        for field in (
            "evidence_conditioning",
            "primary_aggregate_eligible",
            "subprocess_memory_limit_mib",
            "resource_limit_enforcement",
        ):
            if not _has(record, field):
                issues.append(f"missing_v16plus_{field}")
        unavailable_metric = (
            record.get("process_resource_metric_scope")
            == "unavailable_worker_terminated"
        )
        if not unavailable_metric and not _has(record, "process_peak_rss_mib"):
            issues.append("missing_v16plus_process_peak_rss_mib")
        if unavailable_metric and not _has(record, "process_resource_metric_reason"):
            issues.append("unavailable_worker_metric_without_reason")
        enforcement = str(record.get("resource_limit_enforcement") or "")
        if enforcement == "worker_required":
            issues.append("unresolved_worker_memory_limit_enforcement")
    if re.match(
        r"^\d{4}-\d{2}-\d{2}-evidence-contract-v(?:1[7-9]|[2-9][0-9])-", version
    ):
        for field in ("resource_limit_hit", "process_resource_metric_scope"):
            if not _has(record, field):
                issues.append(f"missing_v17plus_{field}")
    if status in CLAIM_STATUSES:
        for field in (
            "sink_reached_observed",
            "sink_semantics",
            "sink_argument_binding_trust",
            "sink_function_name_source",
        ):
            if not _has(record, field):
                issues.append(f"missing_claim_{field}")
    conditioning = str(record.get("evidence_conditioning") or "unconditioned")
    if conditioning != "unconditioned" and record.get("primary_aggregate_eligible"):
        issues.append("conditioned_primary_eligible")
        if conditioning == "fixture_conditioned":
            issues.append("fixture_conditioned_primary_eligible")
    return sorted(set(issues))


def schema_summary(records: list[Mapping[str, Any]]) -> dict[str, Any]:
    issue_counts: dict[str, int] = {}
    bad = 0
    for record in records:
        row_issues = validate_ledger_record(record)
        bad += int(bool(row_issues))
        for issue in row_issues:
            issue_counts[issue] = issue_counts.get(issue, 0) + 1
    return {
        "schema": LEDGER_SCHEMA,
        "records": len(records),
        "records_with_issues": bad,
        "issue_counts": dict(sorted(issue_counts.items())),
        "claim_boundary": (
            "Schema validation checks artifact structure and conditioning metadata; "
            "it does not prove symbolic-analysis semantics or exploitability."
        ),
    }
