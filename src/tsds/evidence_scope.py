"""Typed evidence scope and abstention-aware summaries for TSDS.

This module is deliberately independent of angr, claripy, and the evaluator.
It defines the boundary between a selected sink-instance observation and a
candidate-level conclusion.  Unknown values are retained; callers must not
coerce them to ``False`` when computing binary metrics.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any, Iterable, Mapping, Sequence


EVIDENCE_SCOPE_SCHEMA = "tsds-evidence-scope-v1"

TRI_STATES = frozenset(
    {"CONFIRMED", "CONTRADICTED", "UNKNOWN", "NOT_APPLICABLE"}
)
EVIDENCE_MODES = frozenset({"direct", "conditioned", "local", "static", "residual"})
LOCAL_PROFILES = frozenset({"sv_sat", "ct_sat", "m_filt", "nms", "local_unknown"})
CANDIDATE_STATUSES = frozenset(
    {
        "direct_evidence",
        "conditioned_feasibility",
        "selected_instance_profile",
        "static_observation",
        "residual_obligation",
    }
)
MATRIX_DECISIONS = frozenset({"VECTOR_SAT", "MATRIX_UNSAT", "INCONCLUSIVE"})
TRI_FIELDS = (
    "input_effect",
    "instance_source_realizable",
    "matrix_feasible",
    "bounded_program_effect_exists",
    "candidate_vulnerability",
)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _has_text(record: Mapping[str, Any], key: str) -> bool:
    value = record.get(key)
    return isinstance(value, str) and bool(value.strip())


def _unique_texts(value: Any) -> tuple[list[str], list[str]]:
    if not isinstance(value, list):
        return [], ["not_a_list"]
    values = [str(item) for item in value]
    issues: list[str] = []
    if any(not item.strip() for item in values):
        issues.append("empty_item")
    if len(values) != len(set(values)):
        issues.append("duplicate_item")
    return values, issues


def _valid_state(record: Mapping[str, Any], field: str) -> list[str]:
    value = record.get(field)
    if not isinstance(value, str) or value not in TRI_STATES:
        return [f"invalid_{field}"]
    return []


def _matrix_issues(record: Mapping[str, Any]) -> list[str]:
    matrix = record.get("matrix")
    if not isinstance(matrix, Mapping):
        return ["missing_matrix"]

    expected, expected_issues = _unique_texts(matrix.get("expected_vector_ids"))
    decisions = matrix.get("decisions")
    issues = [f"matrix_expected_{issue}" for issue in expected_issues]
    if not expected:
        issues.append("matrix_expected_vector_ids_empty")
    if not isinstance(decisions, list):
        return issues + ["matrix_decisions_not_a_list"]
    if not decisions:
        issues.append("matrix_decisions_empty")

    decision_ids: list[str] = []
    decision_values: list[str] = []
    for index, row in enumerate(decisions):
        if not isinstance(row, Mapping):
            issues.append(f"matrix_decision_{index}_not_an_object")
            continue
        vector_id = str(row.get("vector_id") or "")
        decision = str(row.get("decision") or "")
        decision_ids.append(vector_id)
        decision_values.append(decision)
        if not vector_id:
            issues.append(f"matrix_decision_{index}_missing_vector_id")
        if decision not in MATRIX_DECISIONS:
            issues.append(f"matrix_decision_{index}_invalid_decision")

    if len(decision_ids) != len(set(decision_ids)):
        issues.append("matrix_duplicate_vector_id")
    if set(expected) != set(decision_ids):
        issues.append("matrix_vector_set_mismatch")
    if matrix.get("complete") is not True:
        issues.append("matrix_not_complete")
    if decision_values and any(value != "MATRIX_UNSAT" for value in decision_values):
        issues.append("matrix_contains_non_unsat_decision")
    return sorted(set(issues))


def validate_scope_record(record: Mapping[str, Any]) -> list[str]:
    """Return scope-contract violations for one new-format record.

    The validator is intentionally conservative.  It checks admission and
    quantifier metadata, not whether a solver or a firmware execution was
    semantically correct.  That semantic question requires the corresponding
    query/model or runtime receipt.
    """

    if not isinstance(record, Mapping):
        return ["record_not_an_object"]

    issues: list[str] = []
    if record.get("schema") != EVIDENCE_SCOPE_SCHEMA:
        issues.append("unsupported_schema")
    for field in ("candidate_id", "instance_id"):
        if not _has_text(record, field):
            issues.append(f"missing_{field}")
    mode = str(record.get("evidence_mode") or "")
    profile = str(record.get("local_profile") or "")
    candidate_status = str(record.get("candidate_status") or "")
    if mode not in EVIDENCE_MODES:
        issues.append("invalid_evidence_mode")
    if profile not in LOCAL_PROFILES:
        issues.append("invalid_local_profile")
    if candidate_status not in CANDIDATE_STATUSES:
        issues.append("invalid_candidate_status")
    for field in TRI_FIELDS:
        issues.extend(_valid_state(record, field))

    if mode == "direct":
        if profile != "sv_sat":
            issues.append("direct_requires_sv_sat_profile")
        if candidate_status != "direct_evidence":
            issues.append("direct_requires_direct_status")
        if record.get("direct_provenance") is not True:
            issues.append("direct_requires_observed_provenance")
        if record.get("source_link_status") not in {"observed", "linked"}:
            issues.append("direct_requires_source_link")
    elif mode == "conditioned":
        if profile != "ct_sat":
            issues.append("conditioned_requires_ct_sat_profile")
        if candidate_status != "conditioned_feasibility":
            issues.append("conditioned_requires_conditioned_status")
        if record.get("primary_aggregate_eligible") is True:
            issues.append("conditioned_primary_eligible")
        if record.get("source_link_status") not in {
            "linked",
            "unlinked",
            "ambiguous",
            "unknown",
        }:
            issues.append("conditioned_requires_link_status")
    elif mode == "local":
        if candidate_status != "selected_instance_profile":
            issues.append("local_requires_selected_instance_status")
        if profile not in {"m_filt", "nms", "local_unknown"}:
            issues.append("local_requires_local_profile")
        if record.get("candidate_vulnerability") == "CONTRADICTED":
            issues.append("local_profile_cannot_be_candidate_negative")
        if profile == "m_filt":
            issues.extend(_matrix_issues(record))
    elif mode == "static":
        if candidate_status != "static_observation":
            issues.append("static_requires_static_status")
        if profile not in {"local_unknown", "nms"}:
            issues.append("static_requires_non_dynamic_profile")
    elif mode == "residual":
        if candidate_status != "residual_obligation":
            issues.append("residual_requires_residual_status")
        if profile != "local_unknown":
            issues.append("residual_requires_unknown_profile")

    if record.get("evidence_mode") != "direct" and record.get("direct_provenance") is True:
        issues.append("direct_provenance_mode_mismatch")
    if record.get("candidate_vulnerability") == "CONTRADICTED" and mode in {
        "conditioned",
        "local",
        "static",
        "residual",
    }:
        issues.append("non_direct_candidate_negative_claim")
    return sorted(set(issues))


def scope_identity(record: Mapping[str, Any]) -> tuple[str, str]:
    """Return the candidate/instance identity used for duplicate detection."""

    return (str(record.get("candidate_id") or ""), str(record.get("instance_id") or ""))


def scope_fingerprint(record: Mapping[str, Any]) -> str:
    """Hash stable scope fields without treating a preview as a command identity."""

    fields = {
        key: record.get(key)
        for key in (
            "schema",
            "candidate_id",
            "instance_id",
            "evidence_mode",
            "local_profile",
            "candidate_status",
            "source_link_status",
            "direct_provenance",
            "matrix",
            "input_effect",
            "instance_source_realizable",
            "matrix_feasible",
            "bounded_program_effect_exists",
            "candidate_vulnerability",
        )
    }
    return hashlib.sha256(_canonical_json(fields).encode("utf-8")).hexdigest()


def tri_state_counts(
    records: Iterable[Mapping[str, Any]], field: str
) -> dict[str, int]:
    """Count all declared states, including abstentions and invalid values."""

    counts = Counter()
    for record in records:
        value = record.get(field)
        counts[str(value) if isinstance(value, str) and value in TRI_STATES else "INVALID"] += 1
    return {state: int(counts[state]) for state in sorted(counts)}


def scoped_binary_metrics(
    pairs: Iterable[tuple[str, str]],
) -> dict[str, Any]:
    """Summarize a tri-valued prediction/truth pairing without false negatives.

    ``resolved_accuracy`` is computed only on pairs whose prediction and truth
    are both CONFIRMED or CONTRADICTED.  ``full_accuracy`` is intentionally
    ``None`` whenever any pair is abstained or not applicable.
    """

    rows = [(str(prediction), str(truth)) for prediction, truth in pairs]
    invalid = [
        row
        for row in rows
        if row[0] not in TRI_STATES or row[1] not in TRI_STATES
    ]
    resolved = [
        row
        for row in rows
        if row[0] in {"CONFIRMED", "CONTRADICTED"}
        and row[1] in {"CONFIRMED", "CONTRADICTED"}
    ]
    unresolved = len(rows) - len(resolved)
    resolved_accuracy = (
        sum(prediction == truth for prediction, truth in resolved) / len(resolved)
        if resolved
        else None
    )
    return {
        "records": len(rows),
        "resolved_records": len(resolved),
        "abstained_or_not_applicable": unresolved,
        "invalid_records": len(invalid),
        "coverage": len(resolved) / len(rows) if rows else None,
        "resolved_accuracy": resolved_accuracy,
        "full_accuracy": (
            resolved_accuracy if rows and unresolved == 0 and not invalid else None
        ),
        "claim_boundary": (
            "Unknown and not-applicable rows are retained; no binary metric is "
            "reported as complete coverage when an abstention remains."
        ),
    }


def conservation_summary(
    records: Sequence[Mapping[str, Any]], expected_total: int | None = None
) -> dict[str, Any]:
    """Summarize new-format records and enforce candidate/instance conservation."""

    identities = [scope_identity(record) for record in records]
    duplicate_count = sum(count - 1 for count in Counter(identities).values() if count > 1)
    issues = [
        issue
        for record in records
        for issue in validate_scope_record(record)
    ]
    mode_counts = Counter(str(record.get("evidence_mode") or "INVALID") for record in records)
    profile_counts = Counter(str(record.get("local_profile") or "INVALID") for record in records)
    if expected_total is not None and len(records) != expected_total:
        issues.append("record_total_mismatch")
    if duplicate_count:
        issues.append("duplicate_candidate_instance")
    return {
        "schema": EVIDENCE_SCOPE_SCHEMA,
        "records": len(records),
        "unique_candidates": len({candidate for candidate, _instance in identities if candidate}),
        "unique_instances": len(set(identities)),
        "duplicate_candidate_instance": duplicate_count,
        "mode_counts": dict(sorted((key, int(value)) for key, value in mode_counts.items())),
        "profile_counts": dict(sorted((key, int(value)) for key, value in profile_counts.items())),
        "tri_state_counts": {
            field: tri_state_counts(records, field) for field in TRI_FIELDS
        },
        "records_with_issues": sum(
            bool(validate_scope_record(record)) for record in records
        ),
        "issues": sorted(set(issues)),
        "valid": not issues,
        "candidate_wide_negative_count": sum(
            record.get("candidate_vulnerability") == "CONTRADICTED"
            for record in records
        ),
        "claim_boundary": (
            "Records preserve selected-instance scope and tri-valued obligations. "
            "A valid record is structurally admissible; it is not a solver proof "
            "or device-level vulnerability ground truth."
        ),
    }
