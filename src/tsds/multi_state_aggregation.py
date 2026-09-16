"""Bounded multi-state aggregation for TSDS sink profiles.

The execution engine may expose more than one sink snapshot for a closure,
but a bounded collection is not a proof that the complete path space was
enumerated.  This module keeps existential positive evidence separate from
non-positive observations and never manufactures a candidate-wide negative
claim from a local collection.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any, Iterable, Mapping, Sequence

from tsds.shell_matrix_spec import VECTOR_IDS


MULTI_STATE_AGGREGATION_SCHEMA = "tsds-bounded-multi-state-aggregation-v2"

# A profile may contain a complete matrix and still be conditioned, synthetic,
# or otherwise ineligible for the direct evidence aggregate.  Keep the direct
# admission vocabulary explicit at this boundary instead of inferring it from
# a legacy status string.
_DIRECT_PROVENANCE = frozenset({
    "direct_sink_byte",
    "direct_observed_sink_byte",
    "observed_sink_snapshot",
})
_DIRECT_MODES = frozenset({"d", "direct"})
_DIRECT_SCOPES = frozenset({"direct", "direct_observed", "observed"})

# These states mean that a seed hypothesis was actually processed.  A
# bounded audit may still be complete over its declared seed set without
# finding a positive profile; it is never complete when a seed was deferred,
# pruned, or failed before producing an observation.
_COMPLETED_SEED_STATUSES = {
    "sink_states_collected",
    "sink_source_dependent",
    "sink_no_source_dependency",
    "sink_snapshot_non_admissible",
    "sink_no_taint_recovery",
    "engine_completed_without_sink",
}


def _decision_rows(profile: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rows = profile.get("vector_decisions")
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, Mapping)]


def _decision_counts(profile: Mapping[str, Any]) -> dict[str, int]:
    counts = Counter(str(row.get("decision") or "UNKNOWN") for row in _decision_rows(profile))
    for key in ("VECTOR_SAT", "MATRIX_UNSAT", "INCONCLUSIVE"):
        counts.setdefault(key, 0)
    return {key: int(counts[key]) for key in sorted(counts)}


def _matrix_complete(profile: Mapping[str, Any]) -> bool:
    """Return true only when the producer explicitly closes the vector matrix."""

    expected = profile.get("expected_vector_ids")
    rows = _decision_rows(profile)
    if profile.get("matrix_complete") is not True:
        return False
    if not isinstance(expected, list) or not expected or len(expected) != len(rows):
        return False
    expected_ids = [str(value) for value in expected]
    observed_ids = [str(row.get("vector_id") or "") for row in rows]
    return (
        len(expected_ids) == len(set(expected_ids))
        and all(expected_ids)
        and tuple(expected_ids) == VECTOR_IDS
        and expected_ids == observed_ids
        and all(str(row.get("decision") or "") in {"VECTOR_SAT", "MATRIX_UNSAT", "INCONCLUSIVE"} for row in rows)
    )


def _profile_issues(profile: Mapping[str, Any]) -> list[str]:
    """Check that summary counts agree with decisions before classifying a profile."""

    rows = _decision_rows(profile)
    counts = _decision_counts(profile)
    issues: list[str] = []
    for field, decision in (
        ("vulnerable_vectors", "VECTOR_SAT"),
        ("secure_vectors", "MATRIX_UNSAT"),
        ("inconclusive_vectors", "INCONCLUSIVE"),
    ):
        if field not in profile:
            continue
        try:
            reported = int(profile.get(field) or 0)
        except (TypeError, ValueError):
            issues.append(f"invalid_{field}")
            continue
        if reported != counts.get(decision, 0):
            issues.append(f"{field}_does_not_match_decisions")
    if rows:
        vector_ids = [str(row.get("vector_id") or "") for row in rows]
        if any(not vector_id for vector_id in vector_ids):
            issues.append("decision_missing_vector_id")
        if len(vector_ids) != len(set(vector_ids)):
            issues.append("duplicate_decision_vector_id")
        if any(
            str(row.get("decision") or "")
            not in {"VECTOR_SAT", "MATRIX_UNSAT", "INCONCLUSIVE"}
            for row in rows
        ):
            issues.append("unsupported_decision")
    else:
        for field in ("vulnerable_vectors", "secure_vectors", "inconclusive_vectors"):
            try:
                reported = int(profile.get(field) or 0)
            except (TypeError, ValueError):
                reported = 0
            if reported > 0:
                issues.append("summary_counts_without_decisions")
                break
    status = str(profile.get("status") or "").lower()
    if (
        status
        in {"matrix_unsat", "m-filt", "m_filt", "filtered", "vector_sat", "inconclusive"}
        and not _matrix_complete(profile)
    ):
        issues.append("matrix_not_complete")
    return sorted(set(issues))


def profile_fingerprint(profile: Mapping[str, Any]) -> str:
    """Return a stable digest for the command, constraints, and vector profile.

    State order and the ordinal ``state_index`` are intentionally excluded.  A
    producer should provide the command/constraint/source digests; legacy
    profiles remain usable but are marked by their older, weaker fields.
    """

    rows = []
    for row in _decision_rows(profile):
        rows.append(_canonicalize(row))
    payload = {
        "status": str(profile.get("status") or ""),
        "evidence_provenance": str(profile.get("evidence_provenance") or ""),
        "sink_function": str(profile.get("sink_function") or ""),
        "sink_addr": str(profile.get("sink_addr") or ""),
        "sink_snapshot_source": str(profile.get("sink_snapshot_source") or ""),
        "mode": str(profile.get("mode") or profile.get("evidence_mode") or ""),
        "evidence_scope_mode": str(profile.get("evidence_scope_mode") or ""),
        "evidence_conditioning": str(profile.get("evidence_conditioning") or ""),
        "primary_aggregate_eligible": profile.get("primary_aggregate_eligible"),
        "claimable": profile.get("claimable"),
        "claimability_reason": str(profile.get("claimability_reason") or ""),
        "snapshot_digest": str(profile.get("snapshot_digest") or ""),
        "snapshot_digest_schema": str(profile.get("snapshot_digest_schema") or ""),
        "command_digest": str(profile.get("command_digest") or ""),
        "constraint_digest": str(profile.get("constraint_digest") or ""),
        "source_variable_digest": str(profile.get("source_variable_digest") or ""),
        "cstring_complete": profile.get("cstring_complete"),
        "controlled_offsets": _canonicalize(profile.get("controlled_offsets") or []),
        "source_after_terminator_offsets": _canonicalize(
            profile.get("source_after_terminator_offsets") or []
        ),
        "matrix_complete": profile.get("matrix_complete"),
        "expected_vector_ids": _canonicalize(profile.get("expected_vector_ids") or []),
        "decisions": rows,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _canonicalize(value: Any) -> Any:
    """Normalize JSON-like and solver-exported values for digest construction."""

    if isinstance(value, Mapping):
        return {
            str(key): _canonicalize(item)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
            if str(key) != "profile_fingerprint"
        }
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def summarize_seed_obligations(
    obligations: Sequence[Mapping[str, Any]] | Iterable[Mapping[str, Any]],
    *,
    expected_count: int | None = None,
) -> dict[str, Any]:
    """Account for every seed hypothesis in a bounded execution.

    The engine can stop after a useful observation, but that does not mean
    untried seeds disappeared.  This summary gives the multi-state contract a
    small, explicit accounting surface for completed, deferred, and failed
    seed work.  It deliberately does not assign a semantic verdict.
    """

    materialized = [item for item in obligations if isinstance(item, Mapping)]
    status_counts = Counter(str(item.get("status") or "unknown") for item in materialized)
    incomplete_statuses = sorted(
        status
        for status in status_counts
        if status not in _COMPLETED_SEED_STATUSES
    )
    expected = None
    if expected_count is not None:
        try:
            expected = max(0, int(expected_count))
        except (TypeError, ValueError):
            expected = None
    missing_count = max(0, expected - len(materialized)) if expected is not None else 0
    blockers = [f"seed_status:{status}" for status in incomplete_statuses]
    for item in materialized:
        try:
            deferred = max(0, int(item.get("deferred_seed_count") or 0))
        except (TypeError, ValueError):
            deferred = 0
        if deferred:
            blockers.append(f"deferred_seed_count:{deferred}")
        if item.get("engine_collection_complete") is False:
            blockers.append("seed_engine_collection_incomplete")
    if missing_count:
        blockers.append(f"seed_obligations_missing:{missing_count}")
    return {
        "expected_count": expected,
        "observed_count": len(materialized),
        "completed_count": sum(
            int(count)
            for status, count in status_counts.items()
            if status in _COMPLETED_SEED_STATUSES
        ),
        "status_counts": dict(sorted(status_counts.items())),
        "incomplete_statuses": incomplete_statuses,
        "missing_count": missing_count,
        "blockers": sorted(set(blockers)),
        "complete": expected is not None
        and len(materialized) == expected
        and not blockers,
    }


def _is_conditioned(profile: Mapping[str, Any]) -> bool:
    """Return true for profiles that require a reconstructed source link.

    Conditioned feasibility is retained for auditability, but it is not a
    direct source-provenance observation and therefore cannot enter the
    primary bounded existential aggregate.
    """

    if profile.get("primary_aggregate_eligible") is False:
        return True
    markers = {
        str(profile.get("evidence_scope_mode") or "").lower(),
        str(profile.get("evidence_mode") or "").lower(),
        str(profile.get("claim_scope") or "").lower(),
        str(profile.get("status") or "").lower(),
        str(profile.get("evidence_provenance") or "").lower(),
        str(profile.get("evidence_conditioning") or "").lower(),
    }
    if markers & {
        "conditioned",
        "conditioned_feasibility",
        "conditioned_template_feasibility",
        "ct_sat",
        "ct-sat",
        "sink_reconciled",
        "refinement_conditioned",
        "summary_conditioned",
        "fixture_conditioned",
    }:
        return True
    conditioning = str(profile.get("evidence_conditioning") or "").lower()
    return bool(conditioning and conditioning != "unconditioned")


def _is_direct_admissible(profile: Mapping[str, Any]) -> bool:
    """Return true only for an explicitly admitted observed direct profile."""

    if _is_conditioned(profile):
        return False
    if profile.get("primary_aggregate_eligible") is not True:
        return False
    mode = str(profile.get("mode") or profile.get("evidence_mode") or "").lower()
    if mode not in _DIRECT_MODES:
        return False
    scope = str(profile.get("evidence_scope_mode") or "").lower()
    if scope not in _DIRECT_SCOPES:
        return False
    provenance = str(profile.get("evidence_provenance") or "").lower()
    return provenance in _DIRECT_PROVENANCE


def _is_positive(profile: Mapping[str, Any]) -> bool:
    """Accept only a complete, claimable direct matrix profile as positive."""

    if not _is_direct_admissible(profile):
        return False
    # A positive aggregate requires an explicit admission decision.  Missing
    # claimability metadata is legacy/insufficient evidence, not permission.
    if profile.get("claimable") is not True:
        return False
    if not _matrix_complete(profile):
        return False
    return any(
        str(row.get("decision") or "") == "VECTOR_SAT"
        for row in _decision_rows(profile)
    )


def _profile_kind(profile: Mapping[str, Any]) -> str:
    if _profile_issues(profile):
        return "invalid"
    if _is_conditioned(profile):
        return "conditioned"
    if _is_positive(profile):
        return "positive"
    counts = _decision_counts(profile)
    if counts.get("INCONCLUSIVE", 0) > 0:
        return "inconclusive"
    if counts.get("MATRIX_UNSAT", 0) > 0 and _matrix_complete(profile):
        return "matrix_unsat"
    status = str(profile.get("status") or "").lower()
    if "no_modeled_source" in status or status in {"nms", "no_taint_sink"}:
        return "no_modeled_source"
    if (
        status in {"filtered", "matrix_unsat", "m-filt", "m_filt"}
        and _matrix_complete(profile)
        and _decision_rows(profile)
        and all(
            str(row.get("decision") or "") == "MATRIX_UNSAT"
            for row in _decision_rows(profile)
        )
    ):
        return "matrix_unsat"
    return "nonpositive_unknown"


def profile_kind(profile: Mapping[str, Any]) -> str:
    """Expose the admission-aware kind used by the bounded aggregator.

    Evaluation drivers should use this public boundary instead of inferring a
    positive result from a legacy top-level status string.  The helper keeps
    conditioned, incomplete, and non-claimable profiles out of direct-positive
    calibration counts.
    """

    return _profile_kind(profile)


def profile_is_direct_positive(profile: Mapping[str, Any]) -> bool:
    """Return whether a profile satisfies the direct-positive admission gate."""

    return _profile_kind(profile) == "positive"


def select_primary_state_index(
    profiles: Sequence[Mapping[str, Any]] | Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Choose a primary state from a bounded, already-collected profile list.

    The ordinary evaluator historically used the first captured sink state.
    During an explicit multi-state audit, a later state with a complete,
    internally consistent positive matrix is a stronger primary instance than
    that fallback.  The fallback is deliberately narrower than the historical
    behavior: it can select only a claimable, complete direct matrix profile.
    If no such profile was collected, the caller must emit a residual instead
    of evaluating an incomplete or non-admissible snapshot as the primary
    result.  This helper never turns a bounded negative observation into a
    candidate-wide claim and never treats an invalid or partial profile as a
    positive witness.
    """

    materialized = [profile for profile in profiles if isinstance(profile, Mapping)]
    if not materialized:
        return {
            "policy": "bounded_positive_first_then_first_complete_admissible",
            "selected_state_index": None,
            "selected_reason": "no_collected_profile",
            "positive_state_indices": [],
            "later_positive_observed": False,
            "selection_scope": "bounded_collected_sink_instances",
        }

    positive_indices: list[int] = []
    for index, profile in enumerate(materialized):
        if profile.get("claimable") is not True:
            continue
        if profile.get("matrix_complete") is not True:
            continue
        if _profile_kind(profile) == "positive":
            positive_indices.append(index)

    complete_admissible_direct_indices = [
        index
        for index, profile in enumerate(materialized)
        if (
            _is_direct_admissible(profile)
            and profile.get("claimable") is True
            and _matrix_complete(profile)
            and _profile_kind(profile) != "invalid"
        )
    ]
    selected_index = (
        positive_indices[0]
        if positive_indices
        else (
            complete_admissible_direct_indices[0]
            if complete_admissible_direct_indices
            else None
        )
    )
    if positive_indices:
        selected_reason = (
            "first_collected_positive"
            if selected_index == 0
            else "later_collected_positive"
        )
    elif selected_index is not None:
        selected_reason = "first_complete_admissible_fallback_no_valid_collected_positive"
    else:
        selected_reason = "no_complete_admissible_direct_profile"

    return {
        "policy": "bounded_positive_first_then_first_complete_admissible",
        "selected_state_index": selected_index,
        "selected_reason": selected_reason,
        "positive_state_indices": positive_indices,
        "complete_admissible_direct_indices": complete_admissible_direct_indices,
        "later_positive_observed": any(index > 0 for index in positive_indices),
        "selection_scope": "bounded_collected_sink_instances",
    }


def aggregate_sink_profiles(
    profiles: Sequence[Mapping[str, Any]] | Iterable[Mapping[str, Any]],
    *,
    collection_complete: bool = False,
    collection_accounting: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Aggregate a bounded collection using conservative path quantifiers.

    A positive profile is existential: one admissible collected instance is
    enough to report ``exists_positive`` for the collected set.  A negative or
    inconclusive profile never becomes a candidate-wide negative conclusion;
    incomplete collection is explicitly reported as ``bounded_incomplete``.
    """

    materialized = [profile for profile in profiles if isinstance(profile, Mapping)]
    fingerprints = [profile_fingerprint(profile) for profile in materialized]
    unique_indices: list[int] = []
    seen: set[str] = set()
    for index, fingerprint in enumerate(fingerprints):
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unique_indices.append(index)

    unique_profiles = [materialized[index] for index in unique_indices]
    all_kinds = [_profile_kind(profile) for profile in unique_profiles]
    all_profile_issues = {
        str(index): _profile_issues(profile)
        for index, profile in zip(unique_indices, unique_profiles)
        if _profile_issues(profile)
    }
    primary_positions = [
        position for position, kind in enumerate(all_kinds) if kind != "conditioned"
    ]
    primary_indices = [unique_indices[position] for position in primary_positions]
    primary_profiles = [unique_profiles[position] for position in primary_positions]
    kinds = [all_kinds[position] for position in primary_positions]
    profile_issues = {
        str(index): all_profile_issues[str(index)]
        for index in primary_indices
        if str(index) in all_profile_issues
    }
    excluded_conditioned_indices = [
        index for index, kind in zip(unique_indices, all_kinds) if kind == "conditioned"
    ]
    accounting = dict(collection_accounting or {})
    accounting_blockers = sorted({
        str(value)
        for value in accounting.get("blockers", [])
        if str(value)
    })
    # An explicit accounting verdict is authoritative even when a producer
    # forgot to materialize individual blocker strings.  This prevents a
    # stale or hand-built payload from turning a partial bounded collection
    # into a negative aggregate.
    accounting_declares_incomplete = accounting.get("complete") is False
    if accounting_declares_incomplete:
        accounting_blockers.append("collection_accounting_incomplete")
    accounting_blockers = sorted(set(accounting_blockers))
    effective_complete = bool(
        collection_complete
        and not accounting_declares_incomplete
        and not accounting_blockers
    )
    positive_indices = [
        index
        for index, profile, kind in zip(primary_indices, primary_profiles, kinds)
        if kind == "positive" and _is_positive(profile)
    ]
    counts = Counter()
    for profile in primary_profiles:
        counts.update(_decision_counts(profile))

    if positive_indices:
        aggregate_class = "exists_positive"
        quantifier = "exists_over_collected_instances"
    elif not effective_complete:
        aggregate_class = "bounded_incomplete"
        quantifier = "no_positive_observed_in_bounded_collection"
    elif profile_issues:
        aggregate_class = "collection_invalid"
        quantifier = "no_negative_quantifier"
    elif kinds and all(kind == "matrix_unsat" for kind in kinds):
        aggregate_class = "all_collected_matrix_unsat"
        quantifier = "all_collected_instances"
    elif kinds and all(kind == "no_modeled_source" for kind in kinds):
        aggregate_class = "all_collected_no_modeled_source"
        quantifier = "all_collected_instances"
    elif any(kind == "inconclusive" for kind in kinds):
        # An INCONCLUSIVE cell is not evidence that the corresponding vector
        # is absent.  Keep the collection visible to auditors, but do not let
        # a mixed or all-inconclusive collection authorize a negative status.
        aggregate_class = "all_collected_inconclusive"
        quantifier = "no_negative_quantifier"
    elif kinds:
        aggregate_class = "all_collected_nonpositive_mixed"
        quantifier = "no_negative_quantifier"
    else:
        aggregate_class = "no_sink_profile"
        quantifier = "none"

    return {
        "schema": MULTI_STATE_AGGREGATION_SCHEMA,
        "profile_count": len(materialized),
        "unique_profile_count": len(unique_profiles),
        "primary_profile_count": len(primary_profiles),
        "conditioned_sidecar_count": len(excluded_conditioned_indices),
        "collection_complete": effective_complete,
        "collection_scope": "bounded_sink_instances_for_selected_closure",
        "aggregate_class": aggregate_class,
        "quantifier": quantifier,
        "profile_kinds": dict(sorted(Counter(all_kinds).items())),
        "positive_profile_indices": positive_indices,
        "invalid_profile_indices": [index for index, kind in zip(primary_indices, kinds) if kind == "invalid"],
        "profile_issues": profile_issues,
        "all_profile_issues": all_profile_issues,
        "excluded_conditioned_profile_indices": excluded_conditioned_indices,
        "collection_accounting": {
            **accounting,
            "blockers": accounting_blockers,
            "effective_complete": effective_complete,
        },
        "decision_counts": {key: int(counts[key]) for key in sorted(counts)},
        "candidate_wide_negative": False,
        "profile_digest": hashlib.sha256(
            json.dumps(sorted(fingerprints), separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }


def gate_negative_status_for_incomplete_collection(
    status: str,
    audit_payload: Mapping[str, Any] | None,
) -> tuple[str, dict[str, Any]]:
    """Prevent an incomplete bounded collection from emitting a negative label.

    ``filtered`` and ``no_taint_sink`` are intentionally local descriptors, but
    downstream triage can still treat either status as a pruning signal.  Once
    the evaluator has entered bounded multi-state mode, a missing or incomplete
    aggregate must therefore remain a residual.  The legacy first-Ready path
    passes ``None`` and retains its historical behavior explicitly.
    """

    requested = str(status or "")
    requested_key = requested.lower().replace("-", "_")
    status_alias = {
        "filtered": "filtered",
        "matrix_unsat": "filtered",
        "m_filt": "filtered",
        "nms": "no_taint_sink",
        "no_modeled_source": "no_taint_sink",
        "no_taint_sink": "no_taint_sink",
    }
    canonical_requested = status_alias.get(requested_key)
    if canonical_requested is None:
        return requested, {}
    if audit_payload is None:
        return requested, {}

    aggregate = audit_payload.get("aggregate")
    collection_complete = (
        isinstance(aggregate, Mapping)
        and aggregate.get("collection_complete") is True
    )
    aggregate_class = (
        str(aggregate.get("aggregate_class") or "")
        if isinstance(aggregate, Mapping)
        else "missing_aggregate"
    )
    # A negative status is admitted only when every collected direct profile
    # supports the same negative predicate.  In particular, INCONCLUSIVE
    # cells and heterogeneous profiles must remain residual.
    allowed_classes = {
        "filtered": {"all_collected_matrix_unsat"},
        "no_taint_sink": {"all_collected_no_modeled_source"},
    }
    status_class_matches = (
        aggregate_class in allowed_classes.get(canonical_requested, set())
    )
    payload_complete = audit_payload.get("collection_complete")
    profiles = audit_payload.get("profiles")
    replayed_aggregate = None
    negative_profiles_are_admissible = False
    if (
        collection_complete
        and status_class_matches
        and payload_complete is True
        and isinstance(profiles, list)
        and profiles
        and isinstance(aggregate, Mapping)
    ):
        # Recompute the negative aggregate from the recorded profiles.  A
        # caller may supply a stale or hand-built aggregate, so matching only
        # ``aggregate_class`` is insufficient for a pruning signal.
        accounting = aggregate.get("collection_accounting")
        replayed_aggregate = aggregate_sink_profiles(
            profiles,
            collection_complete=True,
            collection_accounting=(
                accounting if isinstance(accounting, Mapping) else None
            ),
        )
        aggregate_fields_match = all(
            aggregate.get(field) == replayed_aggregate.get(field)
            for field in (
                "profile_count",
                "unique_profile_count",
                "primary_profile_count",
                "conditioned_sidecar_count",
                "aggregate_class",
                "quantifier",
                "profile_digest",
            )
        )
        direct_profiles_only = (
            replayed_aggregate.get("conditioned_sidecar_count") == 0
            and not replayed_aggregate.get("profile_issues")
            and all(_is_direct_admissible(profile) for profile in profiles)
        )
        if canonical_requested == "filtered":
            same_negative_kind = all(
                _profile_kind(profile) == "matrix_unsat" for profile in profiles
            )
        else:
            same_negative_kind = all(
                _profile_kind(profile) == "no_modeled_source"
                for profile in profiles
            )
        negative_profiles_are_admissible = bool(
            aggregate_fields_match
            and direct_profiles_only
            and same_negative_kind
        )
    if (
        collection_complete
        and status_class_matches
        and negative_profiles_are_admissible
    ):
        return requested, {}

    return "residual", {
        "multi_state_negative_gate": "blocked",
        "multi_state_negative_gate_requested_status": requested,
        "multi_state_negative_gate_canonical_status": canonical_requested,
        "multi_state_negative_gate_scope": "bounded_collected_sink_instances",
        "multi_state_negative_gate_reason": (
            "collection_incomplete_or_aggregate_not_admissible"
        ),
        "multi_state_aggregate_class": aggregate_class,
        "multi_state_collection_complete": collection_complete,
        "residual_diagnosis_class": "bounded_multi_state_collection_incomplete",
        "residual_diagnosis_detail": (
            "A negative selected-instance status was withheld because the "
            "bounded sink collection was incomplete or did not match its "
            "negative aggregate class."
        ),
    }
