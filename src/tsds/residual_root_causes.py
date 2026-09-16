"""Mutually exclusive root-cause accounting for TSDS residual records.

The analyzer records operational stop events and local evidence-contract
failures.  This module maps those fields into a stable taxonomy without
reclassifying any residual as a positive or negative result.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable, Mapping


ROOT_CAUSE_SCHEMA = "tsds-residual-root-cause-v1"
ADMISSIBLE_BINDINGS = frozenset({"direct_abi_arg0", "rendered_format_wrapper"})
ADMISSIBLE_SEMANTICS = frozenset({"shell_command", "shell_format_wrapper"})


ROOT_CAUSE_ACTIONS = {
    "sink_binding_or_semantics_gap": (
        "add or verify the wrapper signature and argument binding before replay"
    ),
    "incomplete_sink_snapshot": (
        "extend bounded command capture and establish a terminating byte"
    ),
    "post_sink_control_transfer_gap": (
        "replay the architecture-specific delay-slot transition with sink-state capture"
    ),
    "sink_contract_residual": (
        "inspect the reached sink ledger against each evidence-contract obligation"
    ),
    "engine_timeout": "repeat under a declared extended time budget",
    "frontier_exhausted": (
        "audit path feasibility and missing environment or wrapper models"
    ),
    "guided_stagnation": (
        "refine sink-distance ranking and semantic state bucketing"
    ),
    "semantic_loop_saturation": (
        "add a loop or parser summary and replay the retained frontier"
    ),
    "source_liveness_saturation": (
        "audit source lifetime, summary coverage, and source-to-buffer transfer"
    ),
    "state_explosion_saturation": (
        "replay the retained frontier with a declared state budget or a refined state-equivalence relation"
    ),
    "step_budget_exhaustion": "repeat with a declared step budget and frontier trace",
    "unclassified_residual": "perform manual trace review and extend the taxonomy",
}


# Every unreached, non-timeout terminal emitted by the v20 execution engine is
# represented explicitly here.  Keeping aliases such as the legacy and adaptive
# source-liveness terminals in one table prevents scheduler evolution from
# silently creating an unaccounted residual class.
UNREACHED_STOP_CLASSIFICATION = {
    "active_empty": (
        "frontier_exhausted",
        "medium",
        "the active frontier became empty; path infeasibility and model gaps remain distinguishable follow-ups",
    ),
    "guided_stagnation_saturated": (
        "guided_stagnation",
        "high",
        "sink-directed progress remained unchanged for the declared saturation budget",
    ),
    "semantic_loop_saturated": (
        "semantic_loop_saturation",
        "high",
        "semantic loop-state bucketing reached its declared saturation threshold",
    ),
    "source_liveness_saturated": (
        "source_liveness_saturation",
        "high",
        "source-dependent state did not survive the declared liveness frontier",
    ),
    "adaptive_source_liveness_saturated": (
        "source_liveness_saturation",
        "high",
        "the adaptive scheduler observed no source-live state after the declared liveness frontier",
    ),
    "state_explosion_saturated": (
        "state_explosion_saturation",
        "high",
        "the active-state cap was reached for the declared number of saturation rounds",
    ),
    "step_budget_exhausted": (
        "step_budget_exhaustion",
        "high",
        "the declared symbolic step budget was consumed",
    ),
}


def _bool(value: Any) -> bool:
    return value is True or str(value).strip().lower() == "true"


def _root_cause(record: Mapping[str, Any]) -> tuple[str, str, str]:
    reached = _bool(record.get("sink_reached_observed"))
    reason = str(record.get("engine_stop_reason") or "")
    status = str(record.get("status") or "")
    binding = str(record.get("sink_argument_binding_trust") or "")
    semantics = str(record.get("sink_semantics") or "")
    snapshot_complete = record.get("sink_snapshot_cstring_complete")

    if reached:
        if binding not in ADMISSIBLE_BINDINGS or semantics not in ADMISSIBLE_SEMANTICS:
            return (
                "sink_binding_or_semantics_gap",
                "high",
                "the sink was observed, but serialized binding or shell semantics were not admissible",
            )
        if snapshot_complete is not True:
            return (
                "incomplete_sink_snapshot",
                "high",
                "the sink was observed with a trusted binding, but the command C string was incomplete",
            )
        if reason == "post_sink_delay_slot":
            return (
                "post_sink_control_transfer_gap",
                "high",
                "the command snapshot is complete but architecture-specific post-call transfer remained",
            )
        return (
            "sink_contract_residual",
            "medium",
            "the sink was observed but at least one remaining evidence obligation was unresolved",
        )

    if reason in UNREACHED_STOP_CLASSIFICATION:
        return UNREACHED_STOP_CLASSIFICATION[reason]
    # The analyzer may retain the coarse worker status ``timeout`` after a
    # scheduler-specific terminal is recorded.  Preserve the explicit engine
    # terminal when available; status is only a fallback for records without
    # a classified stop reason.
    if reason == "engine_timeout" or status == "timeout":
        return "engine_timeout", "high", "the declared execution time budget expired"
    return (
        "unclassified_residual",
        "low",
        "the serialized fields do not match the current mutually exclusive taxonomy",
    )


def classify_residual(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return a stable diagnosis row for a ledger record with verdict RESIDUAL."""

    if str(record.get("verdict") or "") != "RESIDUAL":
        raise ValueError("residual root-cause classification requires verdict RESIDUAL")
    root_cause, confidence, rationale = _root_cause(record)
    reached = _bool(record.get("sink_reached_observed"))
    reason = str(record.get("engine_stop_reason") or "unknown")
    if reached:
        distance = "observed_sink"
    elif reason in {"post_sink_delay_slot", "sink_address", "sink_callsite_in_block"}:
        distance = "near_sink_control_transfer"
    else:
        distance = "unreached_sink"
    static_strength = str(record.get("static_evidence_strength") or "absent")
    epistemic_status = (
        "local_failure_observed"
        if reached or confidence == "high"
        else "mechanism_observed_root_cause_open"
    )
    return {
        "schema": ROOT_CAUSE_SCHEMA,
        "target": record.get("_target") or record.get("target"),
        "closure_idx": record.get("closure_idx"),
        "source_addr": record.get("source_addr"),
        "sink_addr": record.get("sink_addr"),
        "status": record.get("status"),
        "engine_stop_reason": reason,
        "existing_diagnosis": record.get("residual_diagnosis_class"),
        "root_cause": root_cause,
        "root_cause_confidence": confidence,
        "root_cause_rationale": rationale,
        "epistemic_status": epistemic_status,
        "sink_distance_class": distance,
        "sink_reached_observed": reached,
        "static_evidence_strength": static_strength,
        "path_control_class": record.get("path_control_class"),
        "binding_trust": record.get("sink_argument_binding_trust"),
        "sink_semantics": record.get("sink_semantics"),
        "snapshot_cstring_complete": record.get("sink_snapshot_cstring_complete"),
        "follow_up_obligation": ROOT_CAUSE_ACTIONS[root_cause],
    }


def _nested(counter_map: Mapping[str, Counter[str]]) -> dict[str, dict[str, int]]:
    return {
        key: dict(sorted(counter.items()))
        for key, counter in sorted(counter_map.items())
    }


def summarize_residuals(
    records: Iterable[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = [classify_residual(record) for record in records]
    root_causes = Counter(str(row["root_cause"]) for row in rows)
    stop_reasons = Counter(str(row["engine_stop_reason"]) for row in rows)
    distance = Counter(str(row["sink_distance_class"]) for row in rows)
    confidence = Counter(str(row["root_cause_confidence"]) for row in rows)
    epistemic = Counter(str(row["epistemic_status"]) for row in rows)
    obligations = Counter(str(row["follow_up_obligation"]) for row in rows)
    by_target: dict[str, Counter[str]] = defaultdict(Counter)
    by_stop: dict[str, Counter[str]] = defaultdict(Counter)
    by_static: dict[str, Counter[str]] = defaultdict(Counter)
    by_existing: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        cause = str(row["root_cause"])
        by_target[str(row.get("target") or "unknown")][cause] += 1
        by_stop[str(row["engine_stop_reason"])][cause] += 1
        by_static[str(row["static_evidence_strength"])][cause] += 1
        by_existing[str(row.get("existing_diagnosis") or "unknown")][cause] += 1
    summary = {
        "schema": "tsds-residual-root-cause-audit-v1",
        "records": len(rows),
        "classified_records": len(rows) - root_causes.get("unclassified_residual", 0),
        "classification_complete": bool(rows) and not root_causes.get("unclassified_residual"),
        "root_cause_counts": dict(sorted(root_causes.items())),
        "stop_reason_counts": dict(sorted(stop_reasons.items())),
        "sink_distance_counts": dict(sorted(distance.items())),
        "confidence_counts": dict(sorted(confidence.items())),
        "epistemic_status_counts": dict(sorted(epistemic.items())),
        "follow_up_obligations": dict(sorted(obligations.items())),
        "root_causes_by_target": _nested(by_target),
        "root_causes_by_stop_reason": _nested(by_stop),
        "root_causes_by_static_strength": _nested(by_static),
        "root_causes_by_existing_diagnosis": _nested(by_existing),
        "claim_boundary": (
            "The taxonomy accounts for unresolved obligations and observed stop mechanisms; "
            "it does not reinterpret residual records as positive or negative findings."
        ),
    }
    return rows, summary
