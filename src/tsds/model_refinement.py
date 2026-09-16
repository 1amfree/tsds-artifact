"""Guarded residual-driven model refinement for TSDS.

This module turns a residual ledger record into a small set of explicit model
candidates.  It does not promote evidence: candidates must be installed by the
execution adapter, replayed, and admitted through the ordinary sink-byte
contract.  The separation makes the CEGAR loop inspectable and prevents model
synthesis from becoming a second positive-evidence channel.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


REFINEMENT_SCHEMA = "tsds-residual-cegar-v1"
SUPPORTED_KINDS = {
    "source_wrapper_summary",
    "string_transfer_summary",
    "format_binding_summary",
    "environment_predicate_summary",
}
RESIDUAL_STATUSES = {
    "residual",
    "unreachable",
    "timeout",
    "crashed",
    "eval_error",
    "state_error",
}


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _text(value: Any, limit: int = 240) -> str:
    text = str(value or "").strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


@dataclass(frozen=True)
class SummaryCandidate:
    kind: str
    target: str
    source_kind: str
    preconditions: tuple[str, ...]
    effects: tuple[str, ...]
    reason: str
    confidence: str
    evidence: str = ""
    command_template: str = ""
    source_slot: int | None = None
    candidate_id: str = ""
    schema: str = REFINEMENT_SCHEMA

    def normalized(self) -> "SummaryCandidate":
        document = {
            "kind": self.kind,
            "target": self.target,
            "source_kind": self.source_kind,
            "preconditions": sorted(set(self.preconditions)),
            "effects": sorted(set(self.effects)),
            "reason": self.reason,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "command_template": self.command_template,
            "source_slot": self.source_slot,
        }
        candidate_id = self.candidate_id or canonical_digest(document)[:24]
        return SummaryCandidate(
            kind=str(self.kind),
            target=_text(self.target, 160),
            source_kind=_text(self.source_kind, 48) or "source",
            preconditions=tuple(document["preconditions"]),
            effects=tuple(document["effects"]),
            reason=_text(self.reason, 160),
            confidence=str(self.confidence or "low"),
            evidence=_text(self.evidence),
            command_template=_text(self.command_template),
            source_slot=self.source_slot,
            candidate_id=candidate_id,
        )

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self.normalized())
        value["preconditions"] = list(value["preconditions"])
        value["effects"] = list(value["effects"])
        return value


@dataclass(frozen=True)
class AdmissionResult:
    admitted: bool
    violations: tuple[str, ...]
    checks: tuple[str, ...]
    schema: str = REFINEMENT_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "admitted": self.admitted,
            "violations": list(self.violations),
            "checks": list(self.checks),
        }


def candidate_admission(candidate: SummaryCandidate, record: dict[str, Any]) -> AdmissionResult:
    candidate = candidate.normalized()
    violations: list[str] = []
    checks: list[str] = []
    if candidate.kind not in SUPPORTED_KINDS:
        violations.append("unsupported_candidate_kind")
    else:
        checks.append("supported_candidate_kind")
    if not candidate.target:
        violations.append("missing_target")
    else:
        checks.append("target_present")
    if candidate.confidence not in {"high", "medium"}:
        violations.append("confidence_below_admission_threshold")
    else:
        checks.append("confidence_admissible")

    static_strength = str(
        record.get("static_evidence_strength")
        or record.get("static_source_strength")
        or "absent"
    ).lower()
    if candidate.kind in {"source_wrapper_summary", "format_binding_summary"}:
        if static_strength != "strong":
            violations.append("strong_static_source_required")
        else:
            checks.append("strong_static_source")

    if candidate.kind == "format_binding_summary":
        template = candidate.command_template or str(
            record.get("static_sink_template") or record.get("sink_preview") or ""
        )
        if not template or not any(token in template for token in ("%s", "<source", "<src")):
            violations.append("source_slot_not_materialized")
        else:
            checks.append("source_slot_materialized")

    if candidate.kind == "environment_predicate_summary":
        if not any(
            token in (candidate.reason + " " + candidate.evidence).lower()
            for token in ("environment", "config", "nvram", "predicate", "branch")
        ):
            violations.append("environment_evidence_missing")
        else:
            checks.append("environment_evidence")

    return AdmissionResult(
        admitted=not violations,
        violations=tuple(sorted(set(violations))),
        checks=tuple(sorted(set(checks))),
    )


def _target(record: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = _text(record.get(key), 160)
        if value:
            return value
    return ""


def synthesize_candidates(record: dict[str, Any]) -> list[SummaryCandidate]:
    """Generate a bounded, deterministic candidate set from one residual."""

    record = dict(record or {})
    diagnosis = str(record.get("residual_diagnosis_class") or "").lower()
    stop_reason = str(record.get("engine_stop_reason") or "").lower()
    static_strength = str(
        record.get("static_evidence_strength")
        or record.get("static_source_strength")
        or "absent"
    ).lower()
    source_kind = str(
        (record.get("source_kinds") or [record.get("source_class") or "source"])[0]
    )
    trace_summary = _target(record, "trace_summary", "source_function", "sink_function")
    source_target = _target(record, "source_function", "source_addr", "trace_summary")
    sink_target = _target(record, "sink_function", "sink_addr", "trace_summary")
    template = _text(
        record.get("static_sink_template")
        or record.get("inferred_sink_template")
        or record.get("sink_preview")
    )

    requested = {
        str(item.get("kind"))
        for item in (record.get("model_gap_requests") or [])
        if isinstance(item, dict)
    }
    gaps = {str(value) for value in (record.get("residual_plan_model_gaps") or [])}
    candidates: list[SummaryCandidate] = []

    if (
        static_strength == "strong"
        and (
            diagnosis in {"model_gap_reachability", "static_dynamic_taint_disagreement"}
            or "wrapper_summary" in requested
            or "source_wrapper_summary" in gaps
        )
    ):
        candidates.append(
            SummaryCandidate(
                kind="source_wrapper_summary",
                target=source_target,
                source_kind=source_kind,
                preconditions=("strong_static_source", "target_resolves"),
                effects=("return_symbolic_cstring", "attach_source_label"),
                reason=diagnosis or "source_label_missing",
                confidence="high" if source_target else "low",
                evidence=trace_summary,
            ).normalized()
        )

    if (
        diagnosis == "static_dynamic_taint_disagreement"
        or "string_model" in requested
        or "string_copy_summary" in gaps
    ):
        candidates.append(
            SummaryCandidate(
                kind="string_transfer_summary",
                target=sink_target or trace_summary,
                source_kind=source_kind,
                preconditions=("target_resolves", "pointer_arguments_available"),
                effects=("copy_source_to_destination", "preserve_cstring_termination"),
                reason=diagnosis or "taint_carrier_summary",
                confidence="medium" if sink_target else "low",
                evidence=template or trace_summary,
            ).normalized()
        )

    if (
        template
        and static_strength == "strong"
        and (
            "format_template_binding" in gaps
            or "%s" in template
            or "<source" in template
            or "<src" in template
        )
    ):
        candidates.append(
            SummaryCandidate(
                kind="format_binding_summary",
                target=sink_target or trace_summary,
                source_kind=source_kind,
                preconditions=("strong_static_source", "template_compatible"),
                effects=("bind_source_slot", "construct_command_bytes"),
                reason="format_template_binding",
                confidence="high" if sink_target else "medium",
                evidence=template,
                command_template=template,
                source_slot=0,
            ).normalized()
        )

    environment_signal = any(
        token in " ".join(
            [diagnosis, stop_reason, trace_summary.lower(), " ".join(sorted(requested))]
        )
        for token in ("environment", "config", "nvram", "predicate", "branch")
    )
    if environment_signal:
        candidates.append(
            SummaryCandidate(
                kind="environment_predicate_summary",
                target=source_target or trace_summary,
                source_kind=source_kind,
                preconditions=("target_resolves", "predicate_has_no_source_dependency"),
                effects=("fork_boolean_environment_outcome",),
                reason="environment_branch_model",
                confidence="medium" if source_target or trace_summary else "low",
                evidence=" ".join([diagnosis, stop_reason, trace_summary]),
            ).normalized()
        )

    unique: dict[str, SummaryCandidate] = {}
    for candidate in candidates:
        unique.setdefault(candidate.candidate_id, candidate)
    return [unique[key] for key in sorted(unique)]


def build_refinement_bundle(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Build candidates only from explicit unresolved evidence obligations.

    The verdict field is authoritative when present. Legacy records without a
    normalized verdict remain admissible only for an explicit residual status.
    This prevents a post-discovery model from being synthesized from a positive,
    filtered, NMS, or static-reduction ledger row.
    """
    rows = []
    input_records = 0
    skipped_non_residual_records = 0
    for record in records:
        input_records += 1
        verdict = str(record.get("verdict") or "")
        status = str(record.get("status") or "")
        eligible = verdict == "RESIDUAL" if verdict else status in RESIDUAL_STATUSES
        if not eligible:
            skipped_non_residual_records += 1
            continue
        identity = {
            "closure_idx": record.get("closure_idx"),
            "closure_ordinal": record.get("closure_ordinal"),
            "old_status": record.get("status"),
            "old_stop_reason": record.get("engine_stop_reason"),
        }
        candidates = []
        for candidate in synthesize_candidates(record):
            admission = candidate_admission(candidate, record)
            candidates.append(
                {**candidate.to_dict(), "admission": admission.to_dict()}
            )
        if candidates:
            rows.append({**identity, "candidates": candidates})
    document = {
        "schema": REFINEMENT_SCHEMA,
        "records": rows,
        "input_records": input_records,
        "skipped_non_residual_records": skipped_non_residual_records,
        "selection_policy": "explicit_residual_verdict_only",
        "candidate_count": sum(len(row["candidates"]) for row in rows),
        "claim_boundary": (
            "Model candidates only configure bounded replay; positive evidence "
            "still requires a reached sink and controlled-byte certificate."
        ),
    }
    document["bundle_sha256"] = canonical_digest(document)
    return document


def write_refinement_bundle(path: Path, records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    document = build_refinement_bundle(records)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return document


def load_refinement_bundle(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema") != REFINEMENT_SCHEMA:
        raise ValueError("invalid refinement bundle schema")
    expected = document.get("bundle_sha256")
    payload = dict(document)
    payload.pop("bundle_sha256", None)
    if expected != canonical_digest(payload):
        raise ValueError("refinement bundle digest mismatch")
    return document


def candidates_for_closure(bundle: dict[str, Any], closure_idx: int) -> list[dict[str, Any]]:
    values = []
    for row in bundle.get("records") or []:
        if int(row.get("closure_idx", -1)) != int(closure_idx):
            continue
        for candidate in row.get("candidates") or []:
            admission = candidate.get("admission") or {}
            if admission.get("admitted") is True:
                values.append(candidate)
    return values
