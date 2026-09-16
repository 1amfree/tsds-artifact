"""Independent, fail-closed certificates for TSDS ledger records.

The evaluator emits a rich JSONL ledger.  This module deliberately does not
import angr or the evaluator: it constructs a compact certificate and verifies
the certificate's claim invariants using only serialized evidence.  It is not
a second symbolic executor and does not establish device exploitability.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter
from typing import Any, Iterable, Mapping

from tsds.shell_matrix_spec import (
    MATRIX_SPEC_SCHEMA,
    MATRIX_SPEC_VERSION,
    VECTOR_IDS,
    VECTOR_ID_SET,
    matrix_decision_issues,
    matrix_spec_sha256,
    matrix_spec_validation_issues,
)
from tsds.reconciliation_link import reconciliation_link_admission


LEGACY_CERTIFICATE_SCHEMA = "tsds-evidence-certificate-v1"
CERTIFICATE_SCHEMA = "tsds-evidence-certificate-v2"
CERTIFICATE_DIGEST_FIELD = "certificate_sha256"
RECORD_DIGEST_FIELD = "source_record_sha256"

ADMISSIBLE_SHELL_SEMANTICS = frozenset({"shell_command", "shell_format_wrapper"})
ADMISSIBLE_BINDINGS = frozenset({"direct_abi_arg0", "rendered_format_wrapper"})
CLAIM_STATUSES = frozenset({"vulnerable", "conditioned_feasibility", "filtered", "no_taint_sink"})
RECOVERY_CONFIDENCE_CLASSES = frozenset(
    {
        "dynamic_format_wrapper_slot",
        "static_likely_source_with_format_slot",
        "static_sink_marker_with_command_template",
    }
)


def _normalise(value: Any) -> Any:
    """Return a deterministic JSON-compatible representation.

    Lists preserve their semantic order; dictionaries are recursively sorted.
    The evaluator ledger only contains scalar JSON values, but the conversion
    also handles tuples and sets defensively for direct unit-test use.
    """

    if isinstance(value, Mapping):
        return {str(key): _normalise(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, tuple):
        return [_normalise(item) for item in value]
    if isinstance(value, list):
        return [_normalise(item) for item in value]
    if isinstance(value, set):
        return [_normalise(item) for item in sorted(value, key=lambda item: repr(item))]
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value.hex()}
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        _normalise(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None
    return bool(value)


def _observed_reach(record: Mapping[str, Any]) -> bool:
    return bool(record.get("sink_reached_observed")) or _int(record.get("no_taint_reaches")) > 0


def _controlled_offsets(record: Mapping[str, Any]) -> list[int]:
    raw = record.get("controlled_offsets") or record.get("tainted_offsets") or []
    values: list[int] = []
    if isinstance(raw, (list, tuple)):
        for item in raw:
            try:
                value = int(item)
            except (TypeError, ValueError):
                continue
            if value >= 0 and value not in values:
                values.append(value)
    return sorted(values)


def _offset_domain(record: Mapping[str, Any]) -> dict[str, Any]:
    if record.get("evidence_provenance") == "SINK_RECONCILED":
        return {
            "name": "reconciled_matrix_snapshot",
            "length": record.get("matrix_snapshot_capture_length"),
            "terminator_offset": record.get("matrix_snapshot_terminator_offset"),
        }
    return {
        "name": "captured_sink_snapshot",
        "length": record.get("sink_snapshot_capture_length"),
        "terminator_offset": record.get("sink_snapshot_terminator_offset"),
    }


def _recovery_admission(record: Mapping[str, Any]) -> dict[str, Any]:
    applicable = record.get("evidence_provenance") == "SINK_RECONCILED"
    mode = str(record.get("analysis_recovery") or "")
    confidence = str(record.get("recovery_confidence") or "")
    constraint_mode = str(record.get("recovery_constraint_mode") or "")
    constraint_count = _int(record.get("recovery_path_constraint_count"))
    constrained = record.get("matrix_reconciled_constrained") is True
    template = str(record.get("recovered_sink_template") or "")
    violations: list[str] = []
    if applicable:
        if mode != "static_dynamic_taint_reconciliation":
            violations.append("recovery_mode_not_guarded_reconciliation")
        if confidence not in RECOVERY_CONFIDENCE_CLASSES:
            violations.append("recovery_confidence_not_admissible")
        if constraint_mode != "reached_state_plus_command_template":
            violations.append("recovery_constraint_mode_not_path_bound")
        if constraint_count <= 0:
            violations.append("recovery_without_path_constraints")
        if not constrained:
            violations.append("recovery_matrix_not_constrained")
        if not template:
            violations.append("recovery_without_command_template")
    link_admission = reconciliation_link_admission(
        record.get("reconciliation_link"), record=record
    ) if applicable else {
        "schema": "tsds-reconciliation-link-admission-v1",
        "admitted": False,
        "link_present": False,
        "link_status": "not_applicable",
        "issues": [],
        "claim_boundary": "not applicable",
    }
    return {
        "applicable": applicable,
        "admitted": applicable and not violations and link_admission["admitted"],
        "mode": mode or None,
        "confidence": confidence or None,
        "static_evidence_strength": record.get("static_evidence_strength"),
        "constraint_mode": constraint_mode or None,
        "path_constraint_count": constraint_count,
        "matrix_reconciled_constrained": constrained,
        "command_template_sha256": sha256_json(template) if template else None,
        "source_prefix_sha256": (
            sha256_json(str(record.get("recovered_source_prefix")))
            if record.get("recovered_source_prefix")
            else None
        ),
        "reconciliation_link": record.get("reconciliation_link"),
        "reconciliation_link_admission": link_admission,
        "admission_violations": violations,
    }


def _fixture_conditioning(record: Mapping[str, Any]) -> dict[str, Any]:
    usage = record.get("env_fixture_usage") or {}
    summary = record.get("env_fixture_summary") or {}
    hits = _int(usage.get("hits")) if isinstance(usage, Mapping) else 0
    entries = _int(summary.get("entries")) if isinstance(summary, Mapping) else 0
    conditioning = str(record.get("evidence_conditioning") or "")
    if not conditioning:
        conditioning = "fixture_conditioned" if hits else "unconditioned"
    return {
        "fixture_entries": entries,
        "fixture_hits": hits,
        "fixture_digest": summary.get("digest") if isinstance(summary, Mapping) else None,
        "summary_events": _int(record.get("evidence_summary_events")),
        "summary_origins": sorted(
            str(item) for item in (record.get("evidence_summary_origins") or [])
        ),
        "refinement_bundle_sha256": record.get(
            "evidence_refinement_bundle_sha256"
        ),
        "scope": conditioning,
    }


def _decision_view(decision: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "vector_id": str(decision.get("vector_id") or ""),
        "vector": decision.get("vector"),
        "category": decision.get("category"),
        "effect_class": decision.get("effect_class"),
        "decision": str(decision.get("decision") or ""),
        "grammar_complete": bool(decision.get("grammar_complete")),
        "lexical_reason": decision.get("lexical_reason"),
        "quote_context": decision.get("quote_context"),
        "witness_kind": decision.get("witness_kind"),
        "witness": decision.get("witness"),
        "witness_template": decision.get("witness_template"),
        "parser_calibration": decision.get("parser_calibration"),
        "schema": decision.get("schema"),
    }


def _sorted_decisions(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = record.get("vector_decisions") or []
    decisions = [_decision_view(item) for item in raw if isinstance(item, Mapping)]
    return sorted(decisions, key=lambda item: (item["vector_id"], item["decision"], str(item["witness"])))


def _minimal_witness(record: Mapping[str, Any], decisions: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    minimal = record.get("minimal_bypass_vector")
    if isinstance(minimal, Mapping):
        return {
            "vector_id": minimal.get("vector_id") or minimal.get("vector"),
            "vector": minimal.get("vector"),
            "witness": minimal.get("witness") or minimal.get("poc"),
            "grammar_complete": bool(minimal.get("grammar_complete")),
            "parser_calibration": minimal.get("parser_calibration"),
        }
    for decision in decisions:
        if decision.get("decision") == "VECTOR_SAT":
            return {
                "vector_id": decision.get("vector_id"),
                "vector": decision.get("vector"),
                "witness": decision.get("witness"),
                "grammar_complete": bool(decision.get("grammar_complete")),
                "parser_calibration": decision.get("parser_calibration"),
            }
    return {}


def _claim_scope(record: Mapping[str, Any], conditioning: Mapping[str, Any]) -> str:
    if str(record.get("status") or "") == "conditioned_feasibility":
        return "conditioned_template_feasibility"
    conditioned_scope = str(conditioning.get("scope") or "unconditioned")
    if conditioned_scope != "unconditioned":
        return conditioned_scope
    if record.get("sink_snapshot_cstring_complete") is False:
        return "bounded_snapshot"
    return "analyzer_sink_byte"


def certificate_payload(record: Mapping[str, Any], target: str | None = None) -> dict[str, Any]:
    """Build the digest-covered certificate body for one normalized ledger row."""

    record = dict(record or {})
    decisions = _sorted_decisions(record)
    conditioning = _fixture_conditioning(record)
    offset_domain = _offset_domain(record)
    recovery = _recovery_admission(record)
    identity = {
        "target": target or record.get("target") or "",
        "closure_idx": record.get("closure_idx"),
        "closure_ordinal": record.get("closure_ordinal"),
        "source_addr": record.get("source_addr"),
        "sink_addr": record.get("sink_addr"),
        "closure_sink_signature": record.get("closure_sink_signature") or [],
    }
    return {
        "schema": CERTIFICATE_SCHEMA,
        "identity": identity,
        "analysis": {
            "analysis_version": record.get("analysis_version"),
            "evidence_contract_schema": record.get("evidence_contract_schema"),
            "status": record.get("status"),
            "verdict": record.get("verdict"),
            "admissible_claim": record.get("admissible_claim"),
            "evidence_provenance": record.get("evidence_provenance"),
            "evidence_contract_valid": bool(record.get("evidence_contract_valid")),
            "primary_aggregate_eligible": record.get("primary_aggregate_eligible"),
            "claim_scope": _claim_scope(record, conditioning),
        },
        "source": {
            "controlled_offsets": _controlled_offsets(record),
            "tainted_byte_count": _int(record.get("tainted_byte_count")),
            "source_kinds": sorted(str(item) for item in (record.get("source_kinds") or [])),
            "offset_domain": offset_domain,
        },
        "sink": {
            "reached": _observed_reach(record),
            "captured_function": record.get("captured_sink_function_name") or record.get("sink_function"),
            "function_name_source": record.get("sink_function_name_source"),
            "semantics": record.get("sink_semantics"),
            "binding_source": record.get("sink_argument_binding_source"),
            "binding_trust": record.get("sink_argument_binding_trust"),
            "snapshot_cstring_complete": _bool_or_none(record.get("sink_snapshot_cstring_complete")),
            "snapshot_capture_length": record.get("sink_snapshot_capture_length"),
            "snapshot_terminator_offset": record.get("sink_snapshot_terminator_offset"),
            "snapshot_sha256": record.get("tsds_sink_snapshot_digest") or record.get("sink_snapshot_digest"),
            "preview_sha256": sha256_json(str(record.get("sink_preview") or record.get("no_taint_preview") or "")),
        },
        "matrix": {
            "spec": {
                "schema": MATRIX_SPEC_SCHEMA,
                "version": MATRIX_SPEC_VERSION,
                "sha256": matrix_spec_sha256(),
            },
            "expected_vector_ids": list(VECTOR_IDS),
            "decisions": decisions,
            "vulnerable_vectors": _int(record.get("vulnerable_vectors")),
            "secure_vectors": _int(record.get("secure_vectors")),
            "inconclusive_vectors": _int(record.get("inconclusive_vectors")),
            "minimal_witness": _minimal_witness(record, decisions),
        },
        "recovery_admission": recovery,
        "conditioning": conditioning,
        RECORD_DIGEST_FIELD: sha256_json(record),
    }


def build_certificate(record: Mapping[str, Any], target: str | None = None) -> dict[str, Any]:
    """Create an immutable certificate with a self-digest."""

    certificate = certificate_payload(record, target=target)
    certificate[CERTIFICATE_DIGEST_FIELD] = sha256_json(certificate)
    return certificate


def _decision_counts(decisions: Iterable[Mapping[str, Any]]) -> Counter[str]:
    return Counter(str(item.get("decision") or "") for item in decisions)


def certificate_violations(certificate: Mapping[str, Any]) -> list[str]:
    """Validate certificate-local claim invariants without executing anything."""

    certificate = certificate or {}
    issues: list[str] = []
    schema = certificate.get("schema")
    if schema not in {CERTIFICATE_SCHEMA, LEGACY_CERTIFICATE_SCHEMA}:
        issues.append("unsupported_certificate_schema")
    supplied_digest = certificate.get(CERTIFICATE_DIGEST_FIELD)
    digest_body = dict(certificate)
    digest_body.pop(CERTIFICATE_DIGEST_FIELD, None)
    if not supplied_digest or supplied_digest != sha256_json(digest_body):
        issues.append("certificate_digest_mismatch")

    identity = certificate.get("identity") or {}
    if identity.get("closure_idx") is None or not identity.get("sink_addr"):
        issues.append("certificate_missing_closure_identity")

    analysis = certificate.get("analysis") or {}
    source = certificate.get("source") or {}
    sink = certificate.get("sink") or {}
    matrix = certificate.get("matrix") or {}
    conditioning = certificate.get("conditioning") or {}
    status = str(analysis.get("status") or "")
    decisions = [item for item in (matrix.get("decisions") or []) if isinstance(item, Mapping)]
    counts = _decision_counts(decisions)
    vector_ids = {str(item.get("vector_id") or "") for item in decisions}
    controlled = list(source.get("controlled_offsets") or [])
    controlled_count = max(_int(source.get("tainted_byte_count")), len(controlled))
    reached = bool(sink.get("reached"))
    snapshot_complete = sink.get("snapshot_cstring_complete")
    scope = str(analysis.get("claim_scope") or "")

    if schema == CERTIFICATE_SCHEMA:
        spec = matrix.get("spec") or {}
        issues.extend(matrix_spec_validation_issues(spec))
        issues.extend(matrix_decision_issues(decisions))
        domain = source.get("offset_domain") or {}
        domain_length = _int(domain.get("length"))
        if controlled and domain_length <= 0:
            issues.append("controlled_offsets_without_domain_length")
        elif controlled and max(int(value) for value in controlled) >= domain_length:
            issues.append("controlled_offset_outside_domain")
        if analysis.get("evidence_provenance") == "SINK_RECONCILED" and status == "vulnerable":
            recovery = certificate.get("recovery_admission") or {}
            if recovery.get("applicable") is not True or recovery.get("admitted") is not True:
                issues.append("reconciled_positive_without_admission_certificate")
            if recovery.get("admission_violations"):
                issues.append("reconciled_positive_with_admission_violation")
            link_admission = recovery.get("reconciliation_link_admission") or {}
            if link_admission.get("admitted") is not True:
                issues.append("reconciled_positive_without_verified_source_link")

    if status in CLAIM_STATUSES:
        if not analysis.get("evidence_contract_valid"):
            issues.append("claim_without_valid_evidence_contract")
        if sink.get("semantics") not in ADMISSIBLE_SHELL_SEMANTICS:
            issues.append("claim_without_admissible_shell_semantics")
        if sink.get("binding_trust") not in ADMISSIBLE_BINDINGS:
            issues.append("claim_without_trusted_sink_binding")
        if not sink.get("function_name_source"):
            issues.append("claim_without_sink_name_provenance")
        if not reached:
            issues.append("claim_without_observed_sink_reach")
        conditioned_scope = str(conditioning.get("scope") or "unconditioned")
        if conditioning.get("fixture_hits", 0) and "fixture_conditioned" not in scope:
            issues.append("fixture_hit_without_fixture_conditioned_scope")
        if conditioned_scope != "unconditioned" and scope != conditioned_scope:
            issues.append("conditioned_record_scope_mismatch")

    if status == "conditioned_feasibility":
        if analysis.get("evidence_provenance") != "SINK_RECONCILED":
            issues.append("conditioned_without_reconciliation_provenance")
        if scope != "conditioned_template_feasibility":
            issues.append("conditioned_without_conditioned_scope")
        if analysis.get("status") == "conditioned_feasibility" and analysis.get("evidence_contract_valid") is not True:
            issues.append("conditioned_without_valid_evidence_contract")

    if status == "vulnerable":
        if controlled_count <= 0:
            issues.append("positive_without_controlled_offsets")
        if counts["VECTOR_SAT"] <= 0:
            issues.append("positive_without_vector_sat")
        witness = matrix.get("minimal_witness") or {}
        if not witness.get("grammar_complete") or not witness.get("witness"):
            issues.append("positive_without_grammar_complete_witness")
        if not witness.get("parser_calibration"):
            issues.append("positive_without_parser_calibration")
        if snapshot_complete is False and scope != "bounded_snapshot":
            issues.append("positive_incomplete_snapshot_without_bounded_scope")

    if status == "filtered":
        if controlled_count <= 0:
            issues.append("filtered_without_controlled_offsets")
        if snapshot_complete is not True:
            issues.append("filtered_without_complete_cstring_snapshot")
        if vector_ids != VECTOR_ID_SET:
            issues.append("filtered_without_complete_vector_matrix")
        if counts["MATRIX_UNSAT"] != len(VECTOR_IDS):
            issues.append("filtered_without_all_vector_unsat")
        if counts["VECTOR_SAT"] or counts["INCONCLUSIVE"]:
            issues.append("filtered_with_non_unsat_vector_decision")

    if status == "no_taint_sink":
        if controlled_count > 0:
            issues.append("nms_with_controlled_offsets")
        if snapshot_complete is not True:
            issues.append("nms_without_complete_cstring_snapshot")

    return sorted(set(issues))


def verify_record_certificate(record: Mapping[str, Any], certificate: Mapping[str, Any]) -> list[str]:
    """Validate certificate invariants and bind it to the original record."""

    issues = certificate_violations(certificate)
    if certificate.get(RECORD_DIGEST_FIELD) != sha256_json(dict(record or {})):
        issues.append("source_record_digest_mismatch")
    return sorted(set(issues))


def certificate_summary(certificates: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = list(certificates or [])
    statuses = Counter()
    scopes = Counter()
    issues = Counter()
    for certificate in rows:
        statuses[str((certificate.get("analysis") or {}).get("status") or "unknown")] += 1
        scopes[str((certificate.get("analysis") or {}).get("claim_scope") or "unknown")] += 1
        for issue in certificate_violations(certificate):
            issues[issue] += 1
    return {
        "schema": "tsds-evidence-certificate-audit-v2",
        "records": len(rows),
        "valid_certificates": len(rows) - sum(1 for row in rows if certificate_violations(row)),
        "records_with_issues": sum(1 for row in rows if certificate_violations(row)),
        "status_counts": dict(sorted(statuses.items())),
        "claim_scopes": dict(sorted(scopes.items())),
        "issue_counts": dict(sorted(issues.items())),
        "claim_boundary": (
            "Certificates validate serialized sink-byte evidence invariants. "
            "They do not execute commands, prove device reachability, or establish exploitability."
        ),
    }


def certificate_jsonl_rows(records: Iterable[Mapping[str, Any]], target: str | None = None) -> list[dict[str, Any]]:
    return [build_certificate(record, target=target) for record in records]


def copy_without_digest(certificate: Mapping[str, Any]) -> dict[str, Any]:
    """Convenience helper for tests and external independent verifiers."""

    payload = copy.deepcopy(dict(certificate or {}))
    payload.pop(CERTIFICATE_DIGEST_FIELD, None)
    return payload
