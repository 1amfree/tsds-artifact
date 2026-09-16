"""Second-implementation verifier for TSDS evidence certificate v2.

This module deliberately does not import the certificate generator.  It
reimplements canonical hashing and claim checks so that serialization or
generator defects are less likely to pass through a shared code path.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from typing import Any, Iterable, Mapping

from tsds.shell_matrix_spec import (
    VECTOR_ID_SET,
    VECTOR_IDS,
    matrix_spec_validation_issues,
    vector_active,
)


VERIFIER_SCHEMA = "tsds-independent-certificate-verifier-v1"
CERTIFICATE_SCHEMA = "tsds-evidence-certificate-v2"
CERTIFICATE_DIGEST_FIELD = "certificate_sha256"
RECORD_DIGEST_FIELD = "source_record_sha256"
ADMISSIBLE_BINDINGS = frozenset({"direct_abi_arg0", "rendered_format_wrapper"})
ADMISSIBLE_SEMANTICS = frozenset({"shell_command", "shell_format_wrapper"})
CLAIM_STATUSES = frozenset({"vulnerable", "conditioned_feasibility", "filtered", "no_taint_sink"})
HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")


def strict_json_object(payload: str | bytes, label: str = "JSON") -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        row: dict[str, Any] = {}
        for key, value in pairs:
            if key in row:
                raise ValueError(f"duplicate key {key!r} in {label}")
            row[key] = value
        return row

    value = json.loads(payload, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not an object")
    return value


def _normalise(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _normalise(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]
    if isinstance(value, set):
        return [_normalise(item) for item in sorted(value, key=repr)]
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value.hex()}
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        _normalise(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _verify_reconciliation_link(
    link: Mapping[str, Any] | None,
    source: Mapping[str, Any],
    sink: Mapping[str, Any],
) -> list[str]:
    """Independently check the serialized link required by a direct upgrade."""

    if not isinstance(link, Mapping):
        return ["reconciled_source_link_missing"]
    issues: list[str] = []
    if link.get("schema") != "tsds-reconciliation-link-v1":
        issues.append("reconciled_source_link_schema_mismatch")
    if link.get("status") != "verified":
        issues.append("reconciled_source_link_not_verified")
    body = dict(link)
    supplied = body.pop("link_sha256", None)
    if not isinstance(supplied, str) or supplied != sha256_json(body):
        issues.append("reconciled_source_link_digest_mismatch")

    variables = link.get("source_variables")
    if not isinstance(variables, list) or not variables or len(variables) != len(set(str(value) for value in variables)):
        issues.append("reconciled_source_link_variables_invalid")
    else:
        if link.get("source_variable_sha256") != sha256_json(sorted(str(value) for value in variables)):
            issues.append("reconciled_source_link_variable_digest_mismatch")

    chain = link.get("transform_chain")
    if not isinstance(chain, list) or not chain:
        issues.append("reconciled_source_link_transform_chain_invalid")
    elif link.get("transform_chain_sha256") != sha256_json(chain):
        issues.append("reconciled_source_link_transform_digest_mismatch")
    step_records = {
        str(step.get("step_id") or ""): step
        for step in chain
        if isinstance(step, Mapping) and str(step.get("step_id") or "")
    } if isinstance(chain, list) else {}
    steps = set(step_records)

    mapping = link.get("source_to_sink")
    if not isinstance(mapping, list) or not mapping:
        issues.append("reconciled_source_link_mapping_invalid")
    elif link.get("source_to_sink_sha256") != sha256_json(mapping):
        issues.append("reconciled_source_link_mapping_digest_mismatch")
    mapped_offsets: list[int] = []
    variable_names = {str(value) for value in variables} if isinstance(variables, list) else set()
    for index, item in enumerate(mapping if isinstance(mapping, list) else []):
        if not isinstance(item, Mapping):
            issues.append(f"reconciled_source_link_mapping_{index}_invalid")
            continue
        try:
            offset = int(item.get("sink_offset"))
            source_offset = int(item.get("source_offset"))
        except (TypeError, ValueError):
            issues.append(f"reconciled_source_link_mapping_{index}_offset_invalid")
            continue
        if offset < 0 or source_offset < 0 or offset in mapped_offsets:
            issues.append(f"reconciled_source_link_mapping_{index}_offset_invalid")
        mapped_offsets.append(offset)
        if str(item.get("source_variable") or "") not in variable_names:
            issues.append(f"reconciled_source_link_mapping_{index}_variable_invalid")
        if str(item.get("transform_step") or "") not in steps:
            issues.append(f"reconciled_source_link_mapping_{index}_step_invalid")
        else:
            step = step_records[str(item.get("transform_step") or "")]
            input_variables = step.get("input_variables")
            if isinstance(input_variables, list) and str(item.get("source_variable") or "") not in {
                str(value) for value in input_variables
            }:
                issues.append(f"reconciled_source_link_mapping_{index}_source_not_in_transform_inputs")
            output_offsets = step.get("output_offsets")
            try:
                output_set = {int(value) for value in output_offsets}
            except (TypeError, ValueError):
                output_set = set()
            if output_set and offset not in output_set:
                issues.append(f"reconciled_source_link_mapping_{index}_sink_offset_not_in_transform_outputs")
        if item.get("relation") not in {"copy", "derived"}:
            issues.append(f"reconciled_source_link_mapping_{index}_relation_invalid")
        if not isinstance(item.get("constraint_sha256"), str) or len(item.get("constraint_sha256")) != 64:
            issues.append(f"reconciled_source_link_mapping_{index}_constraint_digest_invalid")
        input_contract = link.get("input_contract")
        if isinstance(input_contract, Mapping):
            try:
                if source_offset >= int(input_contract.get("max_length")):
                    issues.append(f"reconciled_source_link_mapping_{index}_source_offset_outside_input")
            except (TypeError, ValueError):
                pass
        cstring = link.get("sink_cstring")
        if isinstance(cstring, Mapping):
            try:
                if offset >= int(cstring.get("terminator_offset")):
                    issues.append(f"reconciled_source_link_mapping_{index}_sink_offset_outside_cstring")
            except (TypeError, ValueError):
                pass
    if not isinstance(mapping, list) or link.get("mapping_count") != len(mapping):
        issues.append("reconciled_source_link_mapping_count_mismatch")

    input_contract = link.get("input_contract")
    if not isinstance(input_contract, Mapping) or input_contract.get("encoding") != "raw_bytes" or input_contract.get("nul_policy") != "first_nul_terminates":
        issues.append("reconciled_source_link_input_contract_invalid")
    cstring = link.get("sink_cstring")
    if not isinstance(cstring, Mapping) or cstring.get("complete") is not True:
        issues.append("reconciled_source_link_cstring_invalid")
    if link.get("ambiguities") not in ([], None):
        issues.append("reconciled_source_link_ambiguous")

    link_sink = link.get("sink_snapshot_sha256")
    cert_sink = sink.get("snapshot_sha256")
    if cert_sink and link_sink != cert_sink:
        issues.append("reconciled_source_link_sink_digest_mismatch")
    controlled = set()
    for value in source.get("controlled_offsets") or []:
        try:
            controlled.add(int(value))
        except (TypeError, ValueError):
            issues.append("reconciled_source_link_record_offset_invalid")
    if controlled and not set(mapped_offsets).issubset(controlled):
        issues.append("reconciled_source_link_offsets_outside_controlled_domain")
    return sorted(set(issues))


def _integer(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def decode_rendered_witness(value: Any) -> str:
    text = HEX_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), str(value or ""))
    nul = text.find("\x00")
    return text if nul < 0 else text[:nul]


def verify_certificate(
    certificate: Mapping[str, Any], source_record_digests: set[str] | None = None
) -> list[str]:
    """Check a certificate without calling generator-side validation code."""

    row = dict(certificate or {})
    issues: list[str] = []
    if row.get("schema") != CERTIFICATE_SCHEMA:
        issues.append("unsupported_certificate_schema")
    supplied_digest = row.get(CERTIFICATE_DIGEST_FIELD)
    body = dict(row)
    body.pop(CERTIFICATE_DIGEST_FIELD, None)
    if supplied_digest != sha256_json(body):
        issues.append("certificate_digest_mismatch")
    source_digest = str(row.get(RECORD_DIGEST_FIELD) or "")
    if len(source_digest) != 64:
        issues.append("source_record_digest_invalid")
    elif source_record_digests is not None and source_digest not in source_record_digests:
        issues.append("source_record_not_found")

    identity = row.get("identity") or {}
    analysis = row.get("analysis") or {}
    source = row.get("source") or {}
    sink = row.get("sink") or {}
    matrix = row.get("matrix") or {}
    recovery = row.get("recovery_admission") or {}
    if identity.get("closure_idx") is None or not identity.get("sink_addr"):
        issues.append("missing_closure_identity")

    spec = matrix.get("spec") or {}
    issues.extend(matrix_spec_validation_issues(spec))
    if tuple(matrix.get("expected_vector_ids") or ()) != VECTOR_IDS:
        issues.append("matrix_expected_vector_order_mismatch")

    decisions = [item for item in (matrix.get("decisions") or []) if isinstance(item, Mapping)]
    decision_counts: Counter[str] = Counter()
    seen: set[str] = set()
    for index, decision in enumerate(decisions):
        vector_id = str(decision.get("vector_id") or "")
        outcome = str(decision.get("decision") or "")
        if vector_id not in VECTOR_ID_SET:
            issues.append(f"decision_{index}_unknown_vector")
        if vector_id in seen:
            issues.append(f"decision_{index}_duplicate_vector")
        seen.add(vector_id)
        if outcome not in {"VECTOR_SAT", "MATRIX_UNSAT", "INCONCLUSIVE"}:
            issues.append(f"decision_{index}_unknown_outcome")
        decision_counts[outcome] += 1
        if outcome == "VECTOR_SAT":
            if decision.get("grammar_complete") is not True or not decision.get("witness"):
                issues.append(f"decision_{index}_sat_witness_incomplete")
            context = str(decision.get("quote_context") or "")
            activity = vector_active(vector_id, context)
            if activity is False and str(decision.get("witness_kind") or "") not in {
                "single_quote_breakout",
                "double_quote_breakout",
            }:
                issues.append(f"decision_{index}_sat_inactive_context")

    declared_counts = {
        "VECTOR_SAT": _integer(matrix.get("vulnerable_vectors")),
        "MATRIX_UNSAT": _integer(matrix.get("secure_vectors")),
        "INCONCLUSIVE": _integer(matrix.get("inconclusive_vectors")),
    }
    for outcome, declared in declared_counts.items():
        if declared != decision_counts[outcome]:
            issues.append(f"matrix_{outcome.lower()}_count_mismatch")

    controlled: list[int] = []
    for value in source.get("controlled_offsets") or []:
        try:
            offset = int(value)
        except (TypeError, ValueError):
            issues.append("controlled_offset_not_integer")
            continue
        if offset < 0 or offset in controlled:
            issues.append("controlled_offsets_not_unique_nonnegative")
        controlled.append(offset)
    if controlled != sorted(controlled):
        issues.append("controlled_offsets_not_sorted")
    domain = source.get("offset_domain") or {}
    domain_length = _integer(domain.get("length"))
    if controlled and domain_length <= 0:
        issues.append("controlled_offsets_without_domain")
    elif controlled and max(controlled) >= domain_length:
        issues.append("controlled_offset_outside_domain")

    status = str(analysis.get("status") or "")
    provenance = str(analysis.get("evidence_provenance") or "")
    if status in CLAIM_STATUSES:
        if analysis.get("evidence_contract_valid") is not True:
            issues.append("claim_without_valid_contract")
        if sink.get("semantics") not in ADMISSIBLE_SEMANTICS:
            issues.append("claim_without_shell_semantics")
        if sink.get("binding_trust") not in ADMISSIBLE_BINDINGS:
            issues.append("claim_without_trusted_binding")
        if sink.get("reached") is not True:
            issues.append("claim_without_observed_sink")
    if status == "vulnerable":
        if not controlled:
            issues.append("positive_without_controlled_offsets")
        if decision_counts["VECTOR_SAT"] <= 0:
            issues.append("positive_without_sat_decision")
        witness = matrix.get("minimal_witness") or {}
        if witness.get("grammar_complete") is not True or not witness.get("witness"):
            issues.append("positive_without_minimal_witness")
        if not witness.get("parser_calibration"):
            issues.append("positive_without_parser_calibration")
        if provenance == "SINK_RECONCILED":
            if recovery.get("applicable") is not True or recovery.get("admitted") is not True:
                issues.append("reconciled_positive_without_admission")
            if recovery.get("admission_violations"):
                issues.append("reconciled_positive_with_admission_violation")
            if _integer(recovery.get("path_constraint_count")) <= 0:
                issues.append("reconciled_positive_without_path_constraints")
            if recovery.get("matrix_reconciled_constrained") is not True:
                issues.append("reconciled_positive_without_constrained_matrix")
            if not recovery.get("command_template_sha256"):
                issues.append("reconciled_positive_without_template_digest")
            issues.extend(_verify_reconciliation_link(recovery.get("reconciliation_link"), source, sink))
    if status == "conditioned_feasibility":
        if provenance != "SINK_RECONCILED":
            issues.append("conditioned_without_reconciliation_provenance")
        if analysis.get("claim_scope") != "conditioned_template_feasibility":
            issues.append("conditioned_without_conditioned_scope")
        if analysis.get("primary_aggregate_eligible") is True:
            issues.append("conditioned_marked_primary")
    elif status == "filtered":
        if not controlled:
            issues.append("filtered_without_controlled_offsets")
        if sink.get("snapshot_cstring_complete") is not True:
            issues.append("filtered_without_complete_snapshot")
        if seen != VECTOR_ID_SET or decision_counts["MATRIX_UNSAT"] != len(VECTOR_IDS):
            issues.append("filtered_without_complete_unsat_matrix")
    elif status == "no_taint_sink":
        if controlled:
            issues.append("nms_with_controlled_offsets")
        if sink.get("snapshot_cstring_complete") is not True:
            issues.append("nms_without_complete_snapshot")
    return sorted(set(issues))


def summarize_verification(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    items = list(rows)
    issue_counts: Counter[str] = Counter()
    for row in items:
        for issue in row.get("issues") or []:
            issue_counts[str(issue)] += 1
    issue_records = sum(bool(row.get("issues")) for row in items)
    parser_counts = Counter(str(row.get("parser_outcome") or "not_requested") for row in items)
    return {
        "schema": VERIFIER_SCHEMA,
        "records": len(items),
        "valid_records": len(items) - issue_records,
        "records_with_issues": issue_records,
        "issue_counts": dict(sorted(issue_counts.items())),
        "parser_outcomes": dict(sorted(parser_counts.items())),
        "valid": bool(items) and issue_records == 0,
        "claim_boundary": (
            "The second implementation checks serialization, matrix identity, offsets, "
            "claim invariants, recovery admission, source binding, and optional no-execution parsing."
        ),
    }
