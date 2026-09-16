"""Fail-closed semantic links for conditioned sink reconstruction.

The evaluator may reconstruct a symbolic source slot from a static template
when byte provenance was lost.  Such a reconstruction is useful as a
conditioned feasibility result, but it is not observed source provenance.
This module defines the additional serialized relation needed before a
conditioned result can support a stronger source-realizability claim.

The link is intentionally data-only and dependency-free.  It records the
source variables, transformation chain, exact sink-byte mapping, C-string
contract, and producer binding.  Hashes provide integrity; they do not by
themselves prove semantic correctness.  A reviewer or independent replayer
must still inspect the referenced transformations and constraints.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence


RECONCILIATION_LINK_SCHEMA = "tsds-reconciliation-link-v1"
LINK_STATUSES = frozenset({"verified", "unverified", "ambiguous", "rejected"})
LINK_KINDS = frozenset({"observed_provenance", "symbolic_transform_equivalence"})
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX64.fullmatch(value))


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _link_body(link: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in link.items() if str(key) != "link_sha256"}


def _mapping_issues(
    link: Mapping[str, Any],
    source_variables: set[str],
    steps: Mapping[str, Mapping[str, Any]],
    *,
    max_input_length: int | None = None,
    terminator_offset: int | None = None,
) -> list[str]:
    issues: list[str] = []
    mapping = link.get("source_to_sink")
    if not isinstance(mapping, list) or not mapping:
        return ["source_to_sink_mapping_missing_or_empty"]
    sink_offsets: list[int] = []
    for index, row in enumerate(mapping):
        if not isinstance(row, Mapping):
            issues.append(f"mapping_{index}_not_an_object")
            continue
        sink_offset = _int(row.get("sink_offset"))
        source_offset = _int(row.get("source_offset"))
        source_variable = str(row.get("source_variable") or "")
        transform_step = str(row.get("transform_step") or "")
        if sink_offset is None or sink_offset < 0:
            issues.append(f"mapping_{index}_invalid_sink_offset")
        else:
            sink_offsets.append(sink_offset)
        if source_offset is None or source_offset < 0:
            issues.append(f"mapping_{index}_invalid_source_offset")
        elif max_input_length is not None and source_offset >= max_input_length:
            issues.append(f"mapping_{index}_source_offset_outside_input")
        if not source_variable:
            issues.append(f"mapping_{index}_missing_source_variable")
        elif source_variable not in source_variables:
            issues.append(f"mapping_{index}_unknown_source_variable")
        if not transform_step or transform_step not in steps:
            issues.append(f"mapping_{index}_unknown_transform_step")
        else:
            step = steps[transform_step]
            step_inputs = step.get("input_variables")
            if isinstance(step_inputs, list) and source_variable not in {
                str(value) for value in step_inputs
            }:
                issues.append(f"mapping_{index}_source_not_in_transform_inputs")
            step_outputs = step.get("output_offsets")
            try:
                output_offsets = {int(value) for value in step_outputs}
            except (TypeError, ValueError):
                output_offsets = set()
            if sink_offset is not None and output_offsets and sink_offset not in output_offsets:
                issues.append(f"mapping_{index}_sink_offset_not_in_transform_outputs")
        if str(row.get("relation") or "") not in {"copy", "derived"}:
            issues.append(f"mapping_{index}_invalid_relation")
        if not _is_digest(row.get("constraint_sha256")):
            issues.append(f"mapping_{index}_missing_constraint_digest")
        if (
            sink_offset is not None
            and terminator_offset is not None
            and sink_offset >= terminator_offset
        ):
            issues.append(f"mapping_{index}_sink_offset_outside_cstring")
    if len(sink_offsets) != len(set(sink_offsets)):
        issues.append("duplicate_sink_offsets")
    return issues


def validate_reconciliation_link(
    link: Mapping[str, Any] | None,
    record: Mapping[str, Any] | None = None,
) -> list[str]:
    """Return violations for a semantic source-to-sink link.

    ``verified`` means that the producer supplied all required binding data;
    it does not mean that this lightweight validator independently proved the
    program semantics.  Missing or ambiguous relations never become a direct
    source claim.
    """

    if not isinstance(link, Mapping):
        return ["reconciliation_link_missing"]
    issues: list[str] = []
    if link.get("schema") != RECONCILIATION_LINK_SCHEMA:
        issues.append("unsupported_reconciliation_link_schema")
    status = str(link.get("status") or "")
    if status not in LINK_STATUSES:
        issues.append("invalid_reconciliation_link_status")
    if status != "verified":
        issues.append("reconciliation_link_not_verified")
    kind = str(link.get("kind") or "")
    if kind not in LINK_KINDS:
        issues.append("invalid_reconciliation_link_kind")
    source_variables = link.get("source_variables")
    if not isinstance(source_variables, list) or not source_variables:
        issues.append("source_variables_missing_or_empty")
        source_variable_set: set[str] = set()
    else:
        source_variable_set = {str(value) for value in source_variables}
        if any(not value.strip() for value in source_variable_set):
            issues.append("source_variables_contain_empty_value")
        if len(source_variable_set) != len(source_variables):
            issues.append("duplicate_source_variable")
    source_variable_digest = link.get("source_variable_sha256")
    if not _is_digest(source_variable_digest):
        issues.append("source_variable_digest_missing")
    elif source_variable_digest != sha256_json(sorted(source_variable_set)):
        issues.append("source_variable_digest_mismatch")

    chain = link.get("transform_chain")
    step_records: dict[str, Mapping[str, Any]] = {}
    if not isinstance(chain, list) or not chain:
        issues.append("transform_chain_missing_or_empty")
        step_ids: set[str] = set()
    else:
        step_ids = set()
        for index, step in enumerate(chain):
            if not isinstance(step, Mapping):
                issues.append(f"transform_step_{index}_not_an_object")
                continue
            step_id = str(step.get("step_id") or "")
            if not step_id:
                issues.append(f"transform_step_{index}_missing_id")
            elif step_id in step_ids:
                issues.append("duplicate_transform_step_id")
            else:
                step_records[step_id] = step
            step_ids.add(step_id)
            if not str(step.get("operation") or ""):
                issues.append(f"transform_step_{index}_missing_operation")
            if not isinstance(step.get("input_variables"), list) or not step.get("input_variables"):
                issues.append(f"transform_step_{index}_missing_inputs")
            if not isinstance(step.get("output_offsets"), list) or not step.get("output_offsets"):
                issues.append(f"transform_step_{index}_missing_outputs")
            if not _is_digest(step.get("constraint_sha256")):
                issues.append(f"transform_step_{index}_missing_constraint_digest")
    chain_digest = link.get("transform_chain_sha256")
    if not _is_digest(chain_digest):
        issues.append("transform_chain_digest_missing")
    elif isinstance(chain, list) and chain_digest != sha256_json(chain):
        issues.append("transform_chain_digest_mismatch")

    input_contract = link.get("input_contract")
    max_input_length = None
    if isinstance(input_contract, Mapping):
        max_input_length = _int(input_contract.get("max_length"))
    cstring = link.get("sink_cstring")
    terminator_offset = None
    if isinstance(cstring, Mapping):
        terminator_offset = _int(cstring.get("terminator_offset"))
    issues.extend(
        _mapping_issues(
            link,
            source_variable_set,
            step_records,
            max_input_length=max_input_length,
            terminator_offset=terminator_offset,
        )
    )
    mapping = link.get("source_to_sink")
    mapping_digest = link.get("source_to_sink_sha256")
    if not _is_digest(mapping_digest):
        issues.append("source_to_sink_digest_missing")
    elif isinstance(mapping, list) and mapping_digest != sha256_json(mapping):
        issues.append("source_to_sink_digest_mismatch")

    program_digest = link.get("program_sha256")
    sink_digest = link.get("sink_snapshot_sha256")
    if not _is_digest(program_digest):
        issues.append("program_digest_missing")
    if not _is_digest(sink_digest):
        issues.append("sink_snapshot_digest_missing")

    if not isinstance(input_contract, Mapping):
        issues.append("input_contract_missing")
    else:
        if input_contract.get("encoding") != "raw_bytes":
            issues.append("input_contract_encoding_not_raw_bytes")
        if input_contract.get("nul_policy") != "first_nul_terminates":
            issues.append("input_contract_nul_policy_missing")
        max_length = _int(input_contract.get("max_length"))
        if max_length is None or max_length <= 0:
            issues.append("input_contract_max_length_invalid")

    if not isinstance(cstring, Mapping):
        issues.append("sink_cstring_contract_missing")
    else:
        if cstring.get("complete") is not True:
            issues.append("sink_cstring_not_complete")
        terminator = _int(cstring.get("terminator_offset"))
        if terminator is None or terminator < 0:
            issues.append("sink_cstring_terminator_invalid")

    ambiguous = link.get("ambiguities", [])
    if not isinstance(ambiguous, list):
        issues.append("ambiguities_not_a_list")
    elif ambiguous:
        issues.append("reconciliation_link_ambiguous")

    mapping_count = _int(link.get("mapping_count"))
    if isinstance(mapping, list) and (mapping_count is None or mapping_count != len(mapping)):
        issues.append("mapping_count_mismatch")

    supplied_digest = link.get("link_sha256")
    if not _is_digest(supplied_digest):
        issues.append("link_digest_missing")
    elif supplied_digest != sha256_json(_link_body(link)):
        issues.append("link_digest_mismatch")

    if isinstance(record, Mapping):
        record_sink_digest = record.get("tsds_sink_snapshot_digest") or record.get("sink_snapshot_digest")
        if record_sink_digest and sink_digest != record_sink_digest:
            issues.append("link_sink_digest_does_not_match_record")
        record_source_digest = record.get("source_variable_digest") or record.get("source_variable_sha256")
        if record_source_digest and source_variable_digest != record_source_digest:
            issues.append("link_source_variable_digest_does_not_match_record")
        if record.get("sink_snapshot_cstring_complete") is False:
            issues.append("link_reuses_incomplete_sink_snapshot")
        controlled = record.get("controlled_offsets") or record.get("tainted_offsets") or []
        if isinstance(controlled, (list, tuple)) and isinstance(mapping, list):
            allowed = set()
            for value in controlled:
                try:
                    allowed.add(int(value))
                except (TypeError, ValueError):
                    continue
            mapped = {int(row.get("sink_offset")) for row in mapping if isinstance(row, Mapping) and _int(row.get("sink_offset")) is not None}
            if allowed and not mapped.issubset(allowed):
                issues.append("link_sink_offsets_outside_record_controlled_offsets")
    return sorted(set(issues))


def reconciliation_link_admission(
    link: Mapping[str, Any] | None,
    record: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    issues = validate_reconciliation_link(link, record=record)
    return {
        "schema": "tsds-reconciliation-link-admission-v1",
        "admitted": not issues,
        "link_present": isinstance(link, Mapping),
        "link_status": str(link.get("status") or "") if isinstance(link, Mapping) else "missing",
        "issues": issues,
        "claim_boundary": (
            "Admission checks serialized source-to-sink binding consistency. "
            "It is not an independent proof of program semantics."
        ),
    }


def build_verified_link(
    *,
    program_sha256: str,
    sink_snapshot_sha256: str,
    source_variables: Sequence[str],
    transform_chain: Sequence[Mapping[str, Any]],
    source_to_sink: Sequence[Mapping[str, Any]],
    max_input_length: int,
    terminator_offset: int,
    kind: str = "symbolic_transform_equivalence",
) -> dict[str, Any]:
    """Build a complete link for fixtures and future producer integrations."""

    body: dict[str, Any] = {
        "schema": RECONCILIATION_LINK_SCHEMA,
        "status": "verified",
        "kind": kind,
        "program_sha256": program_sha256,
        "sink_snapshot_sha256": sink_snapshot_sha256,
        "source_variables": [str(value) for value in source_variables],
        "source_variable_sha256": sha256_json(sorted(str(value) for value in source_variables)),
        "transform_chain": [dict(step) for step in transform_chain],
        "transform_chain_sha256": sha256_json([dict(step) for step in transform_chain]),
        "source_to_sink": [dict(row) for row in source_to_sink],
        "source_to_sink_sha256": sha256_json([dict(row) for row in source_to_sink]),
        "mapping_count": len(source_to_sink),
        "input_contract": {
            "encoding": "raw_bytes",
            "nul_policy": "first_nul_terminates",
            "max_length": int(max_input_length),
        },
        "sink_cstring": {
            "complete": True,
            "terminator_offset": int(terminator_offset),
        },
        "ambiguities": [],
    }
    body["link_sha256"] = sha256_json(body)
    return body


def unverified_link(reason: str, **fields: Any) -> dict[str, Any]:
    """Create an explicit non-admissible diagnostic link for a CT record."""

    return {
        "schema": RECONCILIATION_LINK_SCHEMA,
        "status": "unverified",
        "kind": "symbolic_transform_equivalence",
        "reason": str(reason),
        **fields,
    }


__all__ = [
    "RECONCILIATION_LINK_SCHEMA",
    "build_verified_link",
    "canonical_json",
    "reconciliation_link_admission",
    "sha256_json",
    "unverified_link",
    "validate_reconciliation_link",
]
