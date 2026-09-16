"""Front-end-neutral candidate contract for TSDS evidence construction."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any, Iterable, Mapping


CANDIDATE_CONTRACT_SCHEMA = "tsds-candidate-contract-v1"
NORMALIZED_CANDIDATE_SCHEMA = "tsds-normalized-candidate-v1"
FORBIDDEN_OUTCOME_FIELDS = frozenset(
    {
        "verdict",
        "evidence_contract_valid",
        "vector_decisions",
        "minimal_bypass_vector",
        "controlled_offsets",
        "tainted_offsets",
    }
)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _address(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    try:
        return hex(int(text, 16 if text.startswith("0x") else 0))
    except ValueError:
        return text


def validate_candidate_document(document: Mapping[str, Any]) -> list[str]:
    issues: list[str] = []
    if document.get("schema") != "tsds-closures-v1":
        issues.append("unsupported_candidate_document_schema")
    frontend = str(document.get("frontend") or "")
    if not frontend:
        issues.append("missing_document_frontend")
    closures = document.get("closures") or []
    if not isinstance(closures, list) or not closures:
        issues.append("missing_candidate_closures")
        return sorted(set(issues))
    seen: set[str] = set()
    for index, closure in enumerate(closures):
        prefix = f"closure_{index}"
        if not isinstance(closure, Mapping):
            issues.append(f"{prefix}_not_object")
            continue
        leaked = sorted(FORBIDDEN_OUTCOME_FIELDS & set(closure))
        if leaked:
            issues.append(f"{prefix}_contains_tsds_outcome_fields")
        closure_id = str(closure.get("id") or "")
        if not closure_id:
            issues.append(f"{prefix}_missing_id")
        elif closure_id in seen:
            issues.append(f"{prefix}_duplicate_id")
        seen.add(closure_id)
        if str(closure.get("frontend") or frontend) != frontend:
            issues.append(f"{prefix}_frontend_mismatch")
        trace = closure.get("trace") or []
        if not isinstance(trace, list) or not trace:
            issues.append(f"{prefix}_missing_trace")
        sink = closure.get("sink") or {}
        if not str(sink.get("function") or "") or not _address(sink.get("ins_addr")):
            issues.append(f"{prefix}_missing_sink_identity")
        inputs = closure.get("inputs") or {}
        if not isinstance(inputs, Mapping):
            issues.append(f"{prefix}_inputs_not_object")
        else:
            for field in ("likely", "possibly", "tags", "valid_funcs"):
                if not isinstance(inputs.get(field), list):
                    issues.append(f"{prefix}_inputs_{field}_not_list")
        if frontend == "satc":
            satc = closure.get("satc") or {}
            if satc.get("source_semantics_policy") != "address_provenance_only":
                issues.append(f"{prefix}_satc_source_policy_not_fail_closed")
            if not satc.get("origin_file_sha256"):
                issues.append(f"{prefix}_satc_origin_hash_missing")
    return sorted(set(issues))


def normalized_candidate(
    closure: Mapping[str, Any], document_frontend: str
) -> dict[str, Any]:
    trace = closure.get("trace") or []
    source = trace[0] if trace and isinstance(trace[0], Mapping) else {}
    sink = closure.get("sink") or {}
    inputs = closure.get("inputs") or {}
    frontend = str(closure.get("frontend") or document_frontend)
    source_addr = _address(source.get("ins_addr"))
    sink_addr = _address(sink.get("ins_addr"))
    identity = "|".join([frontend, str(closure.get("id") or ""), source_addr, sink_addr])
    return {
        "schema": NORMALIZED_CANDIDATE_SCHEMA,
        "candidate_id": hashlib.sha256(identity.encode()).hexdigest()[:24],
        "frontend": frontend,
        "frontend_candidate_id": closure.get("id"),
        "source_addr": source_addr,
        "sink_addr": sink_addr,
        "source_function": source.get("function"),
        "sink_function": sink.get("function"),
        "trace_length": len(trace),
        "likely_input_count": len(inputs.get("likely") or []),
        "possible_input_count": len(inputs.get("possibly") or []),
        "source_semantics": "candidate_hint_only",
        "closure_sha256": hashlib.sha256(_canonical_json(closure).encode()).hexdigest(),
    }


def audit_candidate_document(
    document: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    issues = validate_candidate_document(document)
    frontend = str(document.get("frontend") or "")
    rows = [
        normalized_candidate(closure, frontend)
        for closure in (document.get("closures") or [])
        if isinstance(closure, Mapping)
    ]
    summary = {
        "schema": CANDIDATE_CONTRACT_SCHEMA,
        "frontend": frontend,
        "records": len(rows),
        "unique_candidates": len({row["candidate_id"] for row in rows}),
        "sink_functions": dict(sorted(Counter(str(row["sink_function"]) for row in rows).items())),
        "issues": issues,
        "valid": bool(rows) and not issues,
        "claim_boundary": (
            "The contract normalizes candidate identity and provenance only; front-end "
            "addresses and keywords remain hints until final sink-byte evidence is constructed."
        ),
    }
    return rows, summary
