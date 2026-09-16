"""Versioned, content-addressed TSDS shell-vector matrix specification."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping


MATRIX_SPEC_SCHEMA = "tsds-shell-vector-matrix-spec-v1"
# v2 includes the grammar-complete witness in the content-addressed payload.
# The legacy digest is retained so auditors can still read the frozen V20
# release without silently treating its older specification as current.
MATRIX_SPEC_VERSION = "2026.07-posix11-witness-v2"
LEGACY_MATRIX_SPEC_VERSION = "2026.07-posix11"
LEGACY_MATRIX_SPEC_SHA256 = (
    "b15b731c773f5b9cf851e2f2982114f44e7b1eda0524ceee765220932e51c311"
)

VECTOR_DEFINITIONS = (
    {"vector_id": "semicolon", "token": ";", "witness": ":;:;#", "category": "control_operator", "effect_class": "command_sequence", "active_contexts": ["unquoted"]},
    {"vector_id": "newline", "token": "\n", "witness": ":\n:;#", "category": "control_operator", "effect_class": "command_sequence", "active_contexts": ["unquoted"]},
    {"vector_id": "pipe", "token": "|", "witness": ":|:;#", "category": "control_operator", "effect_class": "pipeline", "active_contexts": ["unquoted"]},
    {"vector_id": "background_ampersand", "token": "&", "witness": ":&:;#", "category": "control_operator", "effect_class": "asynchronous_list", "active_contexts": ["unquoted"]},
    {"vector_id": "backtick_substitution", "token": "`", "witness": "`:`", "category": "substitution", "effect_class": "command_substitution", "active_contexts": ["unquoted", "double_quoted"]},
    {"vector_id": "dollar_substitution", "token": "$(", "witness": "$(:)", "category": "substitution", "effect_class": "command_substitution", "active_contexts": ["unquoted", "double_quoted"]},
    {"vector_id": "dollar_expansion", "token": "$", "witness": "$A", "category": "expansion", "effect_class": "parameter_expansion", "active_contexts": ["unquoted", "double_quoted"]},
    {"vector_id": "output_redirection", "token": ">", "witness": ">/dev/null", "category": "redirection", "effect_class": "output_redirection", "active_contexts": ["unquoted"]},
    {"vector_id": "input_redirection", "token": "<", "witness": "</dev/null", "category": "redirection", "effect_class": "input_redirection", "active_contexts": ["unquoted"]},
    {"vector_id": "ifs_word_splitting", "token": "${IFS}", "witness": "${IFS}:", "category": "word_splitting", "effect_class": "argument_boundary", "active_contexts": ["unquoted"]},
    {"vector_id": "tab_word_splitting", "token": "\t", "witness": "\t:", "category": "word_splitting", "effect_class": "argument_boundary", "active_contexts": ["unquoted"]},
)

VECTOR_IDS = tuple(row["vector_id"] for row in VECTOR_DEFINITIONS)
VECTOR_ID_SET = frozenset(VECTOR_IDS)
VECTOR_BY_ID = {row["vector_id"]: row for row in VECTOR_DEFINITIONS}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def matrix_spec_payload() -> dict[str, Any]:
    return {
        "schema": MATRIX_SPEC_SCHEMA,
        "version": MATRIX_SPEC_VERSION,
        "contexts": ["unquoted", "single_quoted", "double_quoted"],
        "context_automaton": {
            "initial": "unquoted",
            "escape": "backslash escapes the next byte outside single quotes",
            "single_quote": "toggles only from unquoted",
            "double_quote": "toggles only from unquoted",
        },
        "dialects": ["busybox_ash", "dash", "bash_posix"],
        "vectors": [dict(row) for row in VECTOR_DEFINITIONS],
    }


def matrix_spec_sha256() -> str:
    return hashlib.sha256(_canonical_json(matrix_spec_payload()).encode()).hexdigest()


def matrix_spec_validation_issues(spec: Mapping[str, Any] | None) -> list[str]:
    """Validate current or explicitly supported legacy matrix identities.

    The frozen V20 release predates witness-bound hashing.  It remains
    readable as a legacy artifact, while every newly generated record uses
    the current digest whose payload includes the complete witness templates.
    """

    value = spec if isinstance(spec, Mapping) else {}
    issues: list[str] = []
    if value.get("schema") != MATRIX_SPEC_SCHEMA:
        issues.append("matrix_spec_schema_mismatch")
        return issues
    version = value.get("version")
    supplied = value.get("sha256")
    if version == MATRIX_SPEC_VERSION:
        if supplied != matrix_spec_sha256():
            issues.append("matrix_spec_digest_mismatch")
    elif version == LEGACY_MATRIX_SPEC_VERSION:
        if supplied != LEGACY_MATRIX_SPEC_SHA256:
            issues.append("matrix_spec_digest_mismatch")
    else:
        issues.append("matrix_spec_version_mismatch")
    return issues


def matrix_spec_manifest() -> dict[str, Any]:
    payload = matrix_spec_payload()
    payload["sha256"] = matrix_spec_sha256()
    return payload


def quote_context_after(prefix: str | bytes) -> str:
    """Evaluate a small deterministic quote-context automaton over a prefix."""

    text = prefix.decode("latin-1") if isinstance(prefix, bytes) else str(prefix)
    state = "unquoted"
    escaped = False
    for char in text:
        if escaped:
            escaped = False
            continue
        if char == "\\" and state != "single_quoted":
            escaped = True
            continue
        if char == "'" and state == "unquoted":
            state = "single_quoted"
        elif char == "'" and state == "single_quoted":
            state = "unquoted"
        elif char == '"' and state == "unquoted":
            state = "double_quoted"
        elif char == '"' and state == "double_quoted":
            state = "unquoted"
    return state


def vector_active(vector_id: str, context: str) -> bool | None:
    definition = VECTOR_BY_ID.get(str(vector_id))
    if definition is None or context not in {"unquoted", "single_quoted", "double_quoted"}:
        return None
    return context in definition["active_contexts"]


def matrix_decision_issues(decisions: Iterable[Mapping[str, Any]]) -> list[str]:
    issues: list[str] = []
    seen: set[str] = set()
    for index, decision in enumerate(decisions):
        vector_id = str(decision.get("vector_id") or "")
        outcome = str(decision.get("decision") or "")
        if vector_id not in VECTOR_ID_SET:
            issues.append(f"decision_{index}_unknown_vector")
        elif vector_id in seen:
            issues.append(f"decision_{index}_duplicate_vector")
        seen.add(vector_id)
        if outcome not in {"VECTOR_SAT", "MATRIX_UNSAT", "INCONCLUSIVE"}:
            issues.append(f"decision_{index}_unknown_outcome")
    return sorted(set(issues))
