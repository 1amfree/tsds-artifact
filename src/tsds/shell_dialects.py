"""Conservative shell-dialect context checks for TSDS vector decisions.

TSDS's primary matrix remains a bounded byte-level feasibility analysis.  This
module adds a separate, pure-Python audit of whether a reported vector is
lexically active in the recorded quote context for the supported POSIX-like
profiles.  Unknown context never strengthens a claim.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable, Mapping

from tsds.shell_matrix_spec import (
    MATRIX_SPEC_VERSION,
    VECTOR_ID_SET,
    matrix_spec_sha256,
)


DIALECT_AUDIT_SCHEMA = "tsds-shell-dialect-profile-v1"

ALL_VECTORS = VECTOR_ID_SET
DOUBLE_QUOTE_ACTIVE = frozenset(
    {"backtick_substitution", "dollar_substitution", "dollar_expansion"}
)

DIALECTS = {
    "busybox_ash": {"vectors": ALL_VECTORS},
    "dash": {"vectors": ALL_VECTORS},
    "bash_posix": {"vectors": ALL_VECTORS},
}


def active_in_quote_context(vector_id: str, quote_context: str | None) -> bool | None:
    """Return lexical activity; ``None`` means TSDS lacks context evidence."""

    context = str(quote_context or "").strip().lower()
    if context in {"", "unknown", "mixed", "unmodeled"}:
        return None
    if context in {"unquoted", "none"}:
        return vector_id in ALL_VECTORS
    if context in {"single_quoted", "single_quote"}:
        return False
    if context in {"double_quoted", "double_quote"}:
        return vector_id in DOUBLE_QUOTE_ACTIVE
    return None


def audit_decision(decision: Mapping[str, Any], dialect: str) -> dict[str, Any]:
    profile = DIALECTS.get(dialect)
    vector_id = str(decision.get("vector_id") or "")
    outcome = str(decision.get("decision") or "")
    witness_kind = str(decision.get("witness_kind") or "")
    quote_context = decision.get("quote_context")
    # TSDS emits explicit quote-breakout witnesses for a source slot inside a
    # quoted literal.  Their lexical gate has already checked that the witness
    # closes the original quote before the vector appears; auditing them as
    # still quoted would be a false negative in the independent profile.
    if witness_kind in {"single_quote_breakout", "double_quote_breakout"}:
        active = vector_id in ALL_VECTORS
        effective_context = "unquoted_after_quote_breakout"
    else:
        active = active_in_quote_context(vector_id, quote_context)
        effective_context = quote_context
    issues: list[str] = []
    if profile is None:
        issues.append("unknown_dialect_profile")
    elif vector_id not in profile["vectors"]:
        issues.append("vector_not_supported_by_profile")
    if outcome == "VECTOR_SAT":
        if not decision.get("grammar_complete"):
            issues.append("sat_without_grammar_complete_witness")
        if decision.get("lexical_reason") not in {"lexically_complete", ""}:
            issues.append("sat_with_incomplete_lexical_context")
        if active is False:
            issues.append("sat_vector_inactive_in_quote_context")
        elif active is None:
            issues.append("sat_vector_with_unknown_quote_context")
    return {
        "dialect": dialect,
        "vector_id": vector_id,
        "decision": outcome,
        "quote_context": decision.get("quote_context"),
        "effective_quote_context": effective_context,
        "witness_kind": witness_kind,
        "lexically_active": active,
        "issues": sorted(set(issues)),
        "portable_sat": outcome == "VECTOR_SAT" and not issues,
    }


def audit_records(records: Iterable[Mapping[str, Any]], dialects: Iterable[str] | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    selected = list(dialects or DIALECTS)
    rows: list[dict[str, Any]] = []
    outcomes: Counter[str] = Counter()
    per_dialect: dict[str, Counter[str]] = defaultdict(Counter)
    issue_counts: Counter[str] = Counter()
    for record in records or []:
        for decision in record.get("vector_decisions") or []:
            if not isinstance(decision, Mapping):
                continue
            for dialect in selected:
                row = audit_decision(decision, dialect)
                row["closure_idx"] = record.get("closure_idx")
                row["status"] = record.get("status")
                rows.append(row)
                outcome = "portable_sat" if row["portable_sat"] else (
                    "sat_issue" if row["decision"] == "VECTOR_SAT" and row["issues"] else "non_sat"
                )
                outcomes[outcome] += 1
                per_dialect[dialect][outcome] += 1
                for issue in row["issues"]:
                    issue_counts[issue] += 1
    summary = {
        "schema": DIALECT_AUDIT_SCHEMA,
        "matrix_spec_version": MATRIX_SPEC_VERSION,
        "matrix_spec_sha256": matrix_spec_sha256(),
        "records": len({row.get("closure_idx") for row in rows}),
        "decision_dialect_rows": len(rows),
        "outcomes": dict(sorted(outcomes.items())),
        "per_dialect": {name: dict(sorted(counts.items())) for name, counts in sorted(per_dialect.items())},
        "issue_counts": dict(sorted(issue_counts.items())),
        "claim_boundary": (
            "Dialect profiles audit lexical activity under recorded quote context. "
            "They do not replace runtime shell calibration or prove command execution."
        ),
    }
    return rows, summary
