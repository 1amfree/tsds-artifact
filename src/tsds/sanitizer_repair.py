"""Counterfactual, matrix-bounded sanitizer repair explanations for TSDS.

The output is a diagnostic planning aid.  It computes minimal *modeled vector*
coverage sets; it does not synthesize source patches or claim that a proposed
filter is complete shell protection.
"""

from __future__ import annotations

from itertools import combinations
from typing import Any, Iterable, Mapping


REPAIR_SCHEMA = "tsds-counterfactual-repair-v1"

# Each proposal is intentionally phrased as a policy/validation obligation,
# not an implementation patch.  Costs favor a narrow modeled filter over a
# broad rule, while the universal shell-avoidance recommendation remains the
# primary engineering alternative.
SAFEGUARDS: tuple[dict[str, Any], ...] = (
    {"id": "reject_semicolon", "vectors": {"semicolon"}, "cost": 1, "scope": "token"},
    {"id": "reject_newline", "vectors": {"newline"}, "cost": 1, "scope": "token"},
    {"id": "reject_pipe", "vectors": {"pipe"}, "cost": 1, "scope": "token"},
    {"id": "reject_ampersand", "vectors": {"background_ampersand"}, "cost": 1, "scope": "token"},
    {"id": "reject_backtick", "vectors": {"backtick_substitution"}, "cost": 1, "scope": "token"},
    {
        "id": "reject_dollar_expansion",
        "vectors": {"dollar_substitution", "dollar_expansion", "ifs_word_splitting"},
        "cost": 2,
        "scope": "token_family",
    },
    {"id": "reject_output_redirection", "vectors": {"output_redirection"}, "cost": 1, "scope": "token"},
    {"id": "reject_input_redirection", "vectors": {"input_redirection"}, "cost": 1, "scope": "token"},
    {"id": "reject_tab", "vectors": {"tab_word_splitting"}, "cost": 1, "scope": "token"},
)


def _decisions(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [row for row in (record.get("vector_decisions") or []) if isinstance(row, Mapping)]


def _minimal_cover(unblocked: set[str]) -> list[dict[str, Any]]:
    if not unblocked:
        return []
    candidates = [item for item in SAFEGUARDS if set(item["vectors"]) & unblocked]
    best: tuple[int, int, tuple[str, ...]] | None = None
    best_rows: list[dict[str, Any]] = []
    for width in range(1, len(candidates) + 1):
        for combo in combinations(candidates, width):
            covered = set().union(*(set(item["vectors"]) for item in combo))
            if not unblocked.issubset(covered):
                continue
            key = (
                sum(int(item["cost"]) for item in combo),
                len(combo),
                tuple(sorted(str(item["id"]) for item in combo)),
            )
            if best is None or key < best:
                best = key
                best_rows = [
                    {
                        **{key: value for key, value in item.items() if key != "vectors"},
                        "vectors": sorted(item["vectors"]),
                    }
                    for item in combo
                ]
        if best is not None:
            # A wider combination cannot improve the secondary cardinality
            # objective once a cover at this width is found.
            break
    return sorted(best_rows, key=lambda item: str(item["id"]))


def counterfactual_repair_plan(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return a modeled-vector repair plan for one serialized ledger row."""

    decisions = _decisions(record)
    sat = sorted({str(row.get("vector_id") or "") for row in decisions if row.get("decision") == "VECTOR_SAT"} - {""})
    unsat = sorted({str(row.get("vector_id") or "") for row in decisions if row.get("decision") == "MATRIX_UNSAT"} - {""})
    inconclusive = sorted({str(row.get("vector_id") or "") for row in decisions if row.get("decision") == "INCONCLUSIVE"} - {""})
    safeguards = _minimal_cover(set(sat))
    return {
        "schema": REPAIR_SCHEMA,
        "closure_idx": record.get("closure_idx"),
        "status": record.get("status"),
        "modeled_sat_vectors": sat,
        "already_unsat_vectors": unsat,
        "inconclusive_vectors": inconclusive,
        "counterfactual_safeguards": safeguards,
        "covered_sat_vectors": sorted(set().union(*(set(item["vectors"]) for item in safeguards)) & set(sat)) if safeguards else [],
        "complete_under_matrix": bool(sat) and not inconclusive and bool(safeguards),
        "preferred_architectural_remediation": "avoid shell interpretation; pass structured arguments to a non-shell execution API when feasible",
        "claim_boundary": (
            "This is a counterfactual explanation over TSDS's implemented vector matrix. "
            "It is not a source patch, a universal sanitizer proof, or an exploitability claim."
        ),
    }


def aggregate_counterfactual_repairs(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    plans = [counterfactual_repair_plan(record) for record in records or []]
    safeguard_counts: dict[str, int] = {}
    complete = 0
    for plan in plans:
        complete += int(bool(plan["complete_under_matrix"]))
        for safeguard in plan["counterfactual_safeguards"]:
            name = str(safeguard["id"])
            safeguard_counts[name] = safeguard_counts.get(name, 0) + 1
    return {
        "schema": "tsds-counterfactual-repair-aggregate-v1",
        "records": len(plans),
        "matrix_complete_plans": complete,
        "safeguards": dict(sorted(safeguard_counts.items(), key=lambda item: (-item[1], item[0]))),
        "claim_boundary": (
            "Aggregate repair counts describe modeled-vector diagnostic coverage, not patch correctness."
        ),
    }
