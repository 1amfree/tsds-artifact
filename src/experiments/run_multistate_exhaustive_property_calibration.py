#!/usr/bin/env python3
"""Exhaustively calibrate the bounded multi-state aggregation contract.

The calibration enumerates short sequences of hand-constructed profile kinds
and compares the implementation with an independent finite oracle. It is
intended to exercise the evidence boundary around first/later selection,
conditioned sidecars, incomplete collections, duplicate profiles, and
negative-status gating. It is not a firmware path-coverage experiment and
does not establish solver, source-realizability, or device-level validity.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.multi_state_aggregation import (  # noqa: E402
    aggregate_sink_profiles,
    gate_negative_status_for_incomplete_collection,
    select_primary_state_index,
)
from tsds.shell_matrix_spec import VECTOR_IDS  # noqa: E402


SEED = 20260916
SEQUENCE_MAX_LENGTH = 4
PROFILE_KINDS = (
    "positive",
    "matrix_unsat",
    "no_modeled_source",
    "inconclusive",
    "conditioned_positive",
    "partial_positive",
    "invalid_duplicate",
)


def _hex_digest(number: int) -> str:
    return f"{number:064x}"


def make_profile(kind: str, ordinal: int) -> dict[str, Any]:
    base: dict[str, Any] = {
        "status": "VECTOR_SAT" if "positive" in kind else "MATRIX_UNSAT",
        "claimable": True,
        "matrix_complete": True,
        "expected_vector_ids": list(VECTOR_IDS),
        "vector_decisions": [],
        "mode": "D",
        "evidence_scope_mode": "direct",
        "evidence_conditioning": "unconditioned",
        "evidence_provenance": "DIRECT_SINK_BYTE",
        "primary_aggregate_eligible": True,
        "command_digest": _hex_digest(1000 + ordinal),
        "constraint_digest": _hex_digest(2000 + ordinal),
        "snapshot_digest": _hex_digest(3000 + ordinal),
    }
    if kind in {"positive", "conditioned_positive", "partial_positive"}:
        base["vector_decisions"] = [
            {
                "vector_id": vector_id,
                "decision": "VECTOR_SAT" if index == 0 else "MATRIX_UNSAT",
            }
            for index, vector_id in enumerate(VECTOR_IDS)
        ]
    elif kind == "matrix_unsat":
        base["vector_decisions"] = [
            {"vector_id": vector_id, "decision": "MATRIX_UNSAT"}
            for vector_id in VECTOR_IDS
        ]
    elif kind == "inconclusive":
        base["vector_decisions"] = [
            {"vector_id": vector_id, "decision": "INCONCLUSIVE"}
            for vector_id in VECTOR_IDS
        ]
    elif kind == "no_modeled_source":
        base.update(
            {
                "status": "NO_MODELED_SOURCE",
                "matrix_complete": False,
                "expected_vector_ids": [],
                "vector_decisions": [],
            }
        )
    elif kind == "invalid_duplicate":
        base["vector_decisions"] = [
            {"vector_id": VECTOR_IDS[0], "decision": "VECTOR_SAT"},
            {"vector_id": VECTOR_IDS[0], "decision": "MATRIX_UNSAT"},
        ]
    else:
        raise ValueError(f"unknown profile kind: {kind}")

    if kind == "conditioned_positive":
        base.update(
            {
                "mode": "C",
                "evidence_scope_mode": "conditioned",
                "evidence_conditioning": "conditioned_template_feasibility",
                "evidence_provenance": "SINK_RECONCILED",
                "primary_aggregate_eligible": False,
            }
        )
    elif kind == "partial_positive":
        base["matrix_complete"] = False
        base["vector_decisions"] = base["vector_decisions"][:1]
    return base


def oracle_selection(kinds: list[str]) -> tuple[int | None, str, list[int]]:
    if not kinds:
        return None, "no_collected_profile", []
    positive = [index for index, kind in enumerate(kinds) if kind == "positive"]
    fallback = [
        index
        for index, kind in enumerate(kinds)
        if kind in {"positive", "matrix_unsat", "inconclusive"}
    ]
    if positive:
        return (
            positive[0],
            "first_collected_positive"
            if positive[0] == 0
            else "later_collected_positive",
            positive,
        )
    if fallback:
        return (
            fallback[0],
            "first_complete_admissible_fallback_no_valid_collected_positive",
            positive,
        )
    return None, "no_complete_admissible_direct_profile", positive


def oracle_aggregate(kinds: list[str], collection_complete: bool) -> str:
    primary = [kind for kind in kinds if kind != "conditioned_positive"]
    if "positive" in primary:
        return "exists_positive"
    if not collection_complete:
        return "bounded_incomplete"
    if "invalid_duplicate" in primary or "partial_positive" in primary:
        return "collection_invalid"
    if not primary:
        return "no_sink_profile"
    if all(kind == "matrix_unsat" for kind in primary):
        return "all_collected_matrix_unsat"
    if all(kind == "no_modeled_source" for kind in primary):
        return "all_collected_no_modeled_source"
    if "inconclusive" in primary:
        return "all_collected_inconclusive"
    return "all_collected_nonpositive_mixed"


def expected_negative_gate(
    kinds: list[str], collection_complete: bool, requested: str
) -> str:
    expected_class = (
        "all_collected_matrix_unsat"
        if requested == "filtered"
        else "all_collected_no_modeled_source"
    )
    negative_kind = "matrix_unsat" if requested == "filtered" else "no_modeled_source"
    admissible = (
        collection_complete
        and bool(kinds)
        and all(kind == negative_kind for kind in kinds)
    )
    return (
        requested
        if admissible and oracle_aggregate(kinds, True) == expected_class
        else "residual"
    )


def check_sequence(
    case_id: str, kinds: list[str], complete: bool
) -> dict[str, Any]:
    profiles = [
        make_profile(kind, index + 10000 * len(kinds))
        for index, kind in enumerate(kinds)
    ]
    selection = select_primary_state_index(profiles)
    expected_index, expected_reason, expected_positive = oracle_selection(kinds)
    aggregate = aggregate_sink_profiles(profiles, collection_complete=complete)
    expected_class = oracle_aggregate(kinds, complete)
    failures: list[str] = []
    if selection.get("selected_state_index") != expected_index:
        failures.append("selection_index_mismatch")
    if selection.get("selected_reason") != expected_reason:
        failures.append("selection_reason_mismatch")
    if selection.get("positive_state_indices") != expected_positive:
        failures.append("selection_positive_indices_mismatch")
    if aggregate.get("aggregate_class") != expected_class:
        failures.append("aggregate_class_mismatch")
    if aggregate.get("candidate_wide_negative") is not False:
        failures.append("candidate_wide_negative_not_false")
    if aggregate.get("conditioned_sidecar_count") != kinds.count(
        "conditioned_positive"
    ):
        failures.append("conditioned_sidecar_count_mismatch")
    for requested in ("filtered", "no_taint_sink"):
        gated_status, _ = gate_negative_status_for_incomplete_collection(
            requested,
            {
                "collection_complete": complete,
                "profiles": profiles,
                "aggregate": aggregate,
            },
        )
        expected_status = (
            expected_negative_gate(kinds, complete, requested)
            if expected_class
            in {"all_collected_matrix_unsat", "all_collected_no_modeled_source"}
            else "residual"
        )
        if gated_status != expected_status:
            failures.append(f"{requested}_gate_mismatch")
    return {
        "case_id": case_id,
        "kinds": kinds,
        "collection_complete": complete,
        "observed_selection_index": selection.get("selected_state_index"),
        "expected_selection_index": expected_index,
        "observed_selection_reason": selection.get("selected_reason"),
        "expected_selection_reason": expected_reason,
        "observed_aggregate_class": aggregate.get("aggregate_class"),
        "expected_aggregate_class": expected_class,
        "observed_profile_count": aggregate.get("profile_count"),
        "observed_unique_profile_count": aggregate.get("unique_profile_count"),
        "conditioned_sidecar_count": aggregate.get("conditioned_sidecar_count"),
        "failures": sorted(set(failures)),
    }


def check_duplicate_and_permutation(seed: int) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    rows: list[dict[str, Any]] = []
    candidate_sequences = [
        ["matrix_unsat", "positive", "inconclusive"],
        ["conditioned_positive", "matrix_unsat"],
        ["no_modeled_source", "no_modeled_source"],
        ["partial_positive", "matrix_unsat"],
        ["inconclusive", "matrix_unsat", "conditioned_positive"],
    ]
    for index, kinds in enumerate(candidate_sequences):
        profiles = [
            make_profile(kind, 50000 + index * 100 + pos)
            for pos, kind in enumerate(kinds)
        ]
        baseline = aggregate_sink_profiles(profiles, collection_complete=True)
        duplicate = aggregate_sink_profiles(
            profiles + [profiles[0]], collection_complete=True
        )
        failures: list[str] = []
        if baseline.get("aggregate_class") != duplicate.get("aggregate_class"):
            failures.append("duplicate_changed_aggregate_class")
        if baseline.get("unique_profile_count") != duplicate.get("unique_profile_count"):
            failures.append("duplicate_changed_unique_profile_count")
        if baseline.get("candidate_wide_negative") != duplicate.get(
            "candidate_wide_negative"
        ):
            failures.append("duplicate_changed_negative_boundary")
        rows.append(
            {
                "case_id": f"duplicate_{index}",
                "kind_sequence": kinds,
                "failures": failures,
            }
        )

        permutation_indices = list(range(len(kinds)))
        rng.shuffle(permutation_indices)
        permutation = [kinds[pos] for pos in permutation_indices]
        perm_profiles = [profiles[pos] for pos in permutation_indices]
        permuted = aggregate_sink_profiles(
            perm_profiles, collection_complete=True
        )
        if baseline.get("aggregate_class") != permuted.get("aggregate_class"):
            failures.append("permutation_changed_aggregate_class")
        if baseline.get("candidate_wide_negative") != permuted.get(
            "candidate_wide_negative"
        ):
            failures.append("permutation_changed_negative_boundary")
        rows.append(
            {
                "case_id": f"permutation_{index}",
                "kind_sequence": permutation,
                "failures": failures,
            }
        )
    return rows


def write_sha256sums(root: Path) -> None:
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            rows.append(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
                f"{path.relative_to(root).as_posix()}"
            )
    (root / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(f"refusing to overwrite non-empty output: {out_dir}")

    rows: list[dict[str, Any]] = []
    sequence_count = 0
    for length in range(SEQUENCE_MAX_LENGTH + 1):
        for sequence in itertools.product(PROFILE_KINDS, repeat=length):
            for complete in (False, True):
                sequence_count += 1
                rows.append(
                    check_sequence(
                        f"sequence_{sequence_count:05d}", list(sequence), complete
                    )
                )
    relation_rows = check_duplicate_and_permutation(SEED)
    rows.extend(
        {
            "case_id": row["case_id"],
            "kinds": row["kind_sequence"],
            "collection_complete": True,
            "failures": row["failures"],
        }
        for row in relation_rows
    )
    failures = [row for row in rows if row.get("failures")]
    summary = {
        "schema": "tsds-multistate-exhaustive-property-calibration-v1",
        "seed": SEED,
        "profile_kinds": list(PROFILE_KINDS),
        "sequence_max_length": SEQUENCE_MAX_LENGTH,
        "sequence_cases": sequence_count,
        "relation_cases": len(relation_rows),
        "case_count": len(rows),
        "failed_case_count": len(failures),
        "all_checks_pass": not failures,
        "claim_boundary": (
            "Finite exhaustive calibration over hand-constructed short profile "
            "sequences plus duplicate/permutation checks. It validates the "
            "bounded aggregation and negative-gating contract only; it does "
            "not establish exhaustive firmware sink-state coverage, solver "
            "soundness, source realizability, firmware ground truth, or "
            "device exploitability."
        ),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "case_results.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        "\n".join(
            [
                "# Multi-state exhaustive property calibration",
                "",
                f"Profile-sequence cases: {sequence_count}.",
                f"Duplicate/permutation relation cases: {len(relation_rows)}.",
                f"Failed cases: {len(failures)}.",
                f"All checks pass: {not failures}.",
                "",
                summary["claim_boundary"],
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    write_sha256sums(out_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
