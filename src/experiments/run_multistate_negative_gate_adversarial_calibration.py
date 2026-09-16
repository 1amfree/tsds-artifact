#!/usr/bin/env python3
"""Adversarially calibrate the bounded negative-status admission gate.

The calibration checks that a negative selected-instance status is admitted
only for a complete, direct, homogeneous collection whose serialized
aggregate exactly matches a fresh recomputation.  It is evidence for the
aggregation contract, not firmware ground truth or solver validation.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.multi_state_aggregation import (  # noqa: E402
    aggregate_sink_profiles,
    gate_negative_status_for_incomplete_collection,
)
from tsds.shell_matrix_spec import VECTOR_IDS  # noqa: E402


SEED = 20260916


def _digest(value: int) -> str:
    return f"{value:064x}"


def direct_profile(kind: str, ordinal: int) -> dict[str, Any]:
    """Construct a small profile with explicit direct-admission metadata."""

    if kind not in {"matrix_unsat", "no_modeled_source"}:
        raise ValueError(f"unsupported direct profile kind: {kind}")
    profile: dict[str, Any] = {
        "status": "filtered" if kind == "matrix_unsat" else "no_taint_sink",
        "claimable": True,
        "matrix_complete": kind == "matrix_unsat",
        "expected_vector_ids": list(VECTOR_IDS) if kind == "matrix_unsat" else [],
        "vector_decisions": (
            [
                {"vector_id": vector_id, "decision": "MATRIX_UNSAT"}
                for vector_id in VECTOR_IDS
            ]
            if kind == "matrix_unsat"
            else []
        ),
        "mode": "D",
        "evidence_scope_mode": "direct",
        "evidence_conditioning": "unconditioned",
        "evidence_provenance": "DIRECT_SINK_BYTE",
        "primary_aggregate_eligible": True,
        "command_digest": _digest(1000 + ordinal),
        "constraint_digest": _digest(2000 + ordinal),
        "snapshot_digest": _digest(3000 + ordinal),
    }
    return profile


def conditioned_profile(ordinal: int) -> dict[str, Any]:
    profile = direct_profile("matrix_unsat", ordinal)
    profile.update(
        {
            "status": "conditioned_feasibility",
            "mode": "C",
            "evidence_scope_mode": "conditioned",
            "evidence_conditioning": "conditioned_template_feasibility",
            "evidence_provenance": "SINK_RECONCILED",
            "primary_aggregate_eligible": False,
        }
    )
    return profile


def invalid_profile(ordinal: int) -> dict[str, Any]:
    profile = direct_profile("matrix_unsat", ordinal)
    profile["vector_decisions"] = [
        {"vector_id": VECTOR_IDS[0], "decision": "MATRIX_UNSAT"},
        {"vector_id": VECTOR_IDS[0], "decision": "MATRIX_UNSAT"},
    ]
    return profile


def payload_for(
    profiles: list[dict[str, Any]],
    *,
    collection_complete: bool = True,
) -> dict[str, Any]:
    return {
        "collection_complete": collection_complete,
        "profiles": profiles,
        "aggregate": aggregate_sink_profiles(
            profiles,
            collection_complete=collection_complete,
        ),
    }


def _mutate(
    name: str,
    payload: dict[str, Any],
    requested_status: str,
) -> dict[str, Any]:
    mutated = copy.deepcopy(payload)
    aggregate = mutated["aggregate"]
    if name == "wrong_class":
        aggregate["aggregate_class"] = (
            "all_collected_matrix_unsat"
            if requested_status == "no_taint_sink"
            else "all_collected_no_modeled_source"
        )
    elif name == "wrong_digest":
        aggregate["profile_digest"] = "0" * 64
    elif name == "wrong_profile_count":
        aggregate["profile_count"] += 1
    elif name == "wrong_unique_count":
        aggregate["unique_profile_count"] = 0
    elif name == "wrong_primary_count":
        aggregate["primary_profile_count"] += 1
    elif name == "wrong_sidecar_count":
        aggregate["conditioned_sidecar_count"] += 1
    elif name == "wrong_quantifier":
        aggregate["quantifier"] = "all_candidates"
    elif name == "aggregate_incomplete":
        aggregate["collection_complete"] = False
    elif name == "payload_incomplete":
        mutated["collection_complete"] = False
    elif name == "profile_claimability":
        mutated["profiles"][0]["claimable"] = False
    elif name == "profile_conditioned":
        mutated["profiles"].append(conditioned_profile(9000))
    elif name == "profile_mixed_kind":
        mutated["profiles"].append(direct_profile("no_modeled_source", 9001))
    elif name == "profile_invalid":
        mutated["profiles"].append(invalid_profile(9002))
    elif name == "accounting_incomplete":
        aggregate["collection_accounting"] = {"complete": False}
    elif name == "stale_profiles":
        mutated["profiles"] = [direct_profile("no_modeled_source", 9003)]
    else:
        raise ValueError(f"unknown mutation: {name}")
    return mutated


def run_case(
    case_id: str,
    profiles: list[dict[str, Any]],
    requested_status: str,
    should_accept: bool,
    mutation: str | None = None,
    collection_complete: bool = True,
) -> dict[str, Any]:
    payload = payload_for(profiles, collection_complete=collection_complete)
    if mutation is not None:
        payload = _mutate(mutation, payload, requested_status)
    observed, detail = gate_negative_status_for_incomplete_collection(
        requested_status,
        payload,
    )
    passed = (observed == requested_status) == should_accept
    return {
        "case_id": case_id,
        "requested_status": requested_status,
        "mutation": mutation,
        "expected_admit": should_accept,
        "observed_status": observed,
        "expected_status": requested_status if should_accept else "residual",
        "gate_detail": detail,
        "pass": passed,
    }


def build_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []

    for status in ("filtered", "matrix_unsat", "m_filt"):
        cases.append(
            run_case(
                f"valid_matrix_{status}",
                [direct_profile("matrix_unsat", 1), direct_profile("matrix_unsat", 2)],
                status,
                True,
            )
        )
    for status in ("no_taint_sink", "nms", "no_modeled_source"):
        cases.append(
            run_case(
                f"valid_nms_{status}",
                [direct_profile("no_modeled_source", 3), direct_profile("no_modeled_source", 4)],
                status,
                True,
            )
        )

    cases.extend(
        [
            run_case(
                "incomplete_matrix",
                [direct_profile("matrix_unsat", 5)],
                "filtered",
                False,
                collection_complete=False,
            ),
            run_case(
                "incomplete_nms",
                [direct_profile("no_modeled_source", 6)],
                "no_taint_sink",
                False,
                collection_complete=False,
            ),
            run_case(
                "mixed_negative_kinds",
                [direct_profile("matrix_unsat", 7), direct_profile("no_modeled_source", 8)],
                "filtered",
                False,
            ),
        ]
    )

    mutations = (
        "wrong_class",
        "wrong_digest",
        "wrong_profile_count",
        "wrong_unique_count",
        "wrong_primary_count",
        "wrong_sidecar_count",
        "wrong_quantifier",
        "aggregate_incomplete",
        "payload_incomplete",
        "profile_claimability",
        "profile_conditioned",
        "profile_mixed_kind",
        "profile_invalid",
        "accounting_incomplete",
        "stale_profiles",
    )
    for index, mutation in enumerate(mutations, 10):
        cases.append(
            run_case(
                f"tampered_matrix_{mutation}",
                [direct_profile("matrix_unsat", index)],
                "filtered",
                False,
                mutation,
            )
        )
    for index, mutation in enumerate(mutations, 30):
        cases.append(
            run_case(
                f"tampered_nms_{mutation}",
                [direct_profile("no_modeled_source", index)],
                "no_taint_sink",
                False,
                mutation,
            )
        )
    return cases


def write_outputs(out_dir: Path, cases: list[dict[str, Any]]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    failed = [case for case in cases if not case["pass"]]
    summary = {
        "schema": "tsds-negative-gate-adversarial-calibration-v1",
        "seed": SEED,
        "case_count": len(cases),
        "valid_admission_cases": sum(case["expected_admit"] for case in cases),
        "rejection_cases": sum(not case["expected_admit"] for case in cases),
        "admissions_observed": sum(
            case["observed_status"] == case["requested_status"] for case in cases
        ),
        "rejections_observed": sum(
            case["observed_status"] == "residual"
            for case in cases
            if not case["expected_admit"]
        ),
        "failed_case_count": len(failed),
        "all_checks_pass": not failed,
        "claim_boundary": (
            "Finite adversarial calibration of the bounded negative-status gate. "
            "It does not establish solver soundness, exhaustive firmware state "
            "coverage, source realizability, firmware ground truth, or device "
            "exploitability."
        ),
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with (out_dir / "case_results.jsonl").open("w", encoding="utf-8", newline="\n") as stream:
        for case in cases:
            stream.write(json.dumps(case, sort_keys=True) + "\n")
    (out_dir / "README.md").write_text(
        "# Negative-gate adversarial calibration\n\n"
        "This finite calibration mutates serialized bounded aggregates and\n"
        "profile metadata. A negative status is expected to pass only when the\n"
        "collection is complete, homogeneous, direct, and exactly replayable.\n"
        "The result is an admission-boundary check, not firmware ground truth.\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    cases = build_cases()
    write_outputs(args.out_dir, cases)
    failed = sum(not case["pass"] for case in cases)
    print(json.dumps({"case_count": len(cases), "failed_case_count": failed}, sort_keys=True))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
