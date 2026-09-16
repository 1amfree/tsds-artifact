#!/usr/bin/env python3
"""Exercise bounded aggregation on a deliberately late positive profile."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.multi_state_aggregation import (
    aggregate_sink_profiles,
    select_primary_state_index,
)
from tsds.shell_matrix_spec import VECTOR_IDS


def profile(status: str, state_index: int) -> dict:
    decisions = [
        {
            "vector_id": vector_id,
            "decision": "VECTOR_SAT" if status == "VECTOR_SAT" else "MATRIX_UNSAT",
        }
        for vector_id in VECTOR_IDS
    ]
    return {
        "status": status,
        "claimable": True,
        "matrix_complete": True,
        "expected_vector_ids": list(VECTOR_IDS),
        "vector_decisions": decisions,
        "mode": "D",
        "evidence_scope_mode": "direct",
        "evidence_conditioning": "unconditioned",
        "evidence_provenance": "DIRECT_SINK_BYTE",
        "primary_aggregate_eligible": True,
        "state_index": state_index,
        "command_digest": f"{state_index + 1:064x}",
        "constraint_digest": f"{state_index + 101:064x}",
        "snapshot_digest": f"{state_index + 201:064x}",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    profiles = [profile("MATRIX_UNSAT", 0), profile("VECTOR_SAT", 1)]
    aggregate = aggregate_sink_profiles(profiles, collection_complete=True)
    selection = select_primary_state_index(profiles)
    result = {
        "schema": "tsds-late-positive-aggregation-calibration-v1",
        "collection_complete": True,
        "legacy_first_hit_status": profiles[0]["status"],
        "aggregate_class": aggregate.get("aggregate_class"),
        "positive_profile_indices": aggregate.get("positive_profile_indices"),
        "selected_state_index": selection.get("selected_state_index"),
        "selected_reason": selection.get("selected_reason"),
        "later_positive_observed": selection.get("later_positive_observed"),
        "candidate_wide_negative": aggregate.get("candidate_wide_negative"),
        "claim_boundary": (
            "Controlled aggregation behavior only; the fixture is not a firmware "
            "ground-truth or exploitability benchmark."
        ),
    }
    expected = {
        "aggregate_class": "exists_positive",
        "positive_profile_indices": [1],
        "selected_state_index": 1,
        "selected_reason": "later_collected_positive",
        "later_positive_observed": True,
        "candidate_wide_negative": False,
    }
    result["expectations_match"] = all(result[key] == value for key, value in expected.items())
    if not result["expectations_match"]:
        result["expected"] = expected
    (args.out_dir / "summary.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["expectations_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
