#!/usr/bin/env python3

from __future__ import annotations

import unittest

from tsds.multi_state_aggregation import (
    aggregate_sink_profiles,
    gate_negative_status_for_incomplete_collection,
    select_primary_state_index,
)
from tsds.shell_matrix_spec import VECTOR_IDS


def matrix_profile(
    *,
    outcome: str = "MATRIX_UNSAT",
    claimable: bool = True,
    complete: bool = True,
    conditioned: bool = False,
) -> dict:
    rows = [
        {
            "vector_id": vector_id,
            "decision": "VECTOR_SAT" if index == 0 and outcome == "VECTOR_SAT" else outcome,
        }
        for index, vector_id in enumerate(VECTOR_IDS if complete else VECTOR_IDS[:1])
    ]
    return {
        "status": outcome,
        "claimable": claimable,
        "matrix_complete": complete,
        "expected_vector_ids": list(VECTOR_IDS),
        "vector_decisions": rows,
        "mode": "C" if conditioned else "D",
        "evidence_scope_mode": "conditioned" if conditioned else "direct",
        "evidence_conditioning": (
            "conditioned_template_feasibility" if conditioned else "unconditioned"
        ),
        "evidence_provenance": "SINK_RECONCILED" if conditioned else "DIRECT_SINK_BYTE",
        "primary_aggregate_eligible": not conditioned,
    }


class MultiStateNegativeGateTest(unittest.TestCase):
    def test_incomplete_filtered_is_residual(self) -> None:
        status, fields = gate_negative_status_for_incomplete_collection(
            "filtered",
            {
                "aggregate": {
                    "aggregate_class": "bounded_incomplete",
                    "collection_complete": False,
                }
            },
        )
        self.assertEqual(status, "residual")
        self.assertEqual(fields["multi_state_negative_gate"], "blocked")
        self.assertEqual(
            fields["multi_state_negative_gate_requested_status"], "filtered"
        )

    def test_incomplete_no_modeled_source_is_residual(self) -> None:
        status, fields = gate_negative_status_for_incomplete_collection(
            "no_taint_sink",
            {
                "aggregate": {
                    "aggregate_class": "bounded_incomplete",
                    "collection_complete": False,
                }
            },
        )
        self.assertEqual(status, "residual")
        self.assertEqual(
            fields["residual_diagnosis_class"],
            "bounded_multi_state_collection_incomplete",
        )

    def test_incomplete_homogeneous_no_source_profiles_cannot_emit_nms(self) -> None:
        # Mirrors the real bounded payload shape observed in the AC15 campaign:
        # every collected profile is locally no-source, but seed accounting is
        # incomplete because the settle budget was exhausted.
        profile = {
            "status": "NO_MODELED_SOURCE",
            "claimable": True,
            "matrix_complete": False,
            "expected_vector_ids": [],
            "vector_decisions": [],
            "mode": "D",
            "evidence_scope_mode": "direct",
            "evidence_conditioning": "unconditioned",
            "evidence_provenance": "DIRECT_SINK_BYTE",
            "primary_aggregate_eligible": True,
        }
        profiles = [
            dict(
                profile,
                state_index=index,
                command_digest=f"{index + 1:064x}",
                constraint_digest=f"{index + 101:064x}",
                snapshot_digest=f"{index + 201:064x}",
            )
            for index in range(8)
        ]
        aggregate = aggregate_sink_profiles(
            profiles,
            collection_complete=False,
            collection_accounting={
                "complete": False,
                "blockers": ["seed_engine_collection_incomplete"],
            },
        )
        self.assertEqual(aggregate["aggregate_class"], "bounded_incomplete")
        self.assertEqual(aggregate["profile_kinds"], {"no_modeled_source": 8})
        self.assertFalse(aggregate["candidate_wide_negative"])

        status, fields = gate_negative_status_for_incomplete_collection(
            "no_taint_sink",
            {
                "collection_complete": False,
                "profiles": profiles,
                "aggregate": aggregate,
            },
        )
        self.assertEqual(status, "residual")
        self.assertEqual(fields["multi_state_negative_gate"], "blocked")

    def test_complete_matching_negative_is_preserved(self) -> None:
        for status, aggregate_class in (
            ("filtered", "all_collected_matrix_unsat"),
            ("no_taint_sink", "all_collected_no_modeled_source"),
        ):
            profile = matrix_profile(
                outcome=(
                    "MATRIX_UNSAT"
                    if aggregate_class == "all_collected_matrix_unsat"
                    else "NO_MODELED_SOURCE"
                )
            )
            if aggregate_class == "all_collected_no_modeled_source":
                profile["vector_decisions"] = []
                profile["matrix_complete"] = False
            gated_status, fields = gate_negative_status_for_incomplete_collection(
                status,
                {
                    "collection_complete": True,
                    "profiles": [profile],
                    "aggregate": aggregate_sink_profiles(
                        [profile], collection_complete=True
                    ),
                },
            )
            self.assertEqual(gated_status, status)
            self.assertEqual(fields, {})

    def test_legacy_path_is_unchanged(self) -> None:
        status, fields = gate_negative_status_for_incomplete_collection(
            "filtered", None
        )
        self.assertEqual(status, "filtered")
        self.assertEqual(fields, {})

    def test_complete_matching_negative_without_profiles_is_blocked(self) -> None:
        status, fields = gate_negative_status_for_incomplete_collection(
            "filtered",
            {
                "collection_complete": True,
                "aggregate": {
                    "aggregate_class": "all_collected_matrix_unsat",
                    "collection_complete": True,
                },
            },
        )
        self.assertEqual(status, "residual")
        self.assertEqual(fields["multi_state_negative_gate"], "blocked")

    def test_stale_negative_aggregate_is_blocked(self) -> None:
        profile = matrix_profile(outcome="MATRIX_UNSAT")
        aggregate = aggregate_sink_profiles([profile], collection_complete=True)
        aggregate["aggregate_class"] = "all_collected_no_modeled_source"
        status, fields = gate_negative_status_for_incomplete_collection(
            "filtered",
            {
                "collection_complete": True,
                "profiles": [profile],
                "aggregate": aggregate,
            },
        )
        self.assertEqual(status, "residual")
        self.assertEqual(fields["multi_state_negative_gate"], "blocked")


class MultiStateAggregationBoundaryTest(unittest.TestCase):
    def test_conditioned_positive_is_sidecar_only(self) -> None:
        aggregate = aggregate_sink_profiles(
            [
                matrix_profile(outcome="VECTOR_SAT", conditioned=True),
                matrix_profile(outcome="MATRIX_UNSAT"),
            ],
            collection_complete=True,
        )
        self.assertEqual(aggregate["aggregate_class"], "all_collected_matrix_unsat")
        self.assertEqual(aggregate["positive_profile_indices"], [])
        self.assertEqual(aggregate["conditioned_sidecar_count"], 1)

    def test_partial_matrix_cannot_be_positive(self) -> None:
        aggregate = aggregate_sink_profiles(
            [matrix_profile(outcome="VECTOR_SAT", complete=False)],
            collection_complete=False,
        )
        self.assertEqual(aggregate["aggregate_class"], "bounded_incomplete")
        self.assertEqual(aggregate["positive_profile_indices"], [])
        self.assertIn("matrix_not_complete", aggregate["profile_issues"]["0"])

    def test_nonclaimable_matrix_cannot_be_positive(self) -> None:
        aggregate = aggregate_sink_profiles(
            [matrix_profile(outcome="VECTOR_SAT", claimable=False)],
            collection_complete=True,
        )
        self.assertNotEqual(aggregate["aggregate_class"], "exists_positive")
        self.assertEqual(aggregate["positive_profile_indices"], [])

    def test_missing_claimability_metadata_cannot_be_positive(self) -> None:
        profile = matrix_profile(outcome="VECTOR_SAT")
        profile.pop("claimable")
        aggregate = aggregate_sink_profiles(
            [profile],
            collection_complete=True,
        )
        self.assertNotEqual(aggregate["aggregate_class"], "exists_positive")
        self.assertEqual(aggregate["positive_profile_indices"], [])

    def test_missing_direct_admission_fields_cannot_be_positive(self) -> None:
        profile = matrix_profile(outcome="VECTOR_SAT")
        profile.pop("mode")
        aggregate = aggregate_sink_profiles([profile], collection_complete=True)
        self.assertNotEqual(aggregate["aggregate_class"], "exists_positive")
        self.assertEqual(aggregate["positive_profile_indices"], [])

    def test_direct_admission_fields_are_part_of_profile_identity(self) -> None:
        from tsds.multi_state_aggregation import profile_fingerprint

        direct = matrix_profile(outcome="VECTOR_SAT")
        conditioned = matrix_profile(outcome="VECTOR_SAT", conditioned=True)
        self.assertNotEqual(profile_fingerprint(direct), profile_fingerprint(conditioned))

    def test_inconclusive_cells_cannot_authorize_a_negative_status(self) -> None:
        aggregate = aggregate_sink_profiles(
            [matrix_profile(outcome="INCONCLUSIVE")],
            collection_complete=True,
        )
        self.assertEqual(aggregate["aggregate_class"], "all_collected_inconclusive")
        self.assertEqual(aggregate["quantifier"], "no_negative_quantifier")
        for requested in ("filtered", "no_taint_sink"):
            status, fields = gate_negative_status_for_incomplete_collection(
                requested, {"aggregate": aggregate}
            )
            self.assertEqual(status, "residual")
            self.assertEqual(fields["multi_state_negative_gate"], "blocked")

    def test_heterogeneous_nonpositive_collection_cannot_authorize_negative(self) -> None:
        aggregate = aggregate_sink_profiles(
            [
                matrix_profile(outcome="MATRIX_UNSAT"),
                {
                    **matrix_profile(outcome="MATRIX_UNSAT"),
                    "status": "no_modeled_source",
                    "matrix_complete": False,
                    "expected_vector_ids": [],
                    "vector_decisions": [],
                },
            ],
            collection_complete=True,
        )
        self.assertEqual(aggregate["aggregate_class"], "all_collected_nonpositive_mixed")
        self.assertEqual(aggregate["quantifier"], "no_negative_quantifier")
        for requested in ("filtered", "no_taint_sink"):
            status, _ = gate_negative_status_for_incomplete_collection(
                requested, {"aggregate": aggregate}
            )
            self.assertEqual(status, "residual")

    def test_negative_aliases_use_the_same_incomplete_collection_gate(self) -> None:
        for status in ("matrix_unsat", "m-filt", "nms", "no_modeled_source"):
            gated_status, fields = gate_negative_status_for_incomplete_collection(
                status,
                {
                    "aggregate": {
                        "aggregate_class": "bounded_incomplete",
                        "collection_complete": False,
                    }
                },
            )
            self.assertEqual(gated_status, "residual")
            self.assertEqual(fields["multi_state_negative_gate"], "blocked")

    def test_empty_matrix_cannot_be_classified_as_filtered(self) -> None:
        profile = {
            "status": "filtered",
            "claimable": True,
            "matrix_complete": True,
            "expected_vector_ids": list(VECTOR_IDS),
            "vector_decisions": [],
        }
        aggregate = aggregate_sink_profiles([profile], collection_complete=True)
        self.assertEqual(aggregate["aggregate_class"], "collection_invalid")
        self.assertIn("matrix_not_complete", aggregate["profile_issues"]["0"])

    def test_later_complete_positive_beats_first_nonpositive(self) -> None:
        selection = select_primary_state_index(
            [
                matrix_profile(outcome="MATRIX_UNSAT"),
                matrix_profile(outcome="VECTOR_SAT"),
            ]
        )
        self.assertEqual(selection["selected_state_index"], 1)
        self.assertEqual(selection["selected_reason"], "later_collected_positive")
        self.assertTrue(selection["later_positive_observed"])

    def test_conditioned_positive_never_drives_primary_selection(self) -> None:
        selection = select_primary_state_index(
            [
                matrix_profile(outcome="VECTOR_SAT", conditioned=True),
                matrix_profile(outcome="MATRIX_UNSAT"),
            ]
        )
        self.assertEqual(selection["selected_state_index"], 1)
        self.assertEqual(selection["positive_state_indices"], [])
        self.assertFalse(selection["later_positive_observed"])

    def test_nonclaimable_profile_cannot_be_fallback_primary(self) -> None:
        selection = select_primary_state_index(
            [matrix_profile(outcome="MATRIX_UNSAT", claimable=False)]
        )
        self.assertIsNone(selection["selected_state_index"])
        self.assertEqual(
            selection["selected_reason"],
            "no_complete_admissible_direct_profile",
        )
        self.assertEqual(selection["complete_admissible_direct_indices"], [])

    def test_partial_profile_cannot_be_fallback_primary(self) -> None:
        selection = select_primary_state_index(
            [matrix_profile(outcome="VECTOR_SAT", complete=False)]
        )
        self.assertIsNone(selection["selected_state_index"])
        self.assertEqual(
            selection["selected_reason"],
            "no_complete_admissible_direct_profile",
        )


if __name__ == "__main__":
    unittest.main()
