#!/usr/bin/env python3
"""Regression tests for TSDS evidence scope and tri-valued statistics."""

from __future__ import annotations

import unittest

from tsds.evidence_scope import (
    EVIDENCE_SCOPE_SCHEMA,
    conservation_summary,
    scoped_binary_metrics,
    validate_scope_record,
)


def direct_record() -> dict[str, object]:
    return {
        "schema": EVIDENCE_SCOPE_SCHEMA,
        "candidate_id": "c-direct",
        "instance_id": "i-direct",
        "evidence_mode": "direct",
        "local_profile": "sv_sat",
        "candidate_status": "direct_evidence",
        "direct_provenance": True,
        "source_link_status": "observed",
        "primary_aggregate_eligible": True,
        "input_effect": "UNKNOWN",
        "instance_source_realizable": "UNKNOWN",
        "matrix_feasible": "CONFIRMED",
        "bounded_program_effect_exists": "UNKNOWN",
        "candidate_vulnerability": "UNKNOWN",
    }


def local_record(profile: str = "nms") -> dict[str, object]:
    row = direct_record()
    row.update(
        {
            "candidate_id": "c-local",
            "instance_id": "i-local",
            "evidence_mode": "local",
            "local_profile": profile,
            "candidate_status": "selected_instance_profile",
            "direct_provenance": False,
            "source_link_status": "unknown",
            "primary_aggregate_eligible": False,
            "matrix_feasible": "UNKNOWN",
        }
    )
    return row


class EvidenceScopeTest(unittest.TestCase):
    def test_direct_record_is_admissible(self) -> None:
        self.assertEqual([], validate_scope_record(direct_record()))

    def test_conditioned_record_cannot_be_primary_direct(self) -> None:
        row = direct_record()
        row.update(
            {
                "evidence_mode": "conditioned",
                "local_profile": "ct_sat",
                "candidate_status": "conditioned_feasibility",
                "direct_provenance": False,
                "source_link_status": "unlinked",
                "primary_aggregate_eligible": True,
            }
        )
        self.assertIn("conditioned_primary_eligible", validate_scope_record(row))

    def test_local_negative_is_rejected_as_candidate_claim(self) -> None:
        row = local_record()
        row["candidate_vulnerability"] = "CONTRADICTED"
        issues = validate_scope_record(row)
        self.assertIn("local_profile_cannot_be_candidate_negative", issues)
        self.assertIn("non_direct_candidate_negative_claim", issues)

    def test_m_filt_requires_a_complete_all_unsat_matrix(self) -> None:
        row = local_record("m_filt")
        row["matrix"] = {
            "expected_vector_ids": ["v0", "v1"],
            "decisions": [{"vector_id": "v0", "decision": "MATRIX_UNSAT"}],
            "complete": False,
        }
        issues = validate_scope_record(row)
        self.assertIn("matrix_vector_set_mismatch", issues)
        self.assertIn("matrix_not_complete", issues)

        row["matrix"] = {
            "expected_vector_ids": ["v0", "v1"],
            "decisions": [
                {"vector_id": "v0", "decision": "MATRIX_UNSAT"},
                {"vector_id": "v1", "decision": "MATRIX_UNSAT"},
            ],
            "complete": True,
        }
        self.assertEqual([], validate_scope_record(row))

    def test_empty_or_non_scalar_states_fail_without_crashing(self) -> None:
        row = local_record("m_filt")
        row["candidate_vulnerability"] = ["UNKNOWN"]
        row["matrix"] = {
            "expected_vector_ids": [],
            "decisions": [],
            "complete": True,
        }
        issues = validate_scope_record(row)
        self.assertIn("invalid_candidate_vulnerability", issues)
        self.assertIn("matrix_expected_vector_ids_empty", issues)
        self.assertIn("matrix_decisions_empty", issues)

    def test_unknown_values_are_not_coerced_to_negative(self) -> None:
        metrics = scoped_binary_metrics(
            [
                ("CONFIRMED", "CONFIRMED"),
                ("UNKNOWN", "CONFIRMED"),
                ("CONTRADICTED", "CONTRADICTED"),
            ]
        )
        self.assertEqual(3, metrics["records"])
        self.assertEqual(2, metrics["resolved_records"])
        self.assertEqual(2 / 3, metrics["coverage"])
        self.assertEqual(1.0, metrics["resolved_accuracy"])
        self.assertIsNone(metrics["full_accuracy"])

    def test_conservation_keeps_duplicate_and_invalid_rows_visible(self) -> None:
        rows = [direct_record(), local_record()]
        summary = conservation_summary(rows, expected_total=3)
        self.assertFalse(summary["valid"])
        self.assertIn("record_total_mismatch", summary["issues"])
        self.assertEqual(2, summary["records"])
        self.assertEqual(2, summary["unique_candidates"])


if __name__ == "__main__":
    unittest.main()
