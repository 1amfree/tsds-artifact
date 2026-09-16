"""Tests for matrix denominator and cell accounting."""

from __future__ import annotations

import unittest

from experiments.audit_matrix_profile_conservation import (
    audit_campaign,
    row_is_complete_matrix_profile,
)


def _row(verdict: str = "VECTOR_SAT", decision: str = "VECTOR_SAT") -> dict:
    return {
        "verdict": verdict,
        "vector_decisions": [
            {"vector_id": f"v{index}", "decision": decision}
            for index in range(11)
        ],
    }


class MatrixProfileConservationTests(unittest.TestCase):
    def test_complete_profile_requires_eleven_unique_supported_rows(self) -> None:
        complete, issues = row_is_complete_matrix_profile(_row())
        self.assertTrue(complete)
        self.assertEqual(issues, [])

        broken = _row()
        broken["vector_decisions"][-1]["vector_id"] = "v0"
        complete, issues = row_is_complete_matrix_profile(broken)
        self.assertFalse(complete)
        self.assertIn("matrix_vector_id_duplicate", issues)

    def test_frozen_campaign_has_102_profiles_and_1122_cells(self) -> None:
        from pathlib import Path

        campaign = Path(
            "experiment_reports/tsds_v20_release_20260718_r7_v8/"
            "tsds_v20_accepted_repeat_20260718_r7/campaign"
        )
        summary = audit_campaign(campaign)
        self.assertTrue(summary["valid"], summary["issues"])
        self.assertEqual(summary["record_count"], 518)
        self.assertEqual(summary["matrix_profile_count"], 102)
        self.assertEqual(summary["non_residual_matrix_profile_count"], 88)
        self.assertEqual(summary["matrix_residual_profile_count"], 14)
        self.assertEqual(summary["matrix_cell_count"], 1122)
        self.assertEqual(
            summary["matrix_cell_decisions"],
            {"INCONCLUSIVE": 151, "MATRIX_UNSAT": 292, "VECTOR_SAT": 679},
        )


if __name__ == "__main__":
    unittest.main()
