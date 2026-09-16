#!/usr/bin/env python3
"""Tests for matrix-bounded counterfactual repair explanations."""

from __future__ import annotations

import unittest

from tsds.sanitizer_repair import counterfactual_repair_plan


class SanitizerRepairTest(unittest.TestCase):
    def test_dollar_family_is_covered_by_one_modelled_safeguard(self) -> None:
        plan = counterfactual_repair_plan(
            {
                "closure_idx": 3,
                "status": "vulnerable",
                "vector_decisions": [
                    {"vector_id": "dollar_substitution", "decision": "VECTOR_SAT"},
                    {"vector_id": "dollar_expansion", "decision": "VECTOR_SAT"},
                    {"vector_id": "semicolon", "decision": "MATRIX_UNSAT"},
                ],
            }
        )
        self.assertEqual(["reject_dollar_expansion"], [item["id"] for item in plan["counterfactual_safeguards"]])
        self.assertTrue(plan["complete_under_matrix"])

    def test_inconclusive_profile_is_not_complete(self) -> None:
        plan = counterfactual_repair_plan(
            {"vector_decisions": [
                {"vector_id": "semicolon", "decision": "VECTOR_SAT"},
                {"vector_id": "pipe", "decision": "INCONCLUSIVE"},
            ]}
        )
        self.assertFalse(plan["complete_under_matrix"])


if __name__ == "__main__":
    unittest.main()
