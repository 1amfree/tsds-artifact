#!/usr/bin/env python3
"""Tests for fail-closed fixture-conditioned residual refinement planning."""

from __future__ import annotations

import unittest

from tsds.residual_refinement import (
    build_refinement_plan,
    classify_transition,
    synthesize_fixture_variants,
    transition_violations,
)


def _residual() -> dict:
    return {
        "closure_idx": 4,
        "closure_ordinal": 5,
        "status": "unreachable",
        "residual_plan_strategy": "firmware_summary_repair",
        "residual_plan_priority": "high",
        "residual_plan_config_overrides": {"max_steps": 1000},
        "model_gap_requests": [
            {"kind": "config_key", "key": "wan_ipaddr", "reason": "mango_likely_input", "confidence": "high"},
            {"kind": "file", "key": "/tmp/state", "reason": "trace_expression_token", "confidence": "medium"},
            {"kind": "wrapper_summary", "key": "sub_1234", "reason": "unresolved_reachability"},
        ],
    }


class ResidualRefinementV2Test(unittest.TestCase):
    def test_fixture_variants_are_bounded_and_conditional(self) -> None:
        variants = synthesize_fixture_variants(_residual(), max_variants=3)
        self.assertEqual(3, len(variants))
        self.assertTrue(all(row["claim_scope"] == "fixture_conditioned" for row in variants))
        self.assertTrue(all(not row["primary_aggregate_eligible"] for row in variants))
        self.assertEqual("1", variants[0]["fixture"]["config"]["wan_ipaddr"])
        self.assertIn("/tmp/state", variants[0]["fixture"]["files"])

    def test_plan_filters_non_residual_rows(self) -> None:
        plan = build_refinement_plan([_residual(), {"closure_idx": 9, "status": "vulnerable"}])
        self.assertEqual(1, plan["summary"]["selected_records"])
        self.assertEqual(2, plan["summary"]["fixture_requests"])

    def test_fixture_resolution_never_enters_primary_aggregate(self) -> None:
        old = _residual()
        new = {"closure_idx": 4, "status": "vulnerable", "evidence_contract_valid": True, "env_fixture_usage": {"hits": 1}}
        transition = classify_transition(old, new, fixture_variant={"fixture_sha256": "abc"})
        self.assertEqual("fixture_conditioned_resolution", transition["transition"])
        self.assertFalse(transition["primary_aggregate_eligible"])
        self.assertEqual([], transition_violations(transition))

    def test_unconditional_valid_resolution_is_primary_eligible(self) -> None:
        transition = classify_transition(
            _residual(),
            {"closure_idx": 4, "status": "filtered", "evidence_contract_valid": True},
        )
        self.assertEqual("unconditional_resolution", transition["transition"])
        self.assertTrue(transition["primary_aggregate_eligible"])


if __name__ == "__main__":
    unittest.main()
