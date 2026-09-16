#!/usr/bin/env python3
"""Tests for the mutually exclusive TSDS residual taxonomy."""

from __future__ import annotations

import unittest

from tsds.residual_root_causes import (
    UNREACHED_STOP_CLASSIFICATION,
    classify_residual,
    summarize_residuals,
)


def residual(**updates):
    row = {
        "verdict": "RESIDUAL",
        "closure_idx": 1,
        "status": "unreachable",
        "engine_stop_reason": "active_empty",
        "static_evidence_strength": "weak",
    }
    row.update(updates)
    return row


class ResidualRootCauseTest(unittest.TestCase):
    def test_reached_sink_binding_gap_precedes_stop_reason(self) -> None:
        row = classify_residual(
            residual(
                sink_reached_observed=True,
                engine_stop_reason="sink_callsite_in_block",
                sink_argument_binding_trust="heuristic",
                sink_semantics="unknown_wrapper",
                sink_snapshot_cstring_complete=True,
            )
        )
        self.assertEqual("sink_binding_or_semantics_gap", row["root_cause"])
        self.assertEqual("observed_sink", row["sink_distance_class"])

    def test_trusted_binding_with_truncated_command_is_snapshot_gap(self) -> None:
        row = classify_residual(
            residual(
                sink_reached_observed=True,
                engine_stop_reason="sink_callsite_in_block",
                sink_argument_binding_trust="direct_abi_arg0",
                sink_semantics="shell_command",
                sink_snapshot_cstring_complete=False,
            )
        )
        self.assertEqual("incomplete_sink_snapshot", row["root_cause"])

    def test_active_empty_preserves_epistemic_boundary(self) -> None:
        row = classify_residual(residual())
        self.assertEqual("frontier_exhausted", row["root_cause"])
        self.assertEqual("mechanism_observed_root_cause_open", row["epistemic_status"])

    def test_adaptive_liveness_alias_has_the_source_liveness_root_cause(self) -> None:
        row = classify_residual(
            residual(engine_stop_reason="adaptive_source_liveness_saturated")
        )
        self.assertEqual("source_liveness_saturation", row["root_cause"])
        self.assertEqual("high", row["root_cause_confidence"])

    def test_explicit_engine_terminal_precedes_coarse_timeout_status(self) -> None:
        row = classify_residual(
            residual(
                engine_stop_reason="guided_stagnation_saturated",
                status="timeout",
            )
        )
        self.assertEqual("guided_stagnation", row["root_cause"])
        self.assertEqual("high", row["root_cause_confidence"])

    def test_state_explosion_is_an_explicit_root_cause(self) -> None:
        row = classify_residual(
            residual(engine_stop_reason="state_explosion_saturated")
        )
        self.assertEqual("state_explosion_saturation", row["root_cause"])
        self.assertEqual("high", row["root_cause_confidence"])

    def test_all_declared_unreached_terminals_are_classified(self) -> None:
        for reason, expected in UNREACHED_STOP_CLASSIFICATION.items():
            with self.subTest(reason=reason):
                row = classify_residual(residual(engine_stop_reason=reason))
                self.assertEqual(expected[0], row["root_cause"])
                self.assertNotEqual("unclassified_residual", row["root_cause"])

    def test_summary_is_complete_and_mutually_exclusive(self) -> None:
        records = [
            residual(),
            residual(engine_stop_reason="engine_timeout", status="timeout"),
            residual(engine_stop_reason="semantic_loop_saturated"),
            residual(engine_stop_reason="source_liveness_saturated"),
            residual(engine_stop_reason="adaptive_source_liveness_saturated"),
            residual(engine_stop_reason="state_explosion_saturated"),
            residual(engine_stop_reason="step_budget_exhausted"),
        ]
        rows, summary = summarize_residuals(records)
        self.assertEqual(len(records), len(rows))
        self.assertEqual(len(records), sum(summary["root_cause_counts"].values()))
        self.assertTrue(summary["classification_complete"])

    def test_non_residual_input_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            classify_residual({"verdict": "VECTOR_SAT"})


if __name__ == "__main__":
    unittest.main()
