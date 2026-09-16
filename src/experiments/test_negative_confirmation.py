#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

from experiments.run_negative_confirmation import (
    confirmation_gate_issues,
    compare_result,
    needs_confirmation,
    vector_signature,
)


class NegativeConfirmationTest(unittest.TestCase):
    def test_script_runs_directly_without_pythonpath(self):
        root = Path(__file__).resolve().parents[1]
        proc = subprocess.run(
            [sys.executable, str(root / "experiments" / "run_negative_confirmation.py"), "--help"],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_selector_requires_negative_and_path_control(self):
        self.assertTrue(
            needs_confirmation(
                {
                    "status": "filtered",
                    "engine_semantic_frontier_pruned_total": 3,
                }
            )
        )
        self.assertFalse(
            needs_confirmation(
                {
                    "status": "vulnerable",
                    "engine_semantic_frontier_pruned_total": 3,
                }
            )
        )
        self.assertFalse(needs_confirmation({"status": "no_taint_sink"}))

    def test_vector_signature_uses_decisions(self):
        first = {
            "status": "filtered",
            "vector_decisions": [
                {
                    "vector_id": "semicolon",
                    "decision": "MATRIX_UNSAT",
                    "witness_kind": "",
                    "quote_context": "",
                }
            ],
        }
        second = {
            "status": "filtered",
            "vector_decisions": list(reversed(first["vector_decisions"])),
        }
        self.assertEqual(vector_signature(first), vector_signature(second))
        self.assertEqual(compare_result(first, second), "stable")

    def test_positive_change_is_not_hidden(self):
        baseline = {"status": "no_taint_sink"}
        confirmation = {
            "status": "vulnerable",
            "vulnerable_vectors": 1,
            "secure_vectors": 10,
        }
        self.assertEqual(
            compare_result(baseline, confirmation),
            "changed_to_vector_sat",
        )

    def test_timeout_is_confirmation_residual(self):
        self.assertEqual(
            compare_result(
                {"status": "filtered"},
                {"status": "timeout"},
            ),
            "confirmation_residual",
        )

    def test_historical_static_nms_is_contract_reclassification(self):
        self.assertEqual(
            compare_result(
                {
                    "status": "no_taint_sink",
                    "analysis_recovery": "binary_static_fixed_command_template",
                },
                {"status": "static_warning_reduction"},
            ),
            "contract_reclassified_static_reduction",
        )

    def test_strict_gate_rejects_replay_errors_and_positive_changes(self):
        summary = {
            "outcomes": {
                "replay_error": 1,
                "changed_to_vector_sat": 2,
                "confirmation_residual": 3,
            }
        }
        self.assertEqual(
            [
                "negative_confirmation_replay_error",
                "negative_confirmation_changed_to_vector_sat",
            ],
            confirmation_gate_issues(
                summary,
                fail_on_replay_errors=True,
                fail_on_positive_change=True,
            ),
        )
        self.assertEqual([], confirmation_gate_issues(summary))

    def test_minimum_record_gate_rejects_empty_confirmation(self):
        # 空选择不能被报告为已完成的负向重放实验。
        self.assertEqual(
            ["negative_confirmation_insufficient_records"],
            confirmation_gate_issues(
                {"records": 0, "outcomes": {}}, minimum_records=1
            ),
        )
        self.assertEqual(
            [],
            confirmation_gate_issues(
                {"records": 1, "outcomes": {"stable": 1}}, minimum_records=1
            ),
        )


if __name__ == "__main__":
    unittest.main()
