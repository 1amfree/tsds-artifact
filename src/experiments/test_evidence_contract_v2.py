#!/usr/bin/env python3
"""Regression tests for TSDS evidence-contract v2 and shell witnesses."""

from __future__ import annotations

import importlib.util
import unittest
from types import SimpleNamespace


@unittest.skipIf(
    importlib.util.find_spec("angr") is None,
    "advanced evaluator dependencies are unavailable",
)
class EvidenceContractV2Test(unittest.TestCase):
    @staticmethod
    def _state():
        import claripy

        return SimpleNamespace(solver=claripy.Solver(), globals={})

    @staticmethod
    def _source(state, count=24, prefix="webvar_contract"):
        import claripy
        from advanced_sanitizer_evaluator import _symbolic_token_byte_constraints

        source = [claripy.BVS(f"{prefix}_{idx}", 8) for idx in range(count)]
        for byte in source:
            state.solver.add(_symbolic_token_byte_constraints(byte))
            state.solver.add(byte != 0)
        return source

    @staticmethod
    def _fixed(text):
        import claripy

        return [claripy.BVV(ord(char), 8) for char in text]

    @staticmethod
    def _nul():
        import claripy

        return claripy.BVV(0, 8)

    def test_direct_positive_contract(self):
        from advanced_sanitizer_evaluator import (
            DIRECT_SINK_BYTE,
            enforce_evidence_contract,
        )

        record = enforce_evidence_contract(
            {
                "status": "vulnerable",
                "sink_reached_observed": True,
                "tainted_offsets": [5, 6, 7],
                "vulnerable_vectors": 1,
                "minimal_bypass_vector": {
                    "vector": ";",
                    "witness": "echo ;:",
                    "grammar_complete": True,
                    "parser_calibration": "unit-test-calibration",
                },
            }
        )
        self.assertEqual(record["status"], "vulnerable")
        self.assertEqual(record["verdict"], "VECTOR_SAT")
        self.assertEqual(record["evidence_provenance"], DIRECT_SINK_BYTE)
        self.assertTrue(record["evidence_contract_valid"])

    def test_positive_without_sink_reach_fails_closed(self):
        from advanced_sanitizer_evaluator import enforce_evidence_contract

        record = enforce_evidence_contract(
            {
                "status": "vulnerable",
                "tainted_offsets": [0, 1],
                "vulnerable_vectors": 1,
                "minimal_bypass_vector": {
                    "witness": ";:",
                    "grammar_complete": True,
                    "parser_calibration": "unit-test-calibration",
                },
            }
        )
        self.assertEqual(record["status"], "residual")
        self.assertIn(
            "positive_without_observed_sink_reach",
            record["contract_violations"],
        )

    def test_static_source_fallback_cannot_become_positive(self):
        from advanced_sanitizer_evaluator import (
            STATIC_SOURCE_INFERENCE,
            enforce_evidence_contract,
        )

        record = enforce_evidence_contract(
            {
                "status": "vulnerable",
                "analysis_recovery": "static_sink_template_fallback",
                "vulnerable_vectors": 11,
            }
        )
        self.assertEqual(record["status"], "static_source_inference")
        self.assertEqual(record["evidence_provenance"], STATIC_SOURCE_INFERENCE)
        self.assertEqual(record["verdict"], "STATIC_SOURCE_INFERENCE")

    def test_static_fixed_template_is_warning_reduction_not_nms(self):
        from advanced_sanitizer_evaluator import (
            STATIC_WARNING_REDUCTION,
            enforce_evidence_contract,
        )

        record = enforce_evidence_contract(
            {
                "status": "no_taint_sink",
                "analysis_recovery": "binary_static_fixed_command_template",
                "no_taint_reaches": 0,
            }
        )
        self.assertEqual(record["status"], "static_warning_reduction")
        self.assertEqual(record["evidence_provenance"], STATIC_WARNING_REDUCTION)

    def test_reconciled_direct_positive_requires_verified_source_link(self):
        from advanced_sanitizer_evaluator import enforce_evidence_contract

        record = enforce_evidence_contract(
            {
                "status": "vulnerable",
                "evidence_provenance": "SINK_RECONCILED",
                "analysis_recovery": "static_dynamic_taint_reconciliation",
                "sink_reached_observed": True,
                "tainted_offsets": [5, 6],
                "vulnerable_vectors": 1,
                "minimal_bypass_vector": {
                    "witness": ";A",
                    "grammar_complete": True,
                    "parser_calibration": "unit-test-calibration",
                },
            }
        )
        self.assertEqual(record["status"], "residual")
        self.assertIn(
            "reconciled_positive_without_verified_source_link",
            record["contract_violations"],
        )

    def test_nms_requires_observed_sink_reach(self):
        from advanced_sanitizer_evaluator import enforce_evidence_contract

        rejected = enforce_evidence_contract({"status": "no_taint_sink"})
        accepted = enforce_evidence_contract(
            {
                "status": "no_taint_sink",
                "sink_reached_observed": True,
                "no_taint_reaches": 1,
            }
        )
        self.assertEqual(rejected["status"], "residual")
        self.assertEqual(accepted["status"], "no_taint_sink")

    def test_filtered_with_inconclusive_vector_fails_closed(self):
        from advanced_sanitizer_evaluator import enforce_evidence_contract

        record = enforce_evidence_contract(
            {
                "status": "filtered",
                "sink_reached_observed": True,
                "tainted_offsets": [2],
                "secure_vectors": 10,
                "inconclusive_vectors": 1,
            }
        )
        self.assertEqual(record["status"], "residual")
        self.assertIn(
            "filtered_with_inconclusive_vector", record["contract_violations"]
        )

    def test_aggregate_uses_contract_normalized_records(self):
        from advanced_sanitizer_evaluator import aggregate_evidence_contract

        ledger = aggregate_evidence_contract(
            [
                {
                    "status": "vulnerable",
                    "vulnerable_vectors": 1,
                    "tainted_offsets": [0],
                    "minimal_bypass_vector": {
                        "grammar_complete": True,
                        "witness": ";:",
                        "parser_calibration": "unit-test-calibration",
                    },
                },
                {
                    "status": "no_taint_sink",
                    "sink_reached_observed": True,
                    "no_taint_reaches": 1,
                },
            ]
        )
        self.assertEqual(ledger["records"], 2)
        self.assertEqual(ledger["contract_downgraded"], 1)
        self.assertEqual(ledger["verdicts"]["RESIDUAL"], 1)
        self.assertEqual(ledger["verdicts"]["NO_MODELED_SOURCE"], 1)

    def test_make_report_record_downgrades_legacy_static_nms(self):
        from advanced_sanitizer_evaluator import make_report_record

        record = make_report_record(
            {
                "status": "no_taint_sink",
                "analysis_recovery": "binary_static_fixed_command_template",
                "no_taint_reaches": 0,
            }
        )
        self.assertEqual(record["status"], "static_warning_reduction")
        self.assertEqual(record["verdict"], "STATIC_WARNING_REDUCTION")

    def test_multibyte_token_requires_all_bytes_controlled(self):
        import claripy
        from advanced_sanitizer_evaluator import ThreatMatrixEvaluator

        state = self._state()
        source = self._source(state, 1, "webvar_overlap")
        target = source + [claripy.BVV(ord("("), 8), self._nul()]
        constraints = ThreatMatrixEvaluator._candidate_constraints(
            target,
            [0],
            [ord("$"), ord("(")],
            state=state,
        )
        self.assertEqual(constraints, [])

    def test_complete_substitution_witnesses(self):
        from advanced_sanitizer_evaluator import ThreatMatrixEvaluator

        state = self._state()
        source = self._source(state, 24, "webvar_complete")
        target = self._fixed("echo ") + source + [self._nul()]
        ThreatMatrixEvaluator.evaluate(state, source, target)
        decisions = {
            item["vector_id"]: item
            for item in state.globals["threat_matrix_decisions"]
        }
        backtick = decisions["backtick_substitution"]
        dollar = decisions["dollar_substitution"]
        complete_backtick = chr(0x60) + ":" + chr(0x60)
        self.assertEqual(backtick["decision"], "VECTOR_SAT")
        self.assertEqual(backtick["witness_template"], complete_backtick)
        self.assertEqual(dollar["decision"], "VECTOR_SAT")
        self.assertEqual(dollar["witness_template"], "$(:)")
        self.assertNotEqual(backtick["witness_template"], chr(0x60))
        self.assertNotEqual(dollar["witness_template"], "$(")

    def test_single_quote_requires_modeled_breakout(self):
        from advanced_sanitizer_evaluator import ThreatMatrixEvaluator

        state = self._state()
        source = self._source(state, 24, "webvar_quote")
        target = (
            self._fixed("echo '")
            + source
            + self._fixed("'")
            + [self._nul()]
        )
        ThreatMatrixEvaluator.evaluate(state, source, target)
        semicolon = next(
            item
            for item in state.globals["threat_matrix_decisions"]
            if item["vector_id"] == "semicolon"
        )
        self.assertEqual(semicolon["decision"], "VECTOR_SAT")
        self.assertEqual(semicolon["quote_context"], "single_quoted")
        self.assertEqual(semicolon["witness_kind"], "single_quote_breakout")
        self.assertTrue(
            set(semicolon["controlled_witness_offsets"]).issubset(
                set(range(len("echo '"), len("echo '") + len(source)))
            )
        )

    def test_symbolic_uncontrolled_quote_context_is_inconclusive(self):
        import claripy
        from advanced_sanitizer_evaluator import ThreatMatrixEvaluator

        state = self._state()
        unknown_prefix = claripy.BVS("unmodeled_prefix", 8)
        state.solver.add(unknown_prefix != 0)
        source = self._source(state, 16, "webvar_unknown_quote")
        target = [unknown_prefix] + source + [self._nul()]
        ThreatMatrixEvaluator.evaluate(state, source, target)
        self.assertTrue(
            any(
                item["decision"] == "INCONCLUSIVE"
                and item.get("reason") == "unknown_quote_context"
                for item in state.globals["threat_matrix_decisions"]
            )
        )

    def test_reconciled_solver_preserves_reached_state_constraints(self):
        import claripy
        from advanced_sanitizer_evaluator import (
            ThreatMatrixEvaluator,
            build_reconciled_sink_bytes,
        )

        state = self._state()
        guard = claripy.BVS("path_guard", 8)
        state.solver.add(guard == 7)
        before = tuple(state.solver.constraints)
        recovered = build_reconciled_sink_bytes(
            state, "echo '%s'", prefix="config_val"
        )
        ThreatMatrixEvaluator.evaluate(state, recovered, recovered)
        self.assertTrue(state.solver.satisfiable())
        self.assertTrue(
            all(constraint in state.solver.constraints for constraint in before)
        )
        self.assertEqual(state.solver.eval(guard, 1)[0], 7)
        self.assertTrue(
            any(
                item["decision"] == "VECTOR_SAT"
                and item.get("witness_kind") == "single_quote_breakout"
                for item in state.globals["threat_matrix_decisions"]
            )
        )


if __name__ == "__main__":
    unittest.main()
