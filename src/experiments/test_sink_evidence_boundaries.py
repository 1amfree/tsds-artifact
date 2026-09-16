#!/usr/bin/env python3
"""Regression tests for TSDS v12 sink-binding and C-string boundaries."""

from __future__ import annotations

import importlib.util
import unittest
from types import SimpleNamespace


@unittest.skipIf(
    importlib.util.find_spec("angr") is None
    or importlib.util.find_spec("claripy") is None,
    "advanced evaluator dependencies are unavailable",
)
class SinkEvidenceBoundaryTest(unittest.TestCase):
    @staticmethod
    def _state():
        import claripy

        return SimpleNamespace(solver=claripy.Solver(), globals={})

    @staticmethod
    def _source(state, count: int, prefix: str):
        import claripy
        from advanced_sanitizer_evaluator import _symbolic_token_byte_constraints

        source = [claripy.BVS(f"{prefix}_{idx}", 8) for idx in range(count)]
        for byte in source:
            state.solver.add(_symbolic_token_byte_constraints(byte))
            state.solver.add(byte != 0)
        return source

    @staticmethod
    def _fixed(text: str):
        import claripy

        return [claripy.BVV(ord(ch), 8) for ch in text]

    @staticmethod
    def _nul():
        import claripy

        return claripy.BVV(0, 8)

    @staticmethod
    def _alnum_constraints(state, source):
        import claripy

        for byte in source:
            state.solver.add(
                claripy.Or(
                    claripy.And(byte >= ord("A"), byte <= ord("Z")),
                    claripy.And(byte >= ord("a"), byte <= ord("z")),
                    claripy.And(byte >= ord("0"), byte <= ord("9")),
                    byte == ord("_"),
                )
            )

    def test_final_controlled_byte_without_nul_is_observed_but_inconclusive(self):
        from advanced_sanitizer_evaluator import (
            ThreatMatrixEvaluator,
            matrix_report_counts,
        )

        state = self._state()
        source = self._source(state, 1, "webvar_final_byte")
        report = ThreatMatrixEvaluator.evaluate(
            state, source, self._fixed("x") + source
        )
        self.assertEqual(state.globals["threat_matrix_controlled_offsets"], [1])
        self.assertFalse(state.globals["threat_matrix_snapshot_cstring_complete"])
        self.assertEqual(matrix_report_counts(report), (0, 0, 11))

    def test_truncated_all_unsat_is_not_a_filtered_claim(self):
        from advanced_sanitizer_evaluator import (
            ThreatMatrixEvaluator,
            matrix_report_counts,
        )

        state = self._state()
        source = self._source(state, 16, "webvar_truncated")
        self._alnum_constraints(state, source)
        report = ThreatMatrixEvaluator.evaluate(state, source, source)
        self.assertEqual(matrix_report_counts(report), (0, 0, 11))
        self.assertTrue(
            all(
                item.get("reason") == "incomplete_sink_snapshot"
                for item in state.globals["threat_matrix_decisions"]
            )
        )

    def test_complete_alnum_string_retains_matrix_unsat(self):
        from advanced_sanitizer_evaluator import (
            ThreatMatrixEvaluator,
            matrix_report_counts,
        )

        state = self._state()
        source = self._source(state, 16, "webvar_complete")
        self._alnum_constraints(state, source)
        report = ThreatMatrixEvaluator.evaluate(state, source, source + [self._nul()])
        self.assertEqual(matrix_report_counts(report), (0, 11, 0))
        self.assertTrue(state.globals["threat_matrix_snapshot_cstring_complete"])

    def test_source_after_explicit_terminator_is_not_a_sink_vector(self):
        from advanced_sanitizer_evaluator import (
            ThreatMatrixEvaluator,
            matrix_report_counts,
        )

        state = self._state()
        source = self._source(state, 16, "webvar_after_nul")
        report = ThreatMatrixEvaluator.evaluate(
            state, source, [self._nul()] + source + [self._nul()]
        )
        self.assertEqual(matrix_report_counts(report), (0, 11, 0))
        self.assertEqual(
            state.globals["threat_matrix_source_after_terminator_offsets"],
            list(range(1, 17)),
        )

    def test_incomplete_fixed_suffix_keeps_comment_witness_but_residualizes_others(self):
        from advanced_sanitizer_evaluator import (
            ThreatMatrixEvaluator,
            render_model_raw_cstring,
            shell_lexical_completeness,
        )

        state = self._state()
        source = self._source(state, 24, "webvar_unterminated_suffix")
        target = self._fixed("mv /tmp/") + source + self._fixed(' "') + [self._nul()]
        dollar = next(
            spec for spec in ThreatMatrixEvaluator.VECTOR_SPECS
            if spec["id"] == "dollar_substitution"
        )
        match, _, _, _ = ThreatMatrixEvaluator._find_satisfying_spec(
            state, target, list(range(len("mv /tmp/"), len("mv /tmp/") + len(source))), dollar
        )
        raw = render_model_raw_cstring(state, target, match["constraints"])
        self.assertTrue(raw)
        self.assertEqual(
            shell_lexical_completeness(raw),
            (False, "unterminated_quote"),
        )
        ThreatMatrixEvaluator.evaluate(state, source, target)
        decisions = {
            item["vector_id"]: item
            for item in state.globals["threat_matrix_decisions"]
        }
        self.assertEqual(decisions["semicolon"]["decision"], "VECTOR_SAT")
        self.assertEqual(
            decisions["dollar_substitution"]["decision"], "INCONCLUSIVE"
        )
        self.assertEqual(
            decisions["dollar_substitution"]["reason"],
            "incomplete_shell_lexeme",
        )

    def test_system_uses_only_abi_argument_zero(self):
        import angr
        import claripy
        from advanced_sanitizer_evaluator import (
            _snapshot_sink_argument_bytes,
            render_model_bytes,
            sink_snapshot_evidence_fields,
        )

        state = angr.SimState(arch="AMD64")
        fixed_addr = 0x500000
        tainted_addr = 0x501000
        state.memory.store(fixed_addr, b"echo fixed\x00")
        state.memory.store(tainted_addr, claripy.BVS("webvar_wrong_arg", 8))
        state.globals["tsds_sink_function_name"] = "system"
        state.globals["tsds_sink_function_name_source"] = (
            "closure_sink_at_exact_callsite"
        )
        snapshot = _snapshot_sink_argument_bytes(
            state,
            None,
            args=[claripy.BVV(fixed_addr, 64), claripy.BVV(tainted_addr, 64)],
        )
        fields = sink_snapshot_evidence_fields(state)
        self.assertEqual(render_model_bytes(state, snapshot), "echo fixed")
        self.assertEqual(fields["sink_argument_binding_source"], "call_arg[0]")
        self.assertEqual(fields["sink_argument_binding_trust"], "direct_abi_arg0")
        self.assertEqual(fields["sink_semantics"], "shell_command")
        self.assertEqual(
            fields["sink_function_name_source"],
            "closure_sink_at_exact_callsite",
        )

    def test_named_sink_capture_metadata_survives_angr_dispatch(self):
        import angr
        import claripy
        from advanced_sanitizer_evaluator import (
            _captured_sink_states,
            _named_sink_capture,
        )

        project = angr.load_shellcode(
            b"\x90" * 0x100, arch="AMD64", load_address=0x400000
        )
        sink_addr = 0x400040
        command_addr = 0x500000
        project.hook(
            sink_addr,
            _named_sink_capture(
                "system",
                sink_addr,
                name_source="closure_sink_at_exact_callsite",
            ),
            replace=True,
        )
        state = project.factory.call_state(
            sink_addr, claripy.BVV(command_addr, project.arch.bits)
        )
        state.memory.store(command_addr, b"echo fixed\x00")
        _captured_sink_states.clear()
        try:
            project.factory.simgr(state).step()
            self.assertTrue(_captured_sink_states)
            captured = _captured_sink_states[-1]
            self.assertEqual(
                captured.globals.get("tsds_sink_function_name"),
                "system",
            )
            self.assertEqual(
                captured.globals.get("tsds_sink_function_name_source"),
                "closure_sink_at_exact_callsite",
            )
            self.assertEqual(
                captured.globals.get("tsds_sink_semantics"),
                "shell_command",
            )
            self.assertEqual(
                captured.globals.get("tsds_sink_argument_binding_trust"),
                "direct_abi_arg0",
            )
        finally:
            _captured_sink_states.clear()

    def test_unknown_wrapper_snapshot_is_heuristic_only(self):
        import angr
        import claripy
        from advanced_sanitizer_evaluator import (
            _snapshot_sink_argument_bytes,
            sink_snapshot_evidence_fields,
            sink_snapshot_is_claimable,
        )

        state = angr.SimState(arch="AMD64")
        command_addr = 0x500000
        state.memory.store(command_addr, b"reboot\x00")
        state.globals["tsds_sink_function_name"] = "mystery_wrapper"
        _snapshot_sink_argument_bytes(
            state,
            None,
            args=[claripy.BVV(0, 64), claripy.BVV(command_addr, 64)],
        )
        fields = sink_snapshot_evidence_fields(state)
        claimable, reason = sink_snapshot_is_claimable(state)
        self.assertEqual(fields["sink_argument_binding_trust"], "heuristic")
        self.assertTrue(fields["sink_argument_binding_source"].startswith("heuristic:"))
        self.assertFalse(claimable)
        self.assertIn("unknown_wrapper", reason)

    def test_direct_exec_is_explicitly_non_shell(self):
        import angr
        import claripy
        from advanced_sanitizer_evaluator import (
            _snapshot_sink_argument_bytes,
            sink_snapshot_evidence_fields,
            sink_snapshot_is_claimable,
        )

        state = angr.SimState(arch="AMD64")
        command_addr = 0x500000
        state.memory.store(command_addr, b"/bin/echo\x00")
        state.globals["tsds_sink_function_name"] = "execve"
        _snapshot_sink_argument_bytes(
            state, None, args=[claripy.BVV(command_addr, 64)]
        )
        fields = sink_snapshot_evidence_fields(state)
        claimable, reason = sink_snapshot_is_claimable(state)
        self.assertEqual(fields["sink_semantics"], "direct_exec_non_shell")
        self.assertEqual(fields["sink_argument_binding_trust"], "non_shell")
        self.assertFalse(claimable)
        self.assertIn("direct_exec_non_shell", reason)

    def test_wrapper_slot_reconciliation_is_counted_as_controlled(self):
        import angr
        from advanced_sanitizer_evaluator import (
            build_reconciled_sink_bytes,
            summarize_taint_provenance,
        )

        state = angr.SimState(arch="AMD64")
        recovered = build_reconciled_sink_bytes(
            state, "rm -rf /tmp/%s", prefix="wrapper_slot"
        )
        provenance = summarize_taint_provenance(recovered)
        self.assertIn("wrapper_slot", provenance["source_kinds"])
        self.assertGreater(provenance["tainted_byte_count"], 0)

    def test_contract_rejects_heuristic_positive_and_incomplete_negative(self):
        from advanced_sanitizer_evaluator import enforce_evidence_contract

        positive = enforce_evidence_contract(
            {
                "status": "vulnerable",
                "sink_reached_observed": True,
                "tainted_offsets": [0, 1],
                "vulnerable_vectors": 1,
                "sink_semantics": "unknown_wrapper",
                "sink_argument_binding_trust": "heuristic",
                "minimal_bypass_vector": {
                    "grammar_complete": True,
                    "witness": ":;:;#",
                    "parser_calibration": "unit-test-calibration",
                },
            }
        )
        self.assertEqual(positive["status"], "residual")
        self.assertIn(
            "claim_without_admissible_shell_sink_semantics",
            positive["contract_violations"],
        )

        prefix_positive = enforce_evidence_contract(
            {
                "status": "vulnerable",
                "sink_reached_observed": True,
                "tainted_offsets": [0, 1],
                "vulnerable_vectors": 1,
                "sink_semantics": "shell_command",
                "sink_argument_binding_trust": "direct_abi_arg0",
                "sink_snapshot_cstring_complete": False,
                "minimal_bypass_vector": {
                    "grammar_complete": True,
                    "witness": ":;:;#",
                    "parser_calibration": "unit-test-calibration",
                },
            }
        )
        self.assertEqual(prefix_positive["status"], "vulnerable")
        self.assertEqual(
            prefix_positive["admissible_claim"],
            "direct_observed_prefix_vector_sat",
        )

        v15_missing_name_provenance = enforce_evidence_contract(
            {
                "status": "vulnerable",
                "analysis_version": (
                    "2026-07-12-evidence-contract-v15-exact-sink-name-binding"
                ),
                "sink_reached_observed": True,
                "tainted_offsets": [0, 1],
                "vulnerable_vectors": 1,
                "sink_semantics": "shell_command",
                "sink_argument_binding_trust": "direct_abi_arg0",
                "minimal_bypass_vector": {
                    "grammar_complete": True,
                    "witness": ":;:;#",
                    "parser_calibration": "unit-test-calibration",
                },
            }
        )
        self.assertEqual(v15_missing_name_provenance["status"], "residual")
        self.assertIn(
            "claim_without_sink_name_provenance",
            v15_missing_name_provenance["contract_violations"],
        )

        v15_named_positive = enforce_evidence_contract(
            {
                "status": "vulnerable",
                "analysis_version": (
                    "2026-07-12-evidence-contract-v15-exact-sink-name-binding"
                ),
                "sink_reached_observed": True,
                "tainted_offsets": [0, 1],
                "vulnerable_vectors": 1,
                "sink_semantics": "shell_command",
                "sink_argument_binding_trust": "direct_abi_arg0",
                "sink_function_name_source": (
                    "closure_sink_at_exact_callsite"
                ),
                "minimal_bypass_vector": {
                    "grammar_complete": True,
                    "witness": ":;:;#",
                    "parser_calibration": "unit-test-calibration",
                },
            }
        )
        self.assertEqual(v15_named_positive["status"], "vulnerable")

        v17_missing_sink_binding = enforce_evidence_contract(
            {
                "status": "vulnerable",
                "analysis_version": (
                    "2026-07-13-evidence-contract-v17-run-locked"
                ),
                "sink_reached_observed": True,
                "tainted_offsets": [0, 1],
                "vulnerable_vectors": 1,
                "minimal_bypass_vector": {
                    "grammar_complete": True,
                    "witness": ":;:;#",
                    "parser_calibration": "unit-test-calibration",
                },
            }
        )
        self.assertEqual(v17_missing_sink_binding["status"], "residual")
        self.assertEqual(
            {
                "claim_without_sink_name_provenance",
                "claim_without_shell_sink_semantics",
                "claim_without_sink_argument_binding",
            },
            set(v17_missing_sink_binding["contract_violations"]),
        )

        negative = enforce_evidence_contract(
            {
                "status": "filtered",
                "sink_reached_observed": True,
                "tainted_offsets": [0],
                "secure_vectors": 11,
                "sink_semantics": "shell_command",
                "sink_argument_binding_trust": "direct_abi_arg0",
                "sink_snapshot_cstring_complete": False,
            }
        )
        self.assertEqual(negative["status"], "residual")
        self.assertIn(
            "negative_claim_from_incomplete_sink_snapshot",
            negative["contract_violations"],
        )


if __name__ == "__main__":
    unittest.main()
