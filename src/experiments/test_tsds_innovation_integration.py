#!/usr/bin/env python3
"""Integration tests for P0/P1/P2 evaluator wiring without firmware inputs."""

from __future__ import annotations

import importlib.util
import unittest
from types import SimpleNamespace


@unittest.skipIf(
    importlib.util.find_spec("angr") is None,
    "advanced evaluator dependencies unavailable",
)
class InnovationConfigTest(unittest.TestCase):
    def test_config_exposes_new_evidence_protocol_features(self) -> None:
        from advanced_sanitizer_evaluator import AnalysisConfig

        config = AnalysisConfig(execution_backend="forkserver")
        features = config.enabled_features()
        self.assertTrue(features["evidence_aware_scheduler"])
        self.assertTrue(features["sink_corridor"])
        self.assertTrue(features["source_projected_constraints"])
        self.assertEqual("forkserver", features["execution_backend"])
        self.assertEqual(1, features["online_refinement_rounds"])
        self.assertTrue(features["byte_provenance"])
        self.assertTrue(features["sink_semantic_plugins"])

        ablated = AnalysisConfig(
            byte_provenance=False,
            sink_semantic_plugins=False,
        ).enabled_features()
        self.assertFalse(ablated["byte_provenance"])
        self.assertFalse(ablated["sink_semantic_plugins"])

    def test_bounded_multi_state_collection_is_the_default(self) -> None:
        from advanced_sanitizer_evaluator import AnalysisConfig

        self.assertTrue(AnalysisConfig().multi_state_audit)
        self.assertFalse(AnalysisConfig(multi_state_audit=False).multi_state_audit)

    def test_execve_shell_c_binds_command_argument(self) -> None:
        import angr
        import claripy
        from advanced_sanitizer_evaluator import (
            _snapshot_sink_argument_bytes,
            sink_snapshot_evidence_fields,
        )

        project = angr.load_shellcode(b"\x90", arch="amd64", load_address=0x400000)
        state = project.factory.blank_state(addr=0x400000)
        path_address = 0x500000
        argv_address = 0x501000
        argv0_address = 0x502000
        flag_address = 0x503000
        command_address = 0x504000
        state.memory.store(path_address, b"/bin/sh\x00")
        state.memory.store(argv0_address, b"sh\x00")
        state.memory.store(flag_address, b"-c\x00")
        command = [claripy.BVS(f"webvar_exec_{index}", 8) for index in range(8)]
        for index, byte in enumerate(command):
            state.memory.store(command_address + index, byte)
        state.memory.store(command_address + len(command), claripy.BVV(0, 8))
        for index, pointer in enumerate(
            (argv0_address, flag_address, command_address, 0)
        ):
            state.memory.store(
                argv_address + index * 8,
                claripy.BVV(pointer, 64),
                endness=project.arch.memory_endness,
            )
        state.globals["tsds_sink_function_name"] = "execve"
        captured = _snapshot_sink_argument_bytes(
            state,
            project,
            args=[claripy.BVV(path_address, 64), claripy.BVV(argv_address, 64)],
        )
        fields = sink_snapshot_evidence_fields(state)
        self.assertEqual("shell_command", fields["sink_semantics"])
        self.assertEqual("direct_exec_shell_c", fields["sink_argument_binding_trust"])
        self.assertEqual("direct_exec_shell_c", fields["sink_semantic_plugin"])
        self.assertTrue(any(byte.symbolic for byte in captured))

    def test_synthesized_source_summary_executes_as_simprocedure(self) -> None:
        import angr
        from advanced_sanitizer_evaluator import install_synthesized_summaries
        from tsds.summary_synthesis import FunctionSummary, SummaryEffect

        project = angr.load_shellcode(b"\x90", arch="amd64", load_address=0x410000)
        summary = FunctionSummary(
            target="0x410000",
            architecture="AMD64",
            calling_convention="default",
            binary_sha256="d" * 64,
            preconditions=(),
            effects=(
                SummaryEffect(
                    "return_symbolic_cstring",
                    source_kind="web",
                    max_bytes=16,
                ),
            ),
            confidence="high",
            origin="residual_cegar",
        )
        installation = install_synthesized_summaries(project, [summary])
        self.assertEqual(1, len(installation["installed"]))
        state = project.factory.call_state(0x410000, ret_addr=0x420000)
        shared_events = []
        state.globals["tsds_summary_events"] = shared_events
        manager = project.factory.simulation_manager(state)
        manager.step()
        successors = manager.active or manager.deadended
        self.assertTrue(successors)
        successor = successors[0]
        pointer = successor.solver.eval(successor.regs.rax)
        byte = successor.memory.load(pointer, 1)
        self.assertTrue(successor.solver.symbolic(byte))
        self.assertTrue(
            any(name.startswith("webvar_") for name in byte.variables)
        )
        self.assertTrue(successor.globals["tsds_summary_events"])
        self.assertTrue(shared_events)
        self.assertEqual(
            "residual_cegar",
            successor.globals["tsds_summary_events"][0]["origin"],
        )

    def test_executed_refinement_summary_is_not_primary_evidence(self) -> None:
        from advanced_sanitizer_evaluator import evidence_conditioning_for_record

        conditioning = evidence_conditioning_for_record(
            {
                "summary_installation": {
                    "refinement_bundle_path": "bundle.json",
                    "refinement_bundle_sha256": "a" * 64,
                },
                "summary_runtime_events": [
                    {
                        "summary_id": "fixture",
                        "origin": "residual_cegar",
                        "effect": "fork_boolean_predicate",
                        "outcome": "forked",
                    }
                ],
            }
        )
        self.assertEqual("refinement_conditioned", conditioning["evidence_conditioning"])
        self.assertFalse(conditioning["primary_aggregate_eligible"])
        self.assertEqual(["residual_cegar"], conditioning["evidence_summary_origins"])

    def test_provenance_defaults_to_compact_ledger_fields(self) -> None:
        import claripy
        from types import SimpleNamespace
        from advanced_sanitizer_evaluator import byte_provenance_fields

        state = SimpleNamespace(globals={"tsds_emit_provenance_graph": False})
        fields = byte_provenance_fields(
            state,
            [claripy.BVS("webvar_compact_0", 8), claripy.BVV(0, 8)],
        )
        self.assertTrue(fields["byte_provenance_graph_sha256"])
        self.assertNotIn("byte_provenance_graph", fields)


@unittest.skipIf(
    importlib.util.find_spec("claripy") is None,
    "claripy unavailable",
)
class ProjectedMatrixIntegrationTest(unittest.TestCase):
    def test_projected_sat_is_full_validated_and_accounted(self) -> None:
        import claripy
        from advanced_sanitizer_evaluator import ThreatMatrixEvaluator
        from tsds.constraint_projection import ConstraintProjectionStore

        state = SimpleNamespace(
            solver=claripy.Solver(),
            globals={
                "tsds_source_projected_constraints": True,
                "tsds_constraint_projection_store": ConstraintProjectionStore(),
            },
        )
        source = [claripy.BVS(f"webvar_projection_{index}", 8) for index in range(16)]
        for byte in source:
            state.solver.add(byte >= 0x20)
            state.solver.add(byte <= 0x7E)
        report = ThreatMatrixEvaluator.evaluate(
            state,
            source,
            target_bytes=source + [claripy.BVV(0, 8)],
        )
        self.assertEqual(11, len(report))
        self.assertGreater(state.globals["threat_matrix_projection_full_constraints"], 0)
        self.assertGreater(state.globals["threat_matrix_projection_selected_constraints"], 0)
        self.assertGreater(state.globals["threat_matrix_projection_full_validations"], 0)
        self.assertGreater(state.globals["threat_matrix_solver_queries"], 0)


if __name__ == "__main__":
    unittest.main()
