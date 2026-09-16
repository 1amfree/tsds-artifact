#!/usr/bin/env python3

from __future__ import annotations

import unittest

from audit_v19_mechanism_invariants import record_issues


def arguments(**updates):
    value = {
        "execution_backend": "forkserver",
        "no_evidence_aware_scheduler": False,
        "no_sink_corridor": False,
        "no_source_projected_constraints": False,
        "no_byte_provenance": False,
        "no_sink_semantic_plugins": False,
        "online_refinement_rounds": 1,
        "online_refinement_candidates": 3,
        "subprocess_memory_limit_mib": 8192,
    }
    value.update(updates)
    return value


def controlled_record(**updates):
    value = {
        "verdict": "VECTOR_SAT",
        "evidence_provenance": "DIRECT_SINK_BYTE",
        "evidence_contract_valid": True,
        "execution_backend": "forkserver",
        "engine_scheduler_schema": "tsds-evidence-aware-scheduler-v1",
        "engine_sink_corridor": {"schema": "tsds-sink-corridor-v1"},
        "vector_decisions": [{"vector_id": "semicolon", "decision": "VECTOR_SAT"}],
        "matrix_projection_full_constraints": 100,
        "matrix_projection_selected_constraints": 20,
        "matrix_projection_full_validations": 1,
        "controlled_offsets": [3, 2],
        "byte_provenance_graph_sha256": "a" * 64,
        "byte_provenance_node_count": 3,
        "byte_provenance_controlled_offsets": [2, 3],
        "sink_semantic_plugin": "shell_string",
        "sink_semantic_contract": {"plugin_id": "shell_string"},
        "subprocess_memory_limit_mib": 8192,
    }
    value.update(updates)
    return value


class V19MechanismInvariantTest(unittest.TestCase):
    def test_complete_controlled_record_passes(self) -> None:
        self.assertEqual([], record_issues(controlled_record(), arguments()))

    def test_projected_sat_requires_full_validation(self) -> None:
        issues = record_issues(
            controlled_record(matrix_projection_full_validations=0), arguments()
        )
        self.assertIn("projected_sat_without_full_validation", issues)

    def test_source_dependent_cstring_terminator_is_boundary_lineage(self) -> None:
        record = controlled_record(
            controlled_offsets=[2, 3],
            byte_provenance_controlled_offsets=[2, 3, 4],
            matrix_snapshot_cstring_complete=True,
            matrix_snapshot_terminator_offset=4,
        )
        self.assertEqual([], record_issues(record, arguments()))
        record["byte_provenance_controlled_offsets"] = [2, 3, 5]
        issues = record_issues(record, arguments())
        self.assertIn("byte_provenance_nonboundary_lineage_offset", issues)

    def test_disabled_mechanisms_must_not_emit_evidence(self) -> None:
        record = controlled_record(
            engine_scheduler_schema="tsds-evidence-aware-scheduler-v1",
            engine_sink_corridor={"schema": "tsds-sink-corridor-v1"},
        )
        issues = record_issues(
            record,
            arguments(
                no_evidence_aware_scheduler=True,
                no_sink_corridor=True,
                no_source_projected_constraints=True,
                no_byte_provenance=True,
                no_sink_semantic_plugins=True,
            ),
        )
        self.assertIn("disabled_scheduler_emitted_ledger", issues)
        self.assertIn("disabled_sink_corridor_emitted_ledger", issues)
        self.assertIn("disabled_projection_emitted_accounting", issues)
        self.assertIn("disabled_byte_provenance_emitted_graph", issues)
        self.assertIn("disabled_sink_semantic_plugin_emitted_contract", issues)

    def test_static_reduction_may_omit_dynamic_search_ledgers(self) -> None:
        record = {
            "verdict": "STATIC_WARNING_REDUCTION",
            "evidence_provenance": "STATIC_WARNING_REDUCTION",
            "evidence_contract_valid": True,
            "subprocess_memory_limit_mib": 8192,
        }
        self.assertEqual([], record_issues(record, arguments()))

    def test_liveness_suppression_requires_a_reason_ledger(self) -> None:
        record = controlled_record(
            engine_scheduler_schema="tsds-evidence-aware-scheduler-v3",
            engine_source_liveness_stop_suppressions=1,
        )
        issues = record_issues(record, arguments())
        self.assertIn("liveness_suppression_reasons_missing", issues)

        record["engine_source_liveness_stop_suppression_reasons"] = {
            "near_sink_frontier": 1
        }
        self.assertEqual([], record_issues(record, arguments()))

    def test_terminated_worker_residual_retains_execution_configuration(self) -> None:
        record = {
            "verdict": "RESIDUAL",
            "evidence_provenance": "RESIDUAL",
            "evidence_contract_valid": True,
            "execution_backend": "forkserver",
            "subprocess_memory_limit_mib": 8192,
            "process_resource_metric_scope": "unavailable_worker_terminated",
            "process_resource_metric_reason": "parent_orchestration_failure",
        }
        self.assertEqual(
            [],
            record_issues(
                record,
                arguments(no_evidence_aware_scheduler=True, no_sink_corridor=True),
            ),
        )

    def test_executed_cegar_summary_requires_conditioned_secondary_scope(self) -> None:
        record = controlled_record(
            summary_runtime_events=[
                {
                    "origin": "residual_cegar",
                    "effect": "fork_boolean_predicate",
                    "outcome": "forked",
                }
            ],
            evidence_conditioning="unconditioned",
            primary_aggregate_eligible=True,
        )
        issues = record_issues(record, arguments())
        self.assertIn("executed_summary_without_matching_conditioning", issues)
        self.assertIn("executed_summary_marked_primary", issues)
        self.assertIn("refinement_conditioning_without_bundle_digest", issues)

        record.update(
            {
                "evidence_conditioning": "refinement_conditioned",
                "primary_aggregate_eligible": False,
                "evidence_refinement_bundle_sha256": "a" * 64,
            }
        )
        self.assertEqual([], record_issues(record, arguments()))


if __name__ == "__main__":
    unittest.main()
