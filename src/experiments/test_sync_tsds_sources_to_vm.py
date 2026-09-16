#!/usr/bin/env python3

from __future__ import annotations

import unittest

from experiments.run_tsds_v14_pipeline import V14_REPRODUCIBILITY_SOURCES
from experiments.run_tsds_v17_pipeline import (
    ADDITIONAL_REPRODUCIBILITY_SOURCES as V17_REPRODUCIBILITY_SOURCES,
    V17_ARTIFACT_SOURCE_SET,
)
from experiments.sync_tsds_sources_to_vm import (
    ACTIVE_PROCESS_MARKERS,
    SOURCE_FILES,
    safe_relative_path,
)


class SourceSyncTest(unittest.TestCase):
    def test_posthoc_evidence_builders_block_source_sync(self) -> None:
        self.assertIn("audit_runtime_repeatability.py", ACTIVE_PROCESS_MARKERS)
        self.assertIn("package_blinded_audit.py", ACTIVE_PROCESS_MARKERS)
        self.assertIn(
            "build_deterministic_artifact_archive.py", ACTIVE_PROCESS_MARKERS
        )
        self.assertIn("verify_deterministic_artifact_archive.py", ACTIVE_PROCESS_MARKERS)
        self.assertIn("audit_release_readiness.py", ACTIVE_PROCESS_MARKERS)
        self.assertIn("run_source_snapshot_self_test.py", ACTIVE_PROCESS_MARKERS)
        self.assertIn("build_repeatability_slice.py", ACTIVE_PROCESS_MARKERS)
        for marker in (
            "export_v10_paper_tables.py",
            "audit_campaign_conservation.py",
            "audit_evidence_contract.py",
            "audit_vector_decision_integrity.py",
            "audit_shell_witness_syntax.py",
            "run_threat_matrix_boundary_suite.py",
            "run_busybox_shell_vector_calibration.py",
            "audit_ledger_schema.py",
            "audit_resource_envelopes.py",
            "audit_shell_dialect_profiles.py",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, ACTIVE_PROCESS_MARKERS)
        self.assertIn("convert_satc_native_results.py", ACTIVE_PROCESS_MARKERS)
        self.assertIn("convert_satc_to_tsds.py", ACTIVE_PROCESS_MARKERS)
        self.assertIn("run_tsds_v19_experiment_matrix.py", ACTIVE_PROCESS_MARKERS)
        self.assertIn("analyze_tsds_v19_experiment_matrix.py", ACTIVE_PROCESS_MARKERS)
        self.assertIn("export_v20_ablation_transitions.py", ACTIVE_PROCESS_MARKERS)
        self.assertIn("build_runtime_validation_expansion_pack.py", ACTIVE_PROCESS_MARKERS)
        self.assertIn("build_v20_claim_evidence_matrix.py", ACTIVE_PROCESS_MARKERS)
        self.assertIn(
            "resume_v20_queue_after_runtime_audit.sh", ACTIVE_PROCESS_MARKERS
        )
        self.assertIn("build_satc_source_snapshot.py", ACTIVE_PROCESS_MARKERS)
        self.assertIn("capture_satc_js_parser_environment.py", ACTIVE_PROCESS_MARKERS)
        self.assertIn("build_reviewed_source_snapshot.py", ACTIVE_PROCESS_MARKERS)

    def test_v19_experiment_matrix_is_deployed_atomically(self) -> None:
        for path in (
            "experiments/run_tsds_v19_experiment_matrix.py",
            "experiments/analyze_tsds_v19_experiment_matrix.py",
            "experiments/test_tsds_v19_experiment_matrix.py",
            "experiments/test_analyze_tsds_v19_experiment_matrix.py",
            "experiments/V19_EXPERIMENT_PROTOCOL.md",
            "experiments/audit_v19_mechanism_invariants.py",
            "experiments/test_v19_mechanism_invariants.py",
            "experiments/audit_v19_refinement_bundles.py",
            "experiments/test_v19_refinement_bundles.py",
            "experiments/build_v20_refinement_bundles.py",
            "experiments/test_build_v20_refinement_bundles.py",
            "experiments/export_v20_ablation_transitions.py",
            "experiments/test_export_v20_ablation_transitions.py",
            "experiments/build_runtime_validation_expansion_pack.py",
            "experiments/test_runtime_validation_v20.py",
            "experiments/build_v20_claim_evidence_matrix.py",
            "experiments/test_build_v20_claim_evidence_matrix.py",
            "experiments/satc_source_snapshot.py",
            "experiments/build_satc_source_snapshot.py",
            "experiments/test_satc_source_snapshot.py",
            "experiments/capture_satc_js_parser_environment.py",
            "experiments/test_capture_satc_js_parser_environment.py",
            "experiments/build_reviewed_source_snapshot.py",
            "experiments/test_build_reviewed_source_snapshot.py",
            "experiments/test_residual_root_causes.py",
            "experiments/resume_v20_queue_after_runtime_audit.sh",
            "experiments/test_v20_queue_resume.py",
        ):
            with self.subTest(path=path):
                self.assertIn(path, SOURCE_FILES)

    def test_source_manifest_is_unique_and_relative(self) -> None:
        self.assertEqual(len(SOURCE_FILES), len(set(SOURCE_FILES)))
        self.assertTrue(all(safe_relative_path(path) for path in SOURCE_FILES))

    def test_parent_escape_is_rejected(self) -> None:
        for value in ("../outside", "..\\outside", "./file", "a//b"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                safe_relative_path(value)

    def test_all_run_locked_sources_are_in_deployment_manifest(self) -> None:
        declared = set(V14_REPRODUCIBILITY_SOURCES) | set(
            V17_REPRODUCIBILITY_SOURCES
        )
        self.assertEqual(set(), declared - set(SOURCE_FILES))
        self.assertEqual(set(), set(V17_ARTIFACT_SOURCE_SET) - set(SOURCE_FILES))


if __name__ == "__main__":
    unittest.main()
