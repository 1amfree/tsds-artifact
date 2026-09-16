#!/usr/bin/env python3
"""Static checks for the TSDS v17 run-locked pipeline."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from experiments.run_tsds_v17_pipeline import (
    ADDITIONAL_REPRODUCIBILITY_SOURCES,
    PIPELINE_SCHEMA,
    PIPELINE_TAG,
    V17_ARTIFACT_SOURCE_SET,
    artifact_source_candidate,
    main,
    v17_mandatory_stages,
)


class V17PipelineEntrypointTest(unittest.TestCase):
    def test_v17_records_run_lock_and_schema_sources(self) -> None:
        self.assertEqual("v17", PIPELINE_TAG)
        self.assertEqual("tsds-v17-pipeline-v6", PIPELINE_SCHEMA)
        self.assertIn(
            "experiments/run_tsds_v17_pipeline.py",
            ADDITIONAL_REPRODUCIBILITY_SOURCES,
        )
        self.assertIn("pytest.ini", ADDITIONAL_REPRODUCIBILITY_SOURCES)
        self.assertIn(
            "operation-mango-public/pyproject.toml",
            ADDITIONAL_REPRODUCIBILITY_SOURCES,
        )
        self.assertIn(
            "experiments/test_release_readiness.py", V17_ARTIFACT_SOURCE_SET
        )
        self.assertIn(
            "experiments/fixtures/external_baseline_schema_example.json",
            V17_ARTIFACT_SOURCE_SET,
        )
        self.assertIn(
            "experiments/run_v20_post_release.sh", V17_ARTIFACT_SOURCE_SET
        )
        self.assertIn(
            "experiments/resume_v20_queue_after_runtime_audit.sh",
            V17_ARTIFACT_SOURCE_SET,
        )
        self.assertNotIn("test_advanced_evaluator.py", V17_ARTIFACT_SOURCE_SET)
        self.assertNotIn("test_auto_detector.py", V17_ARTIFACT_SOURCE_SET)
        self.assertEqual(
            tuple(sorted(set(V17_ARTIFACT_SOURCE_SET))), V17_ARTIFACT_SOURCE_SET
        )
        test_root = Path(__file__).resolve().parent
        expected_tests = {str(path.resolve()) for path in test_root.glob("test_*.py")}
        snapshotted_tests = {
            str((test_root.parent / relative).resolve())
            for relative in V17_ARTIFACT_SOURCE_SET
            if relative.startswith("experiments/test_")
        }
        self.assertEqual(expected_tests, snapshotted_tests)
        self.assertIn(
            "schemas/tsds-ledger-v17.schema.json",
            ADDITIONAL_REPRODUCIBILITY_SOURCES,
        )
        self.assertIn(
            "experiments/compare_external_baseline.py",
            ADDITIONAL_REPRODUCIBILITY_SOURCES,
        )
        self.assertIn(
            "experiments/audit_repeatability.py",
            ADDITIONAL_REPRODUCIBILITY_SOURCES,
        )
        self.assertIn(
            "experiments/audit_runtime_repeatability.py",
            ADDITIONAL_REPRODUCIBILITY_SOURCES,
        )
        self.assertIn(
            "experiments/run_satc_keyword_extraction.py",
            ADDITIONAL_REPRODUCIBILITY_SOURCES,
        )
        self.assertIn(
            "experiments/unblind_ground_truth_audit.py",
            ADDITIONAL_REPRODUCIBILITY_SOURCES,
        )

    def test_artifact_source_filter_rejects_editor_and_migration_backups(self) -> None:
        self.assertTrue(artifact_source_candidate(Path("experiments/test_case.py")))
        self.assertTrue(artifact_source_candidate(Path("experiments/test_case.sh")))
        self.assertTrue(artifact_source_candidate(Path("experiments/fixture.result-alter2")))
        self.assertFalse(
            artifact_source_candidate(
                Path("experiments/test_case.py.bak_20260714")
            )
        )
        self.assertFalse(
            artifact_source_candidate(
                Path("experiments/test_case.py.pre_v10_20260714")
            )
        )

    def test_v17_exports_tables_only_after_acceptance_stages(self) -> None:
        with patch(
            "experiments.run_tsds_v17_pipeline.run_pipeline", return_value=0
        ) as runner:
            self.assertEqual(0, main())
        kwargs = runner.call_args.kwargs
        self.assertEqual("16_paper_tables", kwargs["paper_stage_name"])
        self.assertEqual(8192, kwargs["default_subprocess_memory_limit_mib"])
        self.assertTrue(kwargs["require_resource_calibration"])
        self.assertEqual(
            "15b_repeatability_consensus", kwargs["repeatability_stage_name"]
        )
        self.assertIs(v17_mandatory_stages, kwargs["additional_mandatory_stages_builder"])


if __name__ == "__main__":
    unittest.main()
