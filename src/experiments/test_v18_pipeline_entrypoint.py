#!/usr/bin/env python3
"""Static and orchestration tests for the TSDS v18/v7 pipeline."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from experiments.run_tsds_v18_pipeline import (
    ADDITIONAL_REPRODUCIBILITY_SOURCES,
    PIPELINE_SCHEMA,
    PIPELINE_TAG,
    V18_ARTIFACT_SOURCE_SET,
    main,
    v18_mandatory_stages,
)


class V18PipelineEntrypointTest(unittest.TestCase):
    def test_schema_and_release_sources_are_frozen(self) -> None:
        self.assertEqual("v18", PIPELINE_TAG)
        self.assertEqual("tsds-v18-pipeline-v7", PIPELINE_SCHEMA)
        self.assertIn("tsds/shell_matrix_spec.py", ADDITIONAL_REPRODUCIBILITY_SOURCES)
        self.assertIn("experiments/verify_evidence_certificates.py", ADDITIONAL_REPRODUCIBILITY_SOURCES)
        self.assertIn(
            "experiments/resume_v20_queue_after_runtime_audit.sh",
            ADDITIONAL_REPRODUCIBILITY_SOURCES,
        )
        self.assertIn("advanced_sanitizer_evaluator.py", ADDITIONAL_REPRODUCIBILITY_SOURCES)
        self.assertIn("containers/tsds-reproduction.Dockerfile", V18_ARTIFACT_SOURCE_SET)
        self.assertEqual(tuple(sorted(set(V18_ARTIFACT_SOURCE_SET))), V18_ARTIFACT_SOURCE_SET)

    def test_v18_adds_post_campaign_evidence_stages(self) -> None:
        kwargs = {
            "root": Path("/root"),
            "source_root": Path("/snapshot"),
            "python": Path("/venv/python"),
            "campaign": Path("/run/campaign"),
            "out_dir": Path("/run"),
            "args": type("Args", (), {"subprocess_memory_limit_mib": 8192})(),
        }
        names = [name for name, _, _ in v18_mandatory_stages(**kwargs)]
        self.assertIn("13a_independent_certificate_verifier", names)
        self.assertIn("13b_residual_root_causes", names)
        self.assertIn("13c_performance_diagnostics", names)
        self.assertIn("13d_reproduction_sbom", names)
        self.assertIn("13f_candidate_contract", names)

    def test_main_selects_v18_contract(self) -> None:
        with patch("experiments.run_tsds_v18_pipeline.run_pipeline", return_value=0) as runner:
            self.assertEqual(0, main())
        kwargs = runner.call_args.kwargs
        self.assertEqual("v18", kwargs["default_pipeline_tag"])
        self.assertEqual("tsds-v18-pipeline-v7", kwargs["default_pipeline_schema"])
        self.assertIs(v18_mandatory_stages, kwargs["additional_mandatory_stages_builder"])


if __name__ == "__main__":
    unittest.main()
