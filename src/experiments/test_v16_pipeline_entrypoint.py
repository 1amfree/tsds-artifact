#!/usr/bin/env python3
"""Static entrypoint checks for the TSDS v16 reproducibility pipeline."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from experiments.run_tsds_v16_pipeline import (
    ADDITIONAL_REPRODUCIBILITY_SOURCES,
    DEFAULT_SUBPROCESS_MEMORY_LIMIT_MIB,
    PIPELINE_SCHEMA,
    PIPELINE_TAG,
    main,
    v16_mandatory_stages,
)


class V16PipelineEntrypointTest(unittest.TestCase):
    def test_identity_and_added_gates(self) -> None:
        self.assertEqual("v16", PIPELINE_TAG)
        self.assertEqual("tsds-v16-pipeline-v2", PIPELINE_SCHEMA)
        self.assertEqual(8192, DEFAULT_SUBPROCESS_MEMORY_LIMIT_MIB)
        self.assertIn("tsds/evidence_certificates.py", ADDITIONAL_REPRODUCIBILITY_SOURCES)
        args = type("Args", (), {"subprocess_memory_limit_mib": 4096})()
        stages = v16_mandatory_stages(
            python=Path("python"), campaign=Path("campaign"), out_dir=Path("out"), root=Path("."), args=args, targets=[]
        )
        names = [row[0] for row in stages]
        self.assertIn("08_evidence_certificates", names)
        self.assertIn("13_residual_refinement_plan", names)
        resource_command = next(
            command for name, command, _timeout in stages if name == "09_resource_envelope"
        )
        self.assertIn("--require-memory-limit-enforced", resource_command)
        self.assertIn("--fail-on-resource-limit-hits", resource_command)
        self.assertIn("--fail-on-unavailable-worker-metrics", resource_command)

    def test_paper_export_is_numbered_after_v16_acceptance_gates(self) -> None:
        with patch(
            "experiments.run_tsds_v16_pipeline.run_pipeline", return_value=0
        ) as runner:
            self.assertEqual(0, main())
        self.assertEqual("16_paper_tables", runner.call_args.kwargs["paper_stage_name"])


if __name__ == "__main__":
    unittest.main()
