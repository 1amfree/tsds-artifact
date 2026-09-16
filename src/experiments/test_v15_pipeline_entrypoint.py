from __future__ import annotations

import unittest

from experiments.run_tsds_v15_pipeline import (
    ADDITIONAL_REPRODUCIBILITY_SOURCES,
    PIPELINE_SCHEMA,
    PIPELINE_TAG,
)


class V15PipelineEntrypointTest(unittest.TestCase):
    def test_v15_pipeline_identity_is_explicit(self) -> None:
        self.assertEqual(PIPELINE_TAG, "v15")
        self.assertEqual(PIPELINE_SCHEMA, "tsds-v15-pipeline-v1")
        self.assertIn(
            "experiments/run_tsds_v15_pipeline.py",
            ADDITIONAL_REPRODUCIBILITY_SOURCES,
        )


if __name__ == "__main__":
    unittest.main()
