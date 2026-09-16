#!/usr/bin/env python3
"""Run the reproducible TSDS v15 evidence-contract experiment pipeline."""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.run_tsds_v14_pipeline import main as run_pipeline  # noqa: E402


PIPELINE_TAG = "v15"
PIPELINE_SCHEMA = "tsds-v15-pipeline-v1"
ADDITIONAL_REPRODUCIBILITY_SOURCES = (
    "experiments/run_tsds_v15_pipeline.py",
)


def main() -> int:
    return run_pipeline(
        default_pipeline_tag=PIPELINE_TAG,
        default_pipeline_schema=PIPELINE_SCHEMA,
        additional_reproducibility_sources=ADDITIONAL_REPRODUCIBILITY_SOURCES,
    )


if __name__ == "__main__":
    raise SystemExit(main())
