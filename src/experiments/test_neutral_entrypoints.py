#!/usr/bin/env python3
"""Tests that current public entry points no longer expose legacy versions."""

from __future__ import annotations

import unittest

from experiments import export_paper_tables, run_tsds_pipeline
from experiments.export_v10_paper_tables import main as legacy_export_main
from experiments.run_tsds_v18_pipeline import main as v18_pipeline_main


class NeutralEntrypointsTest(unittest.TestCase):
    def test_paper_export_delegates_to_contract_gated_implementation(self) -> None:
        self.assertIs(legacy_export_main, export_paper_tables.main)

    def test_pipeline_entrypoint_selects_v18(self) -> None:
        self.assertIs(v18_pipeline_main, run_tsds_pipeline.main)


if __name__ == "__main__":
    unittest.main()
