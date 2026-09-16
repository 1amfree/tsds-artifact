#!/usr/bin/env python3
"""Tests for the TSDS runtime-validation expansion pack."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
import unittest
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiment_reports" / "runtime_validation_expansion_pack_20260702"


@pytest.mark.workspace_data
class RuntimeValidationExpansionPackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            [sys.executable, "experiments/build_runtime_validation_expansion_pack.py"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )

    def test_candidate_pack_covers_review_strata(self) -> None:
        with (OUT / "runtime_validation_candidate_expansion.csv").open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        strata = {row["stratum"] for row in rows}
        self.assertTrue({"direct_sv_sat", "guarded_sv_sat", "modeled_vector_filtered", "nms"}.issubset(strata))

    def test_replay_preserves_claim_boundary(self) -> None:
        summary = json.loads((OUT / "runtime_validation_expansion_summary.json").read_text(encoding="utf-8"))
        self.assertIn("no shell execution", summary["claim_boundary"])
        self.assertGreaterEqual(summary["candidate_rows"], 30)

    def test_path_control_targets_include_manual_review_case(self) -> None:
        with (OUT / "path_control_runtime_targets.csv").open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertTrue(any(row["stratum"] == "path_control_changed" for row in rows))
        self.assertTrue(any("not a positive unless manually confirmed" in row["non_claim"] for row in rows))


if __name__ == "__main__":
    unittest.main()
