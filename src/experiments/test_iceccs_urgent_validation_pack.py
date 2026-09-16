#!/usr/bin/env python3
"""Tests for the urgent ICECCS reviewer validation pack."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
import unittest
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiment_reports" / "iceccs_urgent_validation_pack_20260702"


@pytest.mark.workspace_data
class IceccsUrgentValidationPackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            [sys.executable, "experiments/build_iceccs_urgent_validation_pack.py"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )

    def test_recovery_admission_and_rejection_counts(self) -> None:
        summary = json.loads((OUT / "urgent_validation_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["guarded_recovery_admitted"], 33)
        self.assertEqual(summary["guarded_recovery_rejected_attempts"], 5)
        self.assertEqual(summary["guarded_recovery_modes"]["static_sink_template_fallback"], 17)
        self.assertEqual(summary["guarded_recovery_modes"]["static_dynamic_taint_reconciliation"], 12)
        self.assertEqual(summary["guarded_recovery_modes"]["static_direct_source_fallback"], 4)

    def test_path_control_claim_impact_keeps_extra_positive_manual(self) -> None:
        with (OUT / "path_control_claim_impact_analysis.csv").open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 24)
        impacts = {row["claim_impact"] for row in rows}
        self.assertIn("manual_review_only_extra_positive", impacts)
        extra = [row for row in rows if row["claim_impact"] == "manual_review_only_extra_positive"]
        self.assertEqual(len(extra), 1)
        self.assertEqual(extra[0]["review_action"], "manual_review")

    def test_summary_preserves_non_device_claim_boundary(self) -> None:
        text = (OUT / "urgent_validation_summary.md").read_text(encoding="utf-8")
        self.assertIn("No device-confirmed exploit count is added", text)
        self.assertIn("Threat-matrix tests exercise byte predicates", text)


if __name__ == "__main__":
    unittest.main()
