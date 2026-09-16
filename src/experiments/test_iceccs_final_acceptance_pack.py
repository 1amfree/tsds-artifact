#!/usr/bin/env python3
"""Tests for the final TSDS ICECCS acceptance pack."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
import unittest
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiment_reports" / "iceccs_final_acceptance_pack_20260702"


@pytest.mark.workspace_data
class IceccsFinalAcceptancePackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            [sys.executable, "experiments/build_iceccs_final_acceptance_pack.py"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )

    def test_p0_evidence_counts_are_complete(self) -> None:
        summary = json.loads((OUT / "final_acceptance_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["guarded_recovery_records"], 33)
        self.assertEqual(summary["rejected_recovery_attempts"], 5)
        self.assertEqual(summary["path_control_changed_cases"], 24)
        self.assertEqual(summary["stratified_audit_rows"], 60)
        self.assertIn("manual_review_only_extra_positive", summary["path_control_claim_impacts"])

    def test_p1_predicate_and_ledger_artifacts_exist(self) -> None:
        with (OUT / "threat_matrix_predicate_definitions.csv").open(encoding="utf-8") as fh:
            predicates = list(csv.DictReader(fh))
        self.assertEqual(len(predicates), 11)
        ledger = json.loads((OUT / "ledger_running_example.json").read_text(encoding="utf-8"))
        self.assertEqual(ledger["sv_sat_example"]["target"], "xr300")
        self.assertEqual(ledger["sv_sat_example"]["sat_vectors"], 11)
        self.assertEqual(ledger["modeled_filtered_sibling"]["unsat_vectors"], 11)

    def test_p2_runtime_and_frontend_boundaries_are_preserved(self) -> None:
        summary = json.loads((OUT / "final_acceptance_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["runtime_followup"]["runtime_candidate_rows"], 48)
        self.assertEqual(summary["runtime_followup"]["path_control_runtime_targets"], 8)
        self.assertTrue(summary["runtime_followup"]["satc_adapter_smoke_passed"])
        self.assertIn("no device-confirmed exploit", summary["claim_boundary"])
        text = (OUT / "runtime_and_frontend_followup.md").read_text(encoding="utf-8")
        self.assertIn("does not", text)
        self.assertIn("front-end accuracy study", text)


if __name__ == "__main__":
    unittest.main()
