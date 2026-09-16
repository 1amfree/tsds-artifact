import csv
import json
import subprocess
import sys
import unittest
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiment_reports" / "acceptance_strengthening_pack_20260630"


@pytest.mark.workspace_data
class AcceptanceStrengtheningPackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(
            [sys.executable, "experiments/build_acceptance_strengthening_pack.py"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )

    def test_summary_counts_match_paper_claims(self):
        summary = json.loads((OUT / "acceptance_strengthening_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["records"], 518)
        self.assertEqual(summary["audit_records"], 60)
        self.assertEqual(summary["guarded_recovery_records"], 33)
        self.assertEqual(summary["path_control_changed_cases"], 24)
        self.assertEqual(summary["runtime_canary_summary"]["positive_count"], 6)
        self.assertEqual(summary["runtime_canary_summary"]["boundary_probe_count"], 5)

    def test_validator_baseline_keeps_full_tsds_boundary(self):
        with (OUT / "validator_baseline_comparison.csv").open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        by_name = {row["validator"]: row for row in rows}
        self.assertEqual(by_name["Naive guided sink-reach hook"]["positive_or_reached"], "392")
        self.assertEqual(by_name["Naive guided sink-reach hook"]["matrix_relative_spurious"], "168")
        self.assertEqual(by_name["Taint-at-sink hook"]["matrix_relative_missed_sv_sat"], "26")
        self.assertEqual(by_name["Full TSDS"]["filtered_evidence"], "22")
        self.assertEqual(by_name["Full TSDS"]["nms_evidence"], "146")
        self.assertEqual(by_name["Full TSDS"]["blocked_vector_proofs"], "285")

    def test_stratified_audit_covers_all_required_classes(self):
        with (OUT / "stratified_trace_audit_60.csv").open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        strata = {row["stratum"] for row in rows}
        required = {
            "direct_sv_sat",
            "partial_filter_sv_sat",
            "recovered_sv_sat",
            "modeled_vector_filtered",
            "fixed_template_nms",
            "other_nms",
            "residual",
        }
        self.assertTrue(required.issubset(strata))
        self.assertFalse(any(row["audit_verdict"] == "fail" for row in rows))


if __name__ == "__main__":
    unittest.main()
