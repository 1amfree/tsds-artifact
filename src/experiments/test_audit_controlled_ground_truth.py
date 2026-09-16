import json
import tempfile
import unittest
from pathlib import Path

from audit_controlled_ground_truth import audit, binary_metrics, write_outputs


class ControlledGroundTruthAuditTest(unittest.TestCase):
    def test_binary_metrics_include_wilson_intervals(self):
        result = binary_metrics([True, False], [True, False])
        self.assertEqual((result["tp"], result["tn"]), (1, 1))
        self.assertEqual(result["precision"], 1.0)
        self.assertIsNotNone(result["accuracy_wilson_95"])

    def test_audit_recomputes_fixed_labels_and_baselines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = root / "summary.json"
            cases = root / "cases.csv"
            baseline = root / "baseline.json"
            summary.write_text(json.dumps({
                "case_count": 2,
                "expected_positive_cases": 1,
                "native_marker_observed": 1,
                "tsds_matches": 2,
                "tsds_mismatches": 0,
            }), encoding="utf-8")
            cases.write_text(
                "index,case_id,expected,native_returncode,marker_observed,tsds_class,tsds_positive,comparison\n"
                "0,p,POSITIVE,0,True,POSITIVE,True,MATCH\n"
                "1,n,NEGATIVE,0,False,NEGATIVE_PROFILE,False,MATCH\n",
                encoding="utf-8",
            )
            baseline.write_text(json.dumps({"rows": [
                {"case_id": "p", "truth": True, "native_trigger": True, "B0_reached_sink": True, "B1_source_meta": True, "B2_full_string_meta": True, "TSDS": True},
                {"case_id": "n", "truth": False, "native_trigger": False, "B0_reached_sink": True, "B1_source_meta": False, "B2_full_string_meta": False, "TSDS": False},
            ]}), encoding="utf-8")
            result = audit(summary, cases, baseline)
            self.assertTrue(result["valid"])
            self.assertEqual(result["tsds"]["tp"], 1)
            self.assertEqual(result["tsds"]["tn"], 1)
            self.assertEqual(result["validators"]["B0_original_source_to_sink"]["fp"], 1)

    def test_audit_rejects_native_label_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = root / "summary.json"
            cases = root / "cases.csv"
            summary.write_text(json.dumps({
                "case_count": 1,
                "expected_positive_cases": 1,
                "native_marker_observed": 1,
                "tsds_matches": 1,
                "tsds_mismatches": 0,
            }), encoding="utf-8")
            cases.write_text(
                "index,case_id,expected,native_returncode,marker_observed,tsds_class,tsds_positive,comparison\n"
                "0,p,POSITIVE,0,False,POSITIVE,True,MATCH\n",
                encoding="utf-8",
            )
            result = audit(summary, cases)
            self.assertFalse(result["valid"])
            self.assertIn("native_label_mismatch:p", result["issues"])


if __name__ == "__main__":
    unittest.main()
