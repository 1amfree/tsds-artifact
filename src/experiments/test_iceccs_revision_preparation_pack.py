import unittest

from experiments import build_iceccs_revision_preparation_pack as pack


class IceccsRevisionPreparationPackTest(unittest.TestCase):
    def test_percentile_interpolates_distribution(self) -> None:
        values = [1.0, 2.0, 3.0, 4.0]
        self.assertEqual(pack.percentile(values, 50), 2.5)
        self.assertAlmostEqual(pack.percentile(values, 75), 3.25)

    def test_pc_change_flags_no_path_extra_positive_for_review(self) -> None:
        full = {"status": "no_taint_sink"}
        no_path = {"status": "vulnerable"}
        self.assertEqual(
            pack.classify_pc_change(full, no_path),
            "no_path_extra_positive_requires_review",
        )
        note = pack.pc_soundness_note("no_path_extra_positive_requires_review")
        self.assertIn("review required", note)

    def test_nms_classification_avoids_benign_claim(self) -> None:
        row = {
            "status": "no_taint_sink",
            "residual_diagnosis_class": "static_overapprox_no_taint",
            "evidence_confidence": "medium",
        }
        self.assertEqual(pack.nms_subtype(row), "fixed_template_or_static_overapprox_nms")
        self.assertEqual(pack.nms_confidence_band(row), "higher_confidence_for_tsds_contract")
        self.assertIn("source binding", pack.nms_followup("upstream_unbound_candidate_nms"))

    def test_recovered_positive_rows_merge_manual_audit_boundary(self) -> None:
        targets = {
            "fw": [
                {
                    "status": "vulnerable",
                    "closure_idx": 7,
                    "analysis_recovery": "static_sink_template_fallback",
                    "evidence_confidence": "high",
                    "static_evidence_strength": "strong",
                    "sink_addr": "0x1000",
                    "sink_function": "system",
                    "source_addr": "0x2000",
                    "minimal_bypass_vector": {"vector": ";", "category": "Command Chaining"},
                }
            ]
        }
        manual = {
            ("fw.results.jsonl", "7"): {
                "audit_verdict": "PASS_WITH_BOUNDARY",
                "review_outcome": "confirmed_with_boundary",
            }
        }
        rows, summary = pack.recovered_positive_rows(targets, manual)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["manual_trace_audit"], "manual_trace_PASS_WITH_BOUNDARY")
        self.assertIn("not device exploit proof", rows[0]["non_claim"])
        summary_counts = {row["recovery_mode"]: row["records"] for row in summary}
        self.assertEqual(summary_counts["static_sink_template_fallback"], 1)

    def test_runtime_candidate_plan_does_not_claim_validation(self) -> None:
        rows = pack.runtime_validation_candidates(
            {
                "fw": [
                    {
                        "status": "vulnerable",
                        "closure_idx": 1,
                        "analysis_recovery": pack.DIRECT_MODE,
                        "evidence_confidence": "high",
                        "sink_function": "system",
                        "sink_addr": "0x1000",
                        "trace_len": 1,
                        "elapsed_sec": 1.0,
                        "bypass_vector_categories": ["Command Chaining"] * 5,
                    }
                ]
            },
            {"positive_canaries": []},
            limit=5,
        )
        self.assertEqual(len(rows), 1)
        self.assertIn("candidate selection only", rows[0]["non_claim"])


if __name__ == "__main__":
    unittest.main()
