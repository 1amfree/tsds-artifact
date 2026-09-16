import unittest

from experiments import build_iceccs_reviewer_audit_pack as pack


class IceccsReviewerAuditPackTest(unittest.TestCase):
    def test_sv_sat_recovery_summary_splits_recovery_modes(self) -> None:
        targets = {
            "fw": [
                {"status": "vulnerable", "evidence_confidence": "medium"},
                {
                    "status": "vulnerable",
                    "analysis_recovery": "static_sink_template_fallback",
                    "evidence_confidence": "high",
                },
                {
                    "status": "vulnerable",
                    "analysis_recovery": "static_direct_source_fallback",
                    "evidence_confidence": "high",
                },
            ]
        }
        rows, details = pack.sv_sat_recovery_summary(targets)
        counts = {row["tier"]: row["records"] for row in rows}
        self.assertEqual(counts["direct observed sink-byte"], 1)
        self.assertEqual(counts["static sink-template fallback"], 1)
        self.assertEqual(counts["direct-source guarded fallback"], 1)
        self.assertEqual(len(details), 2)

    def test_nms_breakdown_preserves_no_benign_boundary(self) -> None:
        rows = pack.nms_breakdown(
            {
                "fw": [
                    {
                        "status": "no_taint_sink",
                        "residual_diagnosis_class": "static_overapprox_no_taint",
                        "evidence_confidence": "medium",
                    },
                    {
                        "status": "no_taint_sink",
                        "source_obligation_class": "mango_unbound_no_taint",
                        "evidence_confidence": "medium",
                    },
                    {
                        "status": "no_taint_sink",
                        "evidence_confidence": "low",
                    },
                ]
            }
        )
        total = sum(row["records"] for row in rows)
        self.assertEqual(total, 3)
        joined = " ".join(row["boundary"] for row in rows).lower()
        self.assertNotIn("benign", joined)
        self.assertIn("no modeled source", joined)

    def test_path_control_differences_require_signature_change(self) -> None:
        same = {
            "status": "vulnerable",
            "bypass_vector_categories": ["Command Chaining"],
            "blocked_vector_categories": [],
            "partially_filtered": False,
            "paper_claim_bucket": "positive",
        }
        changed = dict(same)
        changed["status"] = "unreachable"
        self.assertEqual(pack.vector_signature(same), pack.vector_signature(dict(same)))
        self.assertNotEqual(pack.vector_signature(same), pack.vector_signature(changed))


if __name__ == "__main__":
    unittest.main()
