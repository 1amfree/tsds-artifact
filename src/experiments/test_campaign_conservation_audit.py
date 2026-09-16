import json
import tempfile
import unittest
from pathlib import Path

from audit_campaign_conservation import audit_campaign


def record(index, verdict):
    return {
        "closure_idx": index,
        "source_addr": hex(0x100 + index),
        "sink_addr": hex(0x200 + index),
        "verdict": verdict,
        "evidence_contract_valid": True,
        "analysis_version": "fixture-v1",
    }


class CampaignConservationAuditTest(unittest.TestCase):
    def _campaign(self, root: Path, rows):
        verdicts = {}
        for row in rows:
            verdicts[row["verdict"]] = verdicts.get(row["verdict"], 0) + 1
        summary = {
            "total_closures": len(rows),
            "unique_pairs_analyzed": len(rows),
            "evidence_contract_ledger": {
                "records": len(rows),
                "contract_valid": len(rows),
                "verdicts": verdicts,
            },
        }
        (root / "fixture.summary.json").write_text(
            json.dumps(summary), encoding="utf-8"
        )
        (root / "fixture.results.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        (root / "fixture.report.md").write_text("# fixture\n", encoding="utf-8")
        aggregate_total = {
            "closures": len(rows),
            "candidate_closures": len(rows),
            "selected_closures": len(rows),
            "evaluated": len(rows),
            "contract_valid": len(rows),
            "vector_sat": verdicts.get("VECTOR_SAT", 0),
            "matrix_unsat": verdicts.get("MATRIX_UNSAT", 0),
            "no_modeled_source": verdicts.get("NO_MODELED_SOURCE", 0),
            "static_source_inference": verdicts.get("STATIC_SOURCE_INFERENCE", 0),
            "static_warning_reduction": verdicts.get("STATIC_WARNING_REDUCTION", 0),
            "contract_residual": verdicts.get("RESIDUAL", 0),
        }
        (root / "full_campaign_aggregate.json").write_text(
            json.dumps({"total": aggregate_total}), encoding="utf-8"
        )

    def test_conserved_campaign_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._campaign(
                root,
                [record(1, "VECTOR_SAT"), record(2, "MATRIX_UNSAT")],
            )
            summary = audit_campaign(root, expected_targets=1)
            self.assertTrue(summary["valid"])
            self.assertEqual(summary["total"]["jsonl_records"], 2)

    def test_duplicate_and_summary_mismatch_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            duplicate = record(1, "VECTOR_SAT")
            self._campaign(root, [duplicate, dict(duplicate)])
            summary_path = root / "fixture.summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["evidence_contract_ledger"]["records"] = 1
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            audited = audit_campaign(root, expected_targets=1)
            self.assertFalse(audited["valid"])
        target_issues = audited["targets"][0]["issues"]
        self.assertIn("duplicate_record_identity", target_issues)
        self.assertIn("ledger_vs_unique_pairs_mismatch", target_issues)

    def test_explicit_candidate_and_selected_totals_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._campaign(
                root,
                [record(1, "VECTOR_SAT"), record(2, "MATRIX_UNSAT")],
            )
            aggregate_path = root / "full_campaign_aggregate.json"
            aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
            aggregate["total"]["selected_closures"] = 1
            aggregate_path.write_text(json.dumps(aggregate), encoding="utf-8")
            audited = audit_campaign(root, expected_targets=1)
            self.assertFalse(audited["valid"])
            self.assertIn("aggregate_selected_closures_mismatch", audited["issues"])

    def test_allowlisted_angr_syslog_info_is_auditable_but_nonfatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._campaign(root, [record(1, "VECTOR_SAT")])
            (root / "fixture.stderr.log").write_text(
                "INFO     | 2026-07-17 12:40:29,647 | "
                "angr.procedures.posix.syslog | Syslog priority <BV32 0x5>: "
                "b'SNTP SYN success ! Current timer is '\n",
                encoding="utf-8",
            )
            audited = audit_campaign(root, expected_targets=1)
            self.assertTrue(audited["valid"])
            stderr = audited["targets"][0]["stderr"]
            self.assertEqual(stderr["classification"], "benign_angr_posix_syslog_info")
            self.assertEqual(stderr["benign_structured_info_lines"], 1)
            self.assertEqual(stderr["unexpected_lines"], 0)
            self.assertRegex(stderr["sha256"], r"^[0-9a-f]{64}$")

    def test_unexpected_stderr_remains_a_hard_conservation_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._campaign(root, [record(1, "VECTOR_SAT")])
            (root / "fixture.stderr.log").write_text(
                "ERROR: unclassified evaluator output\n", encoding="utf-8"
            )
            audited = audit_campaign(root, expected_targets=1)
            self.assertFalse(audited["valid"])
            target = audited["targets"][0]
            self.assertIn("unexpected_stderr", target["issues"])
            self.assertEqual(target["stderr"]["classification"], "unexpected")
            self.assertEqual(target["stderr"]["unexpected_line_numbers"], [1])


if __name__ == "__main__":
    unittest.main()
