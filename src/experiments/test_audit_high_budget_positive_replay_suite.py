from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from experiments.audit_high_budget_positive_replay_suite import audit_suite


def _row(*, collection_complete: bool = True) -> dict:
    return {
        "closure_idx": 2,
        "source_addr": "0x10",
        "sink_addr": "0x20",
        "sink_function": "system",
        "status": "vulnerable",
        "verdict": "VECTOR_SAT",
        "evidence_provenance": "DIRECT_SINK_BYTE",
        "sink_snapshot_digest": "digest",
        "multi_state_audit": {
            "collection_complete": collection_complete,
            "collection_scope": "bounded_sink_instances_for_selected_closure",
            "profiles": [{"status": "VECTOR_SAT"}],
            "aggregate": {
                "aggregate_class": "exists_positive",
                "candidate_wide_negative": False,
                "quantifier": "exists_over_collected_instances",
            },
        },
    }


class HighBudgetReplayAuditTests(unittest.TestCase):
    def test_identity_bound_positive_replay_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = root / "baseline"
            suite = root / "suite"
            baseline.mkdir()
            case = suite / "asus_rt_be57_idx2"
            case.mkdir(parents=True)
            (baseline / "asus_rt_be57.results.jsonl").write_text(
                json.dumps(_row()) + "\n", encoding="utf-8"
            )
            (case / "results.jsonl").write_text(json.dumps(_row()) + "\n", encoding="utf-8")
            (case / "returncode").write_text("0\n", encoding="utf-8")
            report = audit_suite(root, baseline, suite)
            self.assertTrue(report["all_checks_pass"])
            self.assertEqual(report["replay_case_count"], 1)
            self.assertEqual(report["direct_provenance_count"], 1)

    def test_incomplete_positive_replay_is_admitted_with_explicit_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = root / "baseline"
            suite = root / "suite"
            baseline.mkdir()
            case = suite / "asus_rt_be57_idx2"
            case.mkdir(parents=True)
            (baseline / "asus_rt_be57.results.jsonl").write_text(
                json.dumps(_row()) + "\n", encoding="utf-8"
            )
            (case / "results.jsonl").write_text(
                json.dumps(_row(collection_complete=False)) + "\n", encoding="utf-8"
            )
            (case / "returncode").write_text("0\n", encoding="utf-8")
            report = audit_suite(root, baseline, suite)
            self.assertTrue(report["all_checks_pass"])
            self.assertEqual(report["complete_collection_count"], 0)
            self.assertEqual(report["incomplete_collection_count"], 1)
            self.assertEqual(report["warnings"][0]["warning"], "bounded_collection_not_complete")

    def test_missing_replay_is_not_silently_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = root / "baseline"
            suite = root / "suite"
            baseline.mkdir()
            suite.mkdir()
            (baseline / "asus_rt_be57.results.jsonl").write_text(
                json.dumps(_row()) + "\n", encoding="utf-8"
            )
            report = audit_suite(root, baseline, suite)
            self.assertFalse(report["all_checks_pass"])
            self.assertTrue(any(item["issue"] == "positive_row_not_replayed" for item in report["issues"]))
