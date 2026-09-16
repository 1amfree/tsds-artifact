import json
import tempfile
import unittest
from pathlib import Path

from experiments.audit_targeted_multistate_recovery_matrix import build_matrix_audit


def _write_case(directory: Path, *, snapshot_digest: str, preview: str, profiles: int, status: str = "residual") -> None:
    directory.mkdir(parents=True, exist_ok=True)
    audit = {
        "collection_complete": False,
        "collection_scope": "bounded_sink_instances_for_selected_closure",
        "engine_run_count": profiles,
        "aggregate": {
            "candidate_wide_negative": False,
            "aggregate_class": "bounded_incomplete" if status == "residual" else "exists_positive",
            "decision_counts": {},
        },
        "profiles": [{"status": status} for _ in range(profiles)],
    }
    row = {
        "closure_idx": 4,
        "source_addr": "0x100",
        "sink_addr": "0x200",
        "sink_snapshot_command_digest": "command-digest",
        "sink_snapshot_digest": snapshot_digest,
        "sink_preview": preview,
        "status": status,
        "verdict": "RESIDUAL" if status == "residual" else "VECTOR_SAT",
        "evidence_provenance": "RESIDUAL" if status == "residual" else "DIRECT_SINK_BYTE",
        "residual_diagnosis_class": "bounded_incomplete" if status == "residual" else None,
        "multi_state_audit": audit,
    }
    (directory / "results.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    (directory / "summary.json").write_text(json.dumps({"results": {}}), encoding="utf-8")
    (directory / "stderr.log").write_text("", encoding="utf-8")


class TargetedRecoveryMatrixAuditTest(unittest.TestCase):
    def test_snapshot_difference_is_visible_but_not_identity_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            baseline = root / "baseline"
            less_pruned = root / "less_pruned"
            _write_case(baseline, snapshot_digest="snap-a", preview="command-A", profiles=2)
            _write_case(less_pruned, snapshot_digest="snap-b", preview="command-B", profiles=4)
            result = build_matrix_audit([("case", baseline, less_pruned)])
            self.assertTrue(result["valid"])
            self.assertTrue(result["aggregate"]["core_callsite_command_identity_equal_all"])
            self.assertEqual(result["aggregate"]["snapshot_digest_changed_pair_count"], 1)
            self.assertEqual(result["aggregate"]["profile_count_delta_sum"], 2)

    def test_changed_primary_outcome_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            baseline = root / "baseline"
            less_pruned = root / "less_pruned"
            _write_case(baseline, snapshot_digest="snap", preview="command", profiles=2, status="residual")
            _write_case(less_pruned, snapshot_digest="snap", preview="command", profiles=2, status="vulnerable")
            result = build_matrix_audit([("case", baseline, less_pruned)])
            self.assertFalse(result["valid"])
            self.assertIn("primary_outcome_changed", result["issues"])


if __name__ == "__main__":
    unittest.main()
