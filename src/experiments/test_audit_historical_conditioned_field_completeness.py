#!/usr/bin/env python3
"""Tests for the historical conditioned field-completeness audit."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from audit_historical_conditioned_field_completeness import audit


def record(**overrides):
    value = {
        "closure_idx": 1,
        "status": "vulnerable",
        "verdict": "VECTOR_SAT",
        "evidence_provenance": "SINK_RECONCILED",
        "analysis_recovery": "static_dynamic_taint_reconciliation",
        "recovery_path_constraint_count": 3,
        "recovered_sink_template": "cmd <recovered>",
        "recovered_source_prefix": "value",
        "trace_nodes": [{"function": "source", "ins_addr": "0x10"}],
        "sink_snapshot_cstring_complete": True,
        "sink_snapshot_terminator_offset": 4,
        "sink_snapshot_capture_length": 5,
        "controlled_offsets": [1, 2, 3, 4],
    }
    value.update(overrides)
    return value


class HistoricalConditionedFieldCompletenessTest(unittest.TestCase):
    def test_missing_link_is_recorded_without_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Path(tmp)
            (campaign / "campaign_configuration.json").write_text("{}\n", encoding="utf-8")
            (campaign / "target.results.jsonl").write_text(
                json.dumps(record()) + "\n", encoding="utf-8"
            )
            rows, summary = audit(campaign)
            self.assertEqual(len(rows), 1)
            self.assertEqual(summary["serialized_link_records"], 0)
            self.assertEqual(summary["admitted_link_records"], 0)
            self.assertIn("serialized_reconciliation_link_absent", rows[0]["issues"])
            self.assertEqual(summary["records_with_source_to_sink_mapping"], 0)

    def test_inconsistent_snapshot_fails_boundary_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Path(tmp)
            (campaign / "campaign_configuration.json").write_text("{}\n", encoding="utf-8")
            (campaign / "target.results.jsonl").write_text(
                json.dumps(record(sink_snapshot_capture_length=7)) + "\n",
                encoding="utf-8",
            )
            rows, summary = audit(campaign)
            self.assertFalse(summary["all_checks_pass"])
            self.assertFalse(rows[0]["sink_snapshot_boundary_consistent"])


if __name__ == "__main__":
    unittest.main()
