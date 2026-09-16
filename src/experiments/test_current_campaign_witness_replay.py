from __future__ import annotations

import unittest

from experiments.run_current_campaign_witness_replay import (
    current_safety_gate,
    extract_entries,
)


class CurrentCampaignWitnessReplayTests(unittest.TestCase):
    def test_allowlist_is_narrow_and_inert(self) -> None:
        self.assertTrue(current_safety_gate(":;:;#AAAAAAAA ")[0])
        self.assertTrue(current_safety_gate("$(:)AAAAAAAA ")[0])
        self.assertFalse(current_safety_gate("$(cat /etc/passwd)")[0])
        self.assertFalse(current_safety_gate(">/tmp/tsds-danger")[0])

    def test_extracts_only_direct_grammar_complete_vectors(self) -> None:
        row = {
            "_target": "fixture",
            "_source_path": "fixture.results.jsonl",
            "closure_idx": 1,
            "source_addr": "0x10",
            "sink_addr": "0x20",
            "sink_snapshot_digest": "digest",
            "verdict": "VECTOR_SAT",
            "evidence_provenance": "DIRECT_SINK_BYTE",
            "controlled_offsets": [0, 1, 2, 3, 4],
            "vector_decisions": [
                {
                    "decision": "VECTOR_SAT",
                    "grammar_complete": True,
                    "vector_id": "semicolon",
                    "witness": ":;:;#AAAA",
                    "controlled_witness_offsets": [0, 1, 2],
                },
                {
                    "decision": "VECTOR_SAT",
                    "grammar_complete": False,
                    "vector_id": "pipe",
                    "witness": ":|:;#AAAA",
                },
            ],
        }
        entries = extract_entries([row])
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["vector_id"], "semicolon")
        self.assertTrue(entries[0]["controlled_witness_offsets_subset"])

