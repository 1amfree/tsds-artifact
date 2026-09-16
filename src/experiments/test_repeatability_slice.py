#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from experiments.build_repeatability_slice import build_slice


class RepeatabilitySliceTest(unittest.TestCase):
    def test_slice_is_deterministic_and_records_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign = root / "campaign"
            campaign.mkdir()
            rows = [
                {"closure_idx": 2, "source_addr": "0x2", "sink_addr": "0x9"},
                {"closure_idx": 1, "source_addr": "0x1", "sink_addr": "0x8"},
            ]
            (campaign / "target.results.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )
            summary = build_slice(
                campaign,
                root / "slice",
                targets={"target"},
                max_records_per_target=1,
            )
            self.assertEqual(1, summary["records"])
            self.assertEqual(2, summary["selected_records"][0]["closure_idx"])
            self.assertEqual(
                summary["output_ledgers"][0]["sha256"],
                __import__("hashlib").sha256(
                    (root / "slice" / "target.results.jsonl").read_bytes()
                ).hexdigest(),
            )

    def test_empty_selection_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign = root / "campaign"
            campaign.mkdir()
            (campaign / "target.results.jsonl").write_text("{}\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                build_slice(campaign, root / "slice", targets={"missing"})


if __name__ == "__main__":
    unittest.main()
