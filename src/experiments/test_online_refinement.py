#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tsds.online_refinement import OnlineRefinementController


class OnlineRefinementTest(unittest.TestCase):
    def test_controller_bounds_selection_and_writes_checkpoint(self) -> None:
        controller = OnlineRefinementController(max_rounds=1, max_candidates_per_round=2)
        record = {"status": "residual", "residual_diagnosis_class": "model_gap_reachability"}
        self.assertTrue(controller.should_attempt(record))
        selected = controller.select(
            [
                {"candidate_id": "medium", "confidence": "medium", "admission": {"admitted": True}},
                {"candidate_id": "high", "confidence": "high", "admission": {"admitted": True}},
                {"candidate_id": "rejected", "confidence": "high", "admission": {"admitted": False}},
            ]
        )
        self.assertEqual(["high", "medium"], [row["candidate_id"] for row in selected])
        controller.record(
            trigger="model_gap_reachability",
            candidates=selected,
            installed_ids=["high"],
            outcome="replay_residual",
        )
        self.assertFalse(controller.should_attempt(record))
        with tempfile.TemporaryDirectory() as directory:
            document = controller.write_checkpoint(Path(directory) / "checkpoint.json")
            self.assertTrue(document["checkpoint_sha256"])
            self.assertEqual(1, len(document["rounds"]))


if __name__ == "__main__":
    unittest.main()

