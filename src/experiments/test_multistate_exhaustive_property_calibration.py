from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from experiments.run_multistate_exhaustive_property_calibration import main


class MultiStateExhaustivePropertyCalibrationTest(unittest.TestCase):
    def test_finite_oracle_calibration_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            import sys

            previous = list(sys.argv)
            try:
                sys.argv = ["calibration", "--out-dir", directory]
                self.assertEqual(main(), 0)
            finally:
                sys.argv = previous
            summary = json.loads(
                Path(directory, "summary.json").read_text(encoding="utf-8")
            )
            self.assertTrue(summary["all_checks_pass"])
            self.assertEqual(summary["sequence_cases"], 5602)
            self.assertEqual(summary["failed_case_count"], 0)

    def test_output_is_deterministic_for_same_seed(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            import sys

            previous = list(sys.argv)
            try:
                for directory in (first, second):
                    sys.argv = ["calibration", "--out-dir", directory]
                    self.assertEqual(main(), 0)
            finally:
                sys.argv = previous
            self.assertEqual(
                Path(first, "case_results.jsonl").read_bytes(),
                Path(second, "case_results.jsonl").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
