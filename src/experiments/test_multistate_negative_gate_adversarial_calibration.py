from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from experiments.run_multistate_negative_gate_adversarial_calibration import main


class NegativeGateAdversarialCalibrationTest(unittest.TestCase):
    def test_admission_gate_rejects_tampered_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(main(["--out-dir", directory]), 0)
            summary = json.loads(
                Path(directory, "summary.json").read_text(encoding="utf-8")
            )
            self.assertTrue(summary["all_checks_pass"])
            self.assertEqual(summary["case_count"], 39)
            self.assertEqual(summary["valid_admission_cases"], 6)
            self.assertEqual(summary["rejection_cases"], 33)
            self.assertEqual(summary["failed_case_count"], 0)

    def test_output_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            self.assertEqual(main(["--out-dir", first]), 0)
            self.assertEqual(main(["--out-dir", second]), 0)
            self.assertEqual(
                Path(first, "case_results.jsonl").read_bytes(),
                Path(second, "case_results.jsonl").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
