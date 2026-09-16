#!/usr/bin/env python3
"""Tests for the isolated-worker resource calibration driver."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from experiments.run_resource_limit_calibration import (
    CALIBRATION_SCHEMA,
    DETERMINISTIC_CALIBRATION_ENVIRONMENT,
    accepted_case,
    build_calibration_command,
    parse_result_marker,
)


class ResourceLimitCalibrationTest(unittest.TestCase):
    def test_v2_identity_and_environment_are_explicit(self) -> None:
        self.assertEqual("tsds-resource-limit-calibration-v2", CALIBRATION_SCHEMA)
        self.assertEqual("0", DETERMINISTIC_CALIBRATION_ENVIRONMENT["PYTHONHASHSEED"])

    def test_command_preserves_venv_path_and_budget(self) -> None:
        command = build_calibration_command(
            Path("/venv/python"), Path("/workspace/evaluator.py"),
            Path("/firmware/httpd"), Path("/results/closures.json"), 35, 8192,
        )
        self.assertEqual(str(Path("/venv/python")), command[0])
        self.assertIn("--subprocess-memory-limit-mib", command)
        self.assertIn("8192", command)
        self.assertIn("--no-evidence-cache", command)

    def test_last_result_marker_is_used(self) -> None:
        output = "RESULT_JSON: {}\nnoise\nRESULT_JSON: " + json.dumps({"status": "residual"})
        self.assertEqual("residual", parse_result_marker(output)["status"])

    def test_acceptance_requires_complete_resource_row(self) -> None:
        row = {
            "returncode": 0,
            "marker_present": True,
            "result": {
                "subprocess_memory_limit_mib": 8192,
                "resource_limit_enforcement": "enforced",
                "resource_limit_hit": False,
                "process_peak_rss_mib": 128.0,
            },
        }
        self.assertTrue(accepted_case(row, 8192))
        row["result"]["process_peak_rss_mib"] = None
        self.assertFalse(accepted_case(row, 8192))


if __name__ == "__main__":
    unittest.main()
