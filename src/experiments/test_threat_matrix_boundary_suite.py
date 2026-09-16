#!/usr/bin/env python3
"""Tests for the executable TSDS threat-matrix boundary suite."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipIf(
    importlib.util.find_spec("claripy") is None or importlib.util.find_spec("angr") is None,
    "advanced evaluator dependencies are unavailable",
)
class ThreatMatrixBoundarySuiteTest(unittest.TestCase):
    def test_executable_matrix_suite_passes_all_cases(self) -> None:
        from experiments.run_threat_matrix_boundary_suite import run_suite

        rows, summary = run_suite()
        self.assertEqual(summary["vector_cases"], 11)
        self.assertEqual(summary["boundary_cases"], 4)
        self.assertEqual(summary["passed_cases"], summary["total_cases"])
        by_case = {row["case"]: row for row in rows}
        self.assertIn("single_quote_requires_modeled_breakout", by_case)
        self.assertIn(
            "modeled breakout",
            by_case["single_quote_requires_modeled_breakout"]["boundary"],
        )

    def test_cli_stage_does_not_depend_on_pythonpath(self) -> None:
        root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "boundary"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(root / "experiments" / "run_threat_matrix_boundary_suite.py"),
                    "--out-dir",
                    str(out),
                ],
                cwd=root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertTrue((out / "threat_matrix_executable_summary.json").is_file())


if __name__ == "__main__":
    unittest.main()
