#!/usr/bin/env python3
"""Tests for the v18/v7 accepted-run evidence extension."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from experiments.run_tsds_v18_evidence_extension import (
    build_stage_commands,
    preserve_python_executable,
    run_stage,
)


class V18EvidenceExtensionTest(unittest.TestCase):
    def test_python_path_preserves_virtual_environment_component(self) -> None:
        value = preserve_python_executable(Path("relative/.venv/bin/python"))
        self.assertTrue(value.is_absolute())
        self.assertIn(".venv", value.parts)

    def test_stage_graph_contains_all_p0_p1_p2_gates(self) -> None:
        facts = {
            "campaign": Path("/accepted/campaign"),
            "manifest": Path("/accepted/pipeline_manifest.json"),
            "repeatability": Path("/accepted/repeatability_records.csv"),
            "repeatability_summary": Path("/accepted/repeatability_summary.json"),
            "records": 518,
            "residuals": 223,
        }
        stages = build_stage_commands(
            Path("/venv/python"),
            Path("/snapshot"),
            Path("/accepted"),
            Path("/extension"),
            facts,
            seed=1,
            calibration_limit=16,
            audit_per_stratum=8,
        )
        names = [name for name, _, _ in stages]
        self.assertEqual(12, len(names))
        self.assertIn("03_independent_certificate_verifier", names)
        self.assertIn("04_residual_root_causes", names)
        self.assertIn("07_external_calibration_pack", names)
        self.assertIn("08_blinded_ground_truth_sample", names)
        self.assertIn("10_candidate_contract", names)
        self.assertIn("11_reproduction_sbom", names)
        self.assertIn("12_paper_tables", names)

    def test_stage_execution_does_not_mutate_snapshot_with_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "module_under_test.py").write_text("VALUE = 7\n", encoding="utf-8")
            runner = root / "runner.py"
            runner.write_text(
                "import module_under_test\nassert module_under_test.VALUE == 7\n",
                encoding="utf-8",
            )
            logs = root / "logs"
            logs.mkdir()
            result = run_stage(
                "bytecode_probe", [sys.executable, str(runner)], 30, root, logs
            )
            self.assertEqual(0, result["returncode"])
            self.assertEqual("1", result["environment"]["PYTHONDONTWRITEBYTECODE"])
            self.assertFalse((root / "__pycache__").exists())


if __name__ == "__main__":
    unittest.main()
