#!/usr/bin/env python3
"""Tests for target loader smoke report rendering."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_target_loader_smoke_report import markdown, qemu_for_row


class TargetLoaderSmokeReportTest(unittest.TestCase):
    def test_helpers_select_first_values(self) -> None:
        self.assertEqual(qemu_for_row({"qemu_available": "qemu-arm; qemu-mips", "qemu_required": "qemu-mips"}), "qemu-arm")

    def test_markdown_boundary(self) -> None:
        text = markdown(
            [
                {
                    "candidate_id": "poc-01",
                    "target": "Tenda AC15",
                    "qemu": "qemu-arm",
                    "binary_path": "/tmp/httpd",
                    "pass": True,
                }
            ]
        )
        self.assertIn("does not enter firmware main routines", text)
        self.assertIn("not a sink-intercept canary observation", text)


if __name__ == "__main__":
    unittest.main()
