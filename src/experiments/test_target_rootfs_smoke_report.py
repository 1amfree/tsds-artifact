#!/usr/bin/env python3
"""Tests for target-rootfs smoke report rendering."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_target_rootfs_smoke_report import markdown, qemu_for_row


class TargetRootfsSmokeReportTest(unittest.TestCase):
    def test_qemu_selection_prefers_available(self) -> None:
        self.assertEqual(qemu_for_row({"qemu_available": "qemu-arm", "qemu_required": "qemu-mipsel"}), "qemu-arm")
        self.assertEqual(qemu_for_row({"qemu_available": "none", "qemu_required": "qemu-mipsel"}), "qemu-mipsel")

    def test_markdown_boundary_is_not_sink_validation(self) -> None:
        text = markdown(
            [
                {
                    "candidate_id": "poc-01",
                    "target": "Tenda AC15",
                    "qemu": "qemu-arm",
                    "rootfs": "/tmp/rootfs",
                    "busybox": "/tmp/rootfs/bin/busybox",
                    "pass": True,
                }
            ]
        )
        self.assertIn("does not start firmware services", text)
        self.assertIn("not evidence that a firmware service or command sink has been reached", text)


if __name__ == "__main__":
    unittest.main()
