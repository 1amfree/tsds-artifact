#!/usr/bin/env python3
"""Tests for QEMU/rootfs smoke report rendering."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_qemu_rootfs_smoke_report import markdown


class QemuRootfsSmokeReportTest(unittest.TestCase):
    def test_markdown_preserves_boundary(self) -> None:
        text = markdown(
            {
                "pass": True,
                "boundary": "QEMU/rootfs smoke only; no firmware service execution; no command sink execution",
                "qemu_arm": "/usr/bin/qemu-arm",
                "qemu_mipsel": "/usr/bin/qemu-mipsel",
                "busybox_file": "ELF 32-bit LSB executable, ARM",
                "rootfs_interp": "/rootfs/lib/ld-musl-armhf.so.1;",
                "rootfs_libc": "/rootfs/lib/libc.so;",
                "smoke": "TSDS_QEMU_SMOKE_OK",
            },
            "/rootfs",
        )
        self.assertIn("QEMU/rootfs smoke only", text)
        self.assertIn("does not run firmware services", text)
        self.assertIn("still require their own target rootfs/uClibc resources", text)


if __name__ == "__main__":
    unittest.main()
