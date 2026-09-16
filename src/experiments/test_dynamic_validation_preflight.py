#!/usr/bin/env python3
"""Unit tests for dynamic validation preflight helpers."""

from __future__ import annotations

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_dynamic_validation_preflight import (
    blocker_categories,
    global_rootfs_summary,
    readiness_level,
    required_qemu,
    resource_request,
)


class DynamicValidationPreflightTest(unittest.TestCase):
    def test_required_qemu_from_file_output(self) -> None:
        self.assertEqual(required_qemu("arm", "ELF 32-bit LSB executable, ARM"), ["qemu-arm"])
        self.assertEqual(
            required_qemu("mips", "ELF 32-bit LSB executable, MIPS, MIPS32 rel2"),
            ["qemu-mipsel"],
        )
        self.assertEqual(
            required_qemu("mips", "ELF 32-bit MSB executable, MIPS, MIPS32 rel2"),
            ["qemu-mips", "qemu-mipsel"],
        )

    def test_resource_request_is_specific(self) -> None:
        request = resource_request(
            [
                "required qemu-user emulator is missing",
                "target rootfs/interpreter is missing near the binary",
                "target libc/uClibc is missing near the binary",
            ],
            ["qemu-arm"],
            "Tenda AC18",
        )
        self.assertIn("qemu-user", request)
        self.assertIn("Tenda AC18 firmware rootfs", request)

    def test_readiness_level_distinguishes_rootfs_from_qemu(self) -> None:
        self.assertEqual(
            readiness_level(
                [
                    "target rootfs/interpreter is missing near the binary",
                    "target libc/uClibc is missing near the binary",
                ]
            ),
            "rootfs_blocked",
        )
        self.assertEqual(
            readiness_level(
                [
                    "required qemu-user emulator is missing",
                    "target rootfs/interpreter is missing near the binary",
                ]
            ),
            "emulation_resource_blocked",
        )
        self.assertIn(
            "rootfs",
            blocker_categories(["target rootfs/interpreter is missing near the binary"]),
        )

    def test_global_rootfs_summary_is_compact(self) -> None:
        summary = global_rootfs_summary(
            [
                {
                    "candidate": "/tmp/fw/squashfs-root",
                    "interp": ["/tmp/fw/squashfs-root/lib/ld-uClibc.so.0"],
                    "libc": ["/tmp/fw/squashfs-root/lib/libc.so.0"],
                }
            ]
        )
        self.assertIn("squashfs-root", summary)
        self.assertIn("ld-uClibc.so.0", summary)


if __name__ == "__main__":
    unittest.main()
