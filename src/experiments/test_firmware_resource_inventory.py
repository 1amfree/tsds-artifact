#!/usr/bin/env python3
"""Unit checks for corpus firmware resource inventory helpers."""

from __future__ import annotations

import importlib.util
from pathlib import Path


MODULE = Path(__file__).with_name("build_firmware_resource_inventory.py")
spec = importlib.util.spec_from_file_location("build_firmware_resource_inventory", MODULE)
assert spec is not None and spec.loader is not None
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def test_aliases_cover_router_names() -> None:
    assert "rtbe57" in inventory.target_aliases("asus_rt_be57", "ASUS_RT-BE57/httpd")
    assert "r6400v2" in inventory.target_aliases("r6400v2", "R6400v2/httpd")
    assert "tendaac18" in inventory.target_aliases("tenda_ac18", "Tenda_AC18/httpd")
    assert "300" not in inventory.target_aliases("xr300", "XR300/httpd")
    assert "tenda" not in inventory.target_aliases("tenda_ac15", "Tenda_AC15/httpd")


def test_qemu_arch_detection() -> None:
    assert inventory.qemu_for_file("ELF 32-bit LSB executable, MIPS") == "qemu-mipsel"
    assert inventory.qemu_for_file("ELF 32-bit MSB executable, MIPS") == "qemu-mips"
    assert inventory.qemu_for_file("ELF 32-bit LSB executable, ARM") == "qemu-arm"
    assert inventory.qemu_for_file("ASCII text") == ""


def test_best_candidate_prefers_exact_match() -> None:
    rows = [
        {
            "path": "/fw/a/squashfs-root",
            "interp": "/fw/a/lib/ld-uClibc.so.0",
            "libc": "/fw/a/lib/libc.so.0",
            "busybox": "/fw/a/bin/busybox",
            "rootfs_binary": "/fw/a/bin/httpd",
            "rootfs_md5": "old",
        },
        {
            "path": "/fw/b/squashfs-root",
            "interp": "/fw/b/lib/ld-uClibc.so.0",
            "libc": "/fw/b/lib/libc.so.0",
            "busybox": "/fw/b/bin/busybox",
            "rootfs_binary": "/fw/b/bin/httpd",
            "rootfs_md5": "exact",
        },
    ]
    best = inventory.select_best_candidate(rows, "exact", "/fw/a")
    assert best is rows[1]


def test_matching_candidates_uses_aliases() -> None:
    candidates = [
        {"path": "/home/ubuntu/work/sanitizer/_RT-BE57_3.0.trx.extracted/squashfs-root"},
        {"path": "/home/ubuntu/work/sanitizer/Tenda_AC18/extracted_rootfs/squashfs-root"},
    ]
    matched = inventory.matching_candidates(
        candidates,
        "asus_rt_be57",
        "ASUS_RT-BE57/httpd",
        "/home/ubuntu/work/sanitizer/ASUS_RT-BE57",
    )
    assert len(matched) == 1
    assert "RT-BE57" in matched[0]["path"]


def main() -> None:
    tests = [
        test_aliases_cover_router_names,
        test_qemu_arch_detection,
        test_best_candidate_prefers_exact_match,
        test_matching_candidates_uses_aliases,
    ]
    for test in tests:
        test()
    print(f"PASS {len(tests)} firmware resource inventory tests")


if __name__ == "__main__":
    main()
