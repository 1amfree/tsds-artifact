#!/usr/bin/env python3
"""Tests for deterministic TSDS SBOM generation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from generate_reproduction_sbom import build_documents, source_inventory


class ReproductionSbomTest(unittest.TestCase):
    def test_source_inventory_and_sbom_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src/a.py").write_text("print('a')\n", encoding="utf-8")
            (root / "src/b.md").write_text("b\n", encoding="utf-8")
            rows = source_inventory(root, [Path("src")])
            packages = [{"name": "Fixture", "version": "1.0"}]
            first = build_documents(rows, packages, source_date_epoch=0)
            second = build_documents(rows, packages, source_date_epoch=0)
            self.assertEqual(first, second)
            sbom, lock = first
            self.assertEqual("CycloneDX", sbom["bomFormat"])
            self.assertEqual(2, lock["source_files"])
            self.assertEqual(64, len(lock["source_aggregate_sha256"]))


if __name__ == "__main__":
    unittest.main()
