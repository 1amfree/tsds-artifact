"""Tests for the historical V20 source-reconciliation helpers."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from experiments.audit_historical_v20_source_reconciliation import (
    compare_release_file,
    fetch_entries,
    load_jsonl_count,
)


class HistoricalV20SourceReconciliationTests(unittest.TestCase):
    def test_fetch_entries_rejects_duplicate_paths(self) -> None:
        with self.assertRaises(ValueError):
            fetch_entries({"downloads": {"r": [{"path": "a", "sha256": "x"}, {"path": "a", "sha256": "y"}]}}, "r")

    def test_compare_release_file_checks_size_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.jsonl"
            path.write_text('{"x": 1}\n', encoding="utf-8")
            import hashlib

            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            check = compare_release_file(
                path,
                "campaign/sample.results.jsonl",
                {"campaign/sample.results.jsonl": {"sha256": digest, "size": path.stat().st_size}},
            )
            self.assertTrue(check["exists"])
            self.assertTrue(check["sha256_match"])
            self.assertTrue(check["size_match"])

    def test_jsonl_count_ignores_blank_lines_and_validates_objects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rows.jsonl"
            path.write_text('{"x": 1}\n\n{"x": 2}\n', encoding="utf-8")
            self.assertEqual(load_jsonl_count(path), 2)
            path.write_text('[1]\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_jsonl_count(path)


if __name__ == "__main__":
    unittest.main()
