#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from experiments.satc_source_snapshot import SCHEMA, build_snapshot, validate_snapshot


class SaTCSourceSnapshotTest(unittest.TestCase):
    def make_tree(self, root: Path) -> Path:
        satc = root / "SaTC"
        (satc / "src" / "front_analysise").mkdir(parents=True)
        (satc / "src" / "jsparse" / "app").mkdir(parents=True)
        (satc / "src" / "satc.py").write_text("entry\n", encoding="utf-8")
        (satc / "src" / "front_analysise" / "module.py").write_text("front\n", encoding="utf-8")
        (satc / "src" / "requirements.txt").write_text("six==1.16.0\n", encoding="utf-8")
        (satc / "src" / "front_analysise" / "requirements.txt").write_text(
            "lxml==4.9.4\n", encoding="utf-8"
        )
        (satc / "src" / "jsparse" / "package.json").write_text("{}\n", encoding="utf-8")
        (satc / "src" / "jsparse" / "app" / "index.js").write_text("app\n", encoding="utf-8")
        (satc / "README.md").write_text("readme\n", encoding="utf-8")
        (satc / "src" / "__pycache__").mkdir()
        (satc / "src" / "__pycache__" / "ignored.pyc").write_bytes(b"ignored")
        return satc

    def test_snapshot_binds_source_and_excludes_generated_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            satc = self.make_tree(Path(directory))
            snapshot = build_snapshot(satc)
            self.assertEqual(SCHEMA, snapshot["schema"])
            self.assertEqual(7, snapshot["source_files"])
            names = {row["path"] for row in snapshot["files"]}
            self.assertIn("src/requirements.txt", names)
            self.assertIn("src/front_analysise/requirements.txt", names)
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(snapshot), encoding="utf-8")
            self.assertEqual(snapshot, validate_snapshot(path, satc))

    def test_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            satc = self.make_tree(Path(directory))
            snapshot = build_snapshot(satc)
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(snapshot), encoding="utf-8")
            (satc / "src" / "satc.py").write_text("changed\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                validate_snapshot(path, satc)

    def test_incomplete_snapshot_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            satc = self.make_tree(Path(directory))
            snapshot = build_snapshot(satc)
            snapshot["files"] = snapshot["files"][:-1]
            from experiments.satc_source_snapshot import canonical_digest
            snapshot["source_files"] = len(snapshot["files"])
            snapshot["aggregate_sha256"] = canonical_digest(snapshot["files"])
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(snapshot), encoding="utf-8")
            with self.assertRaises(ValueError):
                validate_snapshot(path, satc)


if __name__ == "__main__":
    unittest.main()
