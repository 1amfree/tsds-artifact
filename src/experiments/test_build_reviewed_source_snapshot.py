#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
import subprocess
import sys
from pathlib import Path

from experiments.build_reviewed_source_snapshot import build_snapshot, validate_snapshot


class ReviewedSourceSnapshotTest(unittest.TestCase):
    def test_direct_cli_entrypoint_loads_project_package(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).with_name("build_reviewed_source_snapshot.py")),
                "--help",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("--source-root", result.stdout)

    def test_snapshot_is_content_bound_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            (source / "experiments").mkdir(parents=True)
            (source / "tool.py").write_text("print('tool')\n", encoding="utf-8")
            (source / "experiments" / "audit.py").write_text("AUDIT = True\n", encoding="utf-8")
            output = root / "snapshot"
            manifest = build_snapshot(
                source, output, ("tool.py", "experiments/audit.py")
            )
            self.assertTrue(manifest["valid"])
            self.assertEqual(2, manifest["source_files"])
            self.assertEqual(manifest, validate_snapshot(output))

    def test_mutation_and_extra_member_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "tool.py").write_text("one\n", encoding="utf-8")
            output = root / "snapshot"
            build_snapshot(source, output, ("tool.py",))
            (output / "tool.py").write_text("two\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                validate_snapshot(output)

            second = root / "snapshot2"
            build_snapshot(source, second, ("tool.py",))
            (second / "extra.txt").write_text("extra\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                validate_snapshot(second)

    def test_unsafe_duplicate_and_reused_outputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "tool.py").write_text("one\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                build_snapshot(source, root / "bad", ("../tool.py",))
            with self.assertRaises(ValueError):
                build_snapshot(source, root / "duplicate", ("tool.py", "tool.py"))
            output = root / "snapshot"
            build_snapshot(source, output, ("tool.py",))
            with self.assertRaises(ValueError):
                build_snapshot(source, output, ("tool.py",))


if __name__ == "__main__":
    unittest.main()
