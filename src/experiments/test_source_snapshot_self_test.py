#!/usr/bin/env python3

from __future__ import annotations

import os
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from experiments.run_source_snapshot_self_test import (
    parse_junit,
    run_self_test,
    source_tree_identity,
)


class SourceSnapshotSelfTest(unittest.TestCase):
    def test_tree_identity_is_ordered_and_content_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "b.txt").write_text("b\n", encoding="utf-8")
            (root / "a.txt").write_text("a\n", encoding="utf-8")
            first = source_tree_identity(root)
            second = source_tree_identity(root)
            self.assertEqual(first, second)
            (root / "a.txt").write_text("changed\n", encoding="utf-8")
            self.assertNotEqual(first["sha256"], source_tree_identity(root)["sha256"])

    def test_junit_counts_are_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "junit.xml"
            path.write_text(
                '<testsuites tests="12" failures="1" errors="2" skipped="3"/>',
                encoding="utf-8",
            )
            self.assertEqual(
                {"tests": 12, "failures": 1, "errors": 2, "skipped": 3},
                parse_junit(path),
            )

    def test_minimal_snapshot_executes_in_subprocess(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "pytest.ini").write_text(
                "[pytest]\ntestpaths = .\n", encoding="utf-8"
            )
            (source / "test_sample.py").write_text(
                "def test_sample():\n    assert 2 + 2 == 4\n", encoding="utf-8"
            )
            summary = run_self_test(
                source,
                root / "out",
                python=Path(sys.executable),
                timeout=30,
            )
            self.assertTrue(summary["valid"], summary)
            self.assertEqual(1, summary["counts"]["tests"])
            self.assertTrue(summary["source_identity_stable"])

    @unittest.skipUnless(os.name == "posix", "POSIX symlink semantics required")
    def test_virtualenv_launcher_symlink_is_not_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "pytest.ini").write_text(
                "[pytest]\ntestpaths = .\n", encoding="utf-8"
            )
            launcher = root / "venv" / "bin" / "python"
            launcher.parent.mkdir(parents=True)
            launcher.symlink_to(Path(sys.executable))

            def complete(command, **_kwargs):
                junit = Path(command[command.index("--junitxml") + 1])
                junit.write_text(
                    '<testsuites tests="1" failures="0" errors="0" skipped="0"/>',
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(command, 0, stdout=".", stderr="")

            with patch(
                "experiments.run_source_snapshot_self_test.subprocess.run",
                side_effect=complete,
            ):
                summary = run_self_test(
                    source,
                    root / "out",
                    python=launcher,
                    timeout=30,
                )

            self.assertTrue(summary["valid"], summary)
            self.assertEqual(str(launcher.absolute()), summary["command"][0])
            self.assertEqual(str(launcher.absolute()), summary["python"])
            argument_pairs = list(zip(summary["command"], summary["command"][1:]))
            self.assertIn(("-m", "not workspace_data"), argument_pairs)


if __name__ == "__main__":
    unittest.main()
