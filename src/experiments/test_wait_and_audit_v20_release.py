from __future__ import annotations

import tempfile
import unittest
import json
from pathlib import Path

from experiments.wait_and_audit_v20_release import wait_for_fetch


class WaitForFetchTest(unittest.TestCase):
    def test_existing_manifest_returns_immediately(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "fetch_manifest.json"
            manifest.write_text("{}", encoding="utf-8")
            self.assertEqual(manifest, wait_for_fetch(root, 0, 1))

    def test_missing_manifest_times_out(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(TimeoutError):
                wait_for_fetch(Path(directory), 0, 1)

    def test_failed_fetch_status_stops_the_audit_waiter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status = root / "fetch.status.json"
            status.write_text(
                json.dumps({"state": "failed", "detail": "remote queue stopped"}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "remote queue stopped"):
                wait_for_fetch(root, 30, 1, status)


if __name__ == "__main__":
    unittest.main()
