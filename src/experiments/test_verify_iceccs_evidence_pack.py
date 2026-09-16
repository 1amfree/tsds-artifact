#!/usr/bin/env python3
"""Tests for the evidence-pack integrity verifier."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from verify_iceccs_evidence_pack import verify


class EvidencePackVerifierTest(unittest.TestCase):
    def _write_fixture(self, expected_hash: str | None = None) -> tuple[Path, Path]:
        root = Path(tempfile.mkdtemp(prefix="tsds-evidence-verifier-"))
        artifact = root / "artifact.txt"
        artifact.write_text("immutable evidence\n", encoding="utf-8")
        digest = expected_hash or hashlib.sha256(artifact.read_bytes()).hexdigest()
        manifest = root / "manifest.json"
        manifest.write_text(
            json.dumps({"artifacts": [{"name": "fixture", "path": "artifact.txt", "sha256": digest}]}),
            encoding="utf-8",
        )
        return manifest, root

    def test_matching_hash_passes(self) -> None:
        manifest, _ = self._write_fixture()
        result = verify(manifest)
        self.assertTrue(result["pass"])
        self.assertEqual(0, result["failed_count"])

    def test_hash_mismatch_fails_closed(self) -> None:
        manifest, _ = self._write_fixture("0" * 64)
        result = verify(manifest)
        self.assertFalse(result["pass"])
        self.assertEqual("sha256_mismatch", result["failures"][0]["reason"])

    def test_missing_artifact_fails_closed(self) -> None:
        manifest, root = self._write_fixture()
        (root / "artifact.txt").unlink()
        result = verify(manifest)
        self.assertFalse(result["pass"])
        self.assertEqual("missing", result["failures"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
