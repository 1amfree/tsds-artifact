from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from experiments.verify_satc_keyword_workload import verify_workload


class SaTCKeywordWorkloadIdentityTest(unittest.TestCase):
    def test_identical_workloads_have_content_bound_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate.txt"
            reference = root / "reference.txt"
            candidate.write_text("alpha\nbeta\n", encoding="utf-8")
            reference.write_text("alpha\nbeta\n", encoding="utf-8")
            document = verify_workload(candidate, reference)
            self.assertTrue(document["identical"])
            self.assertEqual(document["candidate"]["sha256"], document["reference"]["sha256"])

    def test_different_workloads_are_not_identical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate.txt"
            reference = root / "reference.txt"
            candidate.write_text("alpha\n", encoding="utf-8")
            reference.write_text("beta\n", encoding="utf-8")
            self.assertFalse(verify_workload(candidate, reference)["identical"])


if __name__ == "__main__":
    unittest.main()
