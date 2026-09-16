from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from experiments.build_v20_paper_evidence_index import build_index, write_outputs
from experiments.test_build_v20_paper_evidence_index import PaperEvidenceIndexTest
from experiments.verify_v20_paper_package import verify_package


class V20PaperPackageVerificationTest(unittest.TestCase):
    def package(self, root: Path) -> Path:
        release, audit_root, paired_root = PaperEvidenceIndexTest().fixture(root)
        index = build_index(release, audit_root, paired_root, "r5", "v2")
        package = root / "package"
        write_outputs(package, index)
        return package

    def test_complete_package_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = self.package(Path(directory))
            document = verify_package(package)
            self.assertTrue(document["valid"], document["issues"])
            self.assertEqual(2, document["records"])
            self.assertEqual(9, len(document["claims"]))

    def test_tampered_snapshot_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = self.package(Path(directory))
            (package / "paper_results_snapshot.json").write_text(
                '{"schema":"tampered"}', encoding="utf-8"
            )
            document = verify_package(package)
            self.assertFalse(document["valid"])
            self.assertTrue(
                any(
                    issue.startswith("sha256_mismatch:paper_results_snapshot.json")
                    for issue in document["issues"]
                )
            )

    def test_extra_package_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = self.package(Path(directory))
            (package / "extra.txt").write_text("extra", encoding="utf-8")
            document = verify_package(package)
            self.assertFalse(document["valid"])
            self.assertTrue(
                any(issue.startswith("package_file_set:") for issue in document["issues"])
            )


if __name__ == "__main__":
    unittest.main()
