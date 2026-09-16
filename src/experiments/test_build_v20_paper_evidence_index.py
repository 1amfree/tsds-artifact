from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from experiments.audit_v20_downloaded_release import audit_release, write_outputs as write_audit
from experiments.build_v20_paper_evidence_index import build_index, write_outputs
from experiments.test_audit_v20_downloaded_release import DownloadedReleaseAuditTest


class PaperEvidenceIndexTest(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, Path]:
        release = root / "release"
        release.mkdir()
        DownloadedReleaseAuditTest().fixture(release)
        audit = audit_release(release, "r5", "v2")
        self.assertTrue(audit["valid"], audit["issues"])
        audit_root = root / "audit"
        write_audit(audit_root, audit)
        paired_root = root / "paired"
        paired_root.mkdir()

        def identity(path: Path) -> dict:
            return {
                "path": path.relative_to(release).as_posix(),
                "size": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }

        matrix_analysis = (
            release / "tsds_v20_matrix_analysis_r5" / "v19_ablation_analysis.json"
        )
        matrix_summary = (
            release
            / "tsds_v20_matrix_transitions_r5"
            / "record_level_ablation_summary.json"
        )
        matrix_csv = matrix_summary.parent / "record_level_ablation_transitions.csv"
        confirm_analysis = (
            release
            / "tsds_v20_confirmatory_analysis_r5"
            / "v19_ablation_analysis.json"
        )
        confirm_summary = (
            release
            / "tsds_v20_confirmatory_transitions_r5"
            / "record_level_ablation_summary.json"
        )
        confirm_csv = confirm_summary.parent / "record_level_ablation_transitions.csv"
        write_json = lambda path, value: path.write_text(json.dumps(value), encoding="utf-8")
        write_json(
            paired_root / "paired_experiment_audit.json",
            {
                "schema": "tsds-v20-paired-experiment-audit-v1",
                "tag": "r5",
                "valid": True,
                "issues": [],
                "accepted_records": 2,
                "inputs": {
                    "bounded_matrix": {
                        "analysis": identity(matrix_analysis),
                        "transition_summary": identity(matrix_summary),
                        "transition_csv": identity(matrix_csv),
                    },
                    "full_corpus_confirmation": {
                        "analysis": identity(confirm_analysis),
                        "transition_summary": identity(confirm_summary),
                        "transition_csv": identity(confirm_csv),
                    },
                },
                "datasets": [
                    {
                        "dataset": "bounded_matrix",
                        "valid": True,
                        "issues": [],
                        "configurations": [
                            {"configuration": "full", "common_records": 1}
                        ],
                    },
                    {
                        "dataset": "full_corpus_confirmation",
                        "valid": True,
                        "issues": [],
                        "configurations": [
                            {"configuration": "p0_all_off", "common_records": 2}
                        ],
                    },
                ],
            },
        )
        (paired_root / "paired_cohort_audit.csv").write_text(
            "dataset,configuration\nfixture,full\n", encoding="utf-8"
        )
        (paired_root / "firmware_clustered_effects.csv").write_text(
            "dataset,metric\nfixture,elapsed_sec\n", encoding="utf-8"
        )
        (paired_root / "README.md").write_text("# Fixture\n", encoding="utf-8")
        return release, audit_root, paired_root

    def test_valid_release_builds_frozen_index(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release, audit_root, paired_root = self.fixture(root)
            index = build_index(release, audit_root, paired_root, "r5", "v2")
            self.assertTrue(index["frozen"])
            self.assertTrue(index["ready_for_full_paper_writing"])
            self.assertEqual(2, index["headline"]["records"])
            self.assertEqual(9, len(index["claims"]))
            self.assertTrue(all(index["evidence_groups"].values()))
            out = root / "paper"
            write_outputs(out, index)
            self.assertTrue((out / "paper_evidence_index.json").is_file())
            self.assertTrue((out / "PAPER_EVIDENCE_INDEX.md").is_file())
            self.assertTrue((out / "paper_evidence_checksums.csv").is_file())
            self.assertTrue((out / "claim_to_evidence.csv").is_file())
            self.assertTrue((out / "FREEZE_STATEMENT.md").is_file())
            self.assertTrue((out / "paper_results_snapshot.json").is_file())
            self.assertTrue((out / "paper_results_macros.tex").is_file())
            self.assertTrue((out / "paper_output_manifest.json").is_file())
            public_index = json.loads(
                (out / "paper_evidence_index.json").read_text(encoding="utf-8")
            )
            self.assertNotIn("_generated_documents", public_index)
            manifest = json.loads(
                (out / "paper_output_manifest.json").read_text(encoding="utf-8")
            )
            self.assertTrue(manifest["ready"])
            self.assertEqual(7, len(manifest["files"]))

    def test_tampering_after_audit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release, audit_root, paired_root = self.fixture(root)
            (release / "tsds_v20_full_r5" / "placeholder.txt").write_text(
                "changed", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "no longer passes"):
                build_index(release, audit_root, paired_root, "r5", "v2")

    def test_invalid_recorded_audit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release, audit_root, paired_root = self.fixture(root)
            path = audit_root / "downloaded_release_audit.json"
            audit = json.loads(path.read_text(encoding="utf-8"))
            audit["valid"] = False
            audit["issues"] = ["fixture"]
            path.write_text(json.dumps(audit), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not valid"):
                build_index(release, audit_root, paired_root, "r5", "v2")

    def test_nonempty_output_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release, audit_root, paired_root = self.fixture(root)
            index = build_index(release, audit_root, paired_root, "r5", "v2")
            out = root / "paper"
            out.mkdir()
            (out / "existing.txt").write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non-empty"):
                write_outputs(out, index)


if __name__ == "__main__":
    unittest.main()
