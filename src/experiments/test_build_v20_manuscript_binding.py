from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from experiments.build_v20_manuscript_binding import build_binding, write_outputs


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


class ManuscriptBindingTest(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path]:
        accepted = root / "accepted"
        manifest = accepted / "pipeline_manifest.json"
        paper = accepted / "paper_tables" / "paper_data_summary.json"
        write_json(manifest, {"schema": "tsds-v18-pipeline-v7", "success": True})
        write_json(
            paper,
            {
                "all_contract_valid": True,
                "records": 10,
                "verdicts": {
                    "VECTOR_SAT": 2,
                    "MATRIX_UNSAT": 1,
                    "NO_MODELED_SOURCE": 2,
                    "STATIC_SOURCE_INFERENCE": 1,
                    "STATIC_WARNING_REDUCTION": 2,
                    "RESIDUAL": 2,
                },
            },
        )
        claim_matrix = root / "claim_evidence_matrix.json"
        write_json(
            claim_matrix,
            {
                "schema": "tsds-v20-claim-evidence-matrix-v1",
                "ready_for_full_paper_writing": True,
                "claims": [{"claim_id": "C1", "status": "supported"}],
                "input_summary": {"accepted_records": 10},
                "evidence": {
                    "accepted_manifest": {"sha256": sha256(manifest)},
                    "paper_tables": {"sha256": sha256(paper)},
                },
            },
        )
        return claim_matrix, accepted

    def test_binds_ready_release_and_emits_latex_macros(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            claim_matrix, accepted = self.fixture(root)
            binding = build_binding(claim_matrix, accepted)
            self.assertTrue(binding["ready"])
            self.assertEqual(10, binding["records"])
            self.assertEqual(2, binding["verdicts"]["VECTOR_SAT"])
            write_outputs(root / "out", binding)
            macros = (root / "out" / "manuscript_counts.tex").read_text(encoding="utf-8")
            self.assertIn(r"\newcommand{\TSDSRecords}{10}", macros)
            self.assertIn(r"\newcommand{\TSDSVectorSatRecords}{2}", macros)

    def test_refuses_claim_matrix_with_pending_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            claim_matrix, accepted = self.fixture(root)
            value = json.loads(claim_matrix.read_text(encoding="utf-8"))
            value["claims"][0]["status"] = "pending"
            write_json(claim_matrix, value)
            with self.assertRaisesRegex(ValueError, "unsupported claims"):
                build_binding(claim_matrix, accepted)

    def test_refuses_paper_data_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            claim_matrix, accepted = self.fixture(root)
            paper = accepted / "paper_tables" / "paper_data_summary.json"
            value = json.loads(paper.read_text(encoding="utf-8"))
            value["records"] = 11
            write_json(paper, value)
            with self.assertRaisesRegex(ValueError, "paper table export digest mismatch"):
                build_binding(claim_matrix, accepted)

    def test_refuses_non_conserving_verdict_counts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            claim_matrix, accepted = self.fixture(root)
            paper = accepted / "paper_tables" / "paper_data_summary.json"
            value = json.loads(paper.read_text(encoding="utf-8"))
            value["verdicts"]["RESIDUAL"] = 3
            write_json(paper, value)
            value = json.loads(claim_matrix.read_text(encoding="utf-8"))
            value["evidence"]["paper_tables"]["sha256"] = sha256(paper)
            write_json(claim_matrix, value)
            with self.assertRaisesRegex(ValueError, "verdict counts do not conserve records"):
                build_binding(claim_matrix, accepted)


if __name__ == "__main__":
    unittest.main()
