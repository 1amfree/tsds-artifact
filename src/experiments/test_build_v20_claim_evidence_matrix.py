#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from experiments.build_v20_claim_evidence_matrix import build_matrix, write_outputs


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


class ClaimEvidenceMatrixTest(unittest.TestCase):
    def fixture_args(self, root: Path, *, satc_success: bool = True):
        accepted = root / "accepted"
        write_json(accepted / "pipeline_manifest.json", {"schema": "tsds-v18-pipeline-v7", "success": True})
        write_json(accepted / "paper_tables" / "paper_data_summary.json", {"all_contract_valid": True, "records": 10})
        write_json(
            accepted / "repeatability_consensus" / "repeatability_summary.json",
            {
                "schema": "tsds-repeatability-audit-v4",
                "baseline_only": 0,
                "replay_only": 0,
                "sink_semantic_core": {
                    "baseline_records": 4,
                    "stable_records": 4,
                    "baseline_reproduced": True,
                    "semantic_drift": 0,
                    "baseline_only": 0,
                },
            },
        )
        configs = [
            "p0_scheduler_off", "p0_corridor_off", "p0_all_off",
            "p1_projection_off", "p1_spawn_backend",
            "p2_provenance_off", "p2_semantics_off", "p2_refinement_off", "p2_refinement_replay",
        ]
        write_json(root / "matrix" / "v19_ablation_analysis.json", {"valid": True, "configurations": [{"configuration": name} for name in configs]})
        write_json(root / "confirm" / "v19_ablation_analysis.json", {"valid": True, "configurations": [{"configuration": "p0_all_off"}, {"configuration": "p1_projection_off"}]})
        write_json(root / "transitions" / "record_level_ablation_summary.json", {"valid": True, "transition_rows": 90, "configurations": [{"configuration": name} for name in configs]})
        write_json(
            root / "confirm_transitions" / "record_level_ablation_summary.json",
            {
                "valid": True,
                "transition_rows": 20,
                "configurations": [
                    {"configuration": "p0_all_off"},
                    {"configuration": "p1_projection_off"},
                ],
            },
        )
        write_json(
            root / "extension" / "extension_verification.json",
            {"schema": "tsds-v18-evidence-extension-verification-v1", "valid": True},
        )
        write_json(
            root / "runtime" / "runtime_validation_expansion_summary.json",
            {
                "schema": "tsds-runtime-validation-expansion-v2",
                "valid": True,
                "runtime_attempts": 5,
                "runtime_attempts_identity_sha256": "a" * 64,
                "candidate_rows_identity_sha256": "c" * 64,
                "path_control_rows_identity_sha256": "d" * 64,
                "campaign_identity": {
                    "result_files": 2,
                    "results_identity_sha256": "b" * 64,
                },
            },
        )
        write_json(
            root / "satc" / "experiment_manifest.json",
            {
                "schema": "tsds-satc-ghidra-ingestion-v1",
                "success": satc_success,
                "satc_candidates": 2,
                "configuration": {
                    "satc_source_snapshot_bound": True,
                    "keyword_provenance_manifest_bound": True,
                },
                "inputs": {
                    "satc_source_snapshot": {"size": 100, "sha256": "c" * 64},
                    "keyword_provenance_manifest": {
                        "size": 100,
                        "sha256": "d" * 64,
                    },
                },
                "tsds": {"unique_pairs_analyzed": 2},
                "tsds_audits": {
                    "candidate_contract": {"valid": satc_success},
                    "evidence_contract": {
                        "records": 2,
                        "records_with_contract_issues": 0,
                    },
                    "vector_integrity": {
                        "records": 2,
                        "records_with_integrity_issues": 0,
                    },
                    "ledger_schema": {"records": 2, "records_with_issues": 0},
                },
            },
        )
        import argparse
        return argparse.Namespace(
            accepted_run=accepted,
            matrix_analysis=root / "matrix",
            confirmatory_analysis=root / "confirm",
            record_transitions=root / "transitions",
            confirmatory_transitions=root / "confirm_transitions",
            extension_verification=root / "extension",
            runtime_pack=root / "runtime",
            satc_manifest=root / "satc",
        )

    def test_complete_evidence_is_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = build_matrix(self.fixture_args(root))
            self.assertTrue(document["ready_for_full_paper_writing"])
            self.assertTrue(all(row["status"] == "supported" for row in document["claims"]))
            write_outputs(root / "out", document)
            self.assertTrue((root / "out" / "claim_evidence_matrix.csv").is_file())

    def test_failed_external_ingestion_keeps_readiness_false(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = build_matrix(self.fixture_args(Path(directory), satc_success=False))
            by_id = {row["claim_id"]: row for row in document["claims"]}
            self.assertEqual("pending", by_id["C8"]["status"])
            self.assertFalse(document["ready_for_full_paper_writing"])

    def test_missing_p2_record_transitions_keeps_mechanism_claim_pending(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture_args(root)
            path = root / "transitions" / "record_level_ablation_summary.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["configurations"] = [
                row
                for row in value["configurations"]
                if row["configuration"] != "p2_semantics_off"
            ]
            write_json(path, value)
            document = build_matrix(args)
            by_id = {row["claim_id"]: row for row in document["claims"]}
            self.assertEqual("pending", by_id["C4"]["status"])
            self.assertFalse(document["ready_for_full_paper_writing"])

    def test_unbound_satc_provenance_keeps_ingestion_claim_pending(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture_args(root)
            path = root / "satc" / "experiment_manifest.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["configuration"]["satc_source_snapshot_bound"] = False
            write_json(path, value)
            document = build_matrix(args)
            by_id = {row["claim_id"]: row for row in document["claims"]}
            self.assertEqual("pending", by_id["C8"]["status"])

    def test_unbound_runtime_population_keeps_canary_claim_pending(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture_args(root)
            path = root / "runtime" / "runtime_validation_expansion_summary.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["runtime_attempts_identity_sha256"] = "not-a-hash"
            write_json(path, value)
            document = build_matrix(args)
            by_id = {row["claim_id"]: row for row in document["claims"]}
            self.assertEqual("pending", by_id["C7"]["status"])

    def test_missing_confirmatory_record_transitions_keeps_confirmation_pending(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture_args(root)
            path = root / "confirm_transitions" / "record_level_ablation_summary.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["configurations"] = [{"configuration": "p0_all_off"}]
            write_json(path, value)
            document = build_matrix(args)
            by_id = {row["claim_id"]: row for row in document["claims"]}
            self.assertEqual("pending", by_id["C9"]["status"])

    def test_satc_identity_rows_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture_args(root)
            path = root / "satc" / "experiment_manifest.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["inputs"].pop("satc_source_snapshot")
            write_json(path, value)
            document = build_matrix(args)
            by_id = {row["claim_id"]: row for row in document["claims"]}
            self.assertEqual("pending", by_id["C8"]["status"])


if __name__ == "__main__":
    unittest.main()
