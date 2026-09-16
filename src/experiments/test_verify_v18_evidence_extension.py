#!/usr/bin/env python3
"""Regression tests for the independent v18 evidence-extension verifier."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.verify_v18_evidence_extension import (
    EXPECTED_STAGES,
    REPORT_PATHS,
    canonical_relative_path,
    sha256_file,
    verify_extension,
)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class V18EvidenceExtensionVerifierTest(unittest.TestCase):
    def test_rejects_unsafe_relative_paths(self) -> None:
        self.assertIsNone(canonical_relative_path("../escape"))
        self.assertIsNone(canonical_relative_path("/absolute"))
        self.assertIsNone(canonical_relative_path("a\\b"))
        self.assertEqual("safe/file.json", canonical_relative_path("safe/file.json").as_posix())

    def build_fixture(self, root: Path) -> tuple[Path, Path]:
        extension = root / "extension"
        accepted = root / "accepted"
        pipeline = {"schema": "tsds-v17-pipeline-v6", "success": True, "artifacts": []}
        write_json(accepted / "pipeline_manifest.json", pipeline)
        pipeline_digest = sha256_file(accepted / "pipeline_manifest.json")

        source_file = extension / "source_snapshot/experiments/example.py"
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_text("VALUE = 1\n", encoding="utf-8")
        for name in EXPECTED_STAGES:
            path = extension / f"logs/{name}.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("ok\n", encoding="utf-8")

        reports = {
            "source_self_test": {
                "schema": "tsds-source-snapshot-self-test-v1", "valid": True,
                "returncode": 0, "timed_out": False, "source_identity_stable": True,
                "counts": {"tests": 1, "failures": 0, "errors": 0, "skipped": 0},
            },
            "certificate_audit": {
                "schema": "tsds-evidence-certificate-audit-v2", "records": 2,
                "valid_certificates": 2, "records_with_issues": 0, "issue_counts": {},
            },
            "independent_verifier": {
                "schema": "tsds-independent-certificate-verifier-v1", "valid": True,
                "records": 2, "valid_records": 2, "source_records": 2,
                "records_with_issues": 0, "parser_preflight": [
                    {"shell": "/bin/bash", "returncode": 0, "no_execution": True},
                    {"shell": "/bin/dash", "returncode": 0, "no_execution": True},
                ],
            },
            "residual_taxonomy": {
                "schema": "tsds-residual-root-cause-audit-v1", "valid": True,
                "classification_complete": True, "records": 1, "classified_records": 1,
                "issues": [], "pipeline_binding": {
                    "verified": True, "issues": [], "manifest_sha256": pipeline_digest,
                },
            },
            "performance": {
                "schema": "tsds-performance-diagnostics-v1", "valid": True,
                "records": 2, "issues": [],
            },
            "matrix_profiles": {
                "schema": "tsds-shell-dialect-profile-v1", "issue_counts": {},
                "matrix_spec_sha256": hashlib.sha256(b"matrix").hexdigest(),
            },
            "calibration": {
                "schema": "tsds-exploitability-calibration-pack-v1",
                "campaign_records": 2, "selected_records": 1,
                "pipeline_manifest_sha256": pipeline_digest,
                "pipeline_binding": {"verified": True, "issues": []},
            },
            "ground_truth_sample": {
                "schema": "tsds-blinded-ground-truth-sample-v4",
                "campaign_records": 2, "sample_records": 1,
                "pipeline_manifest_sha256": pipeline_digest,
            },
            "candidate_contract": {
                "schema": "tsds-candidate-contract-v1", "valid": True,
                "records": 1, "issues": [],
            },
            "environment_lock": {
                "schema": "tsds-reproduction-environment-lock-v1", "source_files": 1,
                "python_packages": [{"name": "example"}],
                "source_aggregate_sha256": hashlib.sha256(b"source").hexdigest(),
            },
            "cyclonedx": {"bomFormat": "CycloneDX", "specVersion": "1.5"},
            "paper_tables": {
                "schema": "tsds-paper-table-export-v2", "all_contract_valid": True,
                "records": 2, "verdicts": {"VECTOR_SAT": 1, "RESIDUAL": 1},
            },
        }
        for key, document in reports.items():
            write_json(extension / REPORT_PATHS[key], document)

        files = sorted(
            (path for path in extension.rglob("*") if path.is_file()),
            key=lambda path: path.relative_to(extension).as_posix(),
        )
        artifacts = [
            {
                "path": path.relative_to(extension).as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in files
        ]
        manifest = {
            "schema": "tsds-v18-evidence-extension-v7",
            "full_pipeline_schema": "tsds-v18-pipeline-v7",
            "success": True,
            "input": {
                "accepted_run": str(accepted.resolve()),
                "pipeline_schema": "tsds-v17-pipeline-v6",
                "pipeline_manifest_sha256": pipeline_digest,
                "targets": 1, "records": 2, "residuals": 1,
            },
            "source_snapshot_files": 1,
            "source_snapshot": [{
                "path": "experiments/example.py", "size": source_file.stat().st_size,
                "sha256": sha256_file(source_file),
            }],
            "stages": [
                {"name": name, "returncode": 0, "log": f"logs/{name}.log"}
                for name in EXPECTED_STAGES
            ],
            "artifacts": artifacts,
        }
        write_json(extension / "extension_manifest.json", manifest)
        return extension, accepted

    def test_valid_fixture_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            extension, accepted = self.build_fixture(Path(temp))
            report = verify_extension(extension, accepted_run=accepted)
            self.assertTrue(report["valid"], report["issues"])
            (extension / "paper_tables/paper_data_summary.json").write_text(
                "{}\n", encoding="utf-8"
            )
            report = verify_extension(extension, accepted_run=accepted)
            self.assertFalse(report["valid"])
            self.assertTrue(
                any("artifact_sha256_mismatch" in value for value in report["issues"])
            )


if __name__ == "__main__":
    unittest.main()
