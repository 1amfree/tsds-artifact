import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from experiments.audit_release_readiness import (
    audit_release,
    report_schema_for_pipeline,
    write_outputs,
)
from experiments.build_deterministic_artifact_archive import build_archive


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


class ReleaseReadinessTest(unittest.TestCase):
    def test_certificate_schema_is_bound_to_pipeline_generation(self):
        self.assertEqual(
            "tsds-evidence-certificate-audit-v1",
            report_schema_for_pipeline("evidence_certificates", "tsds-v17-pipeline-v6"),
        )
        self.assertEqual(
            "tsds-evidence-certificate-audit-v2",
            report_schema_for_pipeline("evidence_certificates", "tsds-v18-pipeline-v7"),
        )

    def _fixture(self, root: Path) -> Path:
        reports = {
            "campaign_conservation": ("campaign_conservation_audit.json", {"schema": "tsds-campaign-conservation-audit-v1", "valid": True, "total": {"selected_closures": 1}}),
            "evidence_contract": ("evidence_contract_audit.json", {"schema": "tsds-evidence-contract-audit-v1", "records": 1, "records_with_contract_issues": 0}),
            "ledger_schema": ("ledger_schema_audit.json", {"schema": "tsds-ledger-schema-v1", "records": 1, "records_with_issues": 0}),
            "vector_decision_integrity": ("vector_decision_integrity_audit.json", {"schema": "tsds-vector-decision-integrity-audit-v1", "records": 1, "records_with_integrity_issues": 0, "integrity_issue_counts": {}}),
            "shell_witness_syntax": ("shell_witness_syntax_summary.json", {"schema": "tsds-shell-witness-syntax-audit-v1", "record_outcomes": {"records_all_witnesses_invalid": 0}}),
            "evidence_certificates": ("evidence_certificate_audit.json", {"schema": "tsds-evidence-certificate-audit-v1", "records": 1, "records_with_issues": 0}),
            "resource_envelope": ("resource_envelope_audit.json", {"schema": "tsds-resource-envelope-v1", "records": 1, "issues": [], "records_missing_required_rss": 0, "records_with_unavailable_worker_metrics": 0, "resource_limit_hits": 0}),
            "busybox_calibration": ("busybox_calibration_summary.json", {"schema": "tsds-busybox-shell-vector-calibration-v2", "calibration_pass": True, "v2_witness_parse_ok": 11, "v2_witness_cases": 11, "complete_effect_observed": 11, "complete_effect_cases": 11}),
            "threat_matrix_boundary": ("threat_matrix_executable_summary.json", {"schema": "tsds-threat-matrix-boundary-v1", "passed_cases": 15, "total_cases": 15}),
            "shell_dialect_profiles": ("shell_dialect_profile_audit.json", {"schema": "tsds-shell-dialect-profile-v1", "issue_counts": {}}),
            "paper_tables": ("paper_data_summary.json", {"schema": "tsds-paper-table-export-v2", "records": 1, "all_contract_valid": True, "verdicts": {"RESIDUAL": 1}}),
            "source_snapshot_self_test": ("source_snapshot_self_test.json", {"schema": "tsds-source-snapshot-self-test-v1", "valid": True, "returncode": 0, "source_identity_stable": True, "counts": {"tests": 3, "failures": 0, "errors": 0, "skipped": 0}}),
        }
        for directory, (name, value) in reports.items():
            write_json(root / directory / name, value)
        campaign = root / "campaign" / "sample.results.jsonl"
        campaign.parent.mkdir(parents=True, exist_ok=True)
        campaign.write_text('{"verdict":"RESIDUAL"}\n', encoding="utf-8")
        write_json(root / "campaign" / "full_campaign_aggregate.json", {"records": 1})
        write_json(root / "reproducibility_drift.json", {"schema": "tsds-run-identity-drift-v1", "stable": True})
        (root / "source_snapshot" / "Taint_demo" / "sanitizer_demo").mkdir(parents=True)
        (root / "source_snapshot" / "Taint_demo" / "sanitizer_demo" / "advanced_sanitizer_evaluator.py").write_text("# fixture\n", encoding="utf-8")
        (root / "source_snapshot" / "experiments").mkdir(parents=True)
        (root / "source_snapshot" / "experiments" / "audit_release_readiness.py").write_text("# fixture\n", encoding="utf-8")
        (root / "source_snapshot" / "experiments" / "test_release_readiness.py").write_text("# fixture\n", encoding="utf-8")
        (root / "source_snapshot" / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
        (root / "source_snapshot" / "operation-mango-public").mkdir(parents=True)
        (root / "source_snapshot" / "operation-mango-public" / "pyproject.toml").write_text(
            "[project]\nname = 'tsds-fixture'\n", encoding="utf-8"
        )
        write_json(
            root / "negative_confirmation" / "negative_confirmation_summary.json",
            {"schema": "tsds-negative-confirmation-v1", "records": 1, "outcomes": {"stable": 1}, "gate_issues": []},
        )
        repeatability_path = root / "repeatability_consensus" / "repeatability_summary.json"
        repeatability_consensus = {
            "records": 1,
            "downgraded_to_residual": 0,
            "verdicts": {"RESIDUAL": 1},
        }
        write_json(
            repeatability_path,
            {
                "schema": "tsds-repeatability-audit-v4",
                "baseline_records": 1,
                "replay_records": 1,
                "baseline_only": 0,
                "replay_only": 0,
                "sink_semantic_core": {"baseline_records": 1, "stable_records": 1, "semantic_drift": 0, "baseline_only": 0, "baseline_reproduced": True},
                "conservative_consensus": repeatability_consensus,
                "inputs": {
                    "baseline": {"result_files": 1, "results_identity_sha256": "a" * 64},
                    "replay": {"result_files": 1, "results_identity_sha256": "b" * 64},
                },
            },
        )
        paper_path = root / "paper_tables" / "paper_data_summary.json"
        paper = json.loads(paper_path.read_text(encoding="utf-8"))
        paper["repeatability_consensus"] = repeatability_consensus
        paper["repeatability_audit_sha256"] = hashlib.sha256(
            repeatability_path.read_bytes()
        ).hexdigest()
        write_json(paper_path, paper)
        stage_names = [
            "01_full_campaign", "02_campaign_conservation", "03_evidence_contract",
            "04_vector_decision_integrity", "05_shell_witness_syntax",
            "06_threat_matrix_boundary", "07_source_snapshot_self_test",
            "08_evidence_certificates",
            "09_resource_envelope", "10_ledger_schema", "11_shell_dialect_profiles",
            "12_counterfactual_repair_pack", "13_residual_refinement_plan",
            "14_busybox_calibration", "15_negative_confirmation",
            "15b_repeatability_consensus", "99_run_identity_drift_gate",
            "16_paper_tables",
        ]
        manifest = {
            "schema": "tsds-v17-pipeline-v6",
            "success": True,
            "invocation": [
                "run_tsds_v17_pipeline.py",
                "--repeatability-baseline",
                "baseline",
                "--run-negative-confirmation",
            ],
            "identity_drift": {"stable": True},
            "exclusive_run_lock": {"schema": "tsds-exclusive-run-lock-v1", "mode": "posix_flock_exclusive_nonblocking"},
            "reproducibility": {"schema": "tsds-reproducibility-v2", "missing_sources": [], "missing_inputs": []},
            "stages": [{"name": name, "returncode": 0} for name in stage_names],
            "artifacts": [],
        }
        # pipeline manifest 本身在产物身份收集之后写入，因此不自引用。
        for artifact in sorted(path for path in root.rglob("*") if path.is_file()):
            payload = artifact.read_bytes()
            manifest["artifacts"].append(
                {
                    "path": artifact.relative_to(root).as_posix(),
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
        path = root / "pipeline_manifest.json"
        write_json(path, manifest)
        return path

    def test_valid_minimal_release_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._fixture(root)
            summary = audit_release(manifest)
            self.assertTrue(summary["valid"], summary["issues"])
            output = root / "audit"
            write_outputs(output, summary)
            self.assertTrue((output / "release_readiness.json").is_file())

    def test_failed_stage_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._fixture(root)
            data = json.loads(manifest.read_text(encoding="utf-8"))
            data["stages"][0]["returncode"] = 2
            manifest.write_text(json.dumps(data), encoding="utf-8")
            summary = audit_release(manifest)
            self.assertFalse(summary["valid"])
            self.assertIn("failed_stage:01_full_campaign", summary["issues"])

    def test_missing_stage_returncode_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._fixture(root)
            data = json.loads(manifest.read_text(encoding="utf-8"))
            data["stages"][0].pop("returncode")
            manifest.write_text(json.dumps(data), encoding="utf-8")
            summary = audit_release(manifest)
            self.assertFalse(summary["valid"])
            self.assertIn("failed_stage:01_full_campaign", summary["issues"])

    def test_declared_artifact_tamper_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._fixture(root)
            artifact = root / "artifact.txt"
            artifact.write_text("original\n", encoding="utf-8")
            data = json.loads(manifest.read_text(encoding="utf-8"))
            data["artifacts"].append({
                "path": "artifact.txt",
                "size": artifact.stat().st_size,
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            })
            manifest.write_text(json.dumps(data), encoding="utf-8")
            artifact.write_text("tampered\n", encoding="utf-8")
            summary = audit_release(manifest)
            self.assertFalse(summary["valid"])
            self.assertIn("artifact_sha256_mismatch:artifact.txt", summary["issues"])

    def test_artifact_path_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._fixture(root)
            data = json.loads(manifest.read_text(encoding="utf-8"))
            data["artifacts"] = [{
                "path": "../outside.txt",
                "size": 0,
                "sha256": "0" * 64,
            }]
            manifest.write_text(json.dumps(data), encoding="utf-8")
            summary = audit_release(manifest)
            self.assertFalse(summary["valid"])
            self.assertIn("unsafe_artifact_path:../outside.txt", summary["issues"])

    def test_missing_required_stage_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._fixture(root)
            data = json.loads(manifest.read_text(encoding="utf-8"))
            data["stages"] = [
                row for row in data["stages"] if row["name"] != "10_ledger_schema"
            ]
            write_json(manifest, data)
            summary = audit_release(manifest)
            self.assertFalse(summary["valid"])
            self.assertTrue(
                any(issue.startswith("missing_required_stage:") for issue in summary["issues"])
            )

    def test_report_schema_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._fixture(root)
            report = root / "paper_tables" / "paper_data_summary.json"
            data = json.loads(report.read_text(encoding="utf-8"))
            data["schema"] = "wrong-schema"
            write_json(report, data)
            summary = audit_release(manifest)
            self.assertFalse(summary["valid"])
            self.assertIn("report_failed:paper_tables", summary["issues"])

    def test_malformed_report_fails_closed_without_crashing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._fixture(root)
            report = root / "paper_tables" / "paper_data_summary.json"
            report.write_text("{not-json\n", encoding="utf-8")
            summary = audit_release(manifest)
            self.assertFalse(summary["valid"])
            self.assertIn("report_unreadable:paper_tables", summary["issues"])

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._fixture(root)
            report = root / "paper_tables" / "paper_data_summary.json"
            report.write_text(
                '{"schema":"wrong","schema":"tsds-paper-table-export-v1",'
                '"records":1,"all_contract_valid":true,"verdicts":{"RESIDUAL":1}}\n',
                encoding="utf-8",
            )
            summary = audit_release(manifest)
            self.assertFalse(summary["valid"])
            self.assertIn("report_unreadable:paper_tables", summary["issues"])

    def test_empty_sink_semantic_repeatability_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._fixture(root)
            report = root / "repeatability_consensus" / "repeatability_summary.json"
            data = json.loads(report.read_text(encoding="utf-8"))
            data["sink_semantic_core"].update({"baseline_records": 0, "stable_records": 0})
            write_json(report, data)
            summary = audit_release(manifest, require_repeatability=True)
            self.assertFalse(summary["valid"])
            self.assertIn("sink_semantic_repeatability_empty", summary["issues"])

    def test_paper_consensus_must_match_repeatability_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._fixture(root)
            report = root / "paper_tables" / "paper_data_summary.json"
            data = json.loads(report.read_text(encoding="utf-8"))
            data["repeatability_consensus"]["downgraded_to_residual"] = 1
            write_json(report, data)
            summary = audit_release(manifest, require_repeatability=True)
            self.assertFalse(summary["valid"])
            self.assertIn("paper_repeatability_consensus_mismatch", summary["issues"])

    def test_empty_negative_confirmation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._fixture(root)
            report = root / "negative_confirmation" / "negative_confirmation_summary.json"
            write_json(report, {"schema": "tsds-negative-confirmation-v1", "records": 0, "outcomes": {}, "gate_issues": []})
            summary = audit_release(manifest, require_negative_confirmation=True)
            self.assertFalse(summary["valid"])
            self.assertIn("negative_confirmation_insufficient_records", summary["issues"])

    def test_archive_is_bound_to_pipeline_manifest_and_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            root = workspace / "run"
            manifest = self._fixture(root)
            archive = workspace / "release.tar.gz"
            archive_manifest = workspace / "release.manifest.json"
            write_json(
                archive_manifest,
                build_archive([("pipeline", root.resolve())], archive.resolve()),
            )
            summary = audit_release(
                manifest,
                archive_path=archive,
                archive_manifest_path=archive_manifest,
            )
            self.assertTrue(summary["valid"], summary["issues"])
            self.assertTrue(summary["archive_binding"]["bound"])

            pipeline = json.loads(manifest.read_text(encoding="utf-8"))
            pipeline["post_archive_tamper"] = True
            write_json(manifest, pipeline)
            tampered = audit_release(
                manifest,
                archive_path=archive,
                archive_manifest_path=archive_manifest,
            )
            self.assertFalse(tampered["valid"])
            self.assertIn("archive_pipeline_manifest_identity_mismatch", tampered["issues"])


if __name__ == "__main__":
    unittest.main()
