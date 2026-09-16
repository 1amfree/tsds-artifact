from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.audit_v20_downloaded_release import audit_release, scan_forbidden_tokens
from experiments.build_deterministic_artifact_archive import build_archive
from experiments.build_v20_manuscript_binding import build_binding, write_outputs
from experiments.fetch_v20_release import release_names
from experiments.verify_deterministic_artifact_archive import verify_archive


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def archive_inputs(root: Path, tag: str) -> list[tuple[str, Path]]:
    post = root / f"tsds_v20_post_release_{tag}_v2"
    return [
        ("pipeline", root / f"tsds_v20_accepted_repeat_{tag}"),
        ("full_campaign", root / f"tsds_v20_full_{tag}"),
        ("full_audits", root / f"tsds_v20_full_audits_{tag}"),
        ("matrix", root / f"tsds_v20_matrix_{tag}"),
        ("matrix_analysis", root / f"tsds_v20_matrix_analysis_{tag}"),
        ("matrix_transitions", root / f"tsds_v20_matrix_transitions_{tag}"),
        ("confirm", root / f"tsds_v20_confirmatory_{tag}"),
        ("confirm_analysis", root / f"tsds_v20_confirmatory_analysis_{tag}"),
        ("confirm_transitions", root / f"tsds_v20_confirmatory_transitions_{tag}"),
        ("resource_calibration", root / f"tsds_v20_resource_calibration_{tag}"),
        ("runtime_repeatability", root / f"tsds_v20_runtime_repeatability_{tag}"),
        ("runtime_pack", root / f"tsds_v20_runtime_validation_expansion_{tag}"),
        ("shell_syntax", root / f"tsds_v20_shell_syntax_{tag}"),
        ("boundary_suite", root / f"tsds_v20_boundary_suite_{tag}"),
        ("extension", root / f"tsds_v20_evidence_extension_{tag}"),
        (
            "extension_verification",
            root / f"tsds_v20_evidence_extension_verification_{tag}",
        ),
        ("blinded_roles", root / f"tsds_v20_blinded_role_packages_{tag}"),
        ("satc_parser", post / "satc_js_parser_environment"),
        ("satc_keyword_extraction", post / "satc_keyword_extraction"),
        ("satc_keyword_slice", post / "satc_keyword_slice"),
        (
            "satc_keyword_workload_identity",
            post / "satc_keyword_workload_identity",
        ),
        ("satc", post / "satc_ingestion"),
        ("claims", post / "claim_evidence"),
        ("liveness_probe", root / "liveness_probe_fixture.json"),
    ]


class DownloadedReleaseAuditTest(unittest.TestCase):
    def fixture(self, root: Path) -> None:
        tag = "r5"
        names = release_names(tag, "v2")
        for name in names:
            directory = root / name
            directory.mkdir(parents=True)
            (directory / "placeholder.txt").write_text(name, encoding="utf-8")
        accepted = root / f"tsds_v20_accepted_repeat_{tag}"
        manifest = accepted / "pipeline_manifest.json"
        paper = accepted / "paper_tables" / "paper_data_summary.json"
        write_json(manifest, {"schema": "tsds-v18-pipeline-v7", "success": True})
        write_json(
            paper,
            {
                "schema": "tsds-paper-table-export-v2",
                "all_contract_valid": True,
                "records": 2,
                "verdicts": {
                    "VECTOR_SAT": 1,
                    "MATRIX_UNSAT": 0,
                    "NO_MODELED_SOURCE": 0,
                    "STATIC_SOURCE_INFERENCE": 0,
                    "STATIC_WARNING_REDUCTION": 0,
                    "RESIDUAL": 1,
                },
            },
        )
        paper_root = paper.parent
        (paper_root / "paper_overall.csv").write_text(
            "evidence_class,count\n"
            "VECTOR_SAT,1\nMATRIX_UNSAT,0\nNO_MODELED_SOURCE,0\n"
            "STATIC_SOURCE_INFERENCE,0\nSTATIC_WARNING_REDUCTION,0\nRESIDUAL,1\n",
            encoding="utf-8",
        )
        verdict_columns = (
            "VECTOR_SAT,MATRIX_UNSAT,NO_MODELED_SOURCE,"
            "STATIC_SOURCE_INFERENCE,STATIC_WARNING_REDUCTION,RESIDUAL"
        )
        per_target_lines = [f"target,records,{verdict_columns}"]
        runtime_lines = ["target,records,total_sec,peak_rss_mb"]
        workload_lines = ["target,records,matrix_solver_queries,engine_steps"]
        for index in range(8):
            vector_sat = 1 if index == 0 else 0
            residual = 1 if index == 1 else 0
            records = vector_sat + residual
            per_target_lines.append(
                f"target_{index},{records},{vector_sat},0,0,0,0,{residual}"
            )
            runtime_lines.append(f"target_{index},{records},{float(records)},1.0")
            workload_lines.append(f"target_{index},{records},{records},{records}")
        runtime_lines.append("TOTAL,2,2.0,1.0")
        workload_lines.append("TOTAL,2,2,2")
        (paper_root / "paper_per_target.csv").write_text(
            "\n".join(per_target_lines) + "\n", encoding="utf-8"
        )
        (paper_root / "paper_runtime.csv").write_text(
            "\n".join(runtime_lines) + "\n", encoding="utf-8"
        )
        (paper_root / "paper_workload.csv").write_text(
            "\n".join(workload_lines) + "\n", encoding="utf-8"
        )
        (paper_root / "paper_residuals.csv").write_text(
            "residual_class,count\nengine_timeout,1\n", encoding="utf-8"
        )
        vector_lines = ["vector_id,token,effect_class,SAT,UNSAT,INCONCLUSIVE"]
        for index in range(11):
            vector_lines.append(f"vector_{index},v{index},fixture,1,0,0")
        (paper_root / "paper_vector_profile.csv").write_text(
            "\n".join(vector_lines) + "\n", encoding="utf-8"
        )
        (paper_root / "paper_tables.tex").write_text(
            "% fixture paper tables\n", encoding="utf-8"
        )
        (paper_root / "README.md").write_text("# Fixture paper tables\n", encoding="utf-8")
        repeatability = accepted / "repeatability_consensus" / "repeatability_summary.json"
        write_json(
            repeatability,
            {
                "schema": "tsds-repeatability-audit-v4",
                "baseline_records": 2,
                "stable_records": 2,
                "semantic_drift": 0,
                "baseline_only": 0,
                "replay_only": 0,
                "sink_semantic_core": {
                    "baseline_records": 1,
                    "stable_records": 1,
                    "semantic_drift": 0,
                    "baseline_reproduced": True,
                },
            },
        )
        write_json(
            accepted / "source_snapshot" / "source_snapshot_manifest.json",
            {"schema": "source-snapshot-fixture", "valid": True},
        )
        post = root / f"tsds_v20_post_release_{tag}_v2"

        evidence_files = {
            "accepted_manifest": manifest,
            "paper_tables": paper,
            "repeatability": repeatability,
            "matrix": root
            / f"tsds_v20_matrix_analysis_{tag}"
            / "v19_ablation_analysis.json",
            "confirmatory": root
            / f"tsds_v20_confirmatory_analysis_{tag}"
            / "v19_ablation_analysis.json",
            "record_transitions": root
            / f"tsds_v20_matrix_transitions_{tag}"
            / "record_level_ablation_summary.json",
            "confirmatory_transitions": root
            / f"tsds_v20_confirmatory_transitions_{tag}"
            / "record_level_ablation_summary.json",
            "extension_verification": root
            / f"tsds_v20_evidence_extension_verification_{tag}"
            / "extension_verification.json",
            "runtime": root
            / f"tsds_v20_runtime_validation_expansion_{tag}"
            / "runtime_validation_expansion_summary.json",
            "satc": root
            / f"tsds_v20_post_release_{tag}_v2"
            / "satc_ingestion"
            / "experiment_manifest.json",
        }
        for key, path in evidence_files.items():
            if not path.exists():
                write_json(path, {"schema": f"{key}-fixture", "valid": True})
        write_json(
            evidence_files["runtime"],
            {
                "schema": "tsds-runtime-validation-expansion-v2",
                "valid": True,
                "runtime_attempts": 2,
                "positive_token_to_sink_attempts": 1,
                "unique_positive_token_callsite_keys": 1,
                "attempt_classes": {"positive_token_to_sink": 1, "boundary": 1},
            },
        )
        write_json(
            evidence_files["satc"],
            {
                "schema": "tsds-satc-ghidra-ingestion-v1",
                "success": True,
                "satc_candidates": 2,
                "tsds": {"unique_pairs_analyzed": 2},
                "tsds_audits": {},
            },
        )
        for name in (
            "satc_js_parser_environment",
            "satc_keyword_extraction",
            "satc_keyword_slice",
            "satc_keyword_workload_identity",
        ):
            write_json(post / name / "fixture.json", {"schema": f"{name}-fixture"})
        for key in ("record_transitions", "confirmatory_transitions"):
            (evidence_files[key].parent / "record_level_ablation_transitions.csv").write_text(
                "configuration,target\nfixture,target\n", encoding="utf-8"
            )
        write_json(
            root
            / f"tsds_v20_resource_calibration_{tag}"
            / "resource_limit_calibration_summary.json",
            {
                "schema": "tsds-resource-limit-calibration-v2",
                "required_cases_accepted": True,
                "input_identity_stable": True,
            },
        )
        write_json(
            root
            / f"tsds_v20_evidence_extension_{tag}"
            / "residual_root_causes"
            / "residual_root_cause_summary.json",
            {
                "schema": "tsds-residual-root-cause-audit-v1",
                "valid": True,
                "classification_complete": True,
                "records": 1,
                "classified_records": 1,
                "root_cause_counts": {"engine_timeout": 1},
                "follow_up_obligations": {"repeat with extended budget": 1},
            },
        )

        def evidence_identity(path: Path) -> dict:
            return {
                "path": "/reports/" + path.relative_to(root).as_posix(),
                "size": path.stat().st_size,
                "sha256": digest(path),
            }

        claim_path = post / "claim_evidence" / "claim_evidence_matrix.json"
        statuses = {f"C{index}": "supported" for index in range(1, 10)}
        claim_evidence = {
            "C1": ["accepted_manifest", "paper_tables"],
            "C2": ["matrix", "record_transitions"],
            "C3": ["matrix", "record_transitions"],
            "C4": ["matrix", "record_transitions"],
            "C5": ["extension_verification"],
            "C6": ["repeatability"],
            "C7": ["runtime"],
            "C8": ["satc"],
            "C9": ["confirmatory", "confirmatory_transitions"],
        }
        write_json(
            claim_path,
            {
                "schema": "tsds-v20-claim-evidence-matrix-v1",
                "ready_for_full_paper_writing": True,
                "claims": [
                    {
                        "claim_id": key,
                        "status": value,
                        "statement": f"{key} fixture statement",
                        "verification_predicate": f"{key} fixture predicate",
                        "non_claim": f"{key} fixture non-claim",
                        "evidence_paths": claim_evidence[key],
                    }
                    for key, value in statuses.items()
                ],
                "input_summary": {"accepted_records": 2},
                "evidence": {
                    key: evidence_identity(path) for key, path in evidence_files.items()
                },
            },
        )
        write_json(
            post / "post_release_summary.json",
            {
                "schema": "tsds-v20-post-release-summary-v1",
                "ready_for_full_paper_writing": True,
                "claim_statuses": statuses,
                "release_readiness_valid": True,
                "evidence_archive_verified": True,
            },
        )
        write_json(
            post / "release_readiness" / "release_readiness.json",
            {"schema": "tsds-release-readiness-v2", "valid": True, "issues": []},
        )
        archive = post / f"tsds_v20_{tag}_evidence.tar.gz"
        archive_manifest = post / f"tsds_v20_{tag}_evidence_manifest.json"
        write_json(
            root / "liveness_probe_fixture.json",
            {"schema": "liveness-probe-fixture", "valid": True},
        )
        archive_summary = build_archive(archive_inputs(root, tag), archive)
        (root / "liveness_probe_fixture.json").unlink()
        write_json(archive_manifest, archive_summary)
        write_json(post / "evidence_archive_verification.json", verify_archive(archive, archive_manifest))
        binding = build_binding(claim_path, accepted)
        write_outputs(root / "manuscript_binding", binding)
        binding_path = root / "manuscript_binding" / "manuscript_binding.json"
        marker = root / f"tsds_v20_experiment_queue_{tag}.complete"
        marker.write_text(
            f"TSDS_V20_EXPERIMENT_QUEUE_COMPLETE {tag}\n", encoding="utf-8"
        )
        downloads = {}
        for name in names:
            directory = root / name
            downloads[name] = [
                {
                    "path": path.relative_to(directory).as_posix(),
                    "size": path.stat().st_size,
                    "sha256": digest(path),
                }
                for path in sorted(directory.rglob("*"))
                if path.is_file()
            ]
        counts_path = root / "manuscript_binding" / "manuscript_counts.tex"
        write_json(
            root / "fetch_manifest.json",
            {
                "schema": "tsds-v20-release-fetch-v1",
                "tag": tag,
                "post_release_suffix": "v2",
                "downloads": downloads,
                "files": sum(len(rows) for rows in downloads.values()),
                "queue_marker": {
                    "path": marker.name,
                    "size": marker.stat().st_size,
                    "sha256": digest(marker),
                },
                "manuscript_binding": {
                    "binding": {
                        "path": "manuscript_binding/manuscript_binding.json",
                        "size": binding_path.stat().st_size,
                        "sha256": digest(binding_path),
                    },
                    "counts_tex": {
                        "path": "manuscript_binding/manuscript_counts.tex",
                        "size": counts_path.stat().st_size,
                        "sha256": digest(counts_path),
                    },
                },
            },
        )

    def test_complete_downloaded_release_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            document = audit_release(root, "r5", "v2")
            self.assertTrue(document["valid"])
            self.assertEqual([], document["issues"])

    def test_diagnostic_run_contamination_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            post = root / "tsds_v20_post_release_r5_v2" / "post_release_summary.json"
            value = json.loads(post.read_text(encoding="utf-8"))
            value["note"] = "tsds_v20_full_20260717_r4"
            write_json(post, value)
            document = audit_release(root, "r5", "v2")
            self.assertFalse(document["valid"])
            self.assertIn("diagnostic_run_exclusion", document["issues"])

    def test_diagnostic_token_in_source_snapshot_is_not_result_contamination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source_snapshot" / "guard.py"
            source.parent.mkdir(parents=True)
            source.write_text("tsds_v20_full_20260717_r4", encoding="utf-8")
            result = root / "paper_tables" / "summary.json"
            result.parent.mkdir(parents=True)
            result.write_text("tsds_v20_full_20260717_r4", encoding="utf-8")
            self.assertEqual([], scan_forbidden_tokens([source]))
            self.assertTrue(scan_forbidden_tokens([result]))

    def test_missing_claim_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            post = root / "tsds_v20_post_release_r5_v2" / "post_release_summary.json"
            value = json.loads(post.read_text(encoding="utf-8"))
            value["claim_statuses"].pop("C9")
            write_json(post, value)
            document = audit_release(root, "r5", "v2")
            self.assertFalse(document["valid"])
            self.assertIn("post_summary_claims", document["issues"])

    def test_unregistered_download_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "tsds_v20_full_r5" / "unregistered.json").write_text(
                "{}", encoding="utf-8"
            )
            document = audit_release(root, "r5", "v2")
            self.assertFalse(document["valid"])
            self.assertIn("download_manifest_integrity", document["issues"])

    def test_tampered_download_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "tsds_v20_full_r5" / "placeholder.txt").write_text(
                "tampered", encoding="utf-8"
            )
            document = audit_release(root, "r5", "v2")
            self.assertFalse(document["valid"])
            self.assertIn("download_manifest_integrity", document["issues"])

    def test_archive_is_bound_to_downloaded_release_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            path = root / "tsds_v20_full_r5" / "placeholder.txt"
            path.write_text("self-consistent-download-tamper", encoding="utf-8")
            fetch_path = root / "fetch_manifest.json"
            fetch = json.loads(fetch_path.read_text(encoding="utf-8"))
            row = next(
                row
                for row in fetch["downloads"]["tsds_v20_full_r5"]
                if row["path"] == "placeholder.txt"
            )
            row["size"] = path.stat().st_size
            row["sha256"] = digest(path)
            write_json(fetch_path, fetch)
            document = audit_release(root, "r5", "v2")
            self.assertFalse(document["valid"])
            self.assertIn("archive_release_bindings", document["issues"])

    def test_claim_evidence_identity_is_reverified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            path = (
                root
                / "tsds_v20_matrix_analysis_r5"
                / "v19_ablation_analysis.json"
            )
            write_json(path, {"schema": "matrix-fixture", "valid": False})
            fetch_path = root / "fetch_manifest.json"
            fetch = json.loads(fetch_path.read_text(encoding="utf-8"))
            row = next(
                row
                for row in fetch["downloads"]["tsds_v20_matrix_analysis_r5"]
                if row["path"] == "v19_ablation_analysis.json"
            )
            row["size"] = path.stat().st_size
            row["sha256"] = digest(path)
            write_json(fetch_path, fetch)
            document = audit_release(root, "r5", "v2")
            self.assertFalse(document["valid"])
            self.assertIn("claim_evidence_identities", document["issues"])

    def test_claim_cannot_be_rewired_to_unregistered_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            claim_path = (
                root
                / "tsds_v20_post_release_r5_v2"
                / "claim_evidence"
                / "claim_evidence_matrix.json"
            )
            claim = json.loads(claim_path.read_text(encoding="utf-8"))
            claim["claims"][0]["evidence_paths"] = ["runtime"]
            write_json(claim_path, claim)

            accepted = root / "tsds_v20_accepted_repeat_r5"
            binding = build_binding(claim_path, accepted)
            binding_path = root / "manuscript_binding" / "manuscript_binding.json"
            write_json(binding_path, binding)

            fetch_path = root / "fetch_manifest.json"
            fetch = json.loads(fetch_path.read_text(encoding="utf-8"))
            claim_row = next(
                row
                for row in fetch["downloads"]["tsds_v20_post_release_r5_v2"]
                if row["path"] == "claim_evidence/claim_evidence_matrix.json"
            )
            claim_row["size"] = claim_path.stat().st_size
            claim_row["sha256"] = digest(claim_path)
            fetch["manuscript_binding"]["binding"]["size"] = binding_path.stat().st_size
            fetch["manuscript_binding"]["binding"]["sha256"] = digest(binding_path)
            write_json(fetch_path, fetch)

            document = audit_release(root, "r5", "v2")
            self.assertFalse(document["valid"])
            self.assertIn("claim_to_evidence_bindings", document["issues"])


if __name__ == "__main__":
    unittest.main()
