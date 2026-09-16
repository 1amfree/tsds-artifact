from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

import experiments.run_tsds_v14_pipeline as pipeline_module
from experiments.run_tsds_v14_pipeline import (
    DETERMINISTIC_CHILD_ENVIRONMENT,
    V14_REPRODUCIBILITY_SOURCES,
    acquire_pipeline_lock,
    build_campaign_command,
    compare_reproducibility_manifests,
    repeatability_baseline_manifest,
    snapshot_repeatability_baseline,
    snapshot_reproducibility_sources,
    validate_resource_calibration,
)


class V14PipelineReproducibilityTest(unittest.TestCase):
    def test_campaign_command_preserves_target_order_and_scope(self) -> None:
        targets = [
            {"name": "first", "label": "First"},
            {"name": "second", "label": "Second"},
        ]
        python = Path("/tmp/python")
        root = Path("/workspace")
        campaign = Path("/output/campaign")
        command = build_campaign_command(
            python,
            root,
            campaign,
            1800,
            39,
            4096,
            targets,
        )
        self.assertEqual(
            command,
            [
                str(python),
                "experiments/run_full_firmware_campaign.py",
                "--root",
                str(root),
                "--out-dir",
                str(campaign),
                "--target-timeout",
                "1800",
                "--subprocess-memory-limit-mib",
                "4096",
                "--max-closures",
                "39",
                "--target",
                "first",
                "--target",
                "second",
            ],
        )

    def test_manifest_captures_v14_lexical_audit_implementation(self) -> None:
        self.assertIn(
            "experiments/audit_vector_decision_integrity.py",
            V14_REPRODUCIBILITY_SOURCES,
        )
        self.assertIn(
            "experiments/run_tsds_v14_pipeline.py",
            V14_REPRODUCIBILITY_SOURCES,
        )
        self.assertIn(
            "experiments/verify_v10_artifact_manifest.py",
            V14_REPRODUCIBILITY_SOURCES,
        )

    def test_deterministic_child_environment_is_explicit(self) -> None:
        self.assertEqual("0", DETERMINISTIC_CHILD_ENVIRONMENT["PYTHONHASHSEED"])
        self.assertEqual("1", DETERMINISTIC_CHILD_ENVIRONMENT["PYTHONDONTWRITEBYTECODE"])
        self.assertEqual("C", DETERMINISTIC_CHILD_ENVIRONMENT["LC_ALL"])
        self.assertEqual("UTC", DETERMINISTIC_CHILD_ENVIRONMENT["TZ"])

    def test_identity_drift_detects_content_change(self) -> None:
        before = {
            "source_files": [{"path": "a.py", "size": 1, "sha256": "old"}],
            "campaign_inputs": [],
            "python_environment": {"python": "3.10.0"},
            "missing_sources": [],
            "missing_inputs": [],
        }
        after = {
            **before,
            "source_files": [{"path": "a.py", "size": 2, "sha256": "new"}],
        }
        drift = compare_reproducibility_manifests(before, after)
        self.assertEqual(1, len(drift))
        self.assertEqual("content_drift", drift[0]["outcome"])

    def test_python_executable_and_host_are_bound(self) -> None:
        before = {
            "host_environment": {"machine": "mips"},
            "python_environment": {"python": "3.11"},
            "python_executable": {
                "path": "python",
                "size": len(b"interpreter-v1"),
                "sha256": hashlib.sha256(b"interpreter-v1").hexdigest(),
            },
            "source_files": [],
            "campaign_inputs": [],
            "missing_sources": [],
            "missing_inputs": [],
        }
        after = json.loads(json.dumps(before))
        after["host_environment"]["machine"] = "arm64"
        after["python_executable"] = {
            "path": "python",
            "size": len(b"interpreter-v2"),
            "sha256": hashlib.sha256(b"interpreter-v2").hexdigest(),
        }
        drift = compare_reproducibility_manifests(before, after)
        self.assertEqual(
            {row["identity"] for row in drift},
            {"host_environment", "python_executable"},
        )

    def test_pipeline_lock_rejects_concurrent_campaign(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, info = acquire_pipeline_lock(root, root / "run-1")
            try:
                self.assertEqual(info["schema"], "tsds-exclusive-run-lock-v1")
                with self.assertRaises(RuntimeError):
                    acquire_pipeline_lock(root, root / "run-2")
            finally:
                first.close()
            third, _info = acquire_pipeline_lock(root, root / "run-3")
            third.close()

    def test_fail_fast_output_collision_releases_pipeline_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "experiment_reports" / "existing-run"
            output.mkdir(parents=True)
            (output / "sentinel").write_text("occupied\n", encoding="utf-8")
            with patch.object(
                pipeline_module,
                "select_targets",
                return_value=[
                    {"name": "fixture", "label": "Fixture", "binary": "bin", "mango": "mango"}
                ],
            ), patch.object(
                sys,
                "argv",
                [
                    "run_tsds_v14_pipeline.py",
                    "--root",
                    str(root),
                    "--python",
                    sys.executable,
                    "--out-dir",
                    str(output),
                ],
            ), redirect_stderr(io.StringIO()):
                self.assertEqual(3, pipeline_module.main())
            handle, _info = acquire_pipeline_lock(root, root / "after-failure")
            handle.close()

    def test_source_snapshot_preserves_declared_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            destination = Path(tmp) / "snapshot"
            source = root / "pkg" / "module.py"
            source.parent.mkdir(parents=True)
            source.write_text("value = 1\n", encoding="utf-8")
            payload = source.read_bytes()
            manifest = {
                "source_files": [
                    {
                        "path": "pkg/module.py",
                        "size": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                ]
            }
            rows = snapshot_reproducibility_sources(root, manifest, destination)
            self.assertEqual(manifest["source_files"][0]["size"], rows[0]["size"])
            self.assertEqual(manifest["source_files"][0]["sha256"], rows[0]["sha256"])
            self.assertEqual(payload, (destination / "pkg" / "module.py").read_bytes())

    def test_repeatability_baseline_is_snapshotted_and_drift_checked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = root / "baseline"
            baseline.mkdir()
            result = baseline / "fixture.results.jsonl"
            result.write_text('{"verdict":"VECTOR_SAT"}\n', encoding="utf-8")
            snapshot = root / "snapshot"
            before = snapshot_repeatability_baseline(baseline, snapshot)
            self.assertEqual(1, before["files_count"])
            self.assertEqual(
                before["aggregate_sha256"],
                repeatability_baseline_manifest(snapshot)["aggregate_sha256"],
            )
            result.write_text('{"verdict":"RESIDUAL"}\n', encoding="utf-8")
            after = repeatability_baseline_manifest(baseline)
            drift = compare_reproducibility_manifests(
                {"repeatability_baseline": before},
                {"repeatability_baseline": after},
            )
            self.assertEqual(1, len(drift))
            self.assertEqual("content_drift", drift[0]["outcome"])

    def test_resource_calibration_must_accept_selected_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.json"
            path.write_text(
                '{"schema":"tsds-resource-limit-calibration-v2",'
                '"required_limits_mib":[8192],"required_cases_accepted":true,'
                '"accepted_by_limit":{"8192":3},"cases_by_limit":{"8192":3},'
                '"input_identity_stable":true,"reproducibility":{'
                '"preflight_identities":['
                '{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},'
                '{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},'
                '{"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},'
                '{"sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},'
                '{"sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}'
                '],"python_environment":{"python":"3.10.0","packages":{'
                '"angr":"9","claripy":"9","z3-solver":"4"}}}}',
                encoding="utf-8",
            )
            self.assertEqual([], validate_resource_calibration(path, 8192))
            self.assertIn(
                "configured_limit_not_calibration_required",
                validate_resource_calibration(path, 4096),
            )

    def test_identity_drift_gate_precedes_paper_export(self) -> None:
        source = Path(pipeline_module.__file__).read_text(encoding="utf-8")
        drift_append = source.index('"name": "99_run_identity_drift_gate"')
        paper_blocking_check = source.index("blocking_stages = [", drift_append)
        paper_export = source.index(
            "stages.append(run_stage(paper_stage_name", paper_blocking_check
        )
        self.assertLess(drift_append, paper_blocking_check)
        self.assertLess(paper_blocking_check, paper_export)

    def test_repeatability_gate_precedes_identity_and_paper_gates(self) -> None:
        source = Path(pipeline_module.__file__).read_text(encoding="utf-8")
        repeatability = source.index('str(out_dir / "repeatability_consensus")')
        postflight = source.index("postflight_reproducibility =", repeatability)
        paper_export = source.index(
            "stages.append(run_stage(paper_stage_name", postflight
        )
        self.assertLess(repeatability, postflight)
        self.assertLess(postflight, paper_export)

    def test_optional_validation_stages_reject_empty_evidence(self) -> None:
        # 编排器必须把两个非空证据参数传给独立审计进程。
        source = Path(pipeline_module.__file__).read_text(encoding="utf-8")
        self.assertIn('"--minimum-records"', source)
        self.assertIn('"--require-sink-semantic-records"', source)
        self.assertIn('"--require-same-record-set"', source)

    def test_required_repeatability_gate_requires_a_baseline(self) -> None:
        with patch.object(
            sys,
            "argv",
            ["run_tsds_v14_pipeline.py", "--require-sink-semantic-repeatability"],
        ):
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    pipeline_module.main()


if __name__ == "__main__":
    unittest.main()
