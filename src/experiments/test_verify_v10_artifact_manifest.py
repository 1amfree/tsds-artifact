import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from verify_v10_artifact_manifest import verify_manifest


def identity(path: Path, base: Path):
    data = path.read_bytes()
    return {
        "path": str(path.relative_to(base)),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


class ArtifactManifestVerificationTest(unittest.TestCase):
    def build_fixture(self, root: Path):
        source = root / "source.py"
        binary = root / "firmware.bin"
        mango = root / "closures.json"
        out = root / "out"
        artifact = out / "paper.csv"
        source.write_text("print('tsds')\n", encoding="utf-8")
        binary.write_bytes(b"firmware")
        mango.write_text('{"closures": []}\n', encoding="utf-8")
        out.mkdir()
        artifact.write_text("class,count\nVECTOR_SAT,1\n", encoding="utf-8")
        manifest = {
            "root": str(root),
            "out_dir": str(out),
            "reproducibility": {
                "source_files": [identity(source, root)],
                "campaign_inputs": [{
                    "target": "fixture",
                    "binary": identity(binary, root),
                    "mango": identity(mango, root),
                }],
            },
            "artifacts": [identity(artifact, out)],
        }
        manifest_path = root / "pipeline_manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, artifact

    def test_valid_manifest_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest, _ = self.build_fixture(Path(tmp))
            _, summary = verify_manifest(manifest)
            self.assertTrue(summary["verified"])
            self.assertEqual(summary["checked"], 4)
            self.assertEqual(summary["outcomes"], {"ok": 4})

    def test_mutated_artifact_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest, artifact = self.build_fixture(Path(tmp))
            artifact.write_text("mutated\n", encoding="utf-8")
            rows, summary = verify_manifest(manifest)
            self.assertFalse(summary["verified"])
            self.assertEqual(summary["outcomes"]["size_and_sha256_mismatch"], 1)
            self.assertEqual([row for row in rows if row["category"] == "artifact"][0]["outcome"], "size_and_sha256_mismatch")

    def test_python_executable_identity_is_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path, _artifact = self.build_fixture(root)
            python = root / "python-bin"
            python.write_bytes(b"python-v1")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["reproducibility"]["python_executable"] = identity(python, root)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            python.write_bytes(b"python-v2")
            rows, summary = verify_manifest(manifest_path)
            python_rows = [
                row for row in rows if row["category"] == "python_executable"
            ]
            self.assertEqual(len(python_rows), 1)
            self.assertEqual(python_rows[0]["outcome"], "sha256_mismatch")
            self.assertFalse(summary["verified"])

    def test_v17_requires_successful_stable_run_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path, _ = self.build_fixture(Path(tmp))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest.update(
                {
                    "schema": "tsds-v17-pipeline-v3",
                    "success": True,
                    "identity_drift": {"stable": True, "drift_count": 0},
                }
            )
            snapshot = Path(tmp) / "out" / "source_snapshot"
            snapshot.mkdir()
            (snapshot / "source.py").write_text("print('tsds')\n", encoding="utf-8")
            manifest["reproducibility"]["source_execution_root"] = "source_snapshot"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _, summary = verify_manifest(manifest_path)
            self.assertTrue(summary["verified"])
            self.assertTrue(summary["run_lock_required"])

            manifest["identity_drift"] = {"stable": False, "drift_count": 1}
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _, summary = verify_manifest(manifest_path)
            self.assertFalse(summary["verified"])
            self.assertFalse(summary["run_identity_stable"])

            manifest["identity_drift"] = {"stable": True, "drift_count": 0}
            manifest["success"] = False
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _, summary = verify_manifest(manifest_path)
            self.assertFalse(summary["verified"])
            self.assertFalse(summary["pipeline_accepted"])

    def test_v5_required_repeatability_gate_verifies_locked_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path, _ = self.build_fixture(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest.update({
                "schema": "tsds-v17-pipeline-v5",
                "success": True,
                "identity_drift": {"stable": True, "drift_count": 0},
                "exclusive_run_lock": {
                    "schema": "tsds-exclusive-run-lock-v1",
                    "mode": "posix_flock_exclusive_nonblocking",
                    "pid": 1234,
                    "path": "/tmp/.tsds_pipeline.lock",
                },
                "invocation": [
                    "run_tsds_v17_pipeline.py",
                    "--require-sink-semantic-repeatability",
                ],
            })
            snapshot = root / "out" / "source_snapshot"
            snapshot.mkdir()
            (snapshot / "source.py").write_text("print('tsds')\n", encoding="utf-8")
            manifest["reproducibility"]["source_execution_root"] = "source_snapshot"
            baseline = root / "out" / "repeatability_baseline_snapshot"
            baseline.mkdir()
            result = baseline / "fixture.results.jsonl"
            result.write_text('{"verdict":"VECTOR_SAT"}\n', encoding="utf-8")
            files = [identity(result, baseline)]
            payload = json.dumps(
                files, sort_keys=True, separators=(",", ":")
            ).encode()
            manifest["reproducibility"]["repeatability_baseline"] = {
                "schema": "tsds-repeatability-baseline-lock-v1",
                "execution_path": "repeatability_baseline_snapshot",
                "files": files,
                "files_count": 1,
                "aggregate_sha256": hashlib.sha256(payload).hexdigest(),
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _, summary = verify_manifest(manifest_path)
            self.assertTrue(summary["verified"])
            self.assertTrue(summary["repeatability_lock_required"])
            self.assertTrue(summary["repeatability_snapshot_valid"])

            without_lock = dict(manifest)
            without_lock.pop("exclusive_run_lock")
            manifest_path.write_text(json.dumps(without_lock), encoding="utf-8")
            _, unlocked = verify_manifest(manifest_path)
            self.assertFalse(unlocked["verified"])
            self.assertFalse(unlocked["exclusive_run_lock_valid"])
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            result.write_text('{"verdict":"RESIDUAL"}\n', encoding="utf-8")
            _, tampered = verify_manifest(manifest_path)
            self.assertFalse(tampered["verified"])
            self.assertEqual(
                sum(
                    count
                    for outcome, count in tampered["outcomes"].items()
                    if "mismatch" in outcome
                ),
                1,
            )


if __name__ == "__main__":
    unittest.main()
