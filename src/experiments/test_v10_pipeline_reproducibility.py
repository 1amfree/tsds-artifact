import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

from run_tsds_v10_pipeline import (
    artifact_identities,
    file_identity,
    prepare_fresh_output_dir,
    query_host_environment,
    query_python_environment,
    sha256_file,
)


class V10PipelineReproducibilityTest(unittest.TestCase):
    def test_sha256_and_identity_are_content_addressed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            item = root / "sample.bin"
            item.write_bytes(b"TSDS\x00fixture")
            expected = hashlib.sha256(b"TSDS\x00fixture").hexdigest()
            self.assertEqual(sha256_file(item), expected)
            identity = file_identity(item, root)
            self.assertEqual(identity["path"], "sample.bin")
            self.assertEqual(identity["size"], 12)
            self.assertEqual(identity["sha256"], expected)

    def test_pipeline_directory_is_immutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "pipeline"
            prepare_fresh_output_dir(out)
            (out / "stage.log").write_text("complete\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                prepare_fresh_output_dir(out)

    def test_artifact_manifest_excludes_self_referential_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "result.json").write_text("{}\n", encoding="utf-8")
            (out / "pipeline_manifest.json").write_text("{}\n", encoding="utf-8")
            identities = artifact_identities(out)
            self.assertEqual([row["path"] for row in identities], ["result.json"])

    def test_environment_manifest_binds_dependency_lock_and_host(self):
        environment = query_python_environment(Path(sys.executable), Path.cwd())
        self.assertEqual(len(environment["dependency_lock_sha256"]), 64)
        self.assertTrue(environment["dependency_lock"])
        self.assertEqual(environment["executable"], sys.executable)
        host = query_host_environment()
        self.assertIn("machine", host)
        self.assertGreater(host["logical_cpu_count"], 0)


if __name__ == "__main__":
    unittest.main()
