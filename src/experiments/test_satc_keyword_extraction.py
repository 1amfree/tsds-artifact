import argparse
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from experiments.run_satc_keyword_extraction import (
    canonicalize_keywords,
    directory_identity,
    resolve_rootfs_binary,
    run_keyword_extraction,
)
from experiments.run_satc_ghidra_experiment import PROJECT_ROOT
from experiments.capture_satc_js_parser_environment import SCHEMA as JS_PARSER_SCHEMA, file_identity


class SaTCKeywordExtractionTest(unittest.TestCase):
    def test_entrypoint_resolves_project_imports(self):
        completed = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "experiments" / "run_satc_keyword_extraction.py"), "--help"],
            cwd=PROJECT_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--satc-root", completed.stdout)

    def fixture(self, root: Path) -> argparse.Namespace:
        satc = root / "SaTC"
        (satc / "src").mkdir(parents=True)
        (satc / "src" / "satc.py").write_text(
            "import argparse\n"
            "from pathlib import Path\n"
            "p=argparse.ArgumentParser(); p.add_argument('-d'); p.add_argument('-o'); p.add_argument('-b')\n"
            "a=p.parse_args()\n"
            "out=Path(a.o)/'keyword_extract_result'/'simple'/'.data'; out.mkdir(parents=True)\n"
            "(out/(a.b+'.result')).write_text('wan_dns1\\n')\n",
            encoding="utf-8",
        )
        rootfs = root / "rootfs"
        (rootfs / "bin").mkdir(parents=True)
        binary = rootfs / "bin" / "httpd"
        binary.write_bytes(b"fixture firmware binary")
        return argparse.Namespace(
            satc_root=satc,
            satc_archive=None,
            rootfs=rootfs,
            binary=binary,
            out_dir=root / "out",
            frontend_python=Path(sys.executable),
            compat_runner=PROJECT_ROOT / "experiments" / "satc_python3_compat.py",
            timeout_sec=60,
            js_parser_environment_manifest=None,
        )

    def write_js_parser_manifest(self, root: Path, satc_root: Path) -> Path:
        parser_root = satc_root / "src" / "jsparse"
        parser_root.mkdir()
        package = parser_root / "package.json"
        package.write_text('{"name":"jsparse"}\n', encoding="utf-8")
        manifest = {
            "schema": JS_PARSER_SCHEMA,
            "success": True,
            "inputs": {"package_json": file_identity(package)},
            "environment": {"node": {"returncode": 0}, "npm_dependencies": {"returncode": 0}},
            "service_probe": {
                "endpoint": "http://127.0.0.1:3000/codeparse",
                "success": True,
                "response_sha256": "a" * 64,
            },
        }
        path = root / "js_parser_manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def test_tree_identity_accounts_for_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").write_text("a", encoding="utf-8")
            try:
                (root / "link").symlink_to("a")
            except OSError as exc:
                self.skipTest(f"symbolic links unavailable in this test environment: {exc}")
            identity = directory_identity(root)
            self.assertEqual(identity["regular_files"], 1)
            self.assertEqual(identity["symlinks"], 1)
            self.assertEqual(len(identity["sha256"]), 64)

    def test_external_binary_must_match_one_rootfs_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rootfs = root / "rootfs"
            (rootfs / "bin").mkdir(parents=True)
            root_binary = rootfs / "bin" / "httpd"
            root_binary.write_bytes(b"binary")
            copy = root / "httpd"
            copy.write_bytes(b"binary")
            self.assertEqual(resolve_rootfs_binary(rootfs, copy), root_binary)

    def test_canonicalization_preserves_set_semantics_and_stabilizes_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_a = root / "raw_a"
            raw_b = root / "raw_b"
            canonical_a = root / "canonical_a"
            canonical_b = root / "canonical_b"
            raw_a.write_text("z a z b\n", encoding="utf-8")
            raw_b.write_text("b z a\n", encoding="utf-8")
            result_a = canonicalize_keywords(raw_a, canonical_a)
            result_b = canonicalize_keywords(raw_b, canonical_b)
            self.assertEqual(canonical_a.read_bytes(), canonical_b.read_bytes())
            self.assertEqual(canonical_a.read_text(encoding="utf-8"), "a\nb\nz\n")
            self.assertEqual(result_a["raw_tokens"], 4)
            self.assertEqual(result_a["unique_tokens"], 3)
            self.assertEqual(result_b["semantic_basis"], "ref2sink_cmdi_set_split")

    def test_keyword_extraction_emits_content_bound_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(Path(directory))
            manifest = run_keyword_extraction(args)
            self.assertTrue(manifest["success"])
            self.assertEqual(manifest["inputs"]["rootfs_tree"]["regular_files"], 1)
            self.assertEqual(manifest["configuration"]["binary_name_passed_to_satc"], "httpd")
            self.assertEqual(
                manifest["configuration"]["keyword_selection"],
                "satc_set_semantics_canonicalized",
            )
            self.assertEqual(manifest["canonicalization"]["unique_tokens"], 1)
            self.assertTrue((args.out_dir / "experiment_manifest.json").is_file())
            self.assertTrue(
                (args.out_dir / "satc_output" / "keyword_extract_result" / "simple" / ".data" / "httpd.result").is_file()
            )
            self.assertEqual(
                (args.out_dir / "keywords.canonical.txt").read_text(encoding="utf-8"),
                "wan_dns1\n",
            )

    def test_keyword_extraction_binds_validated_js_parser_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            args.js_parser_environment_manifest = self.write_js_parser_manifest(root, args.satc_root)
            manifest = run_keyword_extraction(args)
            self.assertTrue(manifest["success"])
            self.assertTrue(manifest["environment"]["js_parser_environment_bound"])
            self.assertIn("js_parser_environment_manifest", manifest["inputs"])


if __name__ == "__main__":
    unittest.main()
