import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

from experiments.run_satc_ghidra_experiment import (
    PROJECT_ROOT,
    build_commands,
    java_stage_environment,
    prepare_direct_ghidra_project,
    keyword_provenance_path,
    run_experiment,
    sha256_file,
    validate_inputs,
)


class SaTCGhidraExperimentTest(unittest.TestCase):
    def fixture(self, root: Path) -> argparse.Namespace:
        satc = root / "SaTC"
        ghidra = root / "ghidra"
        (satc / "src" / "headless").mkdir(parents=True)
        (ghidra / "support").mkdir(parents=True)
        for path in (
            satc / "src" / "headless" / "main.py",
            satc / "src" / "headless" / "ref2sink_cmdi.py",
            ghidra / "support" / "analyzeHeadless",
            root / "binary",
            root / "keywords.txt",
            root / "converter.py",
            root / "evaluator.py",
            root / "python",
        ):
            path.write_text("fixture\n", encoding="utf-8")
        return argparse.Namespace(
            satc_root=satc,
            ghidra_root=ghidra,
            java_home=None,
            satc_archive=None,
            keyword_extraction_manifest=None,
            keyword_provenance_manifest=None,
            binary=root / "binary",
            keywords_file=root / "keywords.txt",
            out_dir=root / "out",
            frontend_python=root / "python",
            tsds_python=root / "python",
            converter=root / "converter.py",
            evaluator=root / "evaluator.py",
            run_tsds=True,
            max_closures=20,
            memory_limit_mib=8192,
            engine_timeout=45,
            closure_timeout=90,
            subprocess_timeout=150,
            ghidra_timeout_sec=60,
            ghidra_analysis_timeout_per_file=None,
            tsds_timeout_sec=60,
        )

    def test_commands_bind_native_output_and_disable_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(Path(directory))
            inputs = validate_inputs(args)
            self.assertIn("ghidra_headless", inputs)
            commands = build_commands(args, args.out_dir)
            self.assertIn("--input-format", commands["convert"])
            self.assertIn("ghidra", commands["convert"])
            self.assertIn("--binary", commands["convert"])
            self.assertIn("--no-evidence-cache", commands["tsds"])
            self.assertTrue(
                any(value.endswith("tsds.results.jsonl") for value in commands["tsds"])
            )
            self.assertIn("evidence_contract", commands)
            self.assertIn("vector_integrity", commands)
            self.assertIn("ledger_schema", commands)
            self.assertIn("candidate_contract", commands)
            self.assertEqual(commands["tsds"][-2:], ["--max-closures", "20"])

    def test_direct_ghidra_mode_binds_analysis_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(Path(directory))
            args.ghidra_analysis_timeout_per_file = 120
            commands = build_commands(args, args.out_dir)
            command = commands["ghidra"]
            self.assertEqual(command[0], str(args.ghidra_root / "support" / "analyzeHeadless"))
            self.assertIn("-analysisTimeoutPerFile", command)
            self.assertIn("120", command)
            self.assertIn("-postscript", command)

    def test_direct_ghidra_mode_creates_project_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(Path(directory))
            args.ghidra_analysis_timeout_per_file = 120
            project = prepare_direct_ghidra_project(args, args.out_dir)
            self.assertEqual(project, args.out_dir / "ghidra_project")
            self.assertTrue(project.is_dir())

    def test_missing_analyzed_binary_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(Path(directory))
            args.binary.unlink()
            with self.assertRaises(ValueError):
                validate_inputs(args)

    def test_optional_satc_archive_and_ghidra_properties_are_content_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            archive = root / "satc-source-deps.tar.gz"
            archive.write_bytes(b"immutable fixture archive\n")
            args.satc_archive = archive
            properties = args.ghidra_root / "Ghidra" / "application.properties"
            properties.parent.mkdir()
            properties.write_text("application.version=9.2.1\n", encoding="utf-8")

            inputs = validate_inputs(args)

            self.assertIn("satc_archive", inputs)
            self.assertIn("ghidra_application_properties", inputs)
            self.assertEqual(inputs["satc_archive"], archive)
            self.assertEqual(inputs["ghidra_application_properties"], properties)

    def test_explicit_java_home_is_bound_and_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            java_home = root / "jdk"
            (java_home / "bin").mkdir(parents=True)
            (java_home / "bin" / "java").write_text("fixture java\n", encoding="utf-8")
            (java_home / "bin" / "javac").write_text("fixture javac\n", encoding="utf-8")
            (java_home / "release").write_text("JAVA_VERSION=11\n", encoding="utf-8")
            args.java_home = java_home

            inputs = validate_inputs(args)
            environment = java_stage_environment(args.java_home)

            self.assertIn("java_binary", inputs)
            self.assertIn("java_compiler", inputs)
            self.assertIn("java_release", inputs)
            self.assertEqual(environment["JAVA_HOME"], str(java_home.resolve()))
            self.assertTrue(environment["PATH"].startswith(str(java_home.resolve() / "bin")))

    def test_keyword_extraction_manifest_must_bind_keywords_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            provenance = root / "keyword_manifest.json"
            provenance.write_text(
                json.dumps(
                    {
                        "schema": "tsds-satc-keyword-extraction-v1",
                        "success": True,
                        "environment": {"js_parser_environment_bound": True},
                        "keyword_output": {
                            "size": args.keywords_file.stat().st_size,
                            "sha256": sha256_file(args.keywords_file),
                        },
                    }
                ),
                encoding="utf-8",
            )
            args.keyword_extraction_manifest = provenance
            self.assertIn("keyword_provenance_manifest", validate_inputs(args))
            provenance.write_text(
                json.dumps(
                    {
                        "schema": "tsds-satc-keyword-extraction-v1",
                        "success": True,
                        "environment": {"js_parser_environment_bound": True},
                        "keyword_output": {"size": 1, "sha256": "0" * 64},
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                validate_inputs(args)

    def test_keyword_extraction_manifest_requires_js_parser_lineage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            provenance = root / "keyword_manifest.json"
            provenance.write_text(
                json.dumps(
                    {
                        "schema": "tsds-satc-keyword-extraction-v1",
                        "success": True,
                        "keyword_output": {
                            "size": args.keywords_file.stat().st_size,
                            "sha256": sha256_file(args.keywords_file),
                        },
                    }
                ),
                encoding="utf-8",
            )
            args.keyword_extraction_manifest = provenance
            with self.assertRaises(ValueError):
                validate_inputs(args)

    def test_slice_provenance_manifest_must_bind_keywords_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            provenance = root / "slice_manifest.json"
            provenance.write_text(
                json.dumps(
                    {
                        "schema": "tsds-satc-keyword-slice-v1",
                        "success": True,
                        "parent_js_parser_environment_bound": True,
                        "slice_output": {
                            "size": args.keywords_file.stat().st_size,
                            "sha256": sha256_file(args.keywords_file),
                        },
                    }
                ),
                encoding="utf-8",
            )
            args.keyword_provenance_manifest = provenance
            self.assertIn("keyword_provenance_manifest", validate_inputs(args))

    def test_keyword_manifest_aliases_are_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            args.keyword_extraction_manifest = root / "extraction.json"
            args.keyword_provenance_manifest = root / "slice.json"
            with self.assertRaisesRegex(ValueError, "provide only one"):
                keyword_provenance_path(args)

    def test_frontend_and_conversion_run_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            args.run_tsds = False
            args.frontend_python = Path(sys.executable)
            args.tsds_python = Path(sys.executable)
            args.converter = PROJECT_ROOT / "experiments" / "convert_satc_to_tsds.py"
            main = args.satc_root / "src" / "headless" / "main.py"
            main.write_text(
                "import argparse\n"
                "p=argparse.ArgumentParser()\n"
                "p.add_argument('--ghidra-path'); p.add_argument('--binary')\n"
                "p.add_argument('--script'); p.add_argument('--project-dir')\n"
                "p.add_argument('--infile'); p.add_argument('--outfile')\n"
                "p.add_argument('--reset', action='store_true')\n"
                "a=p.parse_args()\n"
                "open(a.outfile,'w').write('[Param \\\"wan_dns1\\\"(0x500100), Referenced at sub_401000 : 0x401020] >> 0x402044 -> system\\n')\n",
                encoding="utf-8",
            )
            manifest = run_experiment(args)
            self.assertTrue(manifest["success"])
            self.assertEqual(manifest["satc_candidates"], 1)
            self.assertFalse(manifest["configuration"]["satc_archive_bound"])
            self.assertFalse(manifest["configuration"]["keyword_provenance_manifest_bound"])
            self.assertFalse(manifest["configuration"]["java_home_bound"])
            self.assertEqual(manifest["configuration"]["ghidra_execution_mode"], "satc_headless_wrapper")
            self.assertIn("candidate_contract", manifest["tsds_audits"])
            self.assertIn("output_sha256", manifest["environment"]["frontend_python"]["packages"])
            self.assertIn("output_sha256", manifest["environment"]["tsds_python"]["packages"])
            self.assertTrue((args.out_dir / "experiment_manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()
