#!/usr/bin/env python3
"""Smoke tests for the SaTC-to-TSDS converter."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
CONVERTER = ROOT / "convert_satc_to_tsds.py"
FIXTURES = ROOT / "fixtures"


class SaTCAdapterSmokeTest(unittest.TestCase):
    def run_converter(self, *args: str) -> dict:
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td) / "closures.json"
            cmd = [sys.executable, str(CONVERTER), *args, "-o", str(out)]
            completed = subprocess.run(cmd, check=True, text=True, capture_output=True)
            self.assertIn("closures=", completed.stdout)
            return json.loads(out.read_text())

    def test_alter2_dedupes_identical_source_sink_trace(self) -> None:
        data = self.run_converter(str(FIXTURES / "satc_sample.result-alter2"), "--input-format", "alter2")
        self.assertEqual(data["schema"], "tsds-closures-v1")
        self.assertEqual(data["frontend"], "satc")
        self.assertEqual(len(data["closures"]), 2)
        self.assertEqual(data["metadata"]["stats"]["deduped_closures"], 1)
        self.assertEqual(len(data["metadata"]["input_identities"]), 1)
        self.assertEqual(len(data["metadata"]["input_identities"][0]["sha256"]), 64)
        self.assertEqual(len(data["metadata"]["converter_identity"]["sha256"]), 64)
        first = data["closures"][0]
        self.assertEqual(first["trace"][0]["ins_addr"], "0x401000")
        self.assertEqual(first["sink"]["function"], "system")
        self.assertIn("satc", first["inputs"]["tags"])
        self.assertEqual(first["inputs"]["likely"], [])
        self.assertEqual(first["inputs"]["possibly"], [])
        self.assertIn("taint_addr", first["satc"])

    def test_address_provenance_does_not_create_source_semantics(self) -> None:
        data = self.run_converter(
            str(FIXTURES / "satc_sample.result-alter2"),
            "--input-format",
            "alter2",
        )
        for closure in data["closures"]:
            self.assertEqual(closure["inputs"]["likely"], [])
            self.assertEqual(closure["inputs"]["possibly"], [])
            self.assertIn("satc_taint_site", closure["inputs"]["tags"])
            self.assertEqual(
                closure["satc"]["source_semantics_policy"],
                "address_provenance_only",
            )
            self.assertEqual(len(closure["satc"]["origin_file_sha256"]), 64)

    def test_optional_binary_is_content_bound(self) -> None:
        binary = FIXTURES / "satc_sample_result.txt"
        data = self.run_converter(
            str(FIXTURES / "satc_sample.result-alter2"),
            "--input-format",
            "alter2",
            "--binary",
            str(binary),
        )
        identity = data["metadata"]["binary_identity"]
        self.assertEqual(identity["size"], binary.stat().st_size)
        self.assertEqual(len(identity["sha256"]), 64)

    def test_native_ghidra_output_preserves_shared_keywords(self) -> None:
        data = self.run_converter(
            str(FIXTURES / "satc_sample_ref2sink_cmdi.result"),
            "--input-format",
            "ghidra",
        )
        self.assertEqual(len(data["closures"]), 2)
        first = data["closures"][0]
        self.assertEqual(first["trace"][0]["ins_addr"], "0x401020")
        self.assertEqual(first["sink"]["ins_addr"], "0x402044")
        self.assertEqual(first["inputs"]["likely"], ["wan_dns1"])
        self.assertEqual(first["satc"]["taint_addr"], "0x500100")
        self.assertEqual(data["closures"][1]["sink"]["function"], "doSystemCmd")
        stats = data["metadata"]["stats"]
        self.assertEqual(stats["raw_ghidra_candidate_lines"], 2)
        self.assertEqual(stats["raw_ghidra_malformed_candidate_lines"], 0)

    def test_result_parser_keeps_found_closures_and_accounting(self) -> None:
        data = self.run_converter(
            str(FIXTURES / "satc_sample_result.txt"),
            "--input-format",
            "result",
            "--include-not-found",
        )
        stats = data["metadata"]["stats"]
        self.assertEqual(len(data["closures"]), 2)
        self.assertEqual(stats["result_found_lines"], 1)
        self.assertEqual(stats["result_not_found_lines"], 1)
        self.assertEqual(stats["headers"]["binary"], "sample_httpd")

    def test_directory_input_and_address_shift(self) -> None:
        data = self.run_converter(str(FIXTURES), "--addr-shift", "0x1000")
        self.assertGreaterEqual(len(data["closures"]), 2)
        addresses = {closure["trace"][0]["ins_addr"] for closure in data["closures"]}
        self.assertIn("0x402000", addresses)
        self.assertEqual(data["metadata"]["addr_shift"], 0x1000)


if __name__ == "__main__":
    unittest.main()
