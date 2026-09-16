#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from experiments.capture_satc_js_parser_environment import (
    DEFAULT_ENDPOINT,
    SCHEMA,
    capture_environment,
    file_identity,
    validate_js_parser_manifest,
    validate_loopback_endpoint,
)


def manifest_for(package: Path) -> dict:
    return {
        "schema": SCHEMA,
        "success": True,
        "inputs": {"package_json": file_identity(package)},
        "environment": {
            "node": {"returncode": 0},
            "npm_dependencies": {"returncode": 0},
        },
        "service_probe": {
            "endpoint": DEFAULT_ENDPOINT,
            "success": True,
            "response_sha256": "a" * 64,
        },
    }


class SaTCJavaScriptParserEnvironmentTest(unittest.TestCase):
    def make_root(self, root: Path) -> Path:
        js_root = root / "jsparse"
        js_root.mkdir()
        (js_root / "package.json").write_text(
            json.dumps({"name": "jsparse", "dependencies": {"esprima": "1.0.0"}}),
            encoding="utf-8",
        )
        return js_root

    def test_local_endpoint_validation(self) -> None:
        self.assertEqual(DEFAULT_ENDPOINT, validate_loopback_endpoint(DEFAULT_ENDPOINT))
        for endpoint in (
            "https://127.0.0.1:3000/codeparse",
            "http://example.com/codeparse",
            "http://127.0.0.1:3000/other",
            "http://127.0.0.1:3000/codeparse?x=1",
        ):
            with self.assertRaises(ValueError):
                validate_loopback_endpoint(endpoint)

    def test_manifest_binds_live_package_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            js_root = self.make_root(root)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest_for(js_root / "package.json")), encoding="utf-8")
            self.assertEqual(DEFAULT_ENDPOINT, validate_js_parser_manifest(manifest_path, js_root)["endpoint"])
            (js_root / "package.json").write_text('{"name":"changed"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                validate_js_parser_manifest(manifest_path, js_root)

    def test_capture_records_service_and_dependency_identities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            js_root = self.make_root(root)
            with patch(
                "experiments.capture_satc_js_parser_environment.run_command",
                side_effect=[
                    {"command": ["node", "--version"], "returncode": 0, "elapsed_sec": 0.1, "output_sha256": "b" * 64},
                    {"command": ["npm", "ls"], "returncode": 0, "elapsed_sec": 0.1, "output_sha256": "c" * 64},
                ],
            ), patch(
                "experiments.capture_satc_js_parser_environment.probe_service",
                return_value={
                    "endpoint": DEFAULT_ENDPOINT,
                    "success": True,
                    "http_status": 200,
                    "response_sha256": "d" * 64,
                    "elapsed_sec": 0.1,
                    "error": None,
                },
            ):
                manifest = capture_environment(js_root, "node", "npm", DEFAULT_ENDPOINT, root / "out")
            self.assertTrue(manifest["success"])
            self.assertTrue((root / "out" / "js_parser_environment_manifest.json").is_file())
            self.assertEqual(DEFAULT_ENDPOINT, validate_js_parser_manifest(root / "out" / "js_parser_environment_manifest.json", js_root)["endpoint"])


if __name__ == "__main__":
    unittest.main()
