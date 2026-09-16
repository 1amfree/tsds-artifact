#!/usr/bin/env python3
"""Tests for the TSDS sink-intercept harness-pack generator."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_sink_intercept_harness_pack import build_pack


TASK = {
    "candidate_id": "poc-99",
    "target": "Tenda AC18",
    "functional_theme": "samba",
    "source_function": "formSetSambaConf",
    "sink": "doSystemCmd@0xa55ac",
    "source_keys": "usb.samba.user; usb.samba.pwd",
    "entry_clues": "formSetSambaConf; SetSambaCfg",
    "tsds_preview": "<recovered_config>",
    "repro_signature": "vulnerable; 11 SAT / 0 UNSAT",
    "canary_token": "TSDS_CANARY_POC_99",
}


class SinkInterceptHarnessPackTest(unittest.TestCase):
    def test_pack_contains_safe_artifacts_and_validator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "pack"
            summary = build_pack([TASK], out_dir)
            self.assertEqual(summary["tasks"], 1)

            task_dir = out_dir / "poc-99_tenda_ac18_samba"
            manifest = json.loads((task_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertFalse(manifest["safety_contract"]["shell_execution"])
            self.assertEqual(manifest["sink_function"], "doSystemCmd")
            self.assertEqual(manifest["sink_address"], "0xa55ac")

            hook = (task_dir / "hooks" / "sink_intercept.c").read_text(encoding="utf-8")
            self.assertIn("Never invoke", hook)
            self.assertIn("executed", hook)
            self.assertIn("false", hook)

            fixture = (task_dir / "fixtures" / "config_fixture.env").read_text(encoding="utf-8")
            self.assertIn("TSDS_KEY_USB_SAMBA_USER=TSDS_CANARY_POC_99", fixture)

            log = out_dir / "mock_intercept.log"
            log.write_text(
                '{"sink":"doSystemCmd","arg":"prefix TSDS_CANARY_POC_99 suffix","executed":false}\n',
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(out_dir / "validate_intercept_log.py"),
                    str(task_dir / "manifest.json"),
                    str(log),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            result = json.loads(proc.stdout)
            self.assertEqual(result["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
