"""Tests for the runtime/current-campaign identity-boundary audit."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from experiments.audit_runtime_current_input_alignment import input_descriptors


ROOT = Path(__file__).resolve().parents[1]


class RuntimeCurrentInputAlignmentTests(unittest.TestCase):
    def test_declared_binary_and_mango_inputs_are_identical(self) -> None:
        old_path = ROOT / "experiment_reports/tsds_v20_release_20260718_r7_v8/tsds_v20_accepted_repeat_20260718_r7/campaign/campaign_configuration.json"
        current_path = ROOT / "experiment_reports/full_firmware_campaign_current_tsds_multistate_full_20260916/campaign_configuration.json"
        old = json.loads(old_path.read_text(encoding="utf-8"))
        current = json.loads(current_path.read_text(encoding="utf-8"))
        self.assertEqual(input_descriptors(old), input_descriptors(current))
        self.assertEqual(len(input_descriptors(current)), 8)

    def test_analysis_versions_are_not_collapsed(self) -> None:
        old_path = ROOT / "experiment_reports/tsds_v20_release_20260718_r7_v8/tsds_v20_accepted_repeat_20260718_r7/campaign/campaign_configuration.json"
        current_path = ROOT / "experiment_reports/full_firmware_campaign_current_tsds_multistate_full_20260916/campaign_configuration.json"
        old = json.loads(old_path.read_text(encoding="utf-8"))
        current = json.loads(current_path.read_text(encoding="utf-8"))
        self.assertNotEqual(old.get("evaluator_sha256"), current.get("evaluator_sha256"))
        self.assertNotEqual(old.get("campaign_driver_sha256"), current.get("campaign_driver_sha256"))


if __name__ == "__main__":
    unittest.main()
