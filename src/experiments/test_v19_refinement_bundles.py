#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from audit_v19_refinement_bundles import audit_bundles
from tsds.model_refinement import build_refinement_bundle


class V19RefinementBundleAuditTest(unittest.TestCase):
    def test_bundle_is_recomputed_against_source_residual(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Path(tmp)
            record = {
                "closure_idx": 4,
                "status": "unreachable",
                "verdict": "RESIDUAL",
                "residual_diagnosis_class": "environment_branch_model",
                "engine_stop_reason": "environment_branch_model",
                "source_addr": "0x1000",
                "trace_summary": "sub_1000 -> system",
                "static_evidence_strength": "absent",
            }
            (campaign / "target.results.jsonl").write_text(
                json.dumps(record) + "\n", encoding="utf-8"
            )
            bundle = build_refinement_bundle([record])
            (campaign / "target.refinement.json").write_text(
                json.dumps(bundle), encoding="utf-8"
            )
            rows, summary = audit_bundles(campaign)
            self.assertEqual(1, len(rows))
            self.assertEqual(1, summary["admitted"])
            self.assertEqual({"RESIDUAL": 1}, summary["source_verdicts"])
            self.assertTrue(summary["valid"])

    def test_candidate_from_nonresidual_record_is_rejected_by_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Path(tmp)
            residual = {
                "closure_idx": 1,
                "status": "unreachable",
                "verdict": "RESIDUAL",
                "residual_diagnosis_class": "environment_branch_model",
                "source_addr": "0x1000",
                "trace_summary": "sub_1000 -> system",
            }
            bundle = build_refinement_bundle([residual])
            changed = dict(residual, verdict="NO_MODELED_SOURCE", status="no_taint_sink")
            (campaign / "target.results.jsonl").write_text(
                json.dumps(changed) + "\n", encoding="utf-8"
            )
            (campaign / "target.refinement.json").write_text(
                json.dumps(bundle), encoding="utf-8"
            )
            _, summary = audit_bundles(campaign)
            self.assertFalse(summary["valid"])
            self.assertEqual(1, summary["issue_counts"]["candidate_source_not_residual"])

    def test_audit_can_read_bundles_from_a_separate_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign, bundles = root / "campaign", root / "bundles"
            campaign.mkdir()
            bundles.mkdir()
            record = {
                "closure_idx": 2,
                "status": "unreachable",
                "verdict": "RESIDUAL",
                "residual_diagnosis_class": "environment_branch_model",
                "source_addr": "0x1000",
                "trace_summary": "sub_1000 -> system",
            }
            (campaign / "target.results.jsonl").write_text(
                json.dumps(record) + "\n", encoding="utf-8"
            )
            bundle = build_refinement_bundle([record])
            (bundles / "target.refinement.json").write_text(
                json.dumps(bundle), encoding="utf-8"
            )
            _, summary = audit_bundles(campaign, bundles)
            self.assertTrue(summary["valid"])
            self.assertEqual(str(bundles), summary["bundle_dir"])


if __name__ == "__main__":
    unittest.main()
