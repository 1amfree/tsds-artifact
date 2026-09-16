#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from build_v20_refinement_bundles import build_bundles
from tsds.model_refinement import load_refinement_bundle


class BuildV20RefinementBundlesTest(unittest.TestCase):
    def test_builder_binds_ledgers_and_excludes_nonresidual_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            campaign.mkdir()
            rows = [
                {
                    "closure_idx": 1,
                    "status": "unreachable",
                    "verdict": "RESIDUAL",
                    "residual_diagnosis_class": "environment_branch_model",
                    "source_addr": "0x1000",
                    "trace_summary": "sub_1000 -> system",
                },
                {
                    "closure_idx": 2,
                    "status": "vulnerable",
                    "verdict": "VECTOR_SAT",
                    "source_addr": "0x2000",
                    "trace_summary": "sub_2000 -> system",
                },
            ]
            (campaign / "target.results.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            out = root / "bundles"
            manifest = build_bundles(campaign, out)
            self.assertEqual("explicit_residual_verdict_only", manifest["selection_policy"])
            self.assertEqual(1, manifest["totals"]["candidate_count"])
            self.assertEqual(1, manifest["totals"]["skipped_non_residual_records"])
            bundle = load_refinement_bundle(out / "target.refinement.json")
            self.assertEqual([1], [row["closure_idx"] for row in bundle["records"]])
