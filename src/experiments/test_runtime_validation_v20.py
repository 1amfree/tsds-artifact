#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from experiments.build_runtime_validation_expansion_pack import (
    SCHEMA,
    canonical_rows_sha256,
    campaign_identity,
    classify_record,
    select_candidates,
)


class RuntimeValidationV20Test(unittest.TestCase):
    def test_v20_contract_classes_take_precedence_over_legacy_status(self) -> None:
        self.assertEqual(
            "static_warning_reduction",
            classify_record(
                {
                    "verdict": "STATIC_WARNING_REDUCTION",
                    "status": "no_taint_sink",
                }
            ),
        )
        self.assertEqual(
            "static_source_inference",
            classify_record(
                {
                    "verdict": "STATIC_SOURCE_INFERENCE",
                    "status": "vulnerable",
                }
            ),
        )
        self.assertEqual(
            "nms",
            classify_record({"verdict": "NO_MODELED_SOURCE", "status": "residual"}),
        )

    def test_vector_sat_subclasses_are_preserved(self) -> None:
        self.assertEqual("direct_sv_sat", classify_record({"verdict": "VECTOR_SAT"}))
        self.assertEqual(
            "guarded_sv_sat",
            classify_record(
                {"verdict": "VECTOR_SAT", "analysis_recovery": "guarded_static"}
            ),
        )
        self.assertEqual(
            "partial_sv_sat",
            classify_record(
                {
                    "verdict": "VECTOR_SAT",
                    "vulnerable_vectors": 1,
                    "secure_vectors": 2,
                }
            ),
        )

    def test_candidate_selection_keeps_static_classes_separate(self) -> None:
        rows = [
            {"verdict": "STATIC_SOURCE_INFERENCE", "_target": "t", "closure_idx": 1},
            {"verdict": "STATIC_WARNING_REDUCTION", "_target": "t", "closure_idx": 2},
            {"verdict": "NO_MODELED_SOURCE", "_target": "t", "closure_idx": 3},
        ]
        selected = select_candidates(rows, limit_per_class=1)
        self.assertEqual(
            {"static_source_inference", "static_warning_reduction", "nms"},
            {row["stratum"] for row in selected},
        )

    def test_campaign_identity_is_content_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = root / "target.results.jsonl"
            ledger.write_text('{"verdict":"RESIDUAL"}\n', encoding="utf-8")
            first = campaign_identity(root)
            ledger.write_text('{"verdict":"NO_MODELED_SOURCE"}\n', encoding="utf-8")
            second = campaign_identity(root)
            self.assertEqual(SCHEMA, "tsds-runtime-validation-expansion-v2")
            self.assertNotEqual(
                first["results_identity_sha256"], second["results_identity_sha256"]
            )

    def test_population_identity_is_order_and_content_sensitive(self) -> None:
        rows = [{"id": "a", "result": 1}, {"id": "b", "result": 2}]
        self.assertEqual(canonical_rows_sha256(rows), canonical_rows_sha256(list(rows)))
        self.assertNotEqual(canonical_rows_sha256(rows), canonical_rows_sha256(list(reversed(rows))))
        changed = [dict(row) for row in rows]
        changed[1]["result"] = 3
        self.assertNotEqual(canonical_rows_sha256(rows), canonical_rows_sha256(changed))


if __name__ == "__main__":
    unittest.main()
