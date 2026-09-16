#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tsds.model_refinement import (
    build_refinement_bundle,
    candidate_admission,
    candidates_for_closure,
    load_refinement_bundle,
    synthesize_candidates,
    write_refinement_bundle,
)


class ModelRefinementTest(unittest.TestCase):
    def strong_record(self) -> dict[str, object]:
        return {
            "closure_idx": 4,
            "status": "residual",
            "residual_diagnosis_class": "static_dynamic_taint_disagreement",
            "static_evidence_strength": "strong",
            "source_function": "websGetVar",
            "sink_function": "doSystem",
            "source_kinds": ["web"],
            "static_sink_template": "ping -c 1 %s",
            "residual_plan_model_gaps": [
                "source_wrapper_summary",
                "string_copy_summary",
                "format_template_binding",
            ],
            "model_gap_requests": [{"kind": "string_model"}],
        }

    def test_synthesizes_bounded_guarded_candidates(self) -> None:
        record = self.strong_record()
        candidates = synthesize_candidates(record)
        kinds = {candidate.kind for candidate in candidates}
        self.assertEqual(
            {
                "source_wrapper_summary",
                "string_transfer_summary",
                "format_binding_summary",
            },
            kinds,
        )
        self.assertTrue(all(candidate_admission(c, record).admitted for c in candidates))

    def test_weak_source_does_not_admit_source_creation(self) -> None:
        record = self.strong_record()
        record["static_evidence_strength"] = "weak"
        candidates = synthesize_candidates(record)
        self.assertFalse(
            any(
                candidate_admission(candidate, record).admitted
                for candidate in candidates
                if candidate.kind in {"source_wrapper_summary", "format_binding_summary"}
            )
        )

    def test_bundle_round_trip_and_digest(self) -> None:
        record = self.strong_record()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bundle.json"
            document = write_refinement_bundle(path, [record])
            loaded = load_refinement_bundle(path)
            self.assertEqual(document, loaded)
            self.assertEqual(3, len(candidates_for_closure(loaded, 4)))

    def test_bundle_is_deterministic(self) -> None:
        first = build_refinement_bundle([self.strong_record()])
        second = build_refinement_bundle([self.strong_record()])
        self.assertEqual(first["bundle_sha256"], second["bundle_sha256"])

    def test_bundle_does_not_synthesize_from_nonresidual_verdicts(self) -> None:
        residual = self.strong_record()
        residual["verdict"] = "RESIDUAL"
        positive = dict(residual, closure_idx=5, verdict="VECTOR_SAT", status="vulnerable")
        bundle = build_refinement_bundle([residual, positive])
        self.assertEqual("explicit_residual_verdict_only", bundle["selection_policy"])
        self.assertEqual(1, bundle["skipped_non_residual_records"])
        self.assertEqual([4], [row["closure_idx"] for row in bundle["records"]])


if __name__ == "__main__":
    unittest.main()
