"""Tests for exact and bounded stratified sample quotas."""

from __future__ import annotations

import unittest

from experiments.build_blinded_ground_truth_sample import select_sample


def _records() -> list[dict[str, object]]:
    rows = []
    for stratum, count in (
        ("direct_vector_sat", 3),
        ("reconciled_vector_sat", 3),
        ("matrix_unsat", 2),
    ):
        for index in range(count):
            rows.append(
                {
                    "_target": f"target-{index}",
                    "closure_idx": index,
                    "source_addr": hex(index + 1),
                    "sink_addr": hex(index + 100),
                    "verdict": (
                        "VECTOR_SAT" if stratum != "matrix_unsat" else "MATRIX_UNSAT"
                    ),
                    "evidence_provenance": (
                        "DIRECT_SINK_BYTE"
                        if stratum == "direct_vector_sat"
                        else "SINK_RECONCILED"
                        if stratum == "reconciled_vector_sat"
                        else "DIRECT_SINK_BYTE"
                    ),
                    "_forced_stratum": stratum,
                }
            )
    return rows


class GroundTruthSampleTests(unittest.TestCase):
    def test_exact_quota_is_respected(self) -> None:
        rows = _records()
        # Use the production classifier fields, while replacing the helper's
        # stratum classifier locally is intentionally avoided. This verifies
        # the two production SAT strata and matrix stratum available here.
        sample = select_sample(
            rows,
            per_stratum=1,
            seed=20260913,
            quotas={
                "direct_vector_sat": 2,
                "reconciled_vector_sat": 2,
                "matrix_unsat": 2,
            },
        )
        self.assertEqual(len(sample), 6)

    def test_quota_cannot_exceed_population(self) -> None:
        with self.assertRaises(ValueError):
            select_sample(
                _records(),
                per_stratum=1,
                seed=20260913,
                quotas={
                    "direct_vector_sat": 4,
                    "reconciled_vector_sat": 2,
                    "matrix_unsat": 2,
                },
            )


if __name__ == "__main__":
    unittest.main()
