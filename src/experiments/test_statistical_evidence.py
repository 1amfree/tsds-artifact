#!/usr/bin/env python3
"""Regression tests for deterministic TSDS statistical evidence."""

from __future__ import annotations

import unittest

from tsds.statistical_evidence import (
    agreement_statistics,
    paired_bootstrap_differences,
    percentile_interval,
)


class StatisticalEvidenceTest(unittest.TestCase):
    def test_agreement_statistics_are_deterministic_and_label_complete(self) -> None:
        pairs = [
            ("POSITIVE", "POSITIVE"),
            ("POSITIVE", "NEGATIVE"),
            ("NEGATIVE", "NEGATIVE"),
            ("UNRESOLVED", "UNRESOLVED"),
        ]
        kwargs = {"bootstrap_replicates": 500, "bootstrap_seed": 17}
        first = agreement_statistics(
            pairs, ("POSITIVE", "NEGATIVE", "UNRESOLVED"), **kwargs
        )
        second = agreement_statistics(
            pairs, ("POSITIVE", "NEGATIVE", "UNRESOLVED"), **kwargs
        )
        self.assertEqual(first, second)
        self.assertEqual(1, first["confusion_matrix"]["POSITIVE"]["NEGATIVE"])
        self.assertEqual(3, len(first["per_label"]))
        self.assertEqual(500, first["bootstrap"]["requested_replicates"])
        self.assertIsNotNone(first["cohen_kappa_bootstrap_95"])

    def test_perfect_constant_agreement_has_defined_kappa(self) -> None:
        result = agreement_statistics(
            [("POSITIVE", "POSITIVE")] * 4,
            ("POSITIVE", "NEGATIVE", "UNRESOLVED"),
            bootstrap_replicates=50,
        )
        self.assertEqual(1.0, result["cohen_kappa"])
        self.assertEqual([1.0, 1.0], result["cohen_kappa_bootstrap_95"])

    def test_paired_bootstrap_reports_positive_effect(self) -> None:
        rows = [
            (True, False, True),
            (False, True, False),
            (True, False, True),
            (False, True, False),
        ]
        result = paired_bootstrap_differences(
            rows, bootstrap_replicates=500, bootstrap_seed=23
        )
        accuracy = result["metrics"]["accuracy"]
        self.assertEqual(1.0, accuracy["tsds_minus_external"])
        self.assertEqual([1.0, 1.0], accuracy["bootstrap_95"])
        self.assertEqual(1.0, accuracy["probability_greater_than_zero"])

    def test_empty_percentile_interval_is_explicit(self) -> None:
        self.assertIsNone(percentile_interval([]))


if __name__ == "__main__":
    unittest.main()
