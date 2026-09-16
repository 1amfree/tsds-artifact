#!/usr/bin/env python3
"""Tests for TSDS performance diagnostics."""

from __future__ import annotations

import unittest

from tsds.performance_diagnostics import (
    distribution,
    spearman_correlation,
    summarize_performance,
)


class PerformanceDiagnosticsTest(unittest.TestCase):
    def test_distribution_reports_tail_quantiles_and_mad(self) -> None:
        result = distribution([1, 2, 3, 4, 100])
        self.assertEqual(3.0, result["p50"])
        self.assertEqual(1.0, result["mad"])
        self.assertEqual(100.0, result["max"])

    def test_spearman_correlation_handles_monotonic_data(self) -> None:
        self.assertEqual(1.0, spearman_correlation([(1, 10), (2, 20), (3, 30)]))
        self.assertEqual(-1.0, spearman_correlation([(1, 30), (2, 20), (3, 10)]))

    def test_summary_accounts_for_groups_and_tails(self) -> None:
        records = []
        for index in range(20):
            records.append(
                {
                    "_target": "a" if index < 10 else "b",
                    "closure_idx": index,
                    "verdict": "VECTOR_SAT" if index % 2 else "RESIDUAL",
                    "evidence_provenance": "DIRECT_SINK_BYTE",
                    "elapsed_sec": index + 1,
                    "process_peak_rss_mib": 100 + index,
                    "engine_steps_total": 10 * (index + 1),
                    "subprocess_memory_limit_mib": 8192,
                    "resource_limit_hit": False,
                }
            )
        tails, summary = summarize_performance(records)
        self.assertEqual(20, summary["records"])
        self.assertEqual({"a", "b"}, set(summary["per_target"]))
        self.assertGreaterEqual(len(tails), 1)
        self.assertEqual({}, summary["missing_metrics"])
        self.assertEqual({}, summary["structurally_not_applicable_metrics"])
        self.assertEqual(0, summary["resource_limit_hits"])

    def test_static_reduction_without_engine_steps_is_structural(self) -> None:
        _, summary = summarize_performance(
            [
                {
                    "_target": "a",
                    "closure_idx": 1,
                    "verdict": "STATIC_WARNING_REDUCTION",
                    "elapsed_sec": 0.2,
                    "process_peak_rss_mib": 160,
                    "subprocess_memory_limit_mib": 8192,
                }
            ]
        )
        self.assertEqual({}, summary["missing_metrics"])
        self.assertEqual(
            {"engine_steps_total": 1}, summary["structurally_not_applicable_metrics"]
        )


if __name__ == "__main__":
    unittest.main()
