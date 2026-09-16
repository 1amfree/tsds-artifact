#!/usr/bin/env python3
"""Unit tests for TSDS resource-envelope accounting."""

from __future__ import annotations

import unittest

from tsds.resource_envelopes import envelope_violations, summarize_resource_envelope


class ResourceEnvelopeTest(unittest.TestCase):
    def test_summary_uses_per_closure_metrics(self) -> None:
        summary = summarize_resource_envelope([
            {"status": "vulnerable", "elapsed_sec": 2.0, "process_peak_rss_kb": 1024, "process_user_cpu_sec": 1.0},
            {"status": "residual", "elapsed_sec": 4.0, "process_peak_rss_kb": 3072, "process_system_cpu_sec": 2.0},
        ])
        self.assertEqual(2, summary["records"])
        self.assertEqual(2, summary["records_with_rss"])
        self.assertEqual(3.0, summary["peak_rss_mib"])
        self.assertEqual(3.9, summary["p95_elapsed_sec"])

    def test_require_rss_fails_closed(self) -> None:
        summary = summarize_resource_envelope([{"status": "residual"}])
        self.assertIn(
            "missing_per_record_rss",
            envelope_violations(summary, require_per_record_rss=True),
        )

    def test_required_memory_limit_must_cover_every_executed_record(self) -> None:
        summary = summarize_resource_envelope([
            {
                "status": "vulnerable",
                "process_peak_rss_mib": 128.0,
                "subprocess_memory_limit_mib": 4096,
                "resource_limit_enforcement": "enforced",
            },
            {
                "status": "residual",
                "process_peak_rss_mib": 64.0,
                "subprocess_memory_limit_mib": 0,
                "resource_limit_enforcement": "not_requested",
            },
        ])
        self.assertIn(
            "memory_limit_not_requested_for_all_executed_records",
            envelope_violations(summary, require_memory_limit_enforced=True),
        )

    def test_memoized_records_do_not_require_limit_enforcement(self) -> None:
        summary = summarize_resource_envelope([
            {
                "status": "no_taint_sink",
                "memoized": True,
                "process_peak_rss_mib": 0.0,
                "subprocess_memory_limit_mib": 4096,
                "resource_limit_enforcement": "not_executed_memoized",
            },
            {
                "status": "vulnerable",
                "process_peak_rss_mib": 128.0,
                "subprocess_memory_limit_mib": 4096,
                "resource_limit_enforcement": "enforced",
            },
        ])
        self.assertEqual(
            [], envelope_violations(summary, require_memory_limit_enforced=True)
        )

    def test_terminated_worker_is_explicit_and_can_fail_strict_audit(self) -> None:
        summary = summarize_resource_envelope([
            {
                "status": "crashed",
                "subprocess_memory_limit_mib": 4096,
                "resource_limit_enforcement": "enforced",
                "resource_limit_hit": True,
                "process_resource_metric_scope": "unavailable_worker_terminated",
            },
        ])
        self.assertEqual(1, summary["records_with_unavailable_worker_metrics"])
        issues = envelope_violations(
            summary,
            fail_on_resource_limit_hits=True,
            fail_on_unavailable_worker_metrics=True,
        )
        self.assertIn("resource_limit_hit", issues)
        self.assertIn("unavailable_worker_resource_metrics", issues)


if __name__ == "__main__":
    unittest.main()
