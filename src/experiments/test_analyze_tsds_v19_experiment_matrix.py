#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from analyze_tsds_v19_experiment_matrix import (
    compare_configuration,
    corpus_summary,
    fingerprint_issues,
    load_campaign_records,
    paired_bootstrap_delta,
)


def fixture_record(index: int, **updates):
    record = {
        "closure_idx": index,
        "source_addr": hex(0x1000 + index),
        "sink_addr": "0x2000",
        "closure_sink_signature": [hex(0x1000 + index), "0x2000"],
        "status": "filtered",
        "verdict": "MATRIX_UNSAT",
        "evidence_provenance": "DIRECT_SINK_BYTE",
        "admissible_claim": "matrix_bounded_filtering",
        "evidence_contract_valid": True,
        "controlled_offsets": [1],
        "sink_semantics": "shell_command",
        "sink_argument_binding_trust": "direct_abi_arg0",
        "sink_snapshot_cstring_complete": True,
        "elapsed_sec": 2.0 + index,
        "process_peak_rss_mib": 100.0,
        "engine_steps_total": 20,
        "vector_decisions": [],
    }
    record.update(updates)
    return record


class V19AblationAnalysisTest(unittest.TestCase):
    def test_paired_bootstrap_is_deterministic_and_directional(self) -> None:
        pairs = [(1.0, 2.0), (2.0, 4.0), (3.0, 6.0)]
        first = paired_bootstrap_delta(pairs, replicates=500, seed=7)
        second = paired_bootstrap_delta(pairs, replicates=500, seed=7)
        self.assertEqual(first, second)
        self.assertGreater(first["mean_variant_minus_baseline"], 0)
        self.assertEqual(100.0, first["paired_total_change_pct"])

    def test_comparison_reports_semantic_and_resource_pairing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            baseline_dir = Path(tmp) / "baseline"
            variant_dir = Path(tmp) / "variant"
            baseline_dir.mkdir()
            variant_dir.mkdir()
            rows = [fixture_record(0), fixture_record(1)]
            (baseline_dir / "target.results.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )
            changed = [dict(row, elapsed_sec=row["elapsed_sec"] + 1.0) for row in rows]
            (variant_dir / "target.results.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in changed), encoding="utf-8"
            )
            baseline = load_campaign_records(baseline_dir)
            variant = load_campaign_records(variant_dir)
            result = compare_configuration(
                "p1_projection_off",
                baseline,
                variant,
                bootstrap_replicates=200,
            )
            self.assertEqual(2, result["common_records"])
            self.assertEqual(100.0, result["semantic_agreement_pct"])
            self.assertEqual(100.0, result["sink_semantic_agreement_pct"])
            self.assertEqual(
                1.0,
                result["paired_metrics"]["elapsed_sec"][
                    "mean_variant_minus_baseline"
                ],
            )
            baseline_summary = corpus_summary(baseline)
            self.assertEqual(2, baseline_summary["records"])
            self.assertEqual({"MATRIX_UNSAT": 2}, baseline_summary["verdicts"])

    def test_fingerprint_comparison_binds_evaluator_and_inputs(self) -> None:
        baseline = {
            "evaluator_sha256": "a",
            "targets": {"t": {"binary_sha256": "b", "mango_sha256": "m"}},
        }
        self.assertEqual([], fingerprint_issues(baseline, baseline))
        variant = {
            "evaluator_sha256": "x",
            "targets": {"t": {"binary_sha256": "c", "mango_sha256": "m"}},
        }
        self.assertEqual(
            ["evaluator_sha256_mismatch", "t_binary_sha256_mismatch"],
            fingerprint_issues(baseline, variant),
        )


if __name__ == "__main__":
    unittest.main()
