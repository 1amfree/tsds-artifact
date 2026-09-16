import json
import tempfile
import unittest
from pathlib import Path

from experiments.audit_runtime_repeatability import (
    audit_campaigns,
    audit_issues,
    parse_campaign_specs,
    sample_variation,
    write_outputs,
)


def record(idx, verdict="VECTOR_SAT", elapsed=1.0, rss=100.0):
    return {
        "closure_idx": idx,
        "source_addr": 0x1000 + idx,
        "sink_addr": 0x2000 + idx,
        "closure_sink_signature": f"sink-{idx}",
        "verdict": verdict,
        "evidence_provenance": "direct_sink_observation",
        "admissible_claim": "solver_backed_sink_byte_feasibility",
        "evidence_contract_valid": True,
        "status": "vulnerable" if verdict == "VECTOR_SAT" else "not_vulnerable",
        "vector_decisions": [],
        "elapsed_sec": elapsed,
        "process_peak_rss_mib": rss,
    }


def residual_record(idx, stop_reason, elapsed=1.0, rss=100.0):
    value = record(idx, verdict="RESIDUAL", elapsed=elapsed, rss=rss)
    value.update(
        {
            "engine_stop_reason": stop_reason,
            "path_control_class": "residual_budget_stop",
            "sink_reached_observed": False,
        }
    )
    return value


class RuntimeRepeatabilityTest(unittest.TestCase):
    def write_campaign(self, root, name, rows):
        path = root / name
        path.mkdir()
        (path / "target.results.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        return path

    def test_aligned_stable_records_have_resource_variation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.write_campaign(root, "r1", [record(0, elapsed=1.0, rss=100.0)])
            second = self.write_campaign(root, "r2", [record(0, elapsed=2.0, rss=110.0)])
            rows, measurements, summary = audit_campaigns(
                [("r1", first), ("r2", second)]
            )
            self.assertEqual(summary["common_records"], 1)
            self.assertEqual(summary["semantic_stable_common_records"], 1)
            self.assertEqual(len(measurements), 4)
            self.assertTrue(rows[0]["elapsed_sec_complete"])
            self.assertAlmostEqual(rows[0]["elapsed_sec_max_min_ratio"], 2.0)
            self.assertEqual(
                summary["metrics"]["process_peak_rss_mib"]
                ["complete_semantically_stable_records"],
                1,
            )

    def test_missing_and_semantic_drift_are_explicit_exclusions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.write_campaign(root, "r1", [record(0), record(1)])
            second = self.write_campaign(
                root, "r2", [record(0, verdict="MATRIX_UNSAT")]
            )
            rows, _measurements, summary = audit_campaigns(
                [("r1", first), ("r2", second)]
            )
            self.assertEqual(summary["union_records"], 2)
            self.assertEqual(summary["common_records"], 1)
            self.assertEqual(summary["semantic_drift_common_records"], 1)
            self.assertEqual(summary["semantic_stable_common_records"], 0)
            self.assertFalse(any(row["elapsed_sec_complete"] for row in rows))
            issues = audit_issues(
                summary,
                require_complete_records=True,
                require_semantic_stability=True,
                require_complete_metrics=False,
                max_elapsed_cv_p95=None,
                max_rss_cv_p95=None,
                max_total_elapsed_ratio=None,
            )
            self.assertEqual(len(issues), 3)

    def test_thresholds_are_opt_in_and_fail_closed(self):
        summary = {
            "records_missing_from_at_least_one_run": 0,
            "semantic_drift_common_records": 0,
            "semantic_stable_common_records": 1,
            "metrics": {
                "elapsed_sec": {
                    "complete_semantically_stable_records": 1,
                    "per_record_cv": {"p95": 0.7},
                    "per_run_aggregate": {"max_min_ratio": 1.8},
                },
                "process_peak_rss_mib": {
                    "complete_semantically_stable_records": 1,
                    "per_record_cv": {"p95": 0.1},
                    "per_run_aggregate": {"max_min_ratio": 1.1},
                },
            },
        }
        self.assertEqual(
            audit_issues(
                summary,
                require_complete_records=False,
                require_semantic_stability=False,
                require_complete_metrics=False,
                max_elapsed_cv_p95=None,
                max_rss_cv_p95=None,
                max_total_elapsed_ratio=None,
            ),
            [],
        )
        issues = audit_issues(
            summary,
            require_complete_records=False,
            require_semantic_stability=False,
            require_complete_metrics=False,
            max_elapsed_cv_p95=0.5,
            max_rss_cv_p95=0.2,
            max_total_elapsed_ratio=1.5,
        )
        self.assertEqual(len(issues), 2)

    def test_diagnostic_only_residual_drift_is_accounted_not_measured(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.write_campaign(
                root,
                "r1",
                [
                    record(0, elapsed=1.0, rss=100.0),
                    residual_record(1, "guided_stagnation_saturated"),
                ],
            )
            second = self.write_campaign(
                root,
                "r2",
                [
                    record(0, elapsed=2.0, rss=110.0),
                    residual_record(1, "engine_timeout"),
                ],
            )
            rows, _measurements, summary = audit_campaigns(
                [("r1", first), ("r2", second)]
            )
            self.assertEqual(summary["semantic_drift_common_records"], 1)
            self.assertEqual(summary["sink_semantic_drift_common_records"], 0)
            self.assertEqual(
                summary["accounted_residual_diagnostic_drift_common_records"], 1
            )
            self.assertEqual(
                summary["unaccounted_residual_evidence_drift_common_records"], 0
            )
            self.assertEqual(
                summary["metrics"]["elapsed_sec"]["complete_semantically_stable_records"],
                1,
            )
            self.assertEqual(
                {row["drift_class"] for row in rows},
                {"stable", "accounted_residual_diagnostic_drift"},
            )
            issues = audit_issues(
                summary,
                require_complete_records=True,
                require_semantic_stability=False,
                require_sink_semantic_stability=True,
                require_non_residual_evidence_stability=True,
                require_residual_diagnostic_accounting=True,
                require_sink_semantic_records=True,
                require_complete_metrics=True,
                max_elapsed_cv_p95=None,
                max_rss_cv_p95=None,
                max_total_elapsed_ratio=None,
            )
            self.assertEqual(issues, [])

    def test_residual_evidence_drift_remains_a_release_gate_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_residual = residual_record(1, "guided_stagnation_saturated")
            second_residual = residual_record(1, "engine_timeout")
            second_residual["source_kinds"] = ["configuration"]
            first = self.write_campaign(root, "r1", [record(0), first_residual])
            second = self.write_campaign(root, "r2", [record(0), second_residual])
            _rows, _measurements, summary = audit_campaigns(
                [("r1", first), ("r2", second)]
            )
            self.assertEqual(
                summary["unaccounted_residual_evidence_drift_common_records"], 1
            )
            issues = audit_issues(
                summary,
                require_complete_records=True,
                require_semantic_stability=False,
                require_sink_semantic_stability=True,
                require_non_residual_evidence_stability=True,
                require_residual_diagnostic_accounting=True,
                require_sink_semantic_records=True,
                require_complete_metrics=False,
                max_elapsed_cv_p95=None,
                max_rss_cv_p95=None,
                max_total_elapsed_ratio=None,
            )
            self.assertEqual(
                issues,
                [
                    "one or more residual drifts change evidence outside the "
                    "diagnostic boundary"
                ],
            )

    def test_non_residual_evidence_drift_remains_a_release_gate_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.write_campaign(
                root,
                "r1",
                [record(0), record(1, verdict="STATIC_WARNING_REDUCTION")],
            )
            second = self.write_campaign(
                root,
                "r2",
                [record(0), residual_record(1, "engine_timeout")],
            )
            _rows, _measurements, summary = audit_campaigns(
                [("r1", first), ("r2", second)]
            )
            self.assertEqual(summary["non_residual_evidence_drift_common_records"], 1)
            issues = audit_issues(
                summary,
                require_complete_records=True,
                require_semantic_stability=False,
                require_sink_semantic_stability=True,
                require_non_residual_evidence_stability=True,
                require_residual_diagnostic_accounting=True,
                require_sink_semantic_records=True,
                require_complete_metrics=False,
                max_elapsed_cv_p95=None,
                max_rss_cv_p95=None,
                max_total_elapsed_ratio=None,
            )
            self.assertEqual(
                issues,
                ["one or more non-residual evidence records have semantic drift"],
            )

    def test_campaign_specs_require_unique_labels_and_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").mkdir()
            (root / "b").mkdir()
            parsed = parse_campaign_specs([f"a={root / 'a'}", f"b={root / 'b'}"])
            self.assertEqual([label for label, _path in parsed], ["a", "b"])
            with self.assertRaises(ValueError):
                parse_campaign_specs([f"a={root / 'a'}"])

    def test_zero_metrics_do_not_divide_by_zero(self):
        variation = sample_variation([0.0, 0.0])
        self.assertEqual(variation["cv"], 0.0)
        self.assertEqual(variation["max_min_ratio"], 1.0)

    def test_empty_stable_cohort_writes_explicit_table_placeholders(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.write_campaign(root, "r1", [record(0)])
            second = self.write_campaign(
                root, "r2", [record(0, verdict="MATRIX_UNSAT")]
            )
            rows, measurements, summary = audit_campaigns(
                [("r1", first), ("r2", second)]
            )
            summary["issues"] = ["no stable cohort"]
            output = root / "audit"
            write_outputs(output, rows, measurements, summary)
            latex = (output / "runtime_repeatability_table.tex").read_text(
                encoding="utf-8"
            )
            self.assertIn("--", latex)
            self.assertTrue(
                (output / "runtime_repeatability_summary.json").is_file()
            )


if __name__ == "__main__":
    unittest.main()
