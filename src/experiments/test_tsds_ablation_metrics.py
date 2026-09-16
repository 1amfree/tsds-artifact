import unittest

from run_tsds_ablation import summarize_run


class TsdsAblationMetricsTest(unittest.TestCase):
    def test_ablation_summary_uses_strict_verdict_ledger(self):
        summary = {
            "analysis_version": "2026-07-11-evidence-contract-v11-metrics",
            "total_closures": 5,
            "unique_pairs_analyzed": 3,
            "avg_closure_time_sec": 1.5,
            "avg_engine_steps": 12,
            "results": {
                "vulnerable": 2,
                "filtered": 1,
                "no_taint_sink": 0,
                "matrix_solver_queries_sum": 42,
            },
            "evidence_contract_ledger": {
                "verdicts": {
                    "VECTOR_SAT": 2,
                    "MATRIX_UNSAT": 1,
                    "RESIDUAL": 0,
                },
                "contract_valid": 3,
                "contract_downgraded": 0,
            },
        }
        row = summarize_run("fixture", "full", 4.0, 0, summary)
        self.assertEqual(row["analysis_version"], "2026-07-11-evidence-contract-v11-metrics")
        self.assertEqual(row["vector_sat"], 2)
        self.assertEqual(row["matrix_unsat"], 1)
        self.assertEqual(row["matrix_solver_queries"], 42)
        self.assertEqual(row["contract_downgraded"], 0)


if __name__ == "__main__":
    unittest.main()
