import importlib.util
import unittest
from types import SimpleNamespace


@unittest.skipIf(
    importlib.util.find_spec("claripy") is None,
    "claripy unavailable",
)
class ThreatMatrixMetricsTest(unittest.TestCase):
    def test_solver_queries_are_counted_for_each_matrix_evaluation(self):
        import claripy
        from advanced_sanitizer_evaluator import ThreatMatrixEvaluator

        state = SimpleNamespace(solver=claripy.Solver(), globals={})
        source = [claripy.BVS(f"webvar_metric_{idx}", 8) for idx in range(16)]
        target = source + [claripy.BVV(0, 8)]
        report = ThreatMatrixEvaluator.evaluate(state, source, target_bytes=target)
        self.assertEqual(len(report), 11)
        self.assertGreater(state.globals["threat_matrix_solver_queries"], 0)
        self.assertEqual(len(state.globals["threat_matrix_decisions"]), 11)

    def test_no_controlled_sink_byte_has_zero_matrix_queries(self):
        import claripy
        from advanced_sanitizer_evaluator import ThreatMatrixEvaluator

        state = SimpleNamespace(solver=claripy.Solver(), globals={})
        source = [claripy.BVS("webvar_metric_source", 8)]
        target = [claripy.BVV(ord("x"), 8), claripy.BVV(0, 8)]
        ThreatMatrixEvaluator.evaluate(state, source, target_bytes=target)
        self.assertEqual(state.globals["threat_matrix_solver_queries"], 0)


if __name__ == "__main__":
    unittest.main()
