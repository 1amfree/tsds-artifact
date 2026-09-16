#!/usr/bin/env python3

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from experiments.enforce_memoryerror_passthrough import transform

try:
    from advanced_sanitizer_evaluator import process_resource_snapshot
except (ImportError, ModuleNotFoundError):
    process_resource_snapshot = None


class MemoryLimitFailClosedTest(unittest.TestCase):
    def test_canonical_evaluator_has_no_unguarded_broad_handler(self) -> None:
        target = (
            Path(__file__).resolve().parents[1]
            / "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py"
        )
        _transformed, inserted = transform(target.read_text(encoding="utf-8"))
        self.assertEqual(0, inserted)

    @unittest.skipIf(process_resource_snapshot is None, "advanced evaluator dependencies unavailable")
    def test_memory_error_crosses_best_effort_telemetry_boundary(self) -> None:
        class ExhaustedResource:
            RUSAGE_SELF = 0

            @staticmethod
            def getrusage(_scope):
                raise MemoryError("calibrated limit")

        with patch.dict(
            process_resource_snapshot.__globals__, {"resource": ExhaustedResource}
        ):
            with self.assertRaises(MemoryError):
                process_resource_snapshot()


if __name__ == "__main__":
    unittest.main()
