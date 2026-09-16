#!/usr/bin/env python3

from __future__ import annotations

import unittest

from experiments.run_busybox_shell_vector_calibration import VECTORS, generated_cases


class BusyBoxShellVectorCalibrationTest(unittest.TestCase):
    def test_suite_has_eight_contexts_for_all_eleven_vectors(self) -> None:
        cases = generated_cases()
        self.assertEqual(len(VECTORS), 11)
        self.assertEqual(len(cases), 88)
        by_vector = {name: set() for name, *_ in VECTORS}
        for case in cases:
            by_vector[case["vector"]].add(case["context"])
        for contexts in by_vector.values():
            self.assertEqual(
                contexts,
                {
                    "current_bare",
                    "current_unquoted_argument",
                    "current_single_quoted",
                    "current_double_quoted",
                    "v2_unquoted_witness",
                    "v2_single_quote_breakout",
                    "v2_double_quote_breakout",
                    "complete_canary",
                },
            )


if __name__ == "__main__":
    unittest.main()
