"""Tests for the randomized conditioned-link property calibration."""

from __future__ import annotations

import unittest

from run_conditioned_link_property_calibration import (
    MUTATIONS_PER_OPERATION,
    PAYLOADS_PER_OPERATION,
    _mutations,
    _payloads,
    bind_trace,
    build_link,
    build_trace,
    CASES,
    assess,
    replay_source_trace,
)


class ConditionedLinkPropertyCalibrationTest(unittest.TestCase):
    def test_payload_generation_is_deterministic_and_bounded(self) -> None:
        import random

        first = _payloads(random.Random(20260916))
        second = _payloads(random.Random(20260916))
        self.assertEqual(first, second)
        self.assertEqual(PAYLOADS_PER_OPERATION, len(first))
        self.assertTrue(all(len(payload) <= 64 for payload in first))

    def test_mutation_suite_has_expected_rejections(self) -> None:
        mode, operation, _ = CASES[0]
        trace = bind_trace(build_trace(mode, operation, b"ABC;"))
        replay = replay_source_trace(trace)
        link = build_link(replay, "a" * 64, operation)
        mutations = list(_mutations(trace, link))
        self.assertEqual(MUTATIONS_PER_OPERATION, len(mutations))
        for name, mutated_trace, mutated_link in mutations:
            result = assess(mutated_trace, mutated_link)
            self.assertFalse(result["admitted"], msg=f"mutation admitted: {name}")


if __name__ == "__main__":
    unittest.main()
