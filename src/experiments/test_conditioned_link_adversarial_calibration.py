"""Tests for the conditioned-link adversarial calibration."""

from __future__ import annotations

import unittest

from run_conditioned_link_adversarial_calibration import (
    CASES,
    adversarial_mutations,
    assess,
    make_bound_fixture,
)


class ConditionedLinkAdversarialCalibrationTest(unittest.TestCase):
    def test_all_bounded_transform_cases_are_admitted(self) -> None:
        for _, operation, payloads in CASES:
            for payload in payloads:
                trace, link = make_bound_fixture(operation, payload)
                result = assess(trace, link)
                self.assertTrue(
                    result["admitted"],
                    msg=f"{operation}/{payload!r}: {result['issues']}",
                )

    def test_all_adversarial_mutations_are_rejected(self) -> None:
        trace, link = make_bound_fixture("copy", b"ABC;")
        mutations = list(adversarial_mutations(trace, link))
        self.assertEqual(13, len(mutations))
        for name, mutated_trace, mutated_link in mutations:
            result = assess(mutated_trace, mutated_link)
            self.assertFalse(
                result["admitted"],
                msg=f"mutation {name} was admitted: {result}",
            )


if __name__ == "__main__":
    unittest.main()
