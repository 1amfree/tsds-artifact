"""Unit tests for the controlled witness replay safety boundary."""

from __future__ import annotations

import unittest

from experiments.run_saner2027_witness_replay import (
    decode_rendered_witness,
    safety_gate,
)


class WitnessReplaySafetyTests(unittest.TestCase):
    def test_decodes_encoded_shell_whitespace(self) -> None:
        self.assertEqual(
            decode_rendered_witness(r"echo :\x0a:;#AAAA"),
            "echo :\n:;#AAAA",
        )
        self.assertEqual(
            decode_rendered_witness(r"echo \x09:AAAA"),
            "echo \t:AAAA",
        )

    def test_accepts_observed_benchmark_templates(self) -> None:
        cases = (
            "echo :;:;#AAAA",
            "printf fixed && echo $(:)AAAA",
            "echo '':;:;#AAAA",
            "echo \"\">/dev/null;#AAAA",
            "echo :\n:;#AAAA",
            "echo \t:AAAA",
        )
        for case in cases:
            with self.subTest(case=repr(case)):
                self.assertEqual(safety_gate(case)[0], True)

    def test_rejects_commands_outside_the_allowlist(self) -> None:
        cases = (
            "echo $(cat /etc/passwd)",
            "echo >/tmp/tsds-danger",
            "echo ${TSDS_TRIGGER_PATH}",
            "rm -rf /",
            "echo `:; rm -rf /`AAAA",
        )
        for case in cases:
            with self.subTest(case=repr(case)):
                self.assertEqual(safety_gate(case)[0], False)


if __name__ == "__main__":
    unittest.main()
