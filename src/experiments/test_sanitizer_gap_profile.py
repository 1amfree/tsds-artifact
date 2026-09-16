#!/usr/bin/env python3
"""Unit tests for TSDS sanitizer gap diagnosis."""

from __future__ import annotations

import importlib.util
import unittest


@unittest.skipIf(importlib.util.find_spec("angr") is None, "advanced evaluator dependencies are unavailable")
class SanitizerGapProfileTest(unittest.TestCase):
    def test_partial_filter_profile(self) -> None:
        from advanced_sanitizer_evaluator import sanitizer_gap_profile_from_report

        profile = sanitizer_gap_profile_from_report([
            "[!] VULNERABLE: Vector '$(' (Command Substitution) escapes sanitizer! -> PoC: ping $(id)",
            "[+] SECURE: Vector ';' (Command Chaining) is strongly filtered.",
            "[+] SECURE: Vector '|' (Piping) is strongly filtered.",
        ])
        self.assertEqual(profile["sanitizer_gap_strength"], "partial_filter")
        self.assertIn("Command Substitution", profile["bypass_vector_categories"])
        self.assertIn("Command Chaining", profile["blocked_vector_categories"])
        self.assertEqual(profile["minimal_bypass_vector"]["vector"], "$(")
        self.assertTrue(profile["sanitizer_repair_hints"])

    def test_fully_filtered_profile(self) -> None:
        from advanced_sanitizer_evaluator import sanitizer_gap_profile_from_report

        profile = sanitizer_gap_profile_from_report([
            "[+] SECURE: Vector ';' (Command Chaining) is strongly filtered.",
            "[+] SECURE: Vector '\\n' (Command Chaining) is strongly filtered.",
        ])
        self.assertEqual(profile["sanitizer_gap_strength"], "fully_filtered")
        self.assertEqual(profile["sanitizer_gap_profile"]["secure_count"], 2)
        self.assertFalse(profile["bypass_vector_categories"])

    def test_broadly_bypassable_profile(self) -> None:
        from advanced_sanitizer_evaluator import sanitizer_gap_profile_from_report

        profile = sanitizer_gap_profile_from_report([
            "[!] VULNERABLE: Vector ';' (Command Chaining) escapes sanitizer! -> PoC: ping ;id",
            "[!] VULNERABLE: Vector '|' (Piping) escapes sanitizer! -> PoC: ping |id",
        ])
        self.assertEqual(profile["sanitizer_gap_strength"], "broadly_bypassable")
        self.assertEqual(profile["sanitizer_gap_profile"]["vulnerable_count"], 2)


if __name__ == "__main__":
    unittest.main()
