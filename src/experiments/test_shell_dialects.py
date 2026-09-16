#!/usr/bin/env python3
"""Tests for quote-context-aware shell dialect audit rules."""

from __future__ import annotations

import unittest

from tsds.shell_dialects import active_in_quote_context, audit_decision
from tsds.shell_dialects import audit_records
from tsds.shell_matrix_spec import matrix_spec_sha256


class ShellDialectTest(unittest.TestCase):
    def test_single_quote_deactivates_control_operator(self) -> None:
        self.assertFalse(active_in_quote_context("semicolon", "single_quoted"))
        row = audit_decision(
            {
                "vector_id": "semicolon",
                "decision": "VECTOR_SAT",
                "grammar_complete": True,
                "lexical_reason": "lexically_complete",
                "quote_context": "single_quoted",
            },
            "busybox_ash",
        )
        self.assertIn("sat_vector_inactive_in_quote_context", row["issues"])

    def test_double_quote_allows_dollar_expansion(self) -> None:
        self.assertTrue(active_in_quote_context("dollar_expansion", "double_quoted"))
        row = audit_decision(
            {
                "vector_id": "dollar_expansion",
                "decision": "VECTOR_SAT",
                "grammar_complete": True,
                "lexical_reason": "lexically_complete",
                "quote_context": "double_quoted",
            },
            "dash",
        )
        self.assertTrue(row["portable_sat"])

    def test_quote_breakout_reactivates_control_operator(self) -> None:
        row = audit_decision(
            {
                "vector_id": "semicolon",
                "decision": "VECTOR_SAT",
                "grammar_complete": True,
                "lexical_reason": "lexically_complete",
                "quote_context": "double_quoted",
                "witness_kind": "double_quote_breakout",
            },
            "busybox_ash",
        )
        self.assertTrue(row["portable_sat"])
        self.assertEqual("unquoted_after_quote_breakout", row["effective_quote_context"])

    def test_unknown_context_never_strengthens_sat(self) -> None:
        row = audit_decision(
            {"vector_id": "pipe", "decision": "VECTOR_SAT", "grammar_complete": True},
            "bash_posix",
        )
        self.assertIn("sat_vector_with_unknown_quote_context", row["issues"])

    def test_summary_binds_matrix_specification(self) -> None:
        _, summary = audit_records([])
        self.assertEqual(matrix_spec_sha256(), summary["matrix_spec_sha256"])


if __name__ == "__main__":
    unittest.main()
