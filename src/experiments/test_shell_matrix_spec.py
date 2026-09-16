#!/usr/bin/env python3
"""Tests for the content-addressed shell matrix specification."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest

from tsds.shell_matrix_spec import (
    LEGACY_MATRIX_SPEC_SHA256,
    LEGACY_MATRIX_SPEC_VERSION,
    MATRIX_SPEC_SCHEMA,
    MATRIX_SPEC_VERSION,
    VECTOR_IDS,
    matrix_decision_issues,
    matrix_spec_manifest,
    matrix_spec_sha256,
    matrix_spec_payload,
    matrix_spec_validation_issues,
    quote_context_after,
    vector_active,
)


class ShellMatrixSpecTest(unittest.TestCase):
    def test_manifest_is_stable_and_has_eleven_unique_vectors(self) -> None:
        manifest = matrix_spec_manifest()
        self.assertEqual(11, len(VECTOR_IDS))
        self.assertEqual(11, len(set(VECTOR_IDS)))
        self.assertEqual(matrix_spec_sha256(), manifest["sha256"])
        self.assertEqual(MATRIX_SPEC_VERSION, manifest["version"])
        self.assertTrue(all(row.get("witness") for row in manifest["vectors"]))

    def test_witness_changes_are_digest_bound(self) -> None:
        payload = copy.deepcopy(matrix_spec_payload())
        original = matrix_spec_sha256()
        payload["vectors"][0]["witness"] = "tampered"
        mutated = hashlib.sha256(
            json.dumps(
                payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
        ).hexdigest()
        self.assertNotEqual(original, mutated)

    def test_frozen_legacy_digest_is_explicitly_compatible(self) -> None:
        self.assertEqual(
            [],
            matrix_spec_validation_issues(
                {
                    "schema": MATRIX_SPEC_SCHEMA,
                    "version": LEGACY_MATRIX_SPEC_VERSION,
                    "sha256": LEGACY_MATRIX_SPEC_SHA256,
                }
            ),
        )

    def test_quote_automaton_handles_escaping(self) -> None:
        self.assertEqual("single_quoted", quote_context_after("cmd 'value"))
        self.assertEqual("double_quoted", quote_context_after('cmd "value'))
        self.assertEqual("unquoted", quote_context_after(r"cmd \"value"))
        self.assertEqual("unquoted", quote_context_after("cmd 'value'"))

    def test_vector_activity_is_spec_driven(self) -> None:
        self.assertFalse(vector_active("semicolon", "double_quoted"))
        self.assertTrue(vector_active("dollar_substitution", "double_quoted"))
        self.assertIsNone(vector_active("unknown", "unquoted"))

    def test_duplicate_and_unknown_decisions_are_reported(self) -> None:
        issues = matrix_decision_issues(
            [
                {"vector_id": "semicolon", "decision": "VECTOR_SAT"},
                {"vector_id": "semicolon", "decision": "MATRIX_UNSAT"},
                {"vector_id": "unknown", "decision": "OTHER"},
            ]
        )
        self.assertTrue(any("duplicate_vector" in issue for issue in issues))
        self.assertTrue(any("unknown_vector" in issue for issue in issues))
        self.assertTrue(any("unknown_outcome" in issue for issue in issues))


if __name__ == "__main__":
    unittest.main()
