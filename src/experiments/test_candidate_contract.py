#!/usr/bin/env python3
"""Tests for the front-end-neutral TSDS candidate contract."""

from __future__ import annotations

import unittest

from tsds.candidate_contract import audit_candidate_document


def document():
    return {
        "schema": "tsds-closures-v1",
        "frontend": "satc",
        "closures": [
            {
                "frontend": "satc",
                "id": "fixture-1",
                "trace": [{"function": "sub_100", "ins_addr": "0x100"}],
                "sink": {"function": "system", "ins_addr": "0x200"},
                "inputs": {
                    "likely": ["QUERY_STRING"],
                    "possibly": [],
                    "tags": ["satc"],
                    "valid_funcs": [0x100],
                },
                "satc": {
                    "source_semantics_policy": "address_provenance_only",
                    "origin_file_sha256": "a" * 64,
                },
            }
        ],
    }


class CandidateContractTest(unittest.TestCase):
    def test_satc_candidate_is_normalized_without_promoting_source_semantics(self) -> None:
        rows, summary = audit_candidate_document(document())
        self.assertTrue(summary["valid"])
        self.assertEqual("candidate_hint_only", rows[0]["source_semantics"])
        self.assertEqual("0x100", rows[0]["source_addr"])

    def test_outcome_field_leak_is_rejected(self) -> None:
        fixture = document()
        fixture["closures"][0]["verdict"] = "VECTOR_SAT"
        _, summary = audit_candidate_document(fixture)
        self.assertFalse(summary["valid"])
        self.assertTrue(any("outcome_fields" in issue for issue in summary["issues"]))

    def test_satc_source_policy_is_mandatory(self) -> None:
        fixture = document()
        fixture["closures"][0]["satc"].pop("source_semantics_policy")
        _, summary = audit_candidate_document(fixture)
        self.assertFalse(summary["valid"])


if __name__ == "__main__":
    unittest.main()
