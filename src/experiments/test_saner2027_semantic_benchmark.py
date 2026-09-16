#!/usr/bin/env python3
"""Regression tests for the independent T06 semantic benchmark."""

from __future__ import annotations

import sys
import unittest

from experiments.run_saner2027_semantic_benchmark import (
    CASES,
    FAMILIES,
    PAYLOADS,
    VECTOR_IDS,
    _split_manifest,
    oracle_matrix,
    oracle_transform,
    _make_differential_rows,
)


class Saner2027SemanticBenchmarkTest(unittest.TestCase):
    def test_case_inventory_and_frozen_split(self) -> None:
        self.assertEqual(48, len(CASES))
        self.assertEqual(8, len(FAMILIES))
        self.assertEqual(48, len({case["id"] for case in CASES}))
        self.assertTrue(all(sum(case["family"] == family for case in CASES) == 6 for family in FAMILIES))
        split = _split_manifest()
        development = set(split["development_indices"])
        held_out = set(split["held_out_indices"])
        self.assertEqual(32, len(development))
        self.assertEqual(16, len(held_out))
        self.assertTrue(development.isdisjoint(held_out))
        self.assertEqual(set(range(48)), development | held_out)
        for family in FAMILIES:
            indices = {index for index, case in enumerate(CASES) if case["family"] == family}
            self.assertEqual(4, len(indices & development))
            self.assertEqual(2, len(indices & held_out))

    def test_fixed_bytes_are_not_source_controlled(self) -> None:
        case = next(case for case in CASES if case["id"] == "extent_fixed_vector_only")
        command, origins = oracle_transform(case, b"SAFE")
        profile = oracle_matrix(command, origins)
        self.assertEqual(b"echo fixed;:;#", command)
        self.assertTrue(all(row["decision"] == "MATRIX_UNSAT" for row in profile["decisions"]))
        self.assertTrue(all(origin is None for origin in origins))

    def test_single_quote_and_escape_boundaries(self) -> None:
        single = next(case for case in CASES if case["id"] == "quote_single_literal")
        command, origins = oracle_transform(single, b"SAFE;:")
        profile = oracle_matrix(command, origins)
        semicolon = next(row for row in profile["decisions"] if row["vector_id"] == "semicolon")
        self.assertEqual("MATRIX_UNSAT", semicolon["decision"])

        escaped = next(case for case in CASES if case["id"] == "filter_backslash_meta")
        command, origins = oracle_transform(escaped, b"SAFE;:")
        profile = oracle_matrix(command, origins)
        semicolon = next(row for row in profile["decisions"] if row["vector_id"] == "semicolon")
        self.assertEqual("MATRIX_UNSAT", semicolon["decision"])

    def test_source_witness_is_positive_only_in_one_controlled_extent(self) -> None:
        case = next(case for case in CASES if case["id"] == "source_direct_unquoted")
        command, origins = oracle_transform(case, b":;:;#")
        profile = oracle_matrix(command, origins)
        semicolon = next(row for row in profile["decisions"] if row["vector_id"] == "semicolon")
        self.assertEqual("VECTOR_SAT", semicolon["decision"])
        self.assertEqual("unquoted", semicolon["match"]["quote_context"])

    def test_nul_terminates_the_original_c_string(self) -> None:
        case = next(case for case in CASES if case["id"] == "cstring_prefix")
        command, _ = oracle_transform(case, b"SAFE\x00:;:;#")
        self.assertEqual(b"echo SAFE", command)

    def test_transform_can_create_source_owned_vector(self) -> None:
        case = next(case for case in CASES if case["id"] == "transform_percent_decode")
        command, origins = oracle_transform(case, b"%3b:;#")
        profile = oracle_matrix(command, origins)
        semicolon = next(row for row in profile["decisions"] if row["vector_id"] == "semicolon")
        self.assertEqual("VECTOR_SAT", semicolon["decision"])
        self.assertEqual(len(VECTOR_IDS), len(profile["decisions"]))

    def test_payload_domain_is_explicit_and_nonempty(self) -> None:
        self.assertGreaterEqual(len(PAYLOADS), 20)
        self.assertEqual(len(PAYLOADS), len({name for name, _ in PAYLOADS}))
        self.assertEqual(len(PAYLOADS), len({payload for _, payload in PAYLOADS}))

    def test_differential_receipt_exposes_actual_shell_status(self) -> None:
        rows = _make_differential_rows(_split_manifest(), (sys.executable,))
        self.assertEqual(1000, len(rows))
        self.assertEqual({"FAIL"}, {row["status"] for row in rows})
        self.assertEqual({"FAIL"}, {row["shell_results"][0]["status"] for row in rows})


if __name__ == "__main__":
    unittest.main()
