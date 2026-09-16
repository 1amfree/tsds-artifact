#!/usr/bin/env python3
"""Tests for the dependency-free conditioned source replay contract."""

from __future__ import annotations

import copy
import hashlib
import unittest

from tsds.reconciliation_link import build_verified_link
from tsds.source_realizability import (
    SOURCE_REPLAY_SCHEMA,
    replay_reconciliation_link,
    replay_source_trace,
)


def _trace(
    source: bytes,
    expected_sink: bytes,
    expected_mapping: list[dict[str, int]],
    *,
    steps: list[dict],
    sink_step: str = "cmd",
) -> dict:
    return {
        "schema": SOURCE_REPLAY_SCHEMA,
        "source_variable": "x",
        "source_bytes_hex": source.hex(),
        "steps": steps,
        "sink_step": sink_step,
        "expected_sink_bytes_hex": expected_sink.hex(),
        "expected_mapping": expected_mapping,
    }


def _copy_trace(source: bytes, expected_sink: bytes, mapping: list[dict[str, int]]) -> dict:
    return _trace(
        source,
        expected_sink,
        mapping,
        steps=[
            {"step_id": "src", "operation": "source", "source_variable": "x"},
            {"step_id": "copy0", "operation": "copy", "input_step": "src"},
            {
                "step_id": "cmd",
                "operation": "concat",
                "parts": [
                    {"kind": "literal", "bytes_hex": b"echo ".hex()},
                    {"kind": "step", "step_id": "copy0"},
                ],
            },
        ],
    )


class SourceRealizabilityTest(unittest.TestCase):
    def test_exact_copy_and_concat_replay(self) -> None:
        trace = _copy_trace(
            b"ABC;",
            b"echo ABC;",
            [
                {"sink_offset": 5, "source_offset": 0},
                {"sink_offset": 6, "source_offset": 1},
                {"sink_offset": 7, "source_offset": 2},
                {"sink_offset": 8, "source_offset": 3},
            ],
        )
        result = replay_source_trace(trace)
        self.assertEqual("PASS", result["status"])
        self.assertTrue(result["source_realizable"])

    def test_first_nul_is_part_of_the_replay_contract(self) -> None:
        trace = _copy_trace(
            b"AB\x00;",
            b"echo AB",
            [
                {"sink_offset": 5, "source_offset": 0},
                {"sink_offset": 6, "source_offset": 1},
            ],
        )
        result = replay_source_trace(trace)
        self.assertEqual("PASS", result["status"])
        self.assertEqual("6563686f204142", result["sink_bytes_hex"])

    def test_percent_decode_preserves_origin_at_encoded_token(self) -> None:
        trace = _trace(
            b"%3b",
            b"echo ;",
            [{"sink_offset": 5, "source_offset": 0}],
            steps=[
                {"step_id": "src", "operation": "source", "source_variable": "x"},
                {"step_id": "decoded", "operation": "percent_decode", "input_step": "src"},
                {
                    "step_id": "cmd",
                    "operation": "concat",
                    "parts": [
                        {"kind": "literal", "bytes_hex": b"echo ".hex()},
                        {"kind": "step", "step_id": "decoded"},
                    ],
                },
            ],
        )
        result = replay_source_trace(trace)
        self.assertEqual("PASS", result["status"])
        self.assertEqual(0, result["mapping"][0]["source_offset"])

    def test_expected_bytes_mismatch_is_not_admitted(self) -> None:
        trace = _copy_trace(b"ABC", b"echo WRONG", [])
        result = replay_source_trace(trace)
        self.assertEqual("MISMATCH", result["status"])
        self.assertIn("expected_sink_bytes_mismatch", result["reasons"])

    def test_unsupported_operation_is_explicit(self) -> None:
        trace = _trace(
            b"A",
            b"A",
            [{"sink_offset": 0, "source_offset": 0}],
            steps=[
                {"step_id": "src", "operation": "source", "source_variable": "x"},
                {"step_id": "cmd", "operation": "opaque_wrapper", "input_step": "src"},
            ],
        )
        result = replay_source_trace(trace)
        self.assertEqual("UNSUPPORTED", result["status"])
        self.assertFalse(result["source_realizable"])

    def test_link_admission_requires_matching_replay(self) -> None:
        trace = _copy_trace(
            b"ABC;",
            b"echo ABC;",
            [
                {"sink_offset": 5, "source_offset": 0},
                {"sink_offset": 6, "source_offset": 1},
                {"sink_offset": 7, "source_offset": 2},
                {"sink_offset": 8, "source_offset": 3},
            ],
        )
        constraint = "b" * 64
        link = build_verified_link(
            program_sha256="a" * 64,
            sink_snapshot_sha256=hashlib.sha256(
                b"6563686f204142433b"
            ).hexdigest(),
            source_variables=["x"],
            transform_chain=[
                {
                    "step_id": "copy0",
                    "operation": "copy",
                    "input_variables": ["x"],
                    "output_offsets": [5, 6, 7, 8],
                    "constraint_sha256": constraint,
                }
            ],
            source_to_sink=[
                {
                    "sink_offset": offset,
                    "source_offset": offset - 5,
                    "source_variable": "x",
                    "transform_step": "copy0",
                    "relation": "copy",
                    "constraint_sha256": constraint,
                }
                for offset in range(5, 9)
            ],
            max_input_length=16,
            terminator_offset=9,
        )
        admitted = replay_reconciliation_link(link, trace)
        self.assertTrue(admitted["admitted"])

        tampered = copy.deepcopy(trace)
        tampered["expected_mapping"][0]["source_offset"] = 3
        rejected = replay_reconciliation_link(link, tampered)
        self.assertFalse(rejected["admitted"])
        self.assertIn("source_realizability_replay_not_pass", rejected["issues"])

    def test_replay_rejects_a_digest_not_bound_to_sink_bytes(self) -> None:
        trace = _copy_trace(
            b"ABC;",
            b"echo ABC;",
            [
                {"sink_offset": 5, "source_offset": 0},
                {"sink_offset": 6, "source_offset": 1},
                {"sink_offset": 7, "source_offset": 2},
                {"sink_offset": 8, "source_offset": 3},
            ],
        )
        constraint = "b" * 64
        link = build_verified_link(
            program_sha256="a" * 64,
            sink_snapshot_sha256="c" * 64,
            source_variables=["x"],
            transform_chain=[
                {
                    "step_id": "copy0",
                    "operation": "copy",
                    "input_variables": ["x"],
                    "output_offsets": [5, 6, 7, 8],
                    "constraint_sha256": constraint,
                }
            ],
            source_to_sink=[
                {
                    "sink_offset": offset,
                    "source_offset": offset - 5,
                    "source_variable": "x",
                    "transform_step": "copy0",
                    "relation": "copy",
                    "constraint_sha256": constraint,
                }
                for offset in range(5, 9)
            ],
            max_input_length=16,
            terminator_offset=9,
        )
        result = replay_reconciliation_link(link, trace)
        self.assertFalse(result["admitted"])
        self.assertIn(
            "source_realizability_sink_digest_does_not_match_replay",
            result["issues"],
        )

    def test_replay_rejects_a_link_for_a_different_source_variable(self) -> None:
        trace = _copy_trace(
            b"ABC;",
            b"echo ABC;",
            [
                {"sink_offset": 5, "source_offset": 0},
                {"sink_offset": 6, "source_offset": 1},
                {"sink_offset": 7, "source_offset": 2},
                {"sink_offset": 8, "source_offset": 3},
            ],
        )
        constraint = "b" * 64
        link = build_verified_link(
            program_sha256="a" * 64,
            sink_snapshot_sha256=hashlib.sha256(
                b"6563686f204142433b"
            ).hexdigest(),
            source_variables=["other_source"],
            transform_chain=[
                {
                    "step_id": "copy0",
                    "operation": "copy",
                    "input_variables": ["other_source"],
                    "output_offsets": [5, 6, 7, 8],
                    "constraint_sha256": constraint,
                }
            ],
            source_to_sink=[
                {
                    "sink_offset": offset,
                    "source_offset": offset - 5,
                    "source_variable": "other_source",
                    "transform_step": "copy0",
                    "relation": "copy",
                    "constraint_sha256": constraint,
                }
                for offset in range(5, 9)
            ],
            max_input_length=16,
            terminator_offset=9,
        )
        result = replay_reconciliation_link(link, trace)
        self.assertFalse(result["admitted"])
        self.assertIn("source_realizability_source_variable_not_bound", result["issues"])

    def test_malformed_link_is_reported_without_crashing(self) -> None:
        trace = _copy_trace(
            b"A",
            b"echo A",
            [{"sink_offset": 5, "source_offset": 0}],
        )
        malformed = {"status": "verified", "source_to_sink": [{"sink_offset": "bad"}]}
        result = replay_reconciliation_link(malformed, trace)
        self.assertFalse(result["admitted"])
        self.assertIn("source_realizability_link_mapping_invalid", result["issues"])


if __name__ == "__main__":
    unittest.main()
