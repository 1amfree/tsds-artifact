#!/usr/bin/env python3
"""Regression tests for conditioned source-to-sink link admission."""

from __future__ import annotations

import copy
import unittest

from tsds.reconciliation_link import (
    build_verified_link,
    reconciliation_link_admission,
    sha256_json,
    unverified_link,
    validate_reconciliation_link,
)


def _link() -> dict:
    constraint = "b" * 64
    return build_verified_link(
        program_sha256="a" * 64,
        sink_snapshot_sha256="c" * 64,
        source_variables=["x"],
        transform_chain=[
            {
                "step_id": "copy0",
                "operation": "copy",
                "input_variables": ["x"],
                "output_offsets": [4, 5],
                "constraint_sha256": constraint,
            }
        ],
        source_to_sink=[
            {
                "sink_offset": 4,
                "source_offset": 0,
                "source_variable": "x",
                "transform_step": "copy0",
                "relation": "copy",
                "constraint_sha256": constraint,
            },
            {
                "sink_offset": 5,
                "source_offset": 1,
                "source_variable": "x",
                "transform_step": "copy0",
                "relation": "copy",
                "constraint_sha256": constraint,
            },
        ],
        max_input_length=16,
        terminator_offset=12,
    )


class ReconciliationLinkTest(unittest.TestCase):
    def test_complete_link_is_admitted(self) -> None:
        link = _link()
        self.assertEqual([], validate_reconciliation_link(link))
        self.assertTrue(reconciliation_link_admission(link)["admitted"])

    def test_unverified_reconstruction_is_not_admitted(self) -> None:
        link = unverified_link("new_symbolic_variables_are_not_linked")
        result = reconciliation_link_admission(link)
        self.assertFalse(result["admitted"])
        self.assertIn("reconciliation_link_not_verified", result["issues"])

    def test_tampering_with_mapping_is_detected(self) -> None:
        link = copy.deepcopy(_link())
        link["source_to_sink"][0]["sink_offset"] = 999
        self.assertIn("source_to_sink_digest_mismatch", validate_reconciliation_link(link))
        self.assertIn("link_digest_mismatch", validate_reconciliation_link(link))

    def test_record_binding_checks_snapshot_and_offsets(self) -> None:
        link = _link()
        record = {
            "tsds_sink_snapshot_digest": "d" * 64,
            "source_variable_digest": link["source_variable_sha256"],
            "sink_snapshot_cstring_complete": True,
            "controlled_offsets": [4],
        }
        issues = validate_reconciliation_link(link, record=record)
        self.assertIn("link_sink_digest_does_not_match_record", issues)
        self.assertIn("link_sink_offsets_outside_record_controlled_offsets", issues)

    def test_mapping_must_stay_inside_input_cstring_and_transform_output_domains(self) -> None:
        link = _link()
        link["source_to_sink"][0]["sink_offset"] = 12
        link["source_to_sink_sha256"] = sha256_json(link["source_to_sink"])
        body = dict(link)
        body.pop("link_sha256", None)
        link["link_sha256"] = sha256_json(body)
        issues = validate_reconciliation_link(link)
        self.assertIn("mapping_0_sink_offset_outside_cstring", issues)
        self.assertIn("mapping_0_sink_offset_not_in_transform_outputs", issues)


if __name__ == "__main__":
    unittest.main()
