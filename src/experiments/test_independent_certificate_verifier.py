#!/usr/bin/env python3
"""Cross-implementation tests for TSDS certificate verification."""

from __future__ import annotations

import copy
import unittest

from tsds.evidence_certificates import VECTOR_IDS, build_certificate, sha256_json
from tsds.independent_certificate_verifier import (
    strict_json_object,
    verify_certificate,
)
from tsds.reconciliation_link import build_verified_link


def decision(vector_id: str, outcome: str):
    return {
        "vector_id": vector_id,
        "decision": outcome,
        "grammar_complete": True,
        "lexical_reason": "lexically_complete",
        "quote_context": "unquoted",
        "witness": "; true" if outcome == "VECTOR_SAT" else None,
        "parser_calibration": "fixture",
    }


def record():
    decisions = [
        decision(vector_id, "VECTOR_SAT" if vector_id == "semicolon" else "MATRIX_UNSAT")
        for vector_id in VECTOR_IDS
    ]
    return {
        "analysis_version": "fixture",
        "evidence_contract_schema": "fixture",
        "evidence_contract_valid": True,
        "status": "vulnerable",
        "verdict": "VECTOR_SAT",
        "admissible_claim": "direct_sink_byte_vector_sat",
        "evidence_provenance": "DIRECT_SINK_BYTE",
        "closure_idx": 1,
        "source_addr": "0x100",
        "sink_addr": "0x200",
        "sink_reached_observed": True,
        "captured_sink_function_name": "system",
        "sink_function_name_source": "fixture",
        "sink_semantics": "shell_command",
        "sink_argument_binding_source": "abi:a0",
        "sink_argument_binding_trust": "direct_abi_arg0",
        "sink_snapshot_cstring_complete": True,
        "sink_snapshot_capture_length": 16,
        "sink_snapshot_terminator_offset": 15,
        "sink_preview": "tool <src>",
        "controlled_offsets": [5, 6],
        "tainted_byte_count": 2,
        "source_kinds": ["web"],
        "vector_decisions": decisions,
        "vulnerable_vectors": 1,
        "secure_vectors": 10,
        "inconclusive_vectors": 0,
        "minimal_bypass_vector": {
            "vector_id": "semicolon",
            "vector": ";",
            "witness": "; true",
            "grammar_complete": True,
            "parser_calibration": "fixture",
        },
    }


def resign(certificate):
    body = dict(certificate)
    body.pop("certificate_sha256", None)
    certificate["certificate_sha256"] = sha256_json(body)


def verified_link() -> dict:
    constraint_digest = "b" * 64
    return build_verified_link(
        program_sha256="a" * 64,
        sink_snapshot_sha256="c" * 64,
        source_variables=["wrapper_slot_0"],
        transform_chain=[
            {
                "step_id": "format_0",
                "operation": "format",
                "input_variables": ["wrapper_slot_0"],
                "output_offsets": [5, 6],
                "constraint_sha256": constraint_digest,
            }
        ],
        source_to_sink=[
            {
                "sink_offset": 5,
                "source_offset": 0,
                "source_variable": "wrapper_slot_0",
                "transform_step": "format_0",
                "relation": "copy",
                "constraint_sha256": constraint_digest,
            },
            {
                "sink_offset": 6,
                "source_offset": 1,
                "source_variable": "wrapper_slot_0",
                "transform_step": "format_0",
                "relation": "copy",
                "constraint_sha256": constraint_digest,
            },
        ],
        max_input_length=24,
        terminator_offset=31,
    )


def reconciled_record(status: str = "vulnerable") -> dict:
    row = record()
    row.update(
        {
            "status": status,
            "evidence_provenance": "SINK_RECONCILED",
            "analysis_recovery": "static_dynamic_taint_reconciliation",
            "recovery_confidence": "dynamic_format_wrapper_slot",
            "recovery_constraint_mode": "reached_state_plus_command_template",
            "recovery_path_constraint_count": 17,
            "matrix_reconciled_constrained": True,
            "recovered_sink_template": "tool <recovered_wrapper_slot>",
            "recovered_source_prefix": "wrapper_slot",
            "matrix_snapshot_capture_length": 32,
            "matrix_snapshot_terminator_offset": 31,
            "tsds_sink_snapshot_digest": "c" * 64,
            "reconciliation_link": verified_link(),
        }
    )
    if status == "conditioned_feasibility":
        row.update(
            {
                "verdict": "CT_SAT",
                "admissible_claim": "conditioned_template_feasibility",
                "primary_aggregate_eligible": False,
            }
        )
    return row


class IndependentCertificateVerifierTest(unittest.TestCase):
    def test_generator_output_passes_second_implementation(self) -> None:
        source = record()
        certificate = build_certificate(source, target="fixture")
        self.assertEqual([], verify_certificate(certificate, {sha256_json(source)}))

    def test_matrix_spec_tamper_is_detected_even_when_resigned(self) -> None:
        certificate = copy.deepcopy(build_certificate(record()))
        certificate["matrix"]["spec"]["sha256"] = "0" * 64
        resign(certificate)
        self.assertIn("matrix_spec_digest_mismatch", verify_certificate(certificate))

    def test_offset_domain_tamper_is_detected(self) -> None:
        certificate = copy.deepcopy(build_certificate(record()))
        certificate["source"]["offset_domain"]["length"] = 2
        resign(certificate)
        self.assertIn("controlled_offset_outside_domain", verify_certificate(certificate))

    def test_source_record_binding_is_independent(self) -> None:
        source = record()
        certificate = build_certificate(source)
        self.assertIn("source_record_not_found", verify_certificate(certificate, {"f" * 64}))

    def test_verified_reconciled_direct_certificate_passes(self) -> None:
        source = reconciled_record()
        certificate = build_certificate(source, target="fixture")
        self.assertEqual([], verify_certificate(certificate, {sha256_json(source)}))

    def test_reconciled_mapping_outside_controlled_domain_fails_after_resigning(self) -> None:
        source = reconciled_record()
        certificate = build_certificate(source, target="fixture")
        link = certificate["recovery_admission"]["reconciliation_link"]
        link["source_to_sink"][0]["sink_offset"] = 7
        link["source_to_sink_sha256"] = sha256_json(link["source_to_sink"])
        link_body = dict(link)
        link_body.pop("link_sha256", None)
        link["link_sha256"] = sha256_json(link_body)
        resign(certificate)
        self.assertIn(
            "reconciled_source_link_offsets_outside_controlled_domain",
            verify_certificate(certificate, {sha256_json(source)}),
        )

    def test_reconciled_mapping_outside_cstring_is_rejected_after_resigning(self) -> None:
        source = reconciled_record()
        certificate = build_certificate(source, target="fixture")
        link = certificate["recovery_admission"]["reconciliation_link"]
        link["source_to_sink"][0]["sink_offset"] = 31
        link["source_to_sink_sha256"] = sha256_json(link["source_to_sink"])
        link_body = dict(link)
        link_body.pop("link_sha256", None)
        link["link_sha256"] = sha256_json(link_body)
        resign(certificate)
        self.assertIn(
            "reconciled_source_link_mapping_0_sink_offset_outside_cstring",
            verify_certificate(certificate, {sha256_json(source)}),
        )

    def test_conditioned_certificate_is_not_a_direct_claim(self) -> None:
        source = reconciled_record("conditioned_feasibility")
        certificate = build_certificate(source, target="fixture")
        self.assertEqual([], verify_certificate(certificate, {sha256_json(source)}))
        self.assertEqual(
            "conditioned_template_feasibility",
            certificate["analysis"]["claim_scope"],
        )

    def test_strict_parser_rejects_duplicate_json_keys(self) -> None:
        with self.assertRaises(ValueError):
            strict_json_object('{"schema":"a","schema":"b"}', "fixture")


if __name__ == "__main__":
    unittest.main()
