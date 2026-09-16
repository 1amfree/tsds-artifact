#!/usr/bin/env python3
"""Regression tests for independent TSDS evidence certificates."""

from __future__ import annotations

import copy
import unittest

from tsds.evidence_certificates import (
    CERTIFICATE_SCHEMA,
    VECTOR_IDS,
    build_certificate,
    certificate_violations,
    verify_record_certificate,
)
from tsds.reconciliation_link import build_verified_link


def _decision(vector_id: str, decision: str) -> dict:
    vector = {
        "semicolon": ";",
        "newline": "\\n",
        "pipe": "|",
        "background_ampersand": "&",
        "backtick_substitution": "`",
        "dollar_substitution": "$(",
        "dollar_expansion": "$",
        "output_redirection": ">",
        "input_redirection": "<",
        "ifs_word_splitting": "${IFS}",
        "tab_word_splitting": "\\t",
    }[vector_id]
    row = {
        "vector_id": vector_id,
        "vector": vector,
        "category": "test",
        "effect_class": "test",
        "decision": decision,
        "grammar_complete": True,
        "lexical_reason": "lexically_complete",
        "quote_context": "unquoted",
        "witness_template": vector,
        "parser_calibration": "test-calibration",
        "schema": "tsds-shell-witness-v3",
    }
    if decision == "VECTOR_SAT":
        row["witness"] = vector + "A"
    return row


def _base_record(status: str = "vulnerable") -> dict:
    decisions = [
        _decision(vector_id, "VECTOR_SAT" if vector_id == "semicolon" else "MATRIX_UNSAT")
        for vector_id in VECTOR_IDS
    ]
    return {
        "analysis_version": "test-v16",
        "evidence_contract_schema": "tsds-evidence-contract-v3",
        "evidence_contract_valid": True,
        "status": status,
        "verdict": "VECTOR_SAT",
        "admissible_claim": "direct_sink_byte_vector_sat",
        "evidence_provenance": "DIRECT_SINK_BYTE",
        "closure_idx": 7,
        "closure_ordinal": 8,
        "source_addr": "0x1000",
        "sink_addr": "0x2000",
        "closure_sink_signature": ["system", "0x2000"],
        "sink_reached_observed": True,
        "captured_sink_function_name": "system",
        "sink_function_name_source": "closure_sink_at_exact_callsite",
        "sink_semantics": "shell_command",
        "sink_argument_binding_source": "abi:a0",
        "sink_argument_binding_trust": "direct_abi_arg0",
        "sink_snapshot_cstring_complete": True,
        "sink_snapshot_capture_length": 32,
        "sink_snapshot_terminator_offset": 9,
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
            "witness": ";A",
            "grammar_complete": True,
            "parser_calibration": "test-calibration",
        },
    }


def _verified_reconciliation_link() -> dict:
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


class EvidenceCertificateTest(unittest.TestCase):
    def test_refinement_conditioning_is_digest_covered_claim_scope(self) -> None:
        row = _base_record("vulnerable")
        row.update(
            {
                "evidence_conditioning": "refinement_conditioned",
                "primary_aggregate_eligible": False,
                "evidence_summary_events": 1,
                "evidence_summary_origins": ["residual_cegar"],
                "evidence_refinement_bundle_sha256": "a" * 64,
            }
        )
        certificate = build_certificate(row, target="fixture")
        self.assertEqual(
            "refinement_conditioned", certificate["analysis"]["claim_scope"]
        )
        self.assertEqual(
            ["residual_cegar"], certificate["conditioning"]["summary_origins"]
        )
        self.assertEqual([], certificate_violations(certificate))

    def test_valid_positive_certificate(self) -> None:
        record = _base_record()
        certificate = build_certificate(record, target="fixture")
        self.assertEqual([], certificate_violations(certificate))
        self.assertEqual([], verify_record_certificate(record, certificate))
        self.assertEqual("analyzer_sink_byte", certificate["analysis"]["claim_scope"])
        self.assertEqual("tsds-evidence-certificate-v2", CERTIFICATE_SCHEMA)
        self.assertIn("sha256", certificate["matrix"]["spec"])

    def test_filtered_requires_exact_complete_matrix(self) -> None:
        record = _base_record("filtered")
        record.update(
            {
                "verdict": "MATRIX_UNSAT",
                "admissible_claim": "direct_matrix_bounded_unsat",
                "vulnerable_vectors": 0,
                "secure_vectors": len(VECTOR_IDS),
                "minimal_bypass_vector": {},
                "vector_decisions": [_decision(vector_id, "MATRIX_UNSAT") for vector_id in VECTOR_IDS],
            }
        )
        certificate = build_certificate(record)
        self.assertEqual([], certificate_violations(certificate))
        certificate["matrix"]["decisions"] = certificate["matrix"]["decisions"][:-1]
        certificate["certificate_sha256"] = "tampered"
        issues = certificate_violations(certificate)
        self.assertIn("certificate_digest_mismatch", issues)

    def test_fixture_hit_requires_conditional_scope(self) -> None:
        record = _base_record()
        record["env_fixture_summary"] = {"entries": 1, "digest": "fixture"}
        record["env_fixture_usage"] = {"hits": 1}
        certificate = build_certificate(record)
        self.assertEqual("fixture_conditioned", certificate["analysis"]["claim_scope"])
        certificate = copy.deepcopy(certificate)
        certificate["analysis"]["claim_scope"] = "analyzer_sink_byte"
        body = dict(certificate)
        body.pop("certificate_sha256")
        from tsds.evidence_certificates import sha256_json

        certificate["certificate_sha256"] = sha256_json(body)
        self.assertIn("fixture_hit_without_fixture_conditioned_scope", certificate_violations(certificate))

    def test_record_digest_binds_original_row(self) -> None:
        record = _base_record()
        certificate = build_certificate(record)
        record["sink_preview"] = "changed"
        self.assertIn("source_record_digest_mismatch", verify_record_certificate(record, certificate))

    def test_reconciled_positive_carries_path_bound_admission(self) -> None:
        record = _base_record()
        record.update(
            {
                "evidence_provenance": "SINK_RECONCILED",
                "analysis_recovery": "static_dynamic_taint_reconciliation",
                "recovery_confidence": "dynamic_format_wrapper_slot",
                "recovery_constraint_mode": "reached_state_plus_command_template",
                "recovery_path_constraint_count": 17,
                "matrix_reconciled_constrained": True,
                "recovered_sink_template": "tool <recovered_wrapper_slot>",
                "recovered_source_prefix": "wrapper_slot",
                "reconciliation_link": _verified_reconciliation_link(),
                "matrix_snapshot_capture_length": 32,
                "matrix_snapshot_terminator_offset": 31,
            }
        )
        certificate = build_certificate(record)
        self.assertTrue(certificate["recovery_admission"]["admitted"])
        self.assertEqual([], certificate_violations(certificate))

    def test_reconciled_positive_fails_closed_without_constraints(self) -> None:
        record = _base_record()
        record.update(
            {
                "evidence_provenance": "SINK_RECONCILED",
                "analysis_recovery": "static_dynamic_taint_reconciliation",
                "recovery_confidence": "dynamic_format_wrapper_slot",
                "recovery_constraint_mode": "reached_state_plus_command_template",
                "recovery_path_constraint_count": 0,
                "matrix_reconciled_constrained": False,
                "recovered_sink_template": "tool <recovered_wrapper_slot>",
                "matrix_snapshot_capture_length": 32,
            }
        )
        issues = certificate_violations(build_certificate(record))
        self.assertIn("reconciled_positive_without_admission_certificate", issues)

    def test_conditioned_feasibility_is_valid_but_not_direct(self) -> None:
        record = _base_record()
        record.update(
            {
                "status": "conditioned_feasibility",
                "verdict": "CT_SAT",
                "admissible_claim": "conditioned_template_feasibility",
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
                "primary_aggregate_eligible": False,
            }
        )
        certificate = build_certificate(record)
        self.assertEqual([], certificate_violations(certificate))
        self.assertEqual("conditioned_template_feasibility", certificate["analysis"]["claim_scope"])
        self.assertFalse(certificate["recovery_admission"]["admitted"])

    def test_reconciled_direct_claim_requires_verified_link(self) -> None:
        record = _base_record()
        record.update(
            {
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
            }
        )
        issues = certificate_violations(build_certificate(record))
        self.assertIn("reconciled_positive_without_verified_source_link", issues)


if __name__ == "__main__":
    unittest.main()
