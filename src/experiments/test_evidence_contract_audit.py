#!/usr/bin/env python3

from __future__ import annotations

import unittest
from pathlib import Path

from experiments.audit_evidence_contract import (
    audit_records,
    classify_evidence_tier,
    iter_campaign_records,
)


class EvidenceContractAuditTest(unittest.TestCase):
    def test_provenance_tiers_are_separate(self) -> None:
        direct = {
            "status": "vulnerable",
            "engine_stop_reason": "sink_callsite_in_block",
            "tainted_byte_count": 8,
        }
        direct_prefix = {
            "status": "vulnerable",
            "evidence_provenance": "DIRECT_SINK_BYTE",
            "sink_reached_observed": True,
            "tainted_byte_count": 8,
            "sink_snapshot_cstring_complete": False,
        }
        reconciled = {
            "status": "vulnerable",
            "analysis_recovery": "static_dynamic_taint_reconciliation",
            "no_taint_reaches": 1,
        }
        static_positive = {
            "status": "vulnerable",
            "analysis_recovery": "static_sink_template_fallback",
            "engine_stop_reason": "step_budget_exhausted",
        }
        dynamic_nms = {"status": "no_taint_sink", "no_taint_reaches": 2}
        static_reduction = {
            "status": "no_taint_sink",
            "analysis_recovery": "binary_static_fixed_command_template",
            "static_path_shortcut": True,
        }

        self.assertEqual(classify_evidence_tier(direct), "direct_sv_sat")
        self.assertEqual(
            classify_evidence_tier(direct_prefix), "direct_prefix_sv_sat"
        )
        self.assertEqual(
            classify_evidence_tier(reconciled), "sink_reached_reconciliation"
        )
        self.assertEqual(
            classify_evidence_tier(static_positive), "static_source_slot_inference"
        )
        self.assertEqual(classify_evidence_tier(dynamic_nms), "dynamic_nms")
        self.assertEqual(
            classify_evidence_tier(static_reduction), "static_warning_reduction"
        )

    def test_current_campaign_provenance_counts(self) -> None:
        campaign = Path(
            "experiment_reports/full_firmware_campaign_current_tsds_20260627"
        )
        if not campaign.exists():
            self.skipTest("current campaign ledgers are not available")

        rows, summary = audit_records(iter_campaign_records(campaign))
        self.assertEqual(len(rows), 518)
        self.assertEqual(
            summary["evidence_tiers"],
            {
                "direct_modeled_vector_filtered": 22,
                "direct_sv_sat": 191,
                "dynamic_nms": 14,
                "residual": 126,
                "sink_reached_reconciliation": 12,
                "static_source_slot_inference": 21,
                "static_warning_reduction": 132,
            },
        )

    def test_v15_claim_requires_sink_name_provenance(self) -> None:
        record = {
            "status": "vulnerable",
            "analysis_version": (
                "2026-07-12-evidence-contract-v15-exact-sink-name-binding"
            ),
            "sink_reached_observed": True,
            "tainted_byte_count": 1,
            "sink_semantics": "shell_command",
            "sink_argument_binding_trust": "direct_abi_arg0",
            "minimal_bypass_vector": {
                "grammar_complete": True,
                "witness": ":;:;#",
                "parser_calibration": "unit-test-calibration",
            },
        }
        rows, summary = audit_records([record])
        self.assertIn("claim_without_sink_name_provenance", rows[0]["issues"])
        self.assertEqual(summary["records_with_contract_issues"], 1)

        record["sink_function_name_source"] = (
            "closure_sink_at_exact_callsite"
        )
        rows, summary = audit_records([record])
        self.assertEqual(rows[0]["issues"], "")
        self.assertEqual(summary["records_with_contract_issues"], 0)

    def test_v16_fixture_conditioned_claim_is_not_primary(self) -> None:
        record = {
            "status": "vulnerable",
            "analysis_version": "2026-07-12-evidence-contract-v16-refinement-certificates",
            "sink_reached_observed": True,
            "tainted_byte_count": 1,
            "sink_semantics": "shell_command",
            "sink_argument_binding_trust": "direct_abi_arg0",
            "sink_function_name_source": "closure_sink_at_exact_callsite",
            "evidence_conditioning": "fixture_conditioned",
            "primary_aggregate_eligible": True,
            "minimal_bypass_vector": {
                "grammar_complete": True,
                "witness": ":;:;#",
                "parser_calibration": "unit-test-calibration",
            },
        }
        rows, summary = audit_records([record])
        self.assertIn("fixture_conditioned_claim_marked_primary", rows[0]["issues"])
        self.assertTrue(rows[0]["evidence_tier"].startswith("fixture_conditioned_"))
        self.assertEqual(summary["records_with_contract_issues"], 1)

    def test_v20_refinement_conditioned_claim_is_not_primary(self) -> None:
        record = {
            "status": "no_taint_sink",
            "analysis_version": "2026-07-15-evidence-contract-v20-p012-conditioning",
            "sink_reached_observed": True,
            "sink_semantics": "shell_command",
            "sink_argument_binding_trust": "direct_abi_arg0",
            "sink_function_name_source": "closure_sink_at_exact_callsite",
            "evidence_conditioning": "refinement_conditioned",
            "primary_aggregate_eligible": True,
        }
        rows, summary = audit_records([record])
        self.assertIn("conditioned_claim_marked_primary", rows[0]["issues"])
        self.assertTrue(
            rows[0]["evidence_tier"].startswith("refinement_conditioned_")
        )
        self.assertEqual(summary["records_with_contract_issues"], 1)

    def test_v17_claim_cannot_omit_sink_semantics_or_binding(self) -> None:
        record = {
            "status": "no_taint_sink",
            "analysis_version": "2026-07-13-evidence-contract-v17-run-locked",
            "sink_reached_observed": True,
            "sink_function_name_source": "closure_sink_at_exact_callsite",
        }
        rows, summary = audit_records([record])
        self.assertIn("claim_without_shell_sink_semantics", rows[0]["issues"])
        self.assertIn("claim_without_sink_argument_binding", rows[0]["issues"])
        self.assertEqual(summary["records_with_contract_issues"], 1)


if __name__ == "__main__":
    unittest.main()
