#!/usr/bin/env python3
"""Golden-ledger compatibility tests for v16 artifact structure."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tsds.ledger_schema import schema_summary, validate_ledger_record


class LedgerSchemaTest(unittest.TestCase):
    def test_refinement_conditioned_record_cannot_be_primary(self) -> None:
        row = {
            "status": "vulnerable",
            "analysis_version": "2026-07-15-evidence-contract-v20-p012-conditioning",
            "evidence_contract_schema": "tsds-evidence-contract-v3",
            "evidence_contract_valid": True,
            "evidence_provenance": "DIRECT_SINK_BYTE",
            "verdict": "VECTOR_SAT",
            "admissible_claim": "direct_sink_byte_vector_sat",
            "closure_idx": 0,
            "evidence_conditioning": "refinement_conditioned",
            "primary_aggregate_eligible": True,
            "subprocess_memory_limit_mib": 8192,
            "resource_limit_enforcement": "enforced",
            "resource_limit_hit": False,
            "process_resource_metric_scope": "worker_recorded",
            "process_peak_rss_mib": 100,
            "sink_reached_observed": True,
            "sink_semantics": "shell_command",
            "sink_argument_binding_trust": "direct_abi_arg0",
            "sink_function_name_source": "closure_sink_at_exact_callsite",
        }
        self.assertIn("conditioned_primary_eligible", validate_ledger_record(row))

    def test_golden_v16_rows_validate(self) -> None:
        path = Path(__file__).resolve().parent / "fixtures" / "golden_ledger_v16.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
        self.assertEqual([], [issue for row in rows for issue in validate_ledger_record(row)])
        self.assertEqual(0, schema_summary(rows)["records_with_issues"])

    def test_conditioned_primary_claim_fails(self) -> None:
        row = {
            "status": "residual", "analysis_version": "2026-07-12-evidence-contract-v16-test",
            "evidence_contract_schema": "tsds-evidence-contract-v3",
            "evidence_contract_valid": True, "evidence_provenance": "RESIDUAL",
            "verdict": "RESIDUAL", "admissible_claim": "explicit_residual_obligation",
            "closure_idx": 0, "evidence_conditioning": "fixture_conditioned", "primary_aggregate_eligible": True,
            "subprocess_memory_limit_mib": 0, "resource_limit_enforcement": "not_requested", "process_peak_rss_mib": 1.0,
        }
        self.assertIn("fixture_conditioned_primary_eligible", validate_ledger_record(row))

    def test_terminated_worker_may_preserve_missing_rss_only_with_explicit_scope(self) -> None:
        row = {
            "status": "crashed", "analysis_version": "2026-07-12-evidence-contract-v16-test",
            "evidence_contract_schema": "tsds-evidence-contract-v3",
            "evidence_contract_valid": True, "evidence_provenance": "RESIDUAL",
            "verdict": "RESIDUAL", "admissible_claim": "explicit_residual_obligation",
            "closure_idx": 0, "evidence_conditioning": "unconditioned", "primary_aggregate_eligible": True,
            "subprocess_memory_limit_mib": 4096, "resource_limit_enforcement": "enforced",
            "process_resource_metric_scope": "unavailable_worker_terminated",
            "process_resource_metric_reason": "worker_crash_without_result",
        }
        self.assertEqual([], validate_ledger_record(row))

    def test_claim_requires_sink_binding_and_resolved_worker_limit_state(self) -> None:
        row = {
            "status": "vulnerable",
            "analysis_version": "2026-07-12-evidence-contract-v16-test",
            "evidence_contract_schema": "tsds-evidence-contract-v3",
            "evidence_contract_valid": True,
            "evidence_provenance": "DIRECT_SINK_BYTE",
            "verdict": "VECTOR_SAT",
            "admissible_claim": "direct_sink_byte_vector_sat",
            "closure_idx": 0,
            "evidence_conditioning": "unconditioned",
            "primary_aggregate_eligible": True,
            "subprocess_memory_limit_mib": 8192,
            "resource_limit_enforcement": "worker_required",
            "process_peak_rss_mib": 1.0,
            "sink_reached_observed": True,
        }
        issues = validate_ledger_record(row)
        self.assertIn("missing_claim_sink_semantics", issues)
        self.assertIn("missing_claim_sink_argument_binding_trust", issues)
        self.assertIn("missing_claim_sink_function_name_source", issues)
        self.assertIn("unresolved_worker_memory_limit_enforcement", issues)

    def test_v17_still_requires_resource_fields(self) -> None:
        row = {
            "status": "residual",
            "analysis_version": "2026-07-13-evidence-contract-v17-run-locked",
            "evidence_contract_schema": "tsds-evidence-contract-v3",
            "evidence_contract_valid": True,
            "evidence_provenance": "RESIDUAL",
            "verdict": "RESIDUAL",
            "admissible_claim": "explicit_residual_obligation",
            "closure_idx": 0,
        }
        issues = validate_ledger_record(row)
        self.assertIn("missing_v16plus_subprocess_memory_limit_mib", issues)
        self.assertIn("missing_v16plus_process_peak_rss_mib", issues)
        self.assertIn("missing_v17plus_resource_limit_hit", issues)
        self.assertIn("missing_v17plus_process_resource_metric_scope", issues)


if __name__ == "__main__":
    unittest.main()
