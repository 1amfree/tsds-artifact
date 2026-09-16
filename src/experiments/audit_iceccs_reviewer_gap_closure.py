#!/usr/bin/env python3
"""Audit the evidence pack against the ICECCS reviewer-gap checklist.

The report is intentionally evidence-only.  It verifies that the retained
receipts support their declared finite or target-local properties and records
the claims that remain open.  It never upgrades a replay, calibration, or
ledger check into firmware-wide ground truth or device exploitability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA = "tsds-iceccs-reviewer-gap-closure-audit-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _artifact_map(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item["name"]): item for item in manifest.get("artifacts", [])}


def _read_artifact(
    manifest_root: Path,
    artifacts: dict[str, dict[str, Any]],
    name: str,
) -> tuple[Path, Any]:
    item = artifacts[name]
    path = (manifest_root / str(item["path"])).resolve()
    return path, json.loads(path.read_text(encoding="utf-8"))


def _fact(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def build_audit(manifest_path: Path) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    root = manifest_path.parent
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifacts = _artifact_map(manifest)
    checks: list[dict[str, Any]] = []
    errors: list[str] = []

    def add(
        check_id: str,
        concern: str,
        artifact_names: list[str],
        passed: bool,
        observed: Any,
        scope: str,
    ) -> None:
        checks.append(
            {
                "id": check_id,
                "concern": concern,
                "artifacts": artifact_names,
                "pass": bool(passed),
                "observed": observed,
                "scope": scope,
            }
        )
        if not passed:
            errors.append(check_id)

    loaded: dict[str, Any] = {}
    paths: dict[str, str] = {}

    def load(name: str) -> Any:
        if name not in loaded:
            try:
                path, value = _read_artifact(root, artifacts, name)
                paths[name] = str(path)
                loaded[name] = value
            except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
                errors.append(f"load:{name}:{type(exc).__name__}")
                loaded[name] = None
        return loaded[name]

    guard = load("manuscript_guard")
    add(
        "manuscript_unchanged",
        "Evidence pass must not modify the manuscript projects",
        ["manuscript_guard"],
        manifest.get("manuscript_modified") is False and _fact(guard, "pass") is True,
        {"manifest_modified": manifest.get("manuscript_modified"), "guard": guard},
        "Read-only main.tex guard; not a complete project-tree diff",
    )

    matrix = load("reviewer_gap_calibration")
    add(
        "finite_matrix_calibration",
        "11-vector matrix requires finite construction labels and solver replay",
        ["reviewer_gap_calibration"],
        _fact(matrix, "overall_pass") is True
        and _fact(matrix, "matrix", "all_ground_truth_pass") is True
        and _fact(matrix, "matrix", "all_solver_replay_pass") is True
        and _fact(matrix, "matrix", "ground_truth_passed") == 176
        and _fact(matrix, "matrix", "solver_replay_passed") == 154,
        {
            "overall_pass": _fact(matrix, "overall_pass"),
            "cells": _fact(matrix, "matrix", "cells"),
            "ground_truth_passed": _fact(matrix, "matrix", "ground_truth_passed"),
            "solver_replay_passed": _fact(matrix, "matrix", "solver_replay_passed"),
        },
        "Finite synthetic matrix calibration only",
    )

    late = load("late_positive_symbolic_fixture_audit_summary")
    add(
        "late_positive_retained",
        "First-Ready behavior must not erase a later positive state",
        ["late_positive_symbolic_fixture_audit_summary"],
        _fact(late, "pass") is True
        and _fact(late, "first_profile_nonpositive") is True
        and _fact(late, "later_positive_observed") is True
        and _fact(late, "aggregate_class") == "exists_positive"
        and _fact(late, "candidate_wide_negative") is False,
        {
            "profiles": _fact(late, "profiles"),
            "first_profile_nonpositive": _fact(late, "first_profile_nonpositive"),
            "later_positive_observed": _fact(late, "later_positive_observed"),
            "aggregate_class": _fact(late, "aggregate_class"),
        },
        "One bounded synthetic ELF fixture",
    )

    selection = load("multistate_selection_coverage_audit")
    add(
        "current_multistate_selection_gate",
        "Current selected-instance logic must preserve later positives and avoid negative escalation",
        ["multistate_selection_coverage_audit"],
        _fact(selection, "valid") is True
        and _fact(selection, "record_count") == 518
        and len(_fact(selection, "late_positive_cases") or []) == 3
        and len(_fact(selection, "selected_late_positive_cases") or []) == 3
        and _fact(selection, "selection", "selected_nonpositive_later_positive_records") == 0
        and _fact(selection, "selection", "candidate_wide_negative_flags") == 0
        and _fact(selection, "row_issues") == [],
        {
            "records": _fact(selection, "record_count"),
            "profiles": _fact(selection, "profile_count_total"),
            "first_nonpositive_later_positive": len(_fact(selection, "late_positive_cases") or []),
            "selected_later_positive": len(_fact(selection, "selected_late_positive_cases") or []),
            "selected_nonpositive_later_positive": _fact(selection, "selection", "selected_nonpositive_later_positive_records"),
            "candidate_wide_negative_flags": _fact(selection, "selection", "candidate_wide_negative_flags"),
        },
        "Serialized bounded current-campaign profiles; not exhaustive firmware coverage",
    )

    current_multi = load("completed_eight_target_current_recursive_multistate_audit")
    add(
        "current_eight_target_aggregate",
        "Current campaign aggregation and negative boundary must be auditable",
        ["completed_eight_target_current_recursive_multistate_audit"],
        _fact(current_multi, "valid") is True
        and _fact(current_multi, "target_count") == 8
        and _fact(current_multi, "record_count") == 518
        and _fact(current_multi, "multi_state", "candidate_wide_negative") == 0
        and _fact(current_multi, "issues") == [],
        {
            "targets": _fact(current_multi, "target_count"),
            "records": _fact(current_multi, "record_count"),
            "profiles": _fact(current_multi, "matrix_profile_count"),
            "candidate_wide_negative": _fact(current_multi, "multi_state", "candidate_wide_negative"),
        },
        "Current query-export campaign accounting and bounded gate",
    )

    cross = load("current_cross_solver_replay_aggregate")
    add(
        "cross_solver_replay",
        "SAT/UNSAT outcomes require an external replay consistency check",
        ["current_cross_solver_replay_aggregate"],
        _fact(cross, "valid") is True
        and _fact(cross, "target_count") == 7
        and _fact(cross, "totals", "observed_agreement_count") == _fact(cross, "totals", "paired_replay_count")
        and _fact(cross, "totals", "observed_disagreement_count") == 0
        and _fact(cross, "totals", "missing_left_count") == 0
        and _fact(cross, "totals", "missing_right_count") == 0,
        {
            "targets": _fact(cross, "target_count"),
            "paired_replays": _fact(cross, "totals", "paired_replay_count"),
            "observed_agreement": _fact(cross, "totals", "observed_agreement_count"),
            "observed_disagreement": _fact(cross, "totals", "observed_disagreement_count"),
        },
        "Current exported-query targets; agreement is not source or device validity",
    )

    model_binding = load("current_smt_model_binding_audit")
    add(
        "smt_model_binding_replay",
        "Exported SAT/UNSAT queries require external replay and SAT-model consistency checks",
        ["current_smt_model_binding_audit"],
        _fact(model_binding, "valid") is True
        and _fact(model_binding, "selected_manifest_count") == 31309
        and _fact(model_binding, "query_count") == 62618
        and _fact(model_binding, "status_counts", "SAT") == 37343
        and _fact(model_binding, "status_counts", "UNSAT") == 25275
        and _fact(model_binding, "model_requested_queries") == 37343
        and _fact(model_binding, "model_check_comparisons", "MATCH") == 37343
        and _fact(model_binding, "invalid_query_rows") == 0
        and _fact(model_binding, "issues") == [],
        {
            "selected_manifests": _fact(model_binding, "selected_manifest_count"),
            "queries": _fact(model_binding, "query_count"),
            "sat": _fact(model_binding, "status_counts", "SAT"),
            "unsat": _fact(model_binding, "status_counts", "UNSAT"),
            "model_requested": _fact(model_binding, "model_requested_queries"),
            "model_matches": _fact(model_binding, "model_check_comparisons", "MATCH"),
            "invalid_query_rows": _fact(model_binding, "invalid_query_rows"),
        },
        "Full current exported-query model binding; not solver, source, firmware, or device proof",
    )

    runtime_alignment = load("runtime_historical_alignment_audit")
    add(
        "runtime_historical_alignment",
        "Runtime sink observations require identity-bound correspondence to the analyzed ledger",
        ["runtime_historical_alignment_audit"],
        _fact(runtime_alignment, "summary", "valid") is True
        and _fact(runtime_alignment, "summary", "runtime_attempts") == 17
        and _fact(runtime_alignment, "summary", "positive_attempts") == 10
        and _fact(runtime_alignment, "summary", "exact_sink_join_attempts") == 11
        and _fact(runtime_alignment, "summary", "exact_sink_join_unique_target_callsite_keys") == 5
        and _fact(runtime_alignment, "summary", "entry_join_address_mismatch_attempts") == 1
        and _fact(runtime_alignment, "summary", "summary_files_sha256_passed") == 17
        and _fact(runtime_alignment, "summary", "summary_files_checked") == 17
        and _fact(runtime_alignment, "summary", "campaign_identity_match") is True
        and _fact(runtime_alignment, "summary", "issues") == [],
        {
            "runtime_attempts": _fact(runtime_alignment, "summary", "runtime_attempts"),
            "positive_attempts": _fact(runtime_alignment, "summary", "positive_attempts"),
            "exact_sink_join_attempts": _fact(runtime_alignment, "summary", "exact_sink_join_attempts"),
            "exact_sink_join_unique_target_callsite_keys": _fact(
                runtime_alignment,
                "summary",
                "exact_sink_join_unique_target_callsite_keys",
            ),
            "entry_join_address_mismatch_attempts": _fact(
                runtime_alignment,
                "summary",
                "entry_join_address_mismatch_attempts",
            ),
            "summary_files_sha256_passed": _fact(
                runtime_alignment,
                "summary",
                "summary_files_sha256_passed",
            ),
        },
        "Finite runtime-to-historical correspondence only; no source or device validity",
    )

    witness_replay = load("current_witness_replay_audit")
    add(
        "current_witness_interface_replay",
        "Current final-byte witnesses require a bounded shell-interface replay check",
        ["current_witness_replay_audit"],
        _fact(witness_replay, "valid") is True
        and _fact(witness_replay, "record_count") == 275
        and _fact(witness_replay, "shell_count") == 2
        and _fact(witness_replay, "issues") == [],
        {
            "records": _fact(witness_replay, "record_count"),
            "shells": _fact(witness_replay, "shells"),
            "issues": _fact(witness_replay, "issues"),
        },
        "Current-ledger shell syntax and strict-inert execution only; no source, firmware, or device validity",
    )

    high_budget = load("high_budget_positive_replay_audit")
    add(
        "high_budget_positive_replay",
        "Direct positive outcomes require an identity-bound higher-budget existential replay",
        ["high_budget_positive_replay_audit"],
        _fact(high_budget, "all_checks_pass") is True
        and _fact(high_budget, "baseline_positive_rows") == 41
        and _fact(high_budget, "replay_case_count") == 41
        and _fact(high_budget, "receipt_count") == 41
        and _fact(high_budget, "direct_provenance_count") == 41
        and _fact(high_budget, "outcome_stable_count") == 41
        and _fact(high_budget, "complete_collection_count") == 35
        and _fact(high_budget, "incomplete_collection_count") == 6
        and _fact(high_budget, "issues") == []
        and len(_fact(high_budget, "warnings") or []) == 6,
        {
            "baseline_positive_rows": _fact(high_budget, "baseline_positive_rows"),
            "replay_cases": _fact(high_budget, "replay_case_count"),
            "receipts": _fact(high_budget, "receipt_count"),
            "direct_provenance": _fact(high_budget, "direct_provenance_count"),
            "outcome_stable": _fact(high_budget, "outcome_stable_count"),
            "complete_collections": _fact(high_budget, "complete_collection_count"),
            "incomplete_collections": _fact(high_budget, "incomplete_collection_count"),
            "warnings": len(_fact(high_budget, "warnings") or []),
        },
        "Finite identity-bound positive existential replay; incomplete collections are warnings and do not support exhaustive or negative claims",
    )

    dir878_recovery = load("dir878_bounded_recovery_audit")
    add(
        "dir878_bounded_recovery_boundary",
        "A recovered target-local receipt must retain identity, bounded-collection, and non-escalation boundaries",
        ["dir878_bounded_recovery_audit"],
        _fact(dir878_recovery, "valid") is True
        and _fact(dir878_recovery, "target") == "dir878"
        and _fact(dir878_recovery, "closure_idx") == 2
        and _fact(dir878_recovery, "identity_match", "source_addr") is True
        and _fact(dir878_recovery, "identity_match", "sink_addr") is True
        and _fact(dir878_recovery, "recovery", "collection_complete") is True
        and _fact(dir878_recovery, "recovery", "profile_count") == 160
        and _fact(dir878_recovery, "recovery", "aggregate_class") == "exists_positive"
        and _fact(dir878_recovery, "recovery", "candidate_wide_negative") is False
        and _fact(dir878_recovery, "non_escalation", "original_campaign_rewritten") is False
        and _fact(dir878_recovery, "non_escalation", "manuscript_modified") is False,
        {
            "target": _fact(dir878_recovery, "target"),
            "closure_idx": _fact(dir878_recovery, "closure_idx"),
            "identity_match": _fact(dir878_recovery, "identity_match"),
            "collection_complete": _fact(dir878_recovery, "recovery", "collection_complete"),
            "profiles": _fact(dir878_recovery, "recovery", "profile_count"),
            "aggregate_class": _fact(dir878_recovery, "recovery", "aggregate_class"),
            "candidate_wide_negative": _fact(dir878_recovery, "recovery", "candidate_wide_negative"),
        },
        "One DIR-878 closure under a finite higher-budget recovery; no firmware-wide or device-level claim",
    )

    conditioned_recovery = load("historical_conditioned_recovery_audit")
    add(
        "historical_conditioned_recovery_boundary",
        "Target-local replays of historical conditioned rows must remain identity-bound and fail closed when source links are absent",
        ["historical_conditioned_recovery_audit"],
        _fact(conditioned_recovery, "valid") is True
        and _fact(conditioned_recovery, "case_count") == 3
        and _fact(conditioned_recovery, "identity_match_count") == 3
        and _fact(conditioned_recovery, "current_direct_promotion_count") == 0
        and _fact(conditioned_recovery, "current_conditioned_promotion_count") == 0
        and _fact(conditioned_recovery, "current_nonpromotion_count") == 3
        and _fact(conditioned_recovery, "candidate_wide_negative_count") == 0,
        {
            "cases": _fact(conditioned_recovery, "case_count"),
            "identity_matches": _fact(conditioned_recovery, "identity_match_count"),
            "direct_promotions": _fact(conditioned_recovery, "current_direct_promotion_count"),
            "conditioned_promotions": _fact(conditioned_recovery, "current_conditioned_promotion_count"),
            "nonpromotions": _fact(conditioned_recovery, "current_nonpromotion_count"),
            "candidate_wide_negatives": _fact(conditioned_recovery, "candidate_wide_negative_count"),
        },
        "Three finite historical conditioned rows; no historical source-link or firmware-wide validity claim",
    )

    native_link = load("native_source_link_calibration")
    add(
        "native_source_link_calibration",
        "Conditioned source-link admission requires an original-program byte-trace calibration",
        ["native_source_link_calibration"],
        _fact(native_link, "all_checks_pass") is True
        and _fact(native_link, "case_count") == 18
        and _fact(native_link, "native_trace_byte_matches") == 18
        and _fact(native_link, "trace_replay_pass") == 18
        and _fact(native_link, "link_admission_pass") == 18,
        {
            "cases": _fact(native_link, "case_count"),
            "native_trace_byte_matches": _fact(native_link, "native_trace_byte_matches"),
            "trace_replay_pass": _fact(native_link, "trace_replay_pass"),
            "link_admission_pass": _fact(native_link, "link_admission_pass"),
        },
        "Finite synthetic C fixture; not historical CT-SAT linkage",
    )

    adversarial_link = load("conditioned_link_adversarial_calibration")
    add(
        "conditioned_link_adversarial_boundary",
        "Conditioned source-link admission must reject missing, stale, ambiguous, and malformed bindings",
        ["conditioned_link_adversarial_calibration"],
        _fact(adversarial_link, "all_checks_pass") is True
        and _fact(adversarial_link, "positive_cases") == 18
        and _fact(adversarial_link, "positive_admissions") == 18
        and _fact(adversarial_link, "negative_cases") == 13
        and _fact(adversarial_link, "negative_rejections") == 13
        and _fact(adversarial_link, "false_accepts") == 0
        and _fact(adversarial_link, "false_rejections") == 0
        and _fact(adversarial_link, "native_trace_mismatches") == 0
        and _fact(adversarial_link, "native_execution_failures") == 0,
        {
            "positive_cases": _fact(adversarial_link, "positive_cases"),
            "positive_admissions": _fact(adversarial_link, "positive_admissions"),
            "negative_cases": _fact(adversarial_link, "negative_cases"),
            "negative_rejections": _fact(adversarial_link, "negative_rejections"),
            "false_accepts": _fact(adversarial_link, "false_accepts"),
            "native_trace_mismatches": _fact(adversarial_link, "native_trace_mismatches"),
        },
        "Finite native synthetic fixture plus adversarial replay mutations; not historical linkage",
    )

    property_link = load("conditioned_link_property_calibration")
    add(
        "conditioned_link_property_boundary",
        "Conditioned source-link replay must remain stable across randomized bytes and repeated boundary mutations",
        ["conditioned_link_property_calibration"],
        _fact(property_link, "all_checks_pass") is True
        and _fact(property_link, "positive_cases") == 360
        and _fact(property_link, "positive_admissions") == 360
        and _fact(property_link, "negative_cases") == 384
        and _fact(property_link, "negative_rejections") == 384
        and _fact(property_link, "false_accepts") == 0
        and _fact(property_link, "false_rejections") == 0
        and _fact(property_link, "native_trace_mismatches") == 0
        and _fact(property_link, "native_execution_failures") == 0,
        {
            "positive_cases": _fact(property_link, "positive_cases"),
            "positive_admissions": _fact(property_link, "positive_admissions"),
            "negative_cases": _fact(property_link, "negative_cases"),
            "negative_rejections": _fact(property_link, "negative_rejections"),
            "false_accepts": _fact(property_link, "false_accepts"),
            "false_rejections": _fact(property_link, "false_rejections"),
            "native_trace_mismatches": _fact(property_link, "native_trace_mismatches"),
        },
        "Randomized finite native fixture plus mutation replay; not historical linkage",
    )

    aggregation_property = load("multistate_exhaustive_property_calibration")
    add(
        "multistate_exhaustive_property_boundary",
        "Bounded aggregation must preserve selection, sidecar separation, and negative-gating invariants",
        ["multistate_exhaustive_property_calibration"],
        _fact(aggregation_property, "all_checks_pass") is True
        and _fact(aggregation_property, "sequence_cases") == 5602
        and _fact(aggregation_property, "relation_cases") == 10
        and _fact(aggregation_property, "failed_case_count") == 0,
        {
            "sequence_cases": _fact(aggregation_property, "sequence_cases"),
            "relation_cases": _fact(aggregation_property, "relation_cases"),
            "failed_case_count": _fact(aggregation_property, "failed_case_count"),
        },
        "Finite exhaustive profile-sequence calibration; not exhaustive firmware coverage",
    )

    negative_gate = load("negative_gate_adversarial_calibration")
    add(
        "negative_gate_adversarial_boundary",
        "Negative status admission must reject stale, incomplete, mixed, and tampered aggregates",
        ["negative_gate_adversarial_calibration"],
        _fact(negative_gate, "all_checks_pass") is True
        and _fact(negative_gate, "case_count") == 39
        and _fact(negative_gate, "valid_admission_cases") == 6
        and _fact(negative_gate, "rejection_cases") == 33
        and _fact(negative_gate, "admissions_observed") == 6
        and _fact(negative_gate, "rejections_observed") == 33
        and _fact(negative_gate, "failed_case_count") == 0,
        {
            "cases": _fact(negative_gate, "case_count"),
            "valid_admissions": _fact(negative_gate, "valid_admission_cases"),
            "rejections": _fact(negative_gate, "rejection_cases"),
            "admissions_observed": _fact(negative_gate, "admissions_observed"),
            "rejections_observed": _fact(negative_gate, "rejections_observed"),
            "failed_case_count": _fact(negative_gate, "failed_case_count"),
        },
        "Finite adversarial aggregate-metadata calibration; not firmware ground truth",
    )

    conditioned = load("historical_conditioned_link_audit")
    add(
        "historical_conditioned_nonpromotion",
        "Historical reconciled records must not be promoted without serialized source links",
        ["historical_conditioned_link_audit"],
        _fact(conditioned, "admitted_records") == 0
        and _fact(conditioned, "open_records") == 44
        and _fact(conditioned, "no_links_synthesized") is True,
        {
            "reconciliation_records": _fact(conditioned, "reconciliation_records"),
            "conditioned_records": _fact(conditioned, "conditioned_records"),
            "admitted_records": _fact(conditioned, "admitted_records"),
            "open_records": _fact(conditioned, "open_records"),
        },
        "Historical records remain conditioned/open; no semantic upgrade",
    )

    conditioned_boundary = load("historical_conditioned_snapshot_boundary_audit")
    add(
        "historical_conditioned_snapshot_boundary",
        "Conditioned records must distinguish reconstructed templates from visible final-C-string source bytes",
        ["historical_conditioned_snapshot_boundary_audit"],
        _fact(conditioned_boundary, "valid") is True
        and _fact(conditioned_boundary, "records") == 44
        and _fact(conditioned_boundary, "complete_snapshots") == 44
        and _fact(conditioned_boundary, "terminator_capture_consistent") == 44
        and _fact(conditioned_boundary, "metadata_issue_records") == 0
        and _fact(conditioned_boundary, "reconciliation_links_present") == 0
        and _fact(conditioned_boundary, "reconciliation_links_admitted") == 0,
        {
            "records": _fact(conditioned_boundary, "records"),
            "complete_snapshots": _fact(conditioned_boundary, "complete_snapshots"),
            "terminator_capture_consistent": _fact(conditioned_boundary, "terminator_capture_consistent"),
            "offsets_outside_final_cstring": _fact(conditioned_boundary, "records_with_offsets_outside_final_cstring"),
            "links_present": _fact(conditioned_boundary, "reconciliation_links_present"),
            "links_admitted": _fact(conditioned_boundary, "reconciliation_links_admitted"),
        },
        "Historical conditioned metadata audit; no source-link inference",
    )

    conditioned_fields = load("historical_conditioned_field_completeness")
    add(
        "historical_conditioned_field_completeness",
        "Historical conditioned records require serialized replay fields before source-link admission",
        ["historical_conditioned_field_completeness"],
        _fact(conditioned_fields, "all_checks_pass") is True
        and _fact(conditioned_fields, "records") == 44
        and _fact(conditioned_fields, "serialized_link_records") == 0
        and _fact(conditioned_fields, "admitted_link_records") == 0
        and _fact(conditioned_fields, "records_with_any_link_field") == 0
        and _fact(conditioned_fields, "records_with_source_to_sink_mapping") == 0
        and _fact(conditioned_fields, "records_with_transform_chain") == 0
        and _fact(conditioned_fields, "records_with_source_variables") == 0
        and _fact(conditioned_fields, "complete_snapshots") == 44
        and _fact(conditioned_fields, "terminator_capture_consistent") == 44,
        {
            "records": _fact(conditioned_fields, "records"),
            "serialized_links": _fact(conditioned_fields, "serialized_link_records"),
            "admitted_links": _fact(conditioned_fields, "admitted_link_records"),
            "source_to_sink_maps": _fact(conditioned_fields, "records_with_source_to_sink_mapping"),
            "transform_chains": _fact(conditioned_fields, "records_with_transform_chain"),
            "source_variables": _fact(conditioned_fields, "records_with_source_variables"),
            "complete_snapshots": _fact(conditioned_fields, "complete_snapshots"),
            "terminator_capture_consistent": _fact(conditioned_fields, "terminator_capture_consistent"),
        },
        "Historical field-completeness audit; no source-link inference",
    )

    conditioned_rerun = load("historical_conditioned_rerun_boundary")
    add(
        "historical_conditioned_rerun_nonpromotion",
        "A hardened rerun must not silently promote historical conditioned rows",
        ["historical_conditioned_rerun_boundary"],
        _fact(conditioned_rerun, "valid") is True
        and _fact(conditioned_rerun, "historical_conditioned_rows") == 44
        and _fact(conditioned_rerun, "exactly_joined_rows") == 44
        and _fact(conditioned_rerun, "current_direct_promotion_rows") == 0
        and _fact(conditioned_rerun, "current_conditioned_promotion_rows") == 0
        and _fact(conditioned_rerun, "current_nonpromoted_rows") == 44
        and _fact(conditioned_rerun, "current_link_present_rows") == 0,
        {
            "historical_conditioned_rows": _fact(conditioned_rerun, "historical_conditioned_rows"),
            "exactly_joined_rows": _fact(conditioned_rerun, "exactly_joined_rows"),
            "current_direct_promotion_rows": _fact(conditioned_rerun, "current_direct_promotion_rows"),
            "current_conditioned_promotion_rows": _fact(conditioned_rerun, "current_conditioned_promotion_rows"),
            "current_nonpromoted_rows": _fact(conditioned_rerun, "current_nonpromoted_rows"),
            "current_provenance_counts": _fact(conditioned_rerun, "current_provenance_counts"),
        },
        "Exact-key rerun boundary; same declared input digests, not historical source linkage",
    )

    truth = load("controlled_ground_truth_audit")
    add(
        "controlled_ground_truth_calibration",
        "Positive and negative classifications require fixed-label external calibration",
        ["controlled_ground_truth_audit"],
        _fact(truth, "valid") is True
        and _fact(truth, "tsds", "n") == 24
        and _fact(truth, "tsds", "tp") == 14
        and _fact(truth, "tsds", "fp") == 0
        and _fact(truth, "tsds", "tn") == 10
        and _fact(truth, "tsds", "fn") == 0,
        {
            "cases": _fact(truth, "tsds", "n"),
            "tp": _fact(truth, "tsds", "tp"),
            "fp": _fact(truth, "tsds", "fp"),
            "tn": _fact(truth, "tsds", "tn"),
            "fn": _fact(truth, "tsds", "fn"),
        },
        "Fixed-label synthetic ELF only; not firmware-wide ground truth",
    )

    semantic = load("semantic_benchmark")
    add(
        "semantic_oracle_calibration",
        "Shell semantics require native/oracle parity and held-out calibration",
        ["semantic_benchmark"],
        _fact(semantic, "native_execution_status") == "PASS"
        and _fact(semantic, "parity_pass") is True
        and _fact(semantic, "native_oracle_parity", "MATCH") == 1056
        and _fact(semantic, "held_out_not_used_for_tuning") is True,
        {
            "cases": _fact(semantic, "case_count"),
            "native_oracle_rows": _fact(semantic, "native_rows_expected"),
            "native_oracle_matches": _fact(semantic, "native_oracle_parity", "MATCH"),
            "held_out_not_used_for_tuning": _fact(semantic, "held_out_not_used_for_tuning"),
        },
        "Declared finite semantic input domain",
    )

    source_reconciliation = load("historical_v20_source_reconciliation")
    add(
        "historical_source_reconciliation",
        "Historical counts require release-file and aggregate reconciliation",
        ["historical_v20_source_reconciliation"],
        _fact(source_reconciliation, "valid") is True
        and _fact(source_reconciliation, "file_integrity_pass") is True
        and _fact(source_reconciliation, "issues") == []
        and _fact(source_reconciliation, "raw_record_total") == 518
        and _fact(source_reconciliation, "matrix_checks", "matrix_cell_count") == 1122,
        {
            "raw_files": _fact(source_reconciliation, "raw_result_files"),
            "records": _fact(source_reconciliation, "raw_record_total"),
            "matrix_profiles": _fact(source_reconciliation, "matrix_checks", "matrix_profile_count"),
            "matrix_cells": _fact(source_reconciliation, "matrix_checks", "matrix_cell_count"),
            "file_integrity_pass": _fact(source_reconciliation, "file_integrity_pass"),
        },
        "Historical V20 release integrity and accounting only",
    )

    taxonomy = load("historical_v20_taxonomy_audit")
    add(
        "historical_taxonomy_partition",
        "Direct and reconciled positive evidence must remain separate",
        ["historical_v20_taxonomy_audit"],
        _fact(taxonomy, "valid") is True
        and _fact(taxonomy, "record_count") == 518
        and _fact(taxonomy, "vector_sat_count") == 85
        and _fact(taxonomy, "provenance_counts", "DIRECT_SINK_BYTE") == 51
        and _fact(taxonomy, "provenance_counts", "SINK_RECONCILED") == 34
        and _fact(taxonomy, "conditioning_metadata_mismatch_count") == 34,
        {
            "records": _fact(taxonomy, "record_count"),
            "vector_sat": _fact(taxonomy, "vector_sat_count"),
            "direct": _fact(taxonomy, "provenance_counts", "DIRECT_SINK_BYTE"),
            "reconciled": _fact(taxonomy, "provenance_counts", "SINK_RECONCILED"),
            "raw_conditioning_metadata_mismatch": _fact(taxonomy, "conditioning_metadata_mismatch_count"),
        },
        "Serialized taxonomy accounting; metadata warning retained",
    )

    vector = load("historical_v20_vector_decision_integrity_audit")
    add(
        "historical_vector_ledger_integrity",
        "Historical matrix IDs, decision counts, and lexical metadata require an independent checker",
        ["historical_v20_vector_decision_integrity_audit"],
        _fact(vector, "records") == 518
        and _fact(vector, "records_with_decisions") == 102
        and _fact(vector, "records_with_integrity_issues") == 0
        and _fact(vector, "decision_outcomes", "VECTOR_SAT") == 679
        and _fact(vector, "decision_outcomes", "MATRIX_UNSAT") == 292
        and _fact(vector, "decision_outcomes", "INCONCLUSIVE") == 151,
        {
            "records": _fact(vector, "records"),
            "profiles": _fact(vector, "records_with_decisions"),
            "decisions": _fact(vector, "decision_outcomes"),
            "integrity_issue_records": _fact(vector, "records_with_integrity_issues"),
        },
        "Ledger and lexical metadata only; no command execution or SMT re-solving",
    )

    conservation = load("historical_v20_campaign_conservation_audit")
    add(
        "historical_dedup_conservation",
        "The 546-to-518 denominator requires explicit deduplication conservation",
        ["historical_v20_campaign_conservation_audit"],
        _fact(conservation, "valid") is True
        and _fact(conservation, "issues") == []
        and _fact(conservation, "total", "candidate_closures") == 546
        and _fact(conservation, "total", "unique_pairs") == 518
        and _fact(conservation, "total", "jsonl_records") == 518,
        {
            "candidate_closures": _fact(conservation, "total", "candidate_closures"),
            "unique_pairs": _fact(conservation, "total", "unique_pairs"),
            "jsonl_records": _fact(conservation, "total", "jsonl_records"),
        },
        "Campaign-level ledger conservation; not root-cause uniqueness",
    )

    certificate = load("historical_v20_certificate_audit")
    independent_certificate = load("historical_v20_independent_certificate_verifier")
    add(
        "certificate_structural_audit",
        "Certificate records require independent structural and admission checks",
        ["historical_v20_certificate_audit", "historical_v20_independent_certificate_verifier"],
        _fact(certificate, "valid_certificates") == 518
        and _fact(certificate, "records_with_issues") == 0
        and _fact(independent_certificate, "valid") is True
        and _fact(independent_certificate, "valid_records") == 518
        and _fact(independent_certificate, "records_with_issues") == 0
        and _fact(independent_certificate, "parser_outcomes", "accepted_all") == 85,
        {
            "certificate_valid": _fact(certificate, "valid_certificates"),
            "independent_valid": _fact(independent_certificate, "valid_records"),
            "parser_accepted": _fact(independent_certificate, "parser_outcomes", "accepted_all"),
        },
        "Structural/integrity/admission checking; not solver or device proof",
    )

    performance = load("current_campaign_performance_ledger")
    add(
        "current_performance_accounting",
        "Performance and resource claims require complete campaign accounting",
        ["current_campaign_performance_ledger"],
        _fact(performance, "valid") is True
        and _fact(performance, "campaign", "records") == 518
        and _fact(performance, "campaign", "resource_observation_summary", "resource_limit_hits") == 0
        and _fact(performance, "campaign", "input_closures") == 546,
        {
            "records": _fact(performance, "campaign", "records"),
            "input_closures": _fact(performance, "campaign", "input_closures"),
            "wall_time_sec": _fact(performance, "campaign", "campaign_wall_time_sec_sum"),
            "resource_limit_hits": _fact(performance, "campaign", "resource_observation_summary", "resource_limit_hits"),
        },
        "Descriptive sequential resource accounting; no concurrency claim",
    )

    source_lock = load("current_source_dependency_manifest")
    consistency = load("iceccs_evidence_cross_consistency_audit")
    add(
        "evidence_index_consistency",
        "Evidence dependencies and cross-artifact accounting must be source-locked",
        ["current_source_dependency_manifest", "iceccs_evidence_cross_consistency_audit"],
        _fact(source_lock, "file_count") == 28
        and _fact(source_lock, "unresolved_local_imports") == []
        and _fact(consistency, "valid") is True
        and _fact(consistency, "issues") == [],
        {
            "source_files": _fact(source_lock, "files"),
            "unresolved_local_imports": len(_fact(source_lock, "unresolved_local_imports") or []),
            "cross_consistency_issues": _fact(consistency, "issues"),
        },
        "Source and accounting commitment only",
    )

    open_claims = [
        {
            "id": "historical_exhaustive_multistate_coverage",
            "status": "open",
            "reason": "Frozen historical V20 rows do not serialize multi-state profiles or First-Ready selection metadata.",
            "required_evidence": "Complete historical state enumeration with serialized selection and aggregation receipts.",
        },
        {
            "id": "historical_conditioned_source_linkage",
            "status": "open",
            "reason": "The field-completeness and conditioned-link audits find no serialized replay link in the 44 historical reconciliation rows, so none is admitted.",
            "required_evidence": "Original-program or firmware-level byte-trace linkage for the historical reconciled rows.",
        },
        {
            "id": "independent_blinded_human_labels",
            "status": "open",
            "reason": "The 60-record blinded sample is packaged but contains no human adjudication labels.",
            "required_evidence": "Independent labels and inter-rater agreement from the declared adjudication protocol.",
        },
        {
            "id": "firmware_closed_world_precision_recall",
            "status": "open",
            "reason": "The fixed-label benchmark is a synthetic calibration, not a closed-world firmware ground-truth set.",
            "required_evidence": "Independent labels for a representative firmware candidate sample.",
        },
        {
            "id": "device_level_exploitability",
            "status": "open",
            "reason": "Runtime checks do not execute generated witnesses or establish post-sink device effects.",
            "required_evidence": "Controlled device or high-fidelity rehosting validation under an approved safe protocol.",
        },
    ]

    return {
        "schema": SCHEMA,
        "manifest": str(manifest_path),
        "manifest_artifact_count": len(artifacts),
        "checks": checks,
        "passed_checks": sum(bool(item["pass"]) for item in checks),
        "failed_checks": errors,
        "open_claims": open_claims,
        "status": "evidence_gates_pass_with_declared_open_claims" if not errors else "evidence_gate_failure",
        "valid": not errors and bool(checks),
        "claim_boundary": (
            "This audit verifies declared finite, target-local, structural, and "
            "accounting properties of the evidence pack. It does not prove "
            "firmware-wide precision, exhaustive historical state coverage, "
            "historical conditioned source linkage, human adjudication, solver "
            "soundness, or device-level exploitability."
        ),
        "loaded_paths": paths,
    }


def write_outputs(out_dir: Path, result: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = out_dir / "reviewer_gap_closure_audit.json"
    summary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# ICECCS reviewer-gap closure audit",
        "",
        f"Status: **{result['status']}**",
        f"Passed checks: **{result['passed_checks']}/{len(result['checks'])}**",
        f"Manifest artifacts: **{result['manifest_artifact_count']}**",
        "",
        "## Audited gates",
        "",
        "| Check | Result | Scope |",
        "|---|---|---|",
    ]
    for item in result["checks"]:
        lines.append(
            f"| `{item['id']}` | {'PASS' if item['pass'] else 'FAIL'} | {item['scope']} |"
        )
    lines.extend(["", "## Claims intentionally left open", ""])
    for item in result["open_claims"]:
        lines.append(f"- **{item['id']}**: {item['reason']}")
    lines.extend(["", result["claim_boundary"]])
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    digest_lines = []
    for path in sorted(out_dir.iterdir()):
        if path.name != "SHA256SUMS" and path.is_file():
            digest_lines.append(f"{sha256_file(path)}  {path.name}")
    (out_dir / "SHA256SUMS").write_text("\n".join(digest_lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_audit(args.manifest)
        write_outputs(args.out_dir.resolve(), result)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ICECCS_REVIEWER_GAP_CLOSURE_AUDIT_ERROR: {exc}")
        return 2
    print(json.dumps({
        "status": result["status"],
        "passed_checks": result["passed_checks"],
        "total_checks": len(result["checks"]),
        "failed_checks": result["failed_checks"],
        "open_claims": len(result["open_claims"]),
    }, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
