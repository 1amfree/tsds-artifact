#!/usr/bin/env python3
"""Tests for the ICECCS cross-artifact consistency gate."""

from experiments.verify_iceccs_evidence_consistency import build_report


def test_consistency_gate_accepts_matching_ledgers() -> None:
    report = build_report(
        {
            "schema": "campaign",
            "target_count": 1,
            "record_count": 2,
            "matrix_profile_count": 1,
            "status_counts": {"residual": 2},
            "target_record_counts": {"fixture": 2},
            "valid": True,
        },
        {
            "schema": "performance",
            "valid": True,
            "campaign": {
                "target_count": 1,
                "records": 2,
                "matrix_profile_records": 1,
                "status_counts": {"residual": 2},
            },
            "targets": [{"target": "fixture", "records": 2, "matrix_query_manifest_count": 1}],
        },
        {
            "schema": "cross",
            "target_count": 1,
            "valid": True,
            "totals": {
                "paired_replay_count": 4,
                "observed_agreement_count": 4,
                "observed_disagreement_count": 0,
                "missing_left_count": 0,
                "missing_right_count": 0,
                "expected_disagreement_count": 0,
            },
        },
        {"schema": "tsds-local-python-source-lock-v1", "unresolved_local_imports": []},
        {"schema": "guard", "pass": True},
    )
    assert report["valid"] is True
    assert report["issues"] == []
