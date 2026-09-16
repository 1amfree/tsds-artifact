"""Tests for the historical conditioned snapshot-boundary audit."""

from __future__ import annotations

from audit_historical_v20_conditioned_snapshot_boundary import analyze_record


def _record(**overrides):
    record = {
        "verdict": "VECTOR_SAT",
        "status": "vulnerable",
        "evidence_provenance": "SINK_RECONCILED",
        "analysis_recovery": "static_dynamic_taint_reconciliation",
        "sink_snapshot_cstring_complete": True,
        "sink_snapshot_capture_length": 7,
        "sink_snapshot_terminator_offset": 6,
        "controlled_offsets": [1, 2, 3],
        "recovered_sink_template": "echo <recovered_config_val>",
        "recovered_source_prefix": "config_val",
        "recovery_path_constraint_count": 12,
        "matrix_reconciled_constrained": True,
    }
    record.update(overrides)
    return record


def test_visible_offsets_are_distinguished_from_broad_taint_offsets():
    inside = analyze_record(_record())
    assert inside["boundary_status"] == "inside_final_cstring"
    assert inside["outside_final_cstring_count"] == 0
    assert inside["issues"] == []

    outside = analyze_record(_record(controlled_offsets=[1, 6, 7]))
    assert outside["boundary_status"] == "outside_final_cstring"
    assert outside["inside_final_cstring_count"] == 1
    assert outside["outside_final_cstring_count"] == 2
    assert outside["issues"] == []


def test_missing_recovery_metadata_is_an_issue_not_a_source_link():
    row = analyze_record(
        _record(
            sink_snapshot_cstring_complete=False,
            recovered_sink_template=None,
            recovered_source_prefix=None,
            recovery_path_constraint_count=0,
            matrix_reconciled_constrained=False,
        )
    )
    assert row["issues"]
    assert row["reconciliation_link_present"] is False
    assert row["reconciliation_link_admitted"] is False
