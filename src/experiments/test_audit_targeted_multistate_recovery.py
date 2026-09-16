from __future__ import annotations

import json
from pathlib import Path

try:
    from experiments.audit_targeted_multistate_recovery import build_stress_audit
except ModuleNotFoundError:  # Direct invocation from the experiments directory.
    from audit_targeted_multistate_recovery import build_stress_audit


def _write_case(root: Path, name: str, profile_count: int, complete: bool = False) -> Path:
    directory = root / name
    directory.mkdir()
    profiles = [{"status": "NO_MODELED_SOURCE"} for _ in range(profile_count)]
    row = {
        "closure_idx": 7,
        "source_addr": "0x10",
        "sink_addr": "0x20",
        "status": "residual",
        "verdict": "RESIDUAL",
        "evidence_provenance": "RESIDUAL",
        "residual_diagnosis_class": "bounded_multi_state_no_admissible_primary",
        "sink_snapshot_command_digest": "cmd",
        "sink_snapshot_digest": "snap",
        "sink_preview": "echo fixed",
        "sink_reached_observed": True,
        "engine_multi_state_collection_complete": False,
        "engine_multi_state_capture_count": profile_count,
        "engine_stop_reason": "multi_state_settle_budget_exhausted",
        "multi_state_audit": {
            "collection_complete": complete,
            "collection_scope": "bounded_sink_instances_for_selected_closure",
            "profiles": profiles,
            "aggregate": {
                "aggregate_class": "bounded_incomplete",
                "candidate_wide_negative": False,
                "decision_counts": {"VECTOR_SAT": 0, "MATRIX_UNSAT": 0, "INCONCLUSIVE": 0},
            },
            "primary_selection": {"selected_state_index": None},
        },
    }
    (directory / "results.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    (directory / "summary.json").write_text(json.dumps({"total_closures": 1}) + "\n", encoding="utf-8")
    (directory / "stderr.log").write_text("", encoding="utf-8")
    return directory


def test_stress_audit_accepts_more_profiles_without_negative_upgrade(tmp_path: Path) -> None:
    baseline = _write_case(tmp_path, "baseline", 2)
    less_pruned = _write_case(tmp_path, "less_pruned", 5)

    result = build_stress_audit(baseline, less_pruned)

    assert result["valid"] is True
    assert result["comparisons"]["identity_equal"] is True
    assert result["comparisons"]["profile_count_delta_less_pruned_minus_baseline"] == 3
    assert result["comparisons"]["both_candidate_wide_negative_false"] is True


def test_stress_audit_rejects_outcome_mismatch(tmp_path: Path) -> None:
    baseline = _write_case(tmp_path, "baseline", 2)
    less_pruned = _write_case(tmp_path, "less_pruned", 5)
    row_path = less_pruned / "results.jsonl"
    row = json.loads(row_path.read_text(encoding="utf-8"))
    row["verdict"] = "VECTOR_SAT"
    row_path.write_text(json.dumps(row) + "\n", encoding="utf-8")

    result = build_stress_audit(baseline, less_pruned)

    assert result["valid"] is False
    assert "primary_outcome_changed" in result["issues"]
