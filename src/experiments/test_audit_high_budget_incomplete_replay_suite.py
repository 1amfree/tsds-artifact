from __future__ import annotations

import json
from pathlib import Path

from experiments.audit_high_budget_incomplete_replay_suite import audit_suite


def _write_row(path: Path, row: dict) -> None:
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")


def test_audit_accepts_identity_stable_incomplete_replay(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    suite = tmp_path / "suite"
    baseline.mkdir()
    suite.mkdir()
    baseline_row = {
        "closure_idx": 3,
        "status": "residual",
        "verdict": "RESIDUAL",
        "source_addr": "0x10",
        "sink_addr": "0x20",
        "sink_function": "system",
        "multi_state_audit": {"collection_complete": False, "profiles": []},
    }
    _write_row(baseline / "asus_rt_be57.results.jsonl", baseline_row)
    (suite / "suite_config.json").write_text(
        json.dumps({"selection": "multi_state_audit.collection_complete == false"}), encoding="utf-8"
    )
    case = suite / "asus_rt_be57_idx3"
    case.mkdir()
    replay = {
        **baseline_row,
        "multi_state_audit": {
            "collection_complete": False,
            "profiles": [],
            "aggregate": {"candidate_wide_negative": False},
        },
    }
    _write_row(case / "results.jsonl", replay)
    (case / "returncode").write_text("0\n", encoding="utf-8")

    report = audit_suite(baseline, suite)

    assert report["all_checks_pass"] is True
    assert report["replay_case_count"] == 1
    assert report["candidate_wide_negative_count"] == 0


def test_audit_rejects_missing_replay_case(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    suite = tmp_path / "suite"
    baseline.mkdir()
    suite.mkdir()
    _write_row(
        baseline / "dir878.results.jsonl",
        {"closure_idx": 1, "multi_state_audit": {"collection_complete": False}},
    )
    (suite / "suite_config.json").write_text(
        json.dumps({"selection": "multi_state_audit.collection_complete == false"}), encoding="utf-8"
    )

    report = audit_suite(baseline, suite)

    assert report["all_checks_pass"] is False
    assert any(item["issue"] == "incomplete_baseline_row_not_replayed" for item in report["issues"])
