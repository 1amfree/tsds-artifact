from __future__ import annotations

import json
from pathlib import Path

from experiments.run_high_budget_incomplete_replay_suite import load_incomplete_rows


def test_load_incomplete_rows_selects_only_explicitly_incomplete_records(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    rows = [
        {
            "closure_idx": 4,
            "status": "residual",
            "verdict": "RESIDUAL",
            "source_addr": "0x1",
            "sink_addr": "0x2",
            "sink_snapshot_digest": "a",
            "multi_state_audit": {
                "collection_complete": False,
                "profiles": [{"status": "INCONCLUSIVE"}],
                "collection_accounting": {"blockers": ["state_cap_hits"]},
            },
        },
        {
            "closure_idx": 5,
            "status": "vulnerable",
            "verdict": "VECTOR_SAT",
            "multi_state_audit": {"collection_complete": True, "profiles": []},
        },
        {"closure_idx": 6, "status": "residual", "verdict": "RESIDUAL"},
    ]
    (campaign / "asus_rt_be57.results.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    selected = load_incomplete_rows(campaign)

    assert [(row["target"], row["closure_idx"]) for row in selected] == [("asus_rt_be57", 4)]
    assert selected[0]["baseline_profile_count"] == 1
    assert selected[0]["baseline_collection_blockers"] == ["state_cap_hits"]


def test_load_incomplete_rows_is_deterministic(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    rows = []
    for idx in (9, 2, 7):
        rows.append(
            {
                "closure_idx": idx,
                "status": "residual",
                "verdict": "RESIDUAL",
                "multi_state_audit": {"collection_complete": False},
            }
        )
    (campaign / "dir878.results.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    selected = load_incomplete_rows(campaign)

    assert [row["closure_idx"] for row in selected] == [2, 7, 9]
