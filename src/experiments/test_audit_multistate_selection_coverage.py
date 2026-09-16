from __future__ import annotations

import json
from pathlib import Path

from audit_multistate_selection_coverage import audit_campaign


def _row(profiles, selected, reason="later_collected_positive", complete=True):
    positive = [i for i, profile in enumerate(profiles) if profile["status"] == "VECTOR_SAT"]
    return {
        "closure_idx": 0,
        "status": "vulnerable" if positive else "residual",
        "sink_reached_observed": True,
        "multi_state_audit": {
            "collection_complete": complete,
            "profile_count": len(profiles),
            "profiles": profiles,
            "primary_selection": {
                "selected_state_index": selected,
                "selected_reason": reason,
                "positive_state_indices": positive,
            },
            "aggregate": {
                "profile_count": len(profiles),
                "positive_profile_indices": positive,
                "aggregate_class": "exists_positive" if positive else "bounded_incomplete",
                "candidate_wide_negative": False,
            },
        },
    }


def test_selection_audit_exposes_late_positive(tmp_path: Path):
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    rows = [
        _row(
            [{"status": "NO_MODELED_SOURCE"}, {"status": "VECTOR_SAT"}],
            selected=1,
        ),
        _row([{"status": "NO_MODELED_SOURCE"}], selected=None, complete=False),
    ]
    (campaign / "fixture.results.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    summary = audit_campaign(campaign, expected_targets=1)
    assert summary["valid"] is True
    assert summary["selection"]["first_nonpositive_later_positive_records"] == 1
    assert summary["selection"]["selected_late_positive_records"] == 1
    assert summary["selection"]["selected_nonpositive_later_positive_records"] == 0


def test_selection_audit_rejects_bad_positive_index(tmp_path: Path):
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    row = _row([{"status": "VECTOR_SAT"}], selected=0)
    row["multi_state_audit"]["aggregate"]["positive_profile_indices"] = [3]
    (campaign / "fixture.results.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    summary = audit_campaign(campaign)
    assert summary["valid"] is False
    assert "serialized_positive_index_not_profile_positive" in summary["row_issues"]
