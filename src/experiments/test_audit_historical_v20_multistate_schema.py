from __future__ import annotations

import json
from pathlib import Path

from experiments.audit_historical_v20_multistate_schema import audit_campaign


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def test_schema_audit_distinguishes_missing_multistate_fields(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    _write_jsonl(
        campaign / "target.results.jsonl",
        [
            {
                "sink_reached_observed": True,
                "engine_exit_active_states": 2,
                "vector_decisions": [{"vector_id": str(i)} for i in range(11)],
            },
            {"sink_reached_observed": False, "engine_exit_active_states": 0},
        ],
    )
    result = audit_campaign(campaign, expected_targets=1)
    assert result["valid"] is True
    assert result["record_count"] == 2
    assert result["field_presence"]["multi_state_audit"] == 0
    assert result["serialized_multistate_selection_available"] is False
    assert result["selection_coverage_auditable_from_v20_files"] is False
    assert result["vector_decision_lengths"] == {"11": 1}


def test_schema_audit_flags_serialized_multistate_fields(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    _write_jsonl(campaign / "target.results.jsonl", [{"multi_state_audit": {}}])
    result = audit_campaign(campaign, expected_targets=1)
    assert result["valid"] is False
    assert result["serialized_multistate_selection_available"] is True
    assert "multi_state_audit" not in result["issues"]
