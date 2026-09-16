from __future__ import annotations

import json
from pathlib import Path

from audit_historical_current_multistate_alignment import build_alignment


def _write_campaign(root: Path, name: str, rows: list[dict]) -> Path:
    campaign = root / name
    campaign.mkdir()
    (campaign / "alpha.results.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    return campaign


def _write_config(path: Path, argument: str) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "tsds-v19-campaign-configuration-v1",
                "arguments": {"mode": argument},
                "campaign_driver_sha256": "driver",
                "evaluator_sha256": "evaluator",
                "targets": [
                    {
                        "name": "alpha",
                        "binary": "alpha/bin",
                        "binary_sha256": "binary",
                        "binary_exists": True,
                        "mango": "alpha/mango.json",
                        "mango_sha256": "mango",
                        "mango_exists": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_exact_key_alignment_and_late_positive(tmp_path: Path) -> None:
    old = _write_campaign(
        tmp_path,
        "old",
        [{"source_addr": "s", "sink_addr": "k", "status": "residual"}],
    )
    new = _write_campaign(
        tmp_path,
        "new",
        [
            {
                "source_addr": "s",
                "sink_addr": "k",
                "status": "vulnerable",
                "sink_reached_observed": True,
                "multi_state_audit": {
                    "collection_complete": True,
                    "profiles": [
                        {"status": "NO_MODELED_SOURCE"},
                        {"status": "VECTOR_SAT"},
                    ],
                    "aggregate": {"aggregate_class": "exists_positive", "candidate_wide_negative": False},
                    "primary_selection": {"selected_state_index": 1},
                },
            }
        ],
    )
    old_config = tmp_path / "old.json"
    new_config = tmp_path / "new.json"
    _write_config(old_config, "old")
    _write_config(new_config, "new")

    result = build_alignment(old, new, old_config, new_config)

    assert result["valid"] is True
    assert result["ledger_alignment"]["exact_key_intersection_count"] == 1
    current = result["current_bounded_multistate"]
    assert current["first_nonpositive_later_positive_rows"] == 1
    assert current["selected_later_positive_rows"] == 1
    assert current["selected_nonpositive_later_positive_rows"] == 0
    assert result["configuration"]["old_new_argument_descriptors_equal"] is False


def test_key_mismatch_is_reported(tmp_path: Path) -> None:
    old = _write_campaign(
        tmp_path,
        "old",
        [{"source_addr": "s", "sink_addr": "k", "status": "residual"}],
    )
    new = _write_campaign(
        tmp_path,
        "new",
        [{"source_addr": "other", "sink_addr": "k", "status": "residual"}],
    )
    old_config = tmp_path / "old.json"
    new_config = tmp_path / "new.json"
    _write_config(old_config, "same")
    _write_config(new_config, "same")

    result = build_alignment(old, new, old_config, new_config)

    assert result["valid"] is False
    assert "serialized_key_set_mismatch" in result["issues"]
