from __future__ import annotations

import json
from pathlib import Path

from verify_replay_receipts import verify


def _write_case(tmp_path: Path, summary: dict, receipts: list[dict]) -> tuple[Path, Path]:
    receipts_path = tmp_path / "receipts.jsonl"
    receipts_path.write_text(
        "\n".join(json.dumps(item) for item in receipts) + "\n",
        encoding="utf-8",
    )
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    return receipts_path, summary_path


def _summary() -> dict:
    return {
        "manifest_count": 1,
        "invalid_manifest_count": 0,
        "replay_count": 2,
        "comparison_counts": {
            "MATCH": 1,
            "MISMATCH": 0,
            "UNKNOWN": 0,
            "NOT_APPLICABLE": 1,
        },
        "status_counts": {"OK": 2, "UNKNOWN": 0, "UNAVAILABLE": 0},
        "model_comparison_counts": {
            "MATCH": 0,
            "MISMATCH": 0,
            "UNKNOWN": 0,
            "NOT_APPLICABLE": 2,
        },
    }


def test_receipt_accounting_matches_summary(tmp_path: Path) -> None:
    receipts, summary = _write_case(
        tmp_path,
        _summary(),
        [
            {
                "manifest": "m1",
                "status": "OK",
                "issues": [],
                "replays": [
                    {
                        "comparison": "MATCH",
                        "status": "OK",
                        "model_check": {"comparison": "NOT_APPLICABLE"},
                    },
                    {
                        "comparison": "NOT_APPLICABLE",
                        "status": "OK",
                        "model_check": {"comparison": "NOT_APPLICABLE"},
                    },
                ],
            }
        ],
    )
    result = verify(receipts, summary)
    assert result["valid"] is True
    assert result["issues"] == []


def test_receipt_accounting_detects_mismatch(tmp_path: Path) -> None:
    receipts, summary = _write_case(
        tmp_path,
        _summary(),
        [
            {
                "manifest": "m1",
                "status": "OK",
                "issues": [],
                "replays": [
                    {
                        "comparison": "MISMATCH",
                        "status": "OK",
                        "model_check": {"comparison": "NOT_APPLICABLE"},
                    },
                    {
                        "comparison": "NOT_APPLICABLE",
                        "status": "OK",
                        "model_check": {"comparison": "NOT_APPLICABLE"},
                    },
                ],
            }
        ],
    )
    result = verify(receipts, summary)
    assert result["valid"] is False
    assert "comparison_counts_disagree" in result["issues"]
