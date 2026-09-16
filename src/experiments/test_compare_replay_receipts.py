from __future__ import annotations

import json
from pathlib import Path

from experiments.compare_replay_receipts import compare


def _write(path: Path, observed: str) -> None:
    path.write_text(
        json.dumps(
            {
                "manifest": "m",
                "replays": [
                    {
                        "kind": "full",
                        "expected": "CACHED",
                        "observed": observed,
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_compare_requires_manifest_kind_and_status_agreement(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    _write(left, "SAT")
    _write(right, "SAT")
    result = compare(left, right)
    assert result["valid"] is True
    assert result["paired_replay_count"] == 1
    assert result["observed_agreement_count"] == 1


def test_compare_preserves_disagreement(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    _write(left, "SAT")
    _write(right, "UNSAT")
    result = compare(left, right)
    assert result["valid"] is False
    assert result["observed_disagreement_count"] == 1
