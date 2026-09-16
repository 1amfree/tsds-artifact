from __future__ import annotations

import json
from pathlib import Path

from audit_current_multistate_campaign import audit_campaign


def test_audit_discovers_nested_target_results(tmp_path: Path) -> None:
    for target in ("alpha", "beta"):
        directory = tmp_path / target
        directory.mkdir()
        (directory / f"{target}.results.jsonl").write_text(
            json.dumps({"status": "residual", "admissible_claim": "explicit_residual_obligation"})
            + "\n",
            encoding="utf-8",
        )

    summary = audit_campaign(tmp_path, expected_targets=2)

    assert summary["valid"] is True
    assert summary["target_count"] == 2
    assert summary["record_count"] == 2
    assert summary["target_record_counts"] == {"alpha": 1, "beta": 1}
