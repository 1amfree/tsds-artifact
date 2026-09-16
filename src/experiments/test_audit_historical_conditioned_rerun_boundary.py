from __future__ import annotations

import json
from pathlib import Path

from experiments.audit_historical_conditioned_rerun_boundary import build_audit


def test_historical_conditioned_rows_are_not_promoted_on_exact_rerun(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    result = build_audit(
        root,
        root
        / "experiment_reports/tsds_v20_release_20260718_r7_v8/"
        / "tsds_v20_accepted_repeat_20260718_r7/campaign",
        root / "experiment_reports/full_firmware_campaign_current_tsds_query_export_20260915",
        tmp_path / "audit",
    )
    assert result["valid"] is True
    assert result["historical_conditioned_rows"] == 44
    assert result["exactly_joined_rows"] == 44
    assert result["current_direct_promotion_rows"] == 0
    assert result["current_conditioned_promotion_rows"] == 0
    assert result["current_nonpromoted_rows"] == 44
    assert sum(result["current_provenance_counts"].values()) == 44

    summary = json.loads((tmp_path / "audit" / "summary.json").read_text(encoding="utf-8"))
    assert summary["valid"] is True
    assert (tmp_path / "audit" / "conditioned_rerun_boundary.jsonl").read_text(encoding="utf-8").count("\n") == 44
