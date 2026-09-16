from __future__ import annotations

import json
from pathlib import Path

from experiments.audit_historical_v20_taxonomy import audit_campaign


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def _row(provenance: str, recovery: str | None, claim: str, conditioning: str = "unconditioned") -> dict:
    return {
        "verdict": "VECTOR_SAT",
        "evidence_provenance": provenance,
        "analysis_recovery": recovery,
        "admissible_claim": claim,
        "evidence_conditioning": conditioning,
        "paper_claim_bucket": "bucket",
    }


def test_taxonomy_audit_partitions_direct_and_reconciled_rows(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    rows = [
        _row("DIRECT_SINK_BYTE", None, "direct_sink_byte_vector_sat"),
        _row("DIRECT_SINK_BYTE", None, "direct_observed_prefix_vector_sat"),
        _row("SINK_RECONCILED", "static_dynamic_taint_reconciliation", "reconciled_sink_byte_vector_sat"),
    ]
    _write_jsonl(campaign / "target.results.jsonl", rows)
    result = audit_campaign(campaign, expected_targets=1)
    assert result["valid"] is False  # the production cardinalities are intentionally not met
    assert result["taxonomy_partition"]["sum"] == 3
    assert result["taxonomy_partition"]["equals_vector_sat"] is True
    assert result["conditioning_metadata_mismatch_count"] == 1
    assert result["provenance_counts"]["DIRECT_SINK_BYTE"] == 2
    assert result["provenance_counts"]["SINK_RECONCILED"] == 1


def test_taxonomy_audit_does_not_treat_conditioned_metadata_as_a_source_link(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    rows = []
    rows.extend(_row("DIRECT_SINK_BYTE", None, "direct_sink_byte_vector_sat") for _ in range(51))
    rows.extend(
        _row("SINK_RECONCILED", "static_dynamic_taint_reconciliation", "reconciled_sink_byte_vector_sat")
        for _ in range(34)
    )
    rows.extend(
        {"verdict": "RESIDUAL", "evidence_provenance": "RESIDUAL"}
        for _ in range(433)
    )
    _write_jsonl(campaign / "target.results.jsonl", rows)
    result = audit_campaign(campaign, expected_targets=1)
    assert result["valid"] is False  # claim-count partition is intentionally incomplete
    assert result["vector_sat_count"] == 85
    assert result["conditioning_metadata_mismatch_count"] == 34
    assert result["provenance_counts"]["SINK_RECONCILED"] == 34
    assert result["metadata_warnings"]
