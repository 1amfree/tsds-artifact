from __future__ import annotations

from pathlib import Path

from experiments.audit_iceccs_reviewer_gap_closure import build_audit


def test_evidence_pack_reviewer_gap_closure_audit_passes() -> None:
    root = Path(__file__).resolve().parents[1]
    result = build_audit(root / "paper_work" / "iceccs_evidence_completion_20260915" / "manifest.json")
    assert result["valid"] is True
    assert result["passed_checks"] == 30
    assert result["failed_checks"] == []
    assert len(result["open_claims"]) == 5
