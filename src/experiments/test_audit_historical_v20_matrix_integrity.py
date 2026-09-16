from __future__ import annotations

import json
from pathlib import Path

from experiments.audit_historical_v20_matrix_integrity import audit_campaign


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def _profile(verdict: str = "VECTOR_SAT") -> dict:
    ids = [
        "semicolon",
        "newline",
        "pipe",
        "background_ampersand",
        "backtick_substitution",
        "dollar_substitution",
        "dollar_expansion",
        "output_redirection",
        "input_redirection",
        "ifs_word_splitting",
        "tab_word_splitting",
    ]
    decision = "VECTOR_SAT" if verdict == "VECTOR_SAT" else "MATRIX_UNSAT"
    return {
        "closure_idx": 1,
        "verdict": verdict,
        "vulnerable_vectors": 11 if decision == "VECTOR_SAT" else 0,
        "secure_vectors": 11 if decision == "MATRIX_UNSAT" else 0,
        "inconclusive_vectors": 0,
        "vector_decisions": [{"vector_id": item, "decision": decision} for item in ids],
    }


def test_profile_integrity_checks_decision_counts(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    _write_jsonl(campaign / "target.results.jsonl", [_profile() for _ in range(102)])
    result = audit_campaign(campaign, expected_targets=1)
    assert result["valid"] is False
    assert "m_filt_profile_count_not_3" in result["issues"]
    assert result["matrix_profile_count"] == 102
    assert result["matrix_cell_count"] == 1122


def test_m_filt_is_checked_as_eleven_unsat(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    rows = [_profile("VECTOR_SAT") for _ in range(99)] + [_profile("MATRIX_UNSAT") for _ in range(3)]
    _write_jsonl(campaign / "target.results.jsonl", rows)
    result = audit_campaign(campaign, expected_targets=1)
    assert result["valid"] is True
    assert result["m_filt_profile_count"] == 3
    assert result["m_filt_all_11_unsat"] is True
