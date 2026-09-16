#!/usr/bin/env python3
"""Recompute the historical matrix-profile denominator and cell totals.

This audit is intentionally independent of the evaluator.  It reads the
frozen JSONL records, distinguishes complete matrix profiles from records that
were never sent to the matrix, and checks the published 102/88 relationship:
102 profiled records consist of 88 non-residual profiles and 14 residual
profiles.  It does not reinterpret any verdict or establish semantic truth.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


DECISIONS = {"VECTOR_SAT", "MATRIX_UNSAT", "INCONCLUSIVE"}


def load_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: expected JSON object")
        yield value


def row_is_complete_matrix_profile(row: dict[str, Any]) -> tuple[bool, list[str]]:
    decisions = row.get("vector_decisions")
    if not isinstance(decisions, list) or len(decisions) != 11:
        return False, ["matrix_row_count_not_11"]
    ids = [str(item.get("vector_id") or "") for item in decisions if isinstance(item, dict)]
    issues: list[str] = []
    if len(ids) != 11 or any(not item for item in ids):
        issues.append("matrix_vector_id_missing")
    if len(set(ids)) != len(ids):
        issues.append("matrix_vector_id_duplicate")
    unsupported = [
        str(item.get("decision") or "")
        for item in decisions
        if not isinstance(item, dict) or str(item.get("decision") or "") not in DECISIONS
    ]
    if unsupported:
        issues.append("matrix_decision_unsupported")
    return not issues, sorted(set(issues))


def audit_campaign(campaign_dir: Path) -> dict[str, Any]:
    result_paths = sorted(campaign_dir.glob("*.results.jsonl"))
    rows: list[dict[str, Any]] = []
    target_counts: dict[str, int] = {}
    for path in result_paths:
        target = path.name[: -len(".results.jsonl")]
        target_rows = list(load_jsonl(path))
        target_counts[target] = len(target_rows)
        rows.extend(target_rows)

    profile_rows: list[dict[str, Any]] = []
    invalid_profile_rows: list[dict[str, Any]] = []
    for ordinal, row in enumerate(rows):
        decisions = row.get("vector_decisions")
        if not isinstance(decisions, list):
            continue
        complete, issues = row_is_complete_matrix_profile(row)
        if complete:
            profile_rows.append(row)
        else:
            invalid_profile_rows.append(
                {
                    "ordinal": ordinal,
                    "verdict": str(row.get("verdict") or ""),
                    "issues": issues,
                }
            )

    profile_verdicts = Counter(str(row.get("verdict") or "") for row in profile_rows)
    cell_decisions = Counter(
        str(item.get("decision") or "")
        for row in profile_rows
        for item in row.get("vector_decisions") or []
    )
    expected_non_residual = sum(
        count for verdict, count in profile_verdicts.items() if verdict != "RESIDUAL"
    )
    residual_profiles = int(profile_verdicts.get("RESIDUAL", 0))
    non_residual_verdicts = {
        verdict: int(count)
        for verdict, count in sorted(profile_verdicts.items())
        if verdict != "RESIDUAL"
    }
    issues: list[str] = []
    if len(rows) != 518:
        issues.append("record_count_not_518")
    if len(profile_rows) != 102:
        issues.append("matrix_profile_count_not_102")
    if expected_non_residual != 88:
        issues.append("non_residual_matrix_profile_count_not_88")
    if residual_profiles != 14:
        issues.append("matrix_residual_profile_count_not_14")
    if sum(cell_decisions.values()) != 1122:
        issues.append("matrix_cell_count_not_1122")
    for decision, expected in {
        "VECTOR_SAT": 679,
        "MATRIX_UNSAT": 292,
        "INCONCLUSIVE": 151,
    }.items():
        if int(cell_decisions.get(decision, 0)) != expected:
            issues.append(f"cell_count_not_{decision.lower()}_{expected}")
    if invalid_profile_rows:
        issues.append("incomplete_matrix_rows_present")

    summary = {
        "schema": "tsds-matrix-profile-conservation-audit-v1",
        "claim_boundary": (
            "This audit checks historical record and matrix-cell accounting only. "
            "It does not validate solver semantics, source realizability, or exploitability."
        ),
        "campaign_dir": str(campaign_dir),
        "target_count": len(result_paths),
        "target_record_counts": target_counts,
        "record_count": len(rows),
        "matrix_profile_count": len(profile_rows),
        "matrix_profile_verdicts": dict(sorted(profile_verdicts.items())),
        "non_residual_matrix_profile_count": expected_non_residual,
        "non_residual_matrix_profile_verdicts": non_residual_verdicts,
        "matrix_residual_profile_count": residual_profiles,
        "matrix_cell_count": int(sum(cell_decisions.values())),
        "matrix_cell_decisions": dict(sorted(cell_decisions.items())),
        "incomplete_matrix_rows": invalid_profile_rows,
        "issues": sorted(set(issues)),
        "valid": not issues,
    }
    return summary


def write_outputs(out_dir: Path, summary: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "matrix_profile_conservation.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# Matrix profile conservation audit",
        "",
        f"Valid: **{summary['valid']}**",
        f"Records: **{summary['record_count']}**",
        f"Complete matrix profiles: **{summary['matrix_profile_count']}**",
        f"Non-residual profiles: **{summary['non_residual_matrix_profile_count']}**",
        f"Residual matrix profiles: **{summary['matrix_residual_profile_count']}**",
        f"Cells: **{summary['matrix_cell_count']}**",
        "",
        "The 102 profiled records are 88 non-residual profiles plus 14 residual profiles.",
        "The audit is accounting evidence, not solver or firmware ground truth.",
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    digest = hashlib.sha256(summary_path.read_bytes()).hexdigest()
    (out_dir / "SHA256SUMS").write_text(
        f"{digest}  matrix_profile_conservation.json\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        summary = audit_campaign(args.campaign_dir)
        write_outputs(args.out_dir, summary)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"MATRIX_PROFILE_AUDIT_ERROR: {exc}")
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
