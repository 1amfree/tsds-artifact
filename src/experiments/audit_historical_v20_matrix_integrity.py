#!/usr/bin/env python3
"""Audit per-profile invariants in the frozen V20 matrix records.

The audit is intentionally independent of the evaluator.  It checks the
serialized matrix schema and profile-level accounting, including the three
historical MATRIX_UNSAT profiles.  It does not re-solve queries or establish
source realizability, firmware accuracy, or exploitability.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


VECTOR_IDS = {
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
}
DECISIONS = {"VECTOR_SAT", "MATRIX_UNSAT", "INCONCLUSIVE"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def audit_profile(row: dict[str, Any], ordinal: int) -> tuple[dict[str, Any], list[str]]:
    decisions = row.get("vector_decisions")
    issues: list[str] = []
    if not isinstance(decisions, list):
        return (
            {
                "ordinal": ordinal,
                "closure_idx": row.get("closure_idx"),
                "verdict": row.get("verdict"),
                "decision_counts": {},
                "valid": False,
                "issues": ["vector_decisions_not_list"],
            },
            ["vector_decisions_not_list"],
        )
    ids = [item.get("vector_id") if isinstance(item, dict) else None for item in decisions]
    decision_values = [item.get("decision") if isinstance(item, dict) else None for item in decisions]
    if len(decisions) != 11:
        issues.append("vector_count_not_11")
    if set(ids) != VECTOR_IDS:
        issues.append("vector_id_set_mismatch")
    if len(set(ids)) != len(ids):
        issues.append("vector_id_duplicate")
    if any(value not in DECISIONS for value in decision_values):
        issues.append("unsupported_decision")
    counts = Counter(str(value) for value in decision_values)
    declared = {
        "VECTOR_SAT": _int(row.get("vulnerable_vectors")),
        "MATRIX_UNSAT": _int(row.get("secure_vectors")),
        "INCONCLUSIVE": _int(row.get("inconclusive_vectors")),
    }
    for decision, value in declared.items():
        if value is not None and counts.get(decision, 0) != value:
            issues.append(f"declared_count_mismatch:{decision}")
    verdict = str(row.get("verdict") or "")
    if verdict == "VECTOR_SAT" and counts.get("VECTOR_SAT", 0) == 0:
        issues.append("vector_sat_verdict_without_sat_cell")
    if verdict == "MATRIX_UNSAT" and counts.get("MATRIX_UNSAT", 0) != 11:
        issues.append("matrix_unsat_verdict_not_11_of_11")
    fact = {
        "ordinal": ordinal,
        "closure_idx": row.get("closure_idx"),
        "verdict": verdict,
        "evidence_provenance": row.get("evidence_provenance"),
        "decision_counts": dict(sorted(counts.items())),
        "declared_counts": declared,
        "all_matrix_unsat": counts.get("MATRIX_UNSAT", 0) == 11,
        "has_vector_sat": counts.get("VECTOR_SAT", 0) > 0,
        "valid": not issues,
        "issues": sorted(set(issues)),
    }
    return fact, issues


def audit_campaign(campaign_dir: Path, expected_targets: int | None = None) -> dict[str, Any]:
    paths = sorted(campaign_dir.glob("*.results.jsonl"))
    issues: list[str] = []
    if expected_targets is not None and len(paths) != expected_targets:
        issues.append("target_file_count_mismatch")
    rows: list[dict[str, Any]] = []
    file_inventory: list[dict[str, Any]] = []
    for path in paths:
        file_rows = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected JSON object")
            value["_audit_target"] = path.name[: -len(".results.jsonl")]
            file_rows.append(value)
        rows.extend(file_rows)
        file_inventory.append(
            {
                "name": path.name,
                "rows": len(file_rows),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )

    profile_facts: list[dict[str, Any]] = []
    for ordinal, row in enumerate(rows):
        if isinstance(row.get("vector_decisions"), list):
            fact, row_issues = audit_profile(row, ordinal)
            fact["target"] = row.get("_audit_target")
            profile_facts.append(fact)
            issues.extend(row_issues)

    profile_verdicts = Counter(str(fact["verdict"]) for fact in profile_facts)
    cell_counts = Counter(
        decision
        for fact in profile_facts
        for decision, count in fact["decision_counts"].items()
        for _ in range(count)
    )
    m_filt = [
        fact
        for fact in profile_facts
        if fact["verdict"] == "MATRIX_UNSAT" and fact["all_matrix_unsat"]
    ]
    invalid = [fact for fact in profile_facts if not fact["valid"]]
    if len(profile_facts) != 102:
        issues.append("matrix_profile_count_not_102")
    if sum(cell_counts.values()) != len(profile_facts) * 11:
        issues.append("cell_count_not_profile_count_times_11")
    if len(m_filt) != 3:
        issues.append("m_filt_profile_count_not_3")
    if invalid:
        issues.append("invalid_profile_invariant")

    result = {
        "schema": "tsds-historical-v20-matrix-integrity-audit-v1",
        "campaign_dir": str(campaign_dir),
        "target_count": len(paths),
        "record_count": len(rows),
        "matrix_profile_count": len(profile_facts),
        "matrix_profile_verdicts": dict(sorted(profile_verdicts.items())),
        "matrix_cell_count": int(sum(cell_counts.values())),
        "matrix_cell_decisions": dict(sorted(cell_counts.items())),
        "m_filt_profile_count": len(m_filt),
        "m_filt_all_11_unsat": all(fact["all_matrix_unsat"] for fact in m_filt),
        "invalid_profiles": invalid,
        "file_inventory": file_inventory,
        "profile_facts": profile_facts,
        "claim_boundary": (
            "This audit checks serialized per-profile matrix invariants and the "
            "historical M-Filt row shape. It does not re-solve SMT queries, prove "
            "UNSAT semantics, establish source realizability, or demonstrate "
            "firmware safety or exploitability."
        ),
        "issues": sorted(set(issues)),
        "valid": not issues,
    }
    return result


def write_outputs(out_dir: Path, result: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "matrix_integrity.json"
    summary_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    fields = [
        "target",
        "ordinal",
        "closure_idx",
        "verdict",
        "evidence_provenance",
        "all_matrix_unsat",
        "has_vector_sat",
        "valid",
        "issues",
    ]
    with (out_dir / "profile_integrity.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for fact in result["profile_facts"]:
            writer.writerow({**fact, "issues": ";".join(fact["issues"])})
    lines = [
        "# Historical V20 per-profile matrix integrity audit",
        "",
        f"Valid: **{result['valid']}**",
        f"Profiles: **{result['matrix_profile_count']}**",
        f"Cells: **{result['matrix_cell_count']}**",
        f"M-Filt profiles: **{result['m_filt_profile_count']}** (all 11 UNSAT: **{result['m_filt_all_11_unsat']}**)",
        f"Invalid profiles: **{len(result['invalid_profiles'])}**",
        "",
        "The audit checks serialized invariants only; it is not an independent SMT proof or firmware ground-truth study.",
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    digest_lines = []
    for path in sorted(out_dir.iterdir()):
        if path.name != "SHA256SUMS" and path.is_file():
            digest_lines.append(f"{sha256_file(path)}  {path.name}")
    (out_dir / "SHA256SUMS").write_text("\n".join(digest_lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--expected-targets", type=int, default=None)
    args = parser.parse_args()
    try:
        result = audit_campaign(args.campaign_dir.resolve(), args.expected_targets)
        write_outputs(args.out_dir.resolve(), result)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"HISTORICAL_V20_MATRIX_INTEGRITY_ERROR: {exc}")
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
