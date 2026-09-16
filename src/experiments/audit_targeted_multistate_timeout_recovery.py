#!/usr/bin/env python3
"""Audit targeted high-timeout recovery without promoting any classification."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.run_targeted_multistate_timeout_recovery import CASES, load_baseline_cases


SCHEMA = "tsds-targeted-multistate-timeout-recovery-audit-v1"


def load_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    return rows


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def audit(baseline: Path, suite: Path) -> dict[str, Any]:
    expected = {(c["target"], c["closure_idx"]): c for c in load_baseline_cases(baseline)}
    issues: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    for target, closure_idx in CASES:
        key = (target, closure_idx)
        base = expected[key]
        case_dir = suite / f"{target}_idx{closure_idx}"
        rows = load_rows(case_dir / "results.jsonl")
        row = rows[0] if len(rows) == 1 else None
        returncode = (case_dir / "returncode").read_text(encoding="utf-8", errors="replace").strip() if (case_dir / "returncode").is_file() else None
        record_issues: list[str] = []
        if row is not None:
            for field in ("closure_idx", "source_addr", "sink_addr", "sink_function"):
                expected_value = closure_idx if field == "closure_idx" else base.get("baseline_" + field)
                if row.get(field) != expected_value:
                    record_issues.append(f"{field}_mismatch")
        multi = row.get("multi_state_audit") if row else None
        if isinstance(multi, dict):
            aggregate = multi.get("aggregate") or {}
            candidate_negative = aggregate.get("candidate_wide_negative", multi.get("candidate_wide_negative"))
            if candidate_negative is not False:
                record_issues.append("candidate_wide_negative_not_false")
            boundary = "multi_state_receipt"
        else:
            candidate_negative = None
            boundary = "nonclaimable_without_multistate_receipt"
        cases.append(
            {
                "target": target,
                "closure_idx": closure_idx,
                "receipt_present": row is not None,
                "returncode": returncode,
                "status": row.get("status") if row else None,
                "verdict": row.get("verdict") if row else None,
                "source_addr": row.get("source_addr") if row else None,
                "sink_addr": row.get("sink_addr") if row else None,
                "sink_function": row.get("sink_function") if row else None,
                "collection_complete": multi.get("collection_complete") if isinstance(multi, dict) else None,
                "profile_count": len(multi.get("profiles") or []) if isinstance(multi, dict) else 0,
                "candidate_wide_negative": candidate_negative,
                "boundary": boundary,
                "issues": record_issues,
            }
        )
        issues.extend({"target": target, "closure_idx": closure_idx, "issue": item} for item in record_issues)
    return {
        "schema": SCHEMA,
        "baseline": str(baseline),
        "suite": str(suite),
        "expected_case_count": len(CASES),
        "receipt_count": sum(c["receipt_present"] for c in cases),
        "usable_multistate_receipt_count": sum(c["boundary"] == "multi_state_receipt" for c in cases),
        "complete_collection_count": sum(c["collection_complete"] is True for c in cases),
        "candidate_wide_negative_count": sum(c["candidate_wide_negative"] is True for c in cases),
        "identity_issue_count": sum(len(c["issues"]) for c in cases),
        "nonclaimable_case_count": sum(c["boundary"] != "multi_state_receipt" for c in cases),
        "cases": cases,
        "issues": issues,
        "non_escalation_boundary_pass": not issues and all(c["candidate_wide_negative"] is not True for c in cases),
        "receipt_completeness_pass": len(cases) == sum(c["receipt_present"] for c in cases),
        "claim_boundary": "Finite targeted high-timeout recovery of four previously non-claimable records.  A missing or incomplete receipt remains non-claimable; no class is promoted and no candidate-wide negative conclusion is inferred.  The audit does not establish exhaustive coverage, solver soundness, source realizability, firmware ground truth, or device exploitability.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.baseline.resolve(), args.suite.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("receipt_count", "usable_multistate_receipt_count", "complete_collection_count", "candidate_wide_negative_count", "nonclaimable_case_count", "non_escalation_boundary_pass", "receipt_completeness_pass")}, sort_keys=True))
    return 0 if result["non_escalation_boundary_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
