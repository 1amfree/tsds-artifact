#!/usr/bin/env python3
"""Audit a merged bounded replay suite without promoting incomplete rows.

The older incomplete-replay package contains a few timeout/residual receipts
without a multi-state object.  Those rows are explicit non-claimable
observations, not candidate-wide negatives.  This auditor separates them from
actual identity or accounting errors and reports outcome changes instead of
silently treating them as stable results.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from experiments.run_high_budget_incomplete_replay_suite import load_incomplete_rows


SCHEMA = "tsds-reconciled-incomplete-replay-audit-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def load_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: expected JSON object")
        rows.append(value)
    return rows


def audit(baseline: Path, suite: Path) -> dict[str, Any]:
    baseline_cases = load_incomplete_rows(baseline)
    expected = {(case["target"], case["closure_idx"]): case for case in baseline_cases}
    suite_config_path = suite / "suite_config.json"
    suite_config = load_json(suite_config_path) if suite_config_path.is_file() else {}
    baseline_config_path = baseline / "campaign_configuration.json"
    baseline_config = load_json(baseline_config_path) if baseline_config_path.is_file() else {}
    issues: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    observed: set[tuple[str, int]] = set()
    outcomes_changed = 0
    late_positive = 0
    complete = 0
    incomplete = 0
    nonclaimable = 0
    multi_state_receipts = 0
    receipt_count = 0
    candidate_wide_negative = 0

    if suite_config.get("selection") != "multi_state_audit.collection_complete == false":
        issues.append({"issue": "selection_contract_missing_or_changed"})
    expected_evaluator = baseline_config.get("evaluator_sha256")
    if expected_evaluator and suite_config.get("evaluator_sha256") != expected_evaluator:
        issues.append({"issue": "evaluator_sha256_differs_from_baseline"})

    for case_dir in sorted(suite.glob("*_idx*")):
        if not case_dir.is_dir():
            continue
        target, index_text = case_dir.name.rsplit("_idx", 1)
        closure_idx = int(index_text)
        key = (target, closure_idx)
        observed.add(key)
        baseline_case = expected.get(key)
        rows = load_rows(case_dir / "results.jsonl")
        row = rows[0] if len(rows) == 1 else None
        returncode_path = case_dir / "returncode"
        returncode = returncode_path.read_text(encoding="utf-8", errors="replace").strip() if returncode_path.is_file() else None
        row_issues: list[str] = []
        observations: list[str] = []
        if baseline_case is None:
            row_issues.append("unexpected_replay_case")
        if row is not None:
            receipt_count += 1
            for field in ("closure_idx", "source_addr", "sink_addr", "sink_function"):
                expected_value = closure_idx if field == "closure_idx" else baseline_case.get("baseline_" + field) if baseline_case else None
                if row.get(field) != expected_value:
                    row_issues.append(f"{field}_mismatch")
            audit_obj = row.get("multi_state_audit")
            if isinstance(audit_obj, dict):
                multi_state_receipts += 1
                aggregate = audit_obj.get("aggregate") or {}
                negative = aggregate.get("candidate_wide_negative", audit_obj.get("candidate_wide_negative"))
                if negative is not False:
                    row_issues.append("candidate_wide_negative_not_false")
                    candidate_wide_negative += int(negative is True)
                if audit_obj.get("collection_complete") is True:
                    complete += 1
                    observations.append("collection_complete")
                else:
                    incomplete += 1
                    observations.append("collection_incomplete")
                replay_verdict = row.get("verdict")
                baseline_verdict = baseline_case.get("baseline_verdict") if baseline_case else None
                if replay_verdict != baseline_verdict:
                    outcomes_changed += 1
                    observations.append("outcome_changed_under_higher_budget")
                if replay_verdict == "VECTOR_SAT":
                    observations.append("bounded_vector_sat_observed")
                    if baseline_verdict != "VECTOR_SAT":
                        late_positive += 1
            else:
                # A timeout/residual without a multi-state receipt is retained
                # as an explicit non-claimable observation.
                if row.get("status") in {"timeout", "residual"} or row.get("verdict") == "RESIDUAL":
                    nonclaimable += 1
                    observations.append("explicit_nonclaimable_without_multistate_receipt")
                else:
                    row_issues.append("multi_state_audit_missing_on_claimable_receipt")
        else:
            if returncode == "TIMEOUT":
                nonclaimable += 1
                observations.append("explicit_nonclaimable_missing_receipt")
            else:
                row_issues.append("replay_receipt_missing_or_not_singleton")
        if returncode not in {"0", "TIMEOUT"}:
            row_issues.append("runner_returncode_unexpected")
        if row_issues:
            issues.extend({"target": target, "closure_idx": closure_idx, "issue": issue} for issue in sorted(set(row_issues)))
        cases.append({
            "target": target,
            "closure_idx": closure_idx,
            "baseline_verdict": baseline_case.get("baseline_verdict") if baseline_case else None,
            "replay_verdict": row.get("verdict") if row else None,
            "baseline_status": baseline_case.get("baseline_status") if baseline_case else None,
            "replay_status": row.get("status") if row else None,
            "source_addr": row.get("source_addr") if row else None,
            "sink_addr": row.get("sink_addr") if row else None,
            "sink_function": row.get("sink_function") if row else None,
            "profile_count": len(((row or {}).get("multi_state_audit") or {}).get("profiles") or []) if row else 0,
            "collection_complete": (((row or {}).get("multi_state_audit") or {}).get("collection_complete") if row else None),
            "returncode": returncode,
            "observations": observations,
            "issues": sorted(set(row_issues)),
        })

    for key in sorted(set(expected) - observed):
        issues.append({"target": key[0], "closure_idx": key[1], "issue": "incomplete_baseline_row_not_replayed"})
    for key in sorted(observed - set(expected)):
        issues.append({"target": key[0], "closure_idx": key[1], "issue": "unexpected_replay_case"})

    return {
        "schema": SCHEMA,
        "baseline": str(baseline.resolve()),
        "suite": str(suite.resolve()),
        "expected_case_count": len(expected),
        "replay_case_count": len(cases),
        "receipt_count": receipt_count,
        "multi_state_receipt_count": multi_state_receipts,
        "complete_collection_count": complete,
        "incomplete_collection_count": incomplete,
        "explicit_nonclaimable_count": nonclaimable,
        "outcome_changed_count": outcomes_changed,
        "late_positive_observation_count": late_positive,
        "candidate_wide_negative_count": candidate_wide_negative,
        "outcome_counts": dict(Counter(str(case["replay_verdict"]) for case in cases)),
        "identity": {
            "baseline_configuration_sha256": sha256_file(baseline_config_path) if baseline_config_path.is_file() else None,
            "suite_configuration_sha256": sha256_file(suite_config_path) if suite_config_path.is_file() else None,
            "baseline_evaluator_sha256": expected_evaluator,
            "suite_evaluator_sha256": suite_config.get("evaluator_sha256"),
        },
        "issues": issues,
        "cases": cases,
        "all_checks_pass": not issues and len(cases) == len(expected),
        "claim_boundary": (
            "Finite identity-bound higher-budget replay accounting. Complete multi-state "
            "receipts support only bounded observations; explicit missing/incomplete receipts "
            "remain non-claimable. Outcome changes are reported, not promoted. This audit does "
            "not establish exhaustive sink-state coverage, solver soundness, source realizability, "
            "firmware ground truth, human labels, or device exploitability."
        ),
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
    print(json.dumps({key: result[key] for key in ("all_checks_pass", "expected_case_count", "replay_case_count", "receipt_count", "multi_state_receipt_count", "complete_collection_count", "incomplete_collection_count", "explicit_nonclaimable_count", "outcome_changed_count", "late_positive_observation_count", "candidate_wide_negative_count")}, sort_keys=True))
    return 0 if result["all_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
