#!/usr/bin/env python3
"""Audit the bounded replay of explicitly incomplete current records.

The audit checks identity, receipt completeness, and the non-escalation
boundary.  A changed outcome is reported as an observation, not silently
promoted to a new campaign classification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from experiments.run_high_budget_incomplete_replay_suite import load_incomplete_rows


SCHEMA = "tsds-high-budget-incomplete-replay-audit-v1"


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
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    return rows


def audit_suite(baseline: Path, suite: Path) -> dict[str, Any]:
    baseline_cases = load_incomplete_rows(baseline)
    expected = {(case["target"], case["closure_idx"]): case for case in baseline_cases}
    issues: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []

    baseline_config_path = baseline / "campaign_configuration.json"
    suite_config_path = suite / "suite_config.json"
    baseline_config = load_json(baseline_config_path) if baseline_config_path.is_file() else {}
    suite_config = load_json(suite_config_path) if suite_config_path.is_file() else {}
    identity_issues: list[str] = []
    expected_evaluator = baseline_config.get("evaluator_sha256")
    if expected_evaluator and suite_config.get("evaluator_sha256") != expected_evaluator:
        identity_issues.append("evaluator_sha256_differs_from_baseline")
    if suite_config.get("selection") != "multi_state_audit.collection_complete == false":
        identity_issues.append("selection_contract_missing_or_changed")
    issues.extend({"target": None, "closure_idx": None, "issue": item} for item in identity_issues)

    observed: dict[tuple[str, int], Path] = {}
    for case_dir in sorted(suite.glob("*_idx*")):
        if not case_dir.is_dir():
            continue
        target, idx_text = case_dir.name.rsplit("_idx", 1)
        key = (target, int(idx_text))
        observed[key] = case_dir
        baseline_case = expected.get(key)
        result_rows = load_rows(case_dir / "results.jsonl")
        row = result_rows[0] if len(result_rows) == 1 else None
        case_issues: list[str] = []
        case_observations: list[str] = []
        if baseline_case is None:
            case_issues.append("unexpected_replay_case")
        if row is None:
            case_issues.append("replay_receipt_missing_or_not_singleton")
        returncode_path = case_dir / "returncode"
        returncode = returncode_path.read_text(encoding="utf-8", errors="replace").strip() if returncode_path.is_file() else None
        if returncode != "0":
            case_issues.append("runner_returncode_not_zero")
        if baseline_case is not None and row is not None:
            for field in ("closure_idx", "source_addr", "sink_addr", "sink_function"):
                if row.get(field) != baseline_case.get("baseline_" + field if field != "closure_idx" else field):
                    case_issues.append(f"{field}_mismatch")
            replay_audit = row.get("multi_state_audit")
            if not isinstance(replay_audit, dict):
                case_issues.append("multi_state_audit_missing")
            aggregate = replay_audit.get("aggregate") if isinstance(replay_audit, dict) else None
            if not isinstance(aggregate, dict):
                aggregate = {}
            if aggregate.get("candidate_wide_negative", replay_audit.get("candidate_wide_negative") if isinstance(replay_audit, dict) else None) is not False:
                case_issues.append("candidate_wide_negative_not_false")
            replay_verdict = row.get("verdict")
            baseline_verdict = baseline_case.get("baseline_verdict")
            if replay_verdict != baseline_verdict:
                case_observations.append("outcome_changed_under_higher_budget")
            if replay_verdict == "VECTOR_SAT":
                case_observations.append("bounded_vector_sat_observed")
            if isinstance(replay_audit, dict) and replay_audit.get("collection_complete") is True:
                case_observations.append("collection_completed_under_higher_budget")
            else:
                case_observations.append("collection_remains_incomplete")
        for issue in case_issues:
            issues.append({"target": target, "closure_idx": int(idx_text), "issue": issue})
        for observation in case_observations:
            observations.append({"target": target, "closure_idx": int(idx_text), "observation": observation})
        replay_audit = row.get("multi_state_audit") if row else {}
        if not isinstance(replay_audit, dict):
            replay_audit = {}
        profiles = replay_audit.get("profiles")
        if not isinstance(profiles, list):
            profiles = []
        aggregate = replay_audit.get("aggregate")
        if not isinstance(aggregate, dict):
            aggregate = {}
        cases.append(
            {
                "target": target,
                "closure_idx": int(idx_text),
                "baseline": {
                    "status": baseline_case.get("baseline_status") if baseline_case else None,
                    "verdict": baseline_case.get("baseline_verdict") if baseline_case else None,
                    "source_addr": baseline_case.get("baseline_source_addr") if baseline_case else None,
                    "sink_addr": baseline_case.get("baseline_sink_addr") if baseline_case else None,
                    "collection_complete": False if baseline_case else None,
                },
                "replay": {
                    "status": row.get("status") if row else None,
                    "verdict": row.get("verdict") if row else None,
                    "source_addr": row.get("source_addr") if row else None,
                    "sink_addr": row.get("sink_addr") if row else None,
                    "collection_complete": replay_audit.get("collection_complete"),
                    "profile_count": len(profiles),
                    "candidate_wide_negative": aggregate.get("candidate_wide_negative", replay_audit.get("candidate_wide_negative")),
                },
                "returncode": returncode,
                "issues": case_issues,
                "observations": case_observations,
            }
        )

    expected_keys = set(expected)
    observed_keys = set(observed)
    for target, idx in sorted(expected_keys - observed_keys):
        issues.append({"target": target, "closure_idx": idx, "issue": "incomplete_baseline_row_not_replayed"})
    for target, idx in sorted(observed_keys - expected_keys):
        issues.append({"target": target, "closure_idx": idx, "issue": "unexpected_replay_case"})

    stable = [case for case in cases if not case["issues"] and case["replay"]["verdict"] == case["baseline"]["verdict"]]
    return {
        "schema": SCHEMA,
        "baseline": str(baseline),
        "suite": str(suite),
        "baseline_incomplete_rows": len(expected),
        "replay_case_count": len(cases),
        "receipt_count": sum(case["replay"]["status"] is not None for case in cases),
        "returncode_zero_count": sum(case["returncode"] == "0" for case in cases),
        "identity_stable_count": len(stable),
        "outcome_changed_count": sum("outcome_changed_under_higher_budget" in case["observations"] for case in cases),
        "positive_outcome_count": sum(case["replay"]["verdict"] == "VECTOR_SAT" for case in cases),
        "complete_collection_count": sum(case["replay"]["collection_complete"] is True for case in cases),
        "incomplete_collection_count": sum(case["replay"]["collection_complete"] is not True for case in cases),
        "candidate_wide_negative_count": sum(case["replay"]["candidate_wide_negative"] is True for case in cases),
        "outcome_counts": dict(Counter(str(case["replay"]["verdict"]) for case in cases)),
        "identity": {
            "baseline_configuration": str(baseline_config_path) if baseline_config_path.is_file() else None,
            "baseline_configuration_sha256": sha256_file(baseline_config_path) if baseline_config_path.is_file() else None,
            "suite_configuration": str(suite_config_path) if suite_config_path.is_file() else None,
            "suite_configuration_sha256": sha256_file(suite_config_path) if suite_config_path.is_file() else None,
            "baseline_evaluator_sha256": expected_evaluator,
            "suite_evaluator_sha256": suite_config.get("evaluator_sha256"),
            "issues": identity_issues,
        },
        "issues": issues,
        "observations": observations,
        "cases": cases,
        "all_checks_pass": not issues and len(cases) == len(expected),
        "claim_boundary": (
            "Finite identity-bound higher-budget replay of explicitly incomplete "
            "current records.  Outcome changes and recovered profiles are reported "
            "as observations only; no residual is promoted and no candidate-wide "
            "negative conclusion is inferred.  The audit does not establish "
            "exhaustive sink-state coverage, solver soundness, source realizability, "
            "firmware ground truth, or device exploitability."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit_suite(args.baseline.resolve(), args.suite.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"all_checks_pass": report["all_checks_pass"], "issues": len(report["issues"]), "replay_case_count": report["replay_case_count"]}, sort_keys=True))
    return 0 if report["all_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
