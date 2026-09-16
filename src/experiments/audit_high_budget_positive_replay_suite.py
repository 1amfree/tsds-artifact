#!/usr/bin/env python3
"""Audit the identity and bounded outcome of the positive replay suite."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "tsds-high-budget-positive-replay-audit-v1"


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
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    return rows


def _audit_facts(row: dict[str, Any]) -> dict[str, Any]:
    audit = row.get("multi_state_audit")
    if not isinstance(audit, dict):
        audit = {}
    aggregate = audit.get("aggregate")
    if not isinstance(aggregate, dict):
        aggregate = {}
    profiles = audit.get("profiles")
    if not isinstance(profiles, list):
        profiles = []
    return {
        "audit_present": isinstance(row.get("multi_state_audit"), dict),
        "collection_complete": audit.get("collection_complete"),
        "collection_scope": audit.get("collection_scope"),
        "aggregate_class": aggregate.get("aggregate_class") or audit.get("multi_state_aggregate_class"),
        "candidate_wide_negative": aggregate.get("candidate_wide_negative", audit.get("candidate_wide_negative")),
        "quantifier": aggregate.get("quantifier") or audit.get("quantifier"),
        "profile_count": len(profiles),
        "profile_status_counts": dict(Counter(str((item or {}).get("status")) for item in profiles if isinstance(item, dict))),
        "primary_selection": audit.get("primary_selection"),
    }


def audit_suite(root: Path, baseline: Path, suite: Path) -> dict[str, Any]:
    baseline_rows: dict[tuple[str, int], dict[str, Any]] = {}
    for path in sorted(baseline.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        for row in load_rows(path):
            if row.get("verdict") == "VECTOR_SAT" or row.get("status") == "vulnerable":
                baseline_rows[(target, int(row["closure_idx"]))] = row

    identity_issues: list[str] = []
    input_bindings: dict[str, dict[str, Any]] = {}
    baseline_config_path = baseline / "campaign_configuration.json"
    suite_config_path = suite / "suite_config.json"
    if baseline_config_path.is_file():
        baseline_config = load_json(baseline_config_path)
        for target in baseline_config.get("targets") or []:
            if isinstance(target, dict) and target.get("name"):
                input_bindings[str(target["name"])] = {
                    "binary": target.get("binary"),
                    "binary_sha256": target.get("binary_sha256"),
                    "mango": target.get("mango"),
                    "mango_sha256": target.get("mango_sha256"),
                }
    suite_config: dict[str, Any] = {}
    if suite_config_path.is_file():
        suite_config = load_json(suite_config_path)
        expected_evaluator = None
        if baseline_config_path.is_file():
            expected_evaluator = load_json(baseline_config_path).get("evaluator_sha256")
        observed_evaluator = suite_config.get("evaluator_sha256")
        if expected_evaluator and observed_evaluator != expected_evaluator:
            identity_issues.append("evaluator_sha256_differs_from_baseline")

    cases: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    for case_dir in sorted(suite.glob("*_idx*")):
        if not case_dir.is_dir():
            continue
        name = case_dir.name
        target, idx_text = name.rsplit("_idx", 1)
        key = (target, int(idx_text))
        baseline_row = baseline_rows.get(key)
        result_path = case_dir / "results.jsonl"
        result_rows = load_rows(result_path) if result_path.is_file() else []
        row = result_rows[0] if len(result_rows) == 1 else None
        baseline_facts = _audit_facts(baseline_row or {})
        replay_facts = _audit_facts(row or {})
        case_issues: list[str] = []
        case_warnings: list[str] = []
        if baseline_row is None:
            case_issues.append("baseline_positive_row_missing")
        if row is None:
            case_issues.append("replay_receipt_missing_or_not_singleton")
        if row is not None and baseline_row is not None:
            if row.get("closure_idx") != baseline_row.get("closure_idx"):
                case_issues.append("closure_index_mismatch")
            for field in ("source_addr", "sink_addr", "sink_function"):
                if row.get(field) != baseline_row.get(field):
                    case_issues.append(f"{field}_mismatch")
            if row.get("verdict") != baseline_row.get("verdict"):
                case_issues.append("verdict_changed")
            if row.get("status") != baseline_row.get("status"):
                case_issues.append("status_changed")
            if row.get("evidence_provenance") != "DIRECT_SINK_BYTE":
                case_issues.append("replay_not_direct_sink_byte")
            # Positive aggregation is existential over the instances that were
            # actually collected.  Incomplete collection must remain visible,
            # but it is not a reason to discard an otherwise valid positive
            # replay; it would only block a candidate-wide negative claim.
            if replay_facts["collection_complete"] is not True:
                case_warnings.append("bounded_collection_not_complete")
            if replay_facts["candidate_wide_negative"] is not False:
                case_issues.append("candidate_wide_negative_not_false")
            if replay_facts["aggregate_class"] != "exists_positive":
                case_issues.append("aggregate_class_not_exists_positive")
            if replay_facts["quantifier"] not in {"exists_over_collected_instances", "exists_over_bounded_collected_instances"}:
                case_issues.append("positive_quantifier_missing_or_unexpected")
        for issue in case_issues:
            issues.append({"target": target, "closure_idx": int(idx_text), "issue": issue})
        for warning in case_warnings:
            warnings.append({"target": target, "closure_idx": int(idx_text), "warning": warning})
        returncode = (case_dir / "returncode").read_text(encoding="utf-8", errors="replace").strip() if (case_dir / "returncode").is_file() else None
        cases.append(
            {
                "target": target,
                "closure_idx": int(idx_text),
                "baseline": {
                    "status": baseline_row.get("status") if baseline_row else None,
                    "verdict": baseline_row.get("verdict") if baseline_row else None,
                    "source_addr": baseline_row.get("source_addr") if baseline_row else None,
                    "sink_addr": baseline_row.get("sink_addr") if baseline_row else None,
                    "snapshot_digest": baseline_row.get("sink_snapshot_digest") if baseline_row else None,
                    "facts": baseline_facts,
                },
                "replay": {
                    "status": row.get("status") if row else None,
                    "verdict": row.get("verdict") if row else None,
                    "evidence_provenance": row.get("evidence_provenance") if row else None,
                    "source_addr": row.get("source_addr") if row else None,
                    "sink_addr": row.get("sink_addr") if row else None,
                    "snapshot_digest": row.get("sink_snapshot_digest") if row else None,
                    "facts": replay_facts,
                },
                "returncode": returncode,
                "issues": case_issues,
                "warnings": case_warnings,
            }
        )

    expected_keys = set(baseline_rows)
    observed_keys = {(case["target"], case["closure_idx"]) for case in cases}
    for target, idx in sorted(expected_keys - observed_keys):
        issues.append({"target": target, "closure_idx": idx, "issue": "positive_row_not_replayed"})
    for target, idx in sorted(observed_keys - expected_keys):
        issues.append({"target": target, "closure_idx": idx, "issue": "unexpected_replay_case"})
    for issue in identity_issues:
        issues.append({"target": None, "closure_idx": None, "issue": issue})
    stable = [case for case in cases if not case["issues"]]
    return {
        "schema": SCHEMA,
        "baseline": str(baseline),
        "suite": str(suite),
        "baseline_positive_rows": len(expected_keys),
        "replay_case_count": len(cases),
        "receipt_count": sum(case["replay"]["status"] is not None for case in cases),
        "complete_collection_count": sum(case["replay"]["facts"]["collection_complete"] is True for case in cases),
        "incomplete_collection_count": sum(case["replay"]["facts"]["collection_complete"] is not True for case in cases),
        "direct_provenance_count": sum(
            case["replay"]["evidence_provenance"] == "DIRECT_SINK_BYTE"
            for case in cases
        ),
        "outcome_stable_count": len(stable),
        "returncodes": dict(Counter(str(case["returncode"]) for case in cases)),
        "identity": {
            "baseline_configuration": str(baseline_config_path) if baseline_config_path.is_file() else None,
            "baseline_configuration_sha256": sha256_file(baseline_config_path) if baseline_config_path.is_file() else None,
            "suite_configuration": str(suite_config_path) if suite_config_path.is_file() else None,
            "suite_configuration_sha256": sha256_file(suite_config_path) if suite_config_path.is_file() else None,
            "baseline_evaluator_sha256": (
                load_json(baseline_config_path).get("evaluator_sha256")
                if baseline_config_path.is_file()
                else None
            ),
            "suite_evaluator_sha256": suite_config.get("evaluator_sha256"),
            "input_bindings": input_bindings,
            "issues": identity_issues,
        },
        "issues": issues,
        "warnings": warnings,
        "cases": cases,
        "all_checks_pass": not issues and len(cases) == len(expected_keys),
        "claim_boundary": "Finite identity-bound bounded replay of the direct positive rows in the current campaign. Positive outcomes use existential quantification over collected sink instances; incomplete collection is reported explicitly and cannot support a candidate-wide negative conclusion. The replay does not establish exhaustive sink-state coverage, solver soundness, source realizability, firmware-wide precision/recall, human ground truth, or device exploitability.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit_suite(args.output.parent.resolve(), args.baseline.resolve(), args.suite.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"all_checks_pass": report["all_checks_pass"], "issues": len(report["issues"]), "replay_case_count": report["replay_case_count"]}, sort_keys=True))
    return 0 if report["all_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
