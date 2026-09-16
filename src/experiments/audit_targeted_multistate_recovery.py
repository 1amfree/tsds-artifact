#!/usr/bin/env python3
"""Audit a paired bounded multi-state recovery stress test.

The compared receipts use the same target and closure but different bounded
search policies.  The report records whether a less-pruned run observes more
profiles and whether either run improperly turns an incomplete collection into
a candidate-wide negative.  It is intentionally a finite stress comparison,
not a claim of exhaustive firmware state coverage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA = "tsds-targeted-multistate-recovery-stress-v1"


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _load_one(directory: Path) -> dict[str, Any]:
    result_path = directory / "results.jsonl"
    lines = [line for line in result_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError(f"expected one result row in {result_path}, got {len(lines)}")
    row = json.loads(lines[0])
    if not isinstance(row, dict):
        raise ValueError(f"expected JSON object in {result_path}")
    summary = _load_json(directory / "summary.json")
    stderr = (directory / "stderr.log").read_text(encoding="utf-8")
    audit = row.get("multi_state_audit")
    if not isinstance(audit, dict):
        raise ValueError(f"missing multi_state_audit in {result_path}")
    aggregate = audit.get("aggregate")
    if not isinstance(aggregate, dict):
        raise ValueError(f"missing multi_state_audit.aggregate in {result_path}")
    profiles = audit.get("profiles")
    if not isinstance(profiles, list):
        raise ValueError(f"missing multi_state_audit.profiles in {result_path}")
    return {
        "directory": str(directory.resolve()),
        "result_sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
        "summary_sha256": hashlib.sha256((directory / "summary.json").read_bytes()).hexdigest(),
        "stderr_empty": not stderr,
        "row": row,
        "summary": summary,
        "audit": audit,
        "aggregate": aggregate,
        "profiles": profiles,
    }


def _profile_status_counts(profiles: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for profile in profiles:
        status = str(profile.get("status") or "missing") if isinstance(profile, dict) else "invalid"
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def _case_facts(case: dict[str, Any]) -> dict[str, Any]:
    row = case["row"]
    audit = case["audit"]
    aggregate = case["aggregate"]
    profiles = case["profiles"]
    return {
        "closure_idx": row.get("closure_idx"),
        "source_addr": row.get("source_addr"),
        "sink_addr": row.get("sink_addr"),
        "status": row.get("status"),
        "verdict": row.get("verdict"),
        "evidence_provenance": row.get("evidence_provenance"),
        "sink_snapshot_command_digest": row.get("sink_snapshot_command_digest"),
        "sink_snapshot_digest": row.get("sink_snapshot_digest"),
        "sink_preview": row.get("sink_preview"),
        "sink_reached_observed": row.get("sink_reached_observed"),
        "residual_diagnosis_class": row.get("residual_diagnosis_class"),
        "engine_stop_reason": row.get("engine_stop_reason"),
        "engine_multi_state_capture_count": row.get("engine_multi_state_capture_count"),
        "engine_multi_state_collection_complete": row.get("engine_multi_state_collection_complete"),
        "engine_steps": row.get("engine_steps"),
        "engine_steps_total": row.get("engine_steps_total"),
        "process_peak_rss_mib": row.get("process_peak_rss_mib"),
        "collection_complete": audit.get("collection_complete"),
        "collection_scope": audit.get("collection_scope"),
        "profile_count": len(profiles),
        "profile_status_counts": _profile_status_counts(profiles),
        "candidate_wide_negative": bool(aggregate.get("candidate_wide_negative")),
        "aggregate_class": aggregate.get("aggregate_class"),
        "decision_counts": aggregate.get("decision_counts"),
        "primary_selection": audit.get("primary_selection"),
        "stderr_empty": case["stderr_empty"],
    }


def build_stress_audit(baseline_dir: Path, less_pruned_dir: Path) -> dict[str, Any]:
    baseline = _load_one(baseline_dir.resolve())
    less_pruned = _load_one(less_pruned_dir.resolve())
    baseline_facts = _case_facts(baseline)
    less_pruned_facts = _case_facts(less_pruned)
    identity_fields = (
        "closure_idx",
        "source_addr",
        "sink_addr",
        "sink_snapshot_command_digest",
        "sink_snapshot_digest",
        "sink_preview",
    )
    identity_equal = all(baseline_facts[field] == less_pruned_facts[field] for field in identity_fields)
    same_outcome = all(
        baseline_facts[field] == less_pruned_facts[field]
        for field in ("status", "verdict", "evidence_provenance", "residual_diagnosis_class")
    )
    issues: list[str] = []
    if not identity_equal:
        issues.append("sink_or_closure_identity_changed")
    if not same_outcome:
        issues.append("primary_outcome_changed")
    if baseline_facts["collection_complete"] is not False or less_pruned_facts["collection_complete"] is not False:
        issues.append("incomplete_collection_not_explicit")
    if baseline_facts["candidate_wide_negative"] or less_pruned_facts["candidate_wide_negative"]:
        issues.append("candidate_wide_negative_present")
    if less_pruned_facts["profile_count"] < baseline_facts["profile_count"]:
        issues.append("less_pruned_profile_count_decreased")
    if not baseline_facts["stderr_empty"] or not less_pruned_facts["stderr_empty"]:
        issues.append("stderr_not_empty")

    return {
        "schema": SCHEMA,
        "claim_boundary": (
            "This receipt compares two finite bounded executions of one target "
            "closure.  It supports stress-test observations about profile counts "
            "and negative-gate behavior only; it does not prove exhaustive state "
            "coverage, solver soundness, source realizability, firmware-wide "
            "precision/recall, or device exploitability."
        ),
        "baseline": baseline_facts,
        "less_pruned": less_pruned_facts,
        "comparisons": {
            "identity_equal": identity_equal,
            "primary_outcome_equal": same_outcome,
            "profile_count_delta_less_pruned_minus_baseline": less_pruned_facts["profile_count"] - baseline_facts["profile_count"],
            "both_explicitly_incomplete": baseline_facts["collection_complete"] is False and less_pruned_facts["collection_complete"] is False,
            "both_candidate_wide_negative_false": not baseline_facts["candidate_wide_negative"] and not less_pruned_facts["candidate_wide_negative"],
        },
        "issues": sorted(set(issues)),
        "valid": not issues,
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_outputs(out_dir: Path, result: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "targeted_multistate_recovery_stress.json"
    summary_path.write_text(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    comparison = result["comparisons"]
    lines = [
        "# Targeted multi-state recovery stress audit",
        "",
        f"Valid: **{result['valid']}**",
        f"Identity equal: **{comparison['identity_equal']}**",
        f"Primary outcome equal: **{comparison['primary_outcome_equal']}**",
        f"Profile-count delta (less-pruned minus baseline): **{comparison['profile_count_delta_less_pruned_minus_baseline']}**",
        f"Both collections explicitly incomplete: **{comparison['both_explicitly_incomplete']}**",
        f"Both candidate-wide-negative flags false: **{comparison['both_candidate_wide_negative_false']}**",
        "",
        "The less-pruned receipt observes more bounded profiles for the same closure, but neither receipt establishes exhaustive state coverage.  Incomplete collections remain residual evidence and are not negative verdicts.",
        "",
        result["claim_boundary"],
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    digest_lines = []
    for path in sorted(out_dir.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            digest_lines.append(f"{_sha256(path)}  {path.name}")
    (out_dir / "SHA256SUMS").write_text("\n".join(digest_lines) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-dir", type=Path, required=True)
    parser.add_argument("--less-pruned-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_stress_audit(args.baseline_dir, args.less_pruned_dir)
        _write_outputs(args.out_dir.resolve(), result)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"TARGETED_MULTISTATE_RECOVERY_AUDIT_ERROR: {exc}")
        return 2
    print(json.dumps({"valid": result["valid"], "issues": result["issues"], "comparisons": result["comparisons"]}, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
