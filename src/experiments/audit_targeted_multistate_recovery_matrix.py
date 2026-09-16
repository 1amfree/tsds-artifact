#!/usr/bin/env python3
"""Audit paired bounded multi-state recovery stress tests.

This receipt compares more- and less-pruned executions for several fixed
closures.  It separates stable callsite/command identity from the concrete
symbolic snapshot, because different bounded executions may legitimately
materialize different satisfying assignments.  The receipt is deliberately a
finite stress audit; it does not establish exhaustive state coverage,
solver soundness, firmware-wide precision/recall, or device exploitability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from experiments.audit_targeted_multistate_recovery import _load_one, _profile_status_counts
except ModuleNotFoundError:  # Direct invocation from the experiments directory.
    from audit_targeted_multistate_recovery import _load_one, _profile_status_counts


SCHEMA = "tsds-targeted-multistate-recovery-matrix-v1"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _facts(directory: Path) -> dict[str, Any]:
    case = _load_one(directory.resolve())
    row = case["row"]
    audit = case["audit"]
    aggregate = case["aggregate"]
    profiles = case["profiles"]
    return {
        "directory": case["directory"],
        "result_sha256": case["result_sha256"],
        "summary_sha256": case["summary_sha256"],
        "stderr_empty": case["stderr_empty"],
        "closure_idx": row.get("closure_idx"),
        "source_addr": row.get("source_addr"),
        "sink_addr": row.get("sink_addr"),
        "sink_snapshot_command_digest": row.get("sink_snapshot_command_digest"),
        "sink_snapshot_digest": row.get("sink_snapshot_digest"),
        "sink_preview": row.get("sink_preview"),
        "status": row.get("status"),
        "verdict": row.get("verdict"),
        "evidence_provenance": row.get("evidence_provenance"),
        "residual_diagnosis_class": row.get("residual_diagnosis_class"),
        "collection_complete": audit.get("collection_complete"),
        "collection_scope": audit.get("collection_scope"),
        "profile_count": len(profiles),
        "profile_status_counts": _profile_status_counts(profiles),
        "candidate_wide_negative": bool(aggregate.get("candidate_wide_negative")),
        "aggregate_class": aggregate.get("aggregate_class"),
        "decision_counts": aggregate.get("decision_counts"),
        "engine_run_count": audit.get("engine_run_count"),
    }


def _compare_pair(name: str, baseline_dir: Path, less_pruned_dir: Path) -> dict[str, Any]:
    baseline = _facts(baseline_dir)
    less_pruned = _facts(less_pruned_dir)
    core_fields = (
        "closure_idx",
        "source_addr",
        "sink_addr",
        "sink_snapshot_command_digest",
    )
    outcome_fields = (
        "status",
        "verdict",
        "evidence_provenance",
        "residual_diagnosis_class",
    )
    core_identity_equal = all(baseline[field] == less_pruned[field] for field in core_fields)
    outcome_equal = all(baseline[field] == less_pruned[field] for field in outcome_fields)
    return {
        "name": name,
        "baseline": baseline,
        "less_pruned": less_pruned,
        "comparisons": {
            "core_callsite_command_identity_equal": core_identity_equal,
            "primary_outcome_equal": outcome_equal,
            "snapshot_digest_equal": baseline["sink_snapshot_digest"] == less_pruned["sink_snapshot_digest"],
            "command_preview_equal": baseline["sink_preview"] == less_pruned["sink_preview"],
            "profile_count_delta_less_pruned_minus_baseline": less_pruned["profile_count"] - baseline["profile_count"],
            "both_explicitly_incomplete": baseline["collection_complete"] is False and less_pruned["collection_complete"] is False,
            "both_candidate_wide_negative_false": not baseline["candidate_wide_negative"] and not less_pruned["candidate_wide_negative"],
            "both_stderr_empty": baseline["stderr_empty"] and less_pruned["stderr_empty"],
        },
    }


def build_matrix_audit(pairs: list[tuple[str, Path, Path]]) -> dict[str, Any]:
    cases = [_compare_pair(name, baseline, less_pruned) for name, baseline, less_pruned in pairs]
    comparisons = [case["comparisons"] for case in cases]
    issues: list[str] = []
    if not all(item["core_callsite_command_identity_equal"] for item in comparisons):
        issues.append("core_callsite_command_identity_changed")
    if not all(item["primary_outcome_equal"] for item in comparisons):
        issues.append("primary_outcome_changed")
    if not all(item["both_explicitly_incomplete"] for item in comparisons):
        issues.append("incomplete_collection_not_explicit")
    if not all(item["both_candidate_wide_negative_false"] for item in comparisons):
        issues.append("candidate_wide_negative_present")
    if not all(item["both_stderr_empty"] for item in comparisons):
        issues.append("stderr_not_empty")
    return {
        "schema": SCHEMA,
        "claim_boundary": (
            "This receipt compares finite paired bounded executions for the listed "
            "closures.  It supports observations about callsite/command identity, "
            "primary-outcome stability, profile-count changes, and negative-gate "
            "behavior only.  A different snapshot digest is retained as an observed "
            "model difference, not hidden as identity equality.  The receipt does "
            "not prove exhaustive state coverage, solver soundness, source "
            "realizability, firmware-wide precision/recall, or device exploitability."
        ),
        "cases": cases,
        "aggregate": {
            "pair_count": len(cases),
            "core_callsite_command_identity_equal_all": all(item["core_callsite_command_identity_equal"] for item in comparisons),
            "primary_outcome_equal_all": all(item["primary_outcome_equal"] for item in comparisons),
            "both_explicitly_incomplete_all": all(item["both_explicitly_incomplete"] for item in comparisons),
            "both_candidate_wide_negative_false_all": all(item["both_candidate_wide_negative_false"] for item in comparisons),
            "snapshot_digest_changed_pair_count": sum(not item["snapshot_digest_equal"] for item in comparisons),
            "profile_count_delta_sum": sum(item["profile_count_delta_less_pruned_minus_baseline"] for item in comparisons),
        },
        "issues": sorted(set(issues)),
        "valid": not issues,
    }


def _write_outputs(out_dir: Path, result: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "targeted_multistate_recovery_matrix.json"
    summary_path.write_text(
        json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    aggregate = result["aggregate"]
    lines = [
        "# Targeted multi-state recovery matrix audit",
        "",
        f"Valid: **{result['valid']}**",
        f"Paired cases: **{aggregate['pair_count']}**",
        f"Core callsite/command identity equal for all pairs: **{aggregate['core_callsite_command_identity_equal_all']}**",
        f"Primary outcome equal for all pairs: **{aggregate['primary_outcome_equal_all']}**",
        f"Both collections explicitly incomplete for all pairs: **{aggregate['both_explicitly_incomplete_all']}**",
        f"No candidate-wide negative for all pairs: **{aggregate['both_candidate_wide_negative_false_all']}**",
        f"Pairs with changed concrete snapshot digest: **{aggregate['snapshot_digest_changed_pair_count']}**",
        f"Total profile-count delta: **{aggregate['profile_count_delta_sum']}**",
        "",
        "The audit keeps concrete snapshot differences visible while checking the stronger closure/callsite/command identity and outcome fields separately.  Incomplete collections remain bounded evidence and are not negative verdicts.",
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
    parser.add_argument("--pair", nargs=3, action="append", metavar=("NAME", "BASELINE_DIR", "LESS_PRUNED_DIR"), required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        pairs = [(name, Path(baseline), Path(less_pruned)) for name, baseline, less_pruned in args.pair]
        result = build_matrix_audit(pairs)
        _write_outputs(args.out_dir.resolve(), result)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"TARGETED_MULTISTATE_RECOVERY_MATRIX_AUDIT_ERROR: {exc}")
        return 2
    print(json.dumps({"valid": result["valid"], "issues": result["issues"], "aggregate": result["aggregate"]}, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
