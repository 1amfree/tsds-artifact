#!/usr/bin/env python3
"""Audit a finite suite of high-budget multi-state recovery replays.

The suite compares one current-campaign row with one single-closure recovery
receipt for each declared case.  Core call-site identity is kept separate from
the concrete sink snapshot: a replay may materialize a different constraint
snapshot while still referring to the same source/sink pair.  This tool is
accounting and boundary evidence only; it does not infer firmware ground
truth, exhaustive state coverage, or device exploitability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "tsds-multistate-recovery-suite-audit-v1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _read_one_jsonl(path: Path) -> dict[str, Any]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) != 1 or not isinstance(rows[0], dict):
        raise ValueError(f"expected exactly one JSON object in {path}")
    return rows[0]


def _read_campaign_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_no}: expected JSON object")
        rows.append(value)
    return rows


def _resolve_project_path(value: Any, *, config_path: Path) -> Path:
    path = Path(str(value))
    if path.is_absolute():
        return path.resolve()
    # The checked-in suite configuration lives below paper_work/<suite>; make
    # its project-relative paths independent of the caller's working directory.
    project_root = config_path.resolve().parents[2]
    return (project_root / path).resolve()


def _aggregate(row: dict[str, Any]) -> dict[str, Any]:
    audit = row.get("multi_state_audit")
    if not isinstance(audit, dict):
        raise ValueError("row is missing multi_state_audit")
    aggregate = audit.get("aggregate")
    if not isinstance(aggregate, dict):
        raise ValueError("row is missing multi_state_audit.aggregate")
    profiles = audit.get("profiles")
    if not isinstance(profiles, list):
        raise ValueError("row is missing multi_state_audit.profiles")
    return {"audit": audit, "aggregate": aggregate, "profiles": profiles}


def _facts(row: dict[str, Any], *, source_path: Path) -> dict[str, Any]:
    payload = _aggregate(row)
    audit = payload["audit"]
    aggregate = payload["aggregate"]
    profiles = payload["profiles"]
    status_counts = Counter(
        str(profile.get("status") or "missing")
        for profile in profiles
        if isinstance(profile, dict)
    )
    collection = aggregate.get("collection_accounting")
    if not isinstance(collection, dict):
        collection = audit.get("collection_accounting")
    if not isinstance(collection, dict):
        collection = {}
    return {
        "source_path": str(source_path.resolve()),
        "source_sha256": _sha256(source_path),
        "target": row.get("target") or row.get("target_name"),
        "closure_idx": row.get("closure_idx"),
        "source_addr": row.get("source_addr"),
        "sink_addr": row.get("sink_addr"),
        "sink_function": row.get("sink_function"),
        "sink_snapshot_command_digest": row.get("sink_snapshot_command_digest"),
        "sink_snapshot_digest": row.get("sink_snapshot_digest"),
        "status": row.get("status"),
        "verdict": row.get("verdict"),
        "evidence_provenance": row.get("evidence_provenance"),
        "residual_diagnosis_class": row.get("residual_diagnosis_class"),
        "collection_complete": aggregate.get("collection_complete"),
        "collection_scope": aggregate.get("collection_scope"),
        "collection_blockers": list(collection.get("blockers") or []),
        "profile_count": len(profiles),
        "profile_status_counts": dict(sorted(status_counts.items())),
        "aggregate_class": aggregate.get("aggregate_class"),
        "quantifier": aggregate.get("quantifier"),
        "candidate_wide_negative": bool(aggregate.get("candidate_wide_negative")),
        "decision_counts": aggregate.get("decision_counts"),
        "primary_selection": audit.get("primary_selection"),
        "engine_env_branch_relaxations": row.get("engine_env_branch_relaxations"),
        "engine_pruned_states": row.get("engine_pruned_states"),
        "engine_semantic_frontier_pruned": row.get("engine_semantic_frontier_pruned"),
        "engine_source_liveness_cuts": row.get("engine_source_liveness_cuts"),
        "engine_state_cap_hits": row.get("engine_state_cap_hits"),
        "engine_steps_total": row.get("engine_steps_total"),
    }


def _find_baseline(path: Path, closure_idx: int) -> dict[str, Any]:
    matches = [row for row in _read_campaign_rows(path) if row.get("closure_idx") == closure_idx]
    if len(matches) != 1:
        raise ValueError(f"expected one baseline row for closure {closure_idx} in {path}, got {len(matches)}")
    return matches[0]


def _core_identity(facts: dict[str, Any]) -> tuple[Any, ...]:
    return (
        facts.get("target"),
        facts.get("closure_idx"),
        facts.get("source_addr"),
        facts.get("sink_addr"),
        facts.get("sink_function"),
        facts.get("sink_snapshot_command_digest"),
    )


def _case(
    case: dict[str, Any],
    *,
    baseline_campaign: Path,
    config_path: Path,
) -> dict[str, Any]:
    target = str(case["target"])
    closure_idx = int(case["closure_idx"])
    baseline_path = baseline_campaign / f"{target}.results.jsonl"
    recovery_dir = _resolve_project_path(case["recovery_dir"], config_path=config_path)
    recovery_path = recovery_dir / "results.jsonl"
    baseline_row = _find_baseline(baseline_path, closure_idx)
    recovery_row = _read_one_jsonl(recovery_path)
    baseline = _facts(baseline_row, source_path=baseline_path)
    recovery = _facts(recovery_row, source_path=recovery_path)
    identity_equal = _core_identity(baseline) == _core_identity(recovery)
    recovery_complete = recovery.get("collection_complete")
    recovery_negative = bool(recovery.get("candidate_wide_negative"))
    issues: list[str] = []
    if not identity_equal:
        issues.append("core_callsite_identity_changed")
    if recovery_negative:
        issues.append("candidate_wide_negative_present")
    if recovery_complete is None:
        issues.append("recovery_completeness_missing")
    return {
        "target": target,
        "closure_idx": closure_idx,
        "baseline": baseline,
        "recovery": recovery,
        "comparison": {
            "core_callsite_identity_equal": identity_equal,
            "sink_snapshot_digest_equal": baseline.get("sink_snapshot_digest") == recovery.get("sink_snapshot_digest"),
            "primary_outcome_equal": all(
                baseline.get(field) == recovery.get(field)
                for field in ("status", "verdict", "evidence_provenance")
            ),
            "profile_count_delta_recovery_minus_baseline": recovery["profile_count"] - baseline["profile_count"],
            "recovery_explicitly_incomplete": recovery_complete is False,
            "recovery_candidate_wide_negative_false": not recovery_negative,
        },
        "issues": sorted(set(issues)),
        "valid": not issues,
    }


def build_audit(config: dict[str, Any], *, config_path: Path) -> dict[str, Any]:
    baseline_campaign = _resolve_project_path(
        config["baseline_campaign"], config_path=config_path
    )
    cases = config.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("config.cases must be a non-empty list")
    results = [
        _case(case, baseline_campaign=baseline_campaign, config_path=config_path)
        for case in cases
    ]
    return {
        "schema": SCHEMA,
        "config_path": str(config_path.resolve()),
        "config_sha256": _sha256(config_path),
        "baseline_campaign": str(baseline_campaign),
        "claim_boundary": (
            "This artifact compares a finite set of identity-bound, single-closure "
            "bounded replays.  It supports recovery and negative-gate accounting "
            "only; it does not prove exhaustive sink-state coverage, solver "
            "soundness, source realizability, firmware precision/recall, or device "
            "exploitability."
        ),
        "cases": results,
        "summary": {
            "case_count": len(results),
            "valid_case_count": sum(item["valid"] for item in results),
            "invalid_case_count": sum(not item["valid"] for item in results),
            "core_identity_equal_count": sum(item["comparison"]["core_callsite_identity_equal"] for item in results),
            "primary_outcome_equal_count": sum(item["comparison"]["primary_outcome_equal"] for item in results),
            "recovery_incomplete_count": sum(item["comparison"]["recovery_explicitly_incomplete"] for item in results),
            "candidate_wide_negative_count": sum(
                not item["comparison"]["recovery_candidate_wide_negative_false"] for item in results
            ),
            "profile_count_delta_sum": sum(
                item["comparison"]["profile_count_delta_recovery_minus_baseline"] for item in results
            ),
        },
        "valid": all(item["valid"] for item in results),
    }


def write_outputs(out_dir: Path, result: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "multistate_recovery_suite_audit.json"
    json_path.write_text(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = result["summary"]
    lines = [
        "# Multi-state recovery suite audit",
        "",
        f"Valid: **{result['valid']}**",
        f"Cases: **{summary['case_count']}**",
        f"Core call-site identities equal: **{summary['core_identity_equal_count']}**",
        f"Recovery collections explicitly incomplete: **{summary['recovery_incomplete_count']}**",
        f"Candidate-wide negative flags: **{summary['candidate_wide_negative_count']}**",
        f"Profile-count delta sum: **{summary['profile_count_delta_sum']}**",
        "",
        "Snapshot digests are reported separately from core call-site identity because bounded replays may materialize different concrete constraints.",
        "",
        result["claim_boundary"],
        "",
        "| Target | Closure | Baseline profiles | Recovery profiles | Delta | Recovery class | Complete | Issues |",
        "|---|---:|---:|---:|---:|---|---|---|",
    ]
    for item in result["cases"]:
        base = item["baseline"]
        recovery = item["recovery"]
        lines.append(
            "| {target} | {idx} | {bp} | {rp} | {delta} | {cls} | {complete} | {issues} |".format(
                target=item["target"],
                idx=item["closure_idx"],
                bp=base["profile_count"],
                rp=recovery["profile_count"],
                delta=item["comparison"]["profile_count_delta_recovery_minus_baseline"],
                cls=recovery.get("aggregate_class"),
                complete=recovery.get("collection_complete"),
                issues=", ".join(item["issues"]) or "--",
            )
        )
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    sums = [
        f"{_sha256(path)}  {path.name}"
        for path in sorted(out_dir.iterdir())
        if path.is_file() and path.name != "SHA256SUMS"
    ]
    (out_dir / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        config_path = args.config.resolve()
        result = build_audit(_read_json(config_path), config_path=config_path)
        write_outputs(args.out_dir.resolve(), result)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"MULTISTATE_RECOVERY_SUITE_AUDIT_ERROR: {exc}")
        return 2
    print(json.dumps({"valid": result["valid"], "summary": result["summary"]}, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
