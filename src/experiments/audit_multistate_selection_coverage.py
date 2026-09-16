#!/usr/bin/env python3
"""Audit selected-instance versus bounded multi-state outcomes.

This report is evidence-only.  It recomputes the selection facts recorded in
the current campaign exports and makes the important first-state/later-state
cases explicit.  It does not claim exhaustive path coverage, solver
soundness, source realizability, or device exploitability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


POSITIVE_STATUS = "VECTOR_SAT"


def _int(value: Any) -> int:
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


def _load_rows(campaign_dir: Path) -> tuple[list[dict[str, Any]], list[Path]]:
    rows: list[dict[str, Any]] = []
    paths = sorted(campaign_dir.rglob("*.results.jsonl"))
    for path in paths:
        target = path.name[: -len(".results.jsonl")]
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1
        ):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected JSON object")
            value["_audit_target"] = target
            rows.append(value)
    if not paths:
        raise ValueError(f"no results JSONL files found under {campaign_dir}")
    return rows, paths


def _profile_positive(profile: dict[str, Any]) -> bool:
    return str(profile.get("status") or "") == POSITIVE_STATUS


def _audit_row(row: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    audit = row.get("multi_state_audit")
    if not isinstance(audit, dict):
        raise ValueError("audited row is missing multi_state_audit")
    aggregate = audit.get("aggregate")
    if not isinstance(aggregate, dict):
        raise ValueError("audited row is missing multi_state_audit.aggregate")
    profiles = audit.get("profiles")
    if not isinstance(profiles, list):
        raise ValueError("audited row is missing multi_state_audit.profiles")
    if _int(audit.get("profile_count")) != len(profiles):
        raise ValueError("profile_count disagrees with serialized profiles")
    if _int(aggregate.get("profile_count")) != len(profiles):
        raise ValueError("aggregate profile_count disagrees with serialized profiles")

    positive_indices = [
        index
        for index, profile in enumerate(profiles)
        if isinstance(profile, dict) and _profile_positive(profile)
    ]
    primary_selection = audit.get("primary_selection")
    if not isinstance(primary_selection, dict):
        primary_selection = {}
    if "positive_profile_indices" in aggregate:
        supplied_positive_raw = aggregate.get("positive_profile_indices")
    elif "positive_state_indices" in primary_selection:
        supplied_positive_raw = primary_selection.get("positive_state_indices")
    else:
        supplied_positive_raw = []
    supplied_positive = sorted({_int(index) for index in (supplied_positive_raw or [])})
    issues: list[str] = []
    # The serialized aggregate list is the set used by the aggregator's
    # primary-selection bookkeeping, not necessarily every positive profile.
    # It is sound for this audit only when it is a subset of the profiles that
    # actually carry VECTOR_SAT status.
    if not set(supplied_positive).issubset(set(positive_indices)):
        issues.append("serialized_positive_index_not_profile_positive")

    selection = primary_selection
    selected = selection.get("selected_state_index")
    if selected is not None:
        selected = _int(selected)
        if selected < 0 or selected >= len(profiles):
            issues.append("selected_state_index_out_of_range")

    first_positive = 0 in positive_indices
    later_positive = any(index > 0 for index in positive_indices)
    first_nonpositive_later_positive = bool(profiles) and not first_positive and later_positive
    selected_positive = selected in positive_indices if selected is not None else False
    selected_nonpositive_later_positive = (
        selected is not None and not selected_positive and later_positive
    )
    collection_complete = bool(audit.get("collection_complete"))
    fact = {
        "target": row.get("_audit_target"),
        "closure_idx": row.get("closure_idx"),
        "closure_ordinal": row.get("closure_ordinal"),
        "status": row.get("status"),
        "sink_function": row.get("sink_function"),
        "sink_addr": row.get("sink_addr"),
        "source_addr": row.get("source_addr"),
        "collection_complete": collection_complete,
        "profile_count": len(profiles),
        "first_profile_status": (
            profiles[0].get("status") if profiles and isinstance(profiles[0], dict) else None
        ),
        "profile_statuses": [
            profile.get("status") if isinstance(profile, dict) else None
            for profile in profiles
        ],
        "profile_positive_indices": positive_indices,
        "serialized_positive_profile_indices": supplied_positive,
        "aggregate_class": aggregate.get("aggregate_class"),
        "selected_state_index": selected,
        "selected_reason": selection.get("selected_reason"),
        "first_profile_positive": first_positive,
        "later_positive_after_first": later_positive,
        "first_nonpositive_later_positive": first_nonpositive_later_positive,
        "selected_positive": selected_positive,
        "selected_nonpositive_later_positive": selected_nonpositive_later_positive,
        "candidate_wide_negative": bool(aggregate.get("candidate_wide_negative")),
        "issues": sorted(set(issues)),
    }
    return fact, issues


def audit_campaign(campaign_dir: Path, expected_targets: int | None = None) -> dict[str, Any]:
    rows, paths = _load_rows(campaign_dir)
    audited_rows = [row for row in rows if isinstance(row.get("multi_state_audit"), dict)]
    facts: list[dict[str, Any]] = []
    issues: list[str] = []
    for row in audited_rows:
        fact, row_issues = _audit_row(row)
        facts.append(fact)
        issues.extend(row_issues)

    sink_reached = [row for row in rows if bool(row.get("sink_reached_observed"))]
    if len(audited_rows) != len(sink_reached):
        issues.append("sink_reached_audit_count_mismatch")
    if expected_targets is not None and len(paths) != expected_targets:
        issues.append("target_count_mismatch")

    aggregate_classes = Counter(str(fact.get("aggregate_class")) for fact in facts)
    status_counts = Counter(str(fact.get("status")) for fact in facts)
    complete_counts = Counter(
        "complete" if fact["collection_complete"] else "incomplete" for fact in facts
    )
    selected_facts = [fact for fact in facts if fact["selected_state_index"] is not None]
    late_cases = [fact for fact in facts if fact["first_nonpositive_later_positive"]]
    selected_late_cases = [
        fact for fact in facts if fact["selected_state_index"] is not None and fact["selected_state_index"] > 0 and fact["selected_positive"]
    ]
    selected_bad_cases = [
        fact for fact in facts if fact["selected_nonpositive_later_positive"]
    ]
    negative_flags = sum(bool(fact["candidate_wide_negative"]) for fact in facts)
    if negative_flags:
        issues.append("candidate_wide_negative_flag_present")

    by_target: dict[str, dict[str, Any]] = {}
    for target in sorted({str(fact["target"]) for fact in facts}):
        target_facts = [fact for fact in facts if str(fact["target"]) == target]
        by_target[target] = {
            "audited_rows": len(target_facts),
            "complete": sum(fact["collection_complete"] for fact in target_facts),
            "incomplete": sum(not fact["collection_complete"] for fact in target_facts),
            "selected_rows": sum(fact["selected_state_index"] is not None for fact in target_facts),
            "first_nonpositive_later_positive": sum(
                fact["first_nonpositive_later_positive"] for fact in target_facts
            ),
            "selected_late_positive": sum(
                fact["selected_state_index"] is not None
                and fact["selected_state_index"] > 0
                and fact["selected_positive"]
                for fact in target_facts
            ),
            "selected_nonpositive_later_positive": sum(
                fact["selected_nonpositive_later_positive"] for fact in target_facts
            ),
            "aggregate_classes": dict(
                sorted(Counter(str(fact["aggregate_class"]) for fact in target_facts).items())
            ),
        }

    source_hashes = {
        str(path.relative_to(campaign_dir)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }
    summary = {
        "schema": "tsds-multistate-selection-coverage-v1",
        "claim_boundary": (
            "This audit recomputes selection and bounded-collection facts from the "
            "serialized current campaign. It does not establish exhaustive sink-state "
            "coverage, solver soundness, source realizability, firmware precision, or "
            "device exploitability."
        ),
        "campaign_dir": str(campaign_dir),
        "input_result_files": source_hashes,
        "target_count": len(paths),
        "record_count": len(rows),
        "sink_reached_records": len(sink_reached),
        "audited_records": len(facts),
        "profile_count_total": sum(fact["profile_count"] for fact in facts),
        "collection_completeness": dict(sorted(complete_counts.items())),
        "aggregate_classes": dict(sorted(aggregate_classes.items())),
        "status_counts": dict(sorted(status_counts.items())),
        "selection": {
            "selected_records": len(selected_facts),
            "selection_blocked_records": len(facts) - len(selected_facts),
            "selected_positive_records": sum(fact["selected_positive"] for fact in selected_facts),
            "selected_first_positive_records": sum(
                fact["selected_state_index"] == 0 and fact["selected_positive"]
                for fact in selected_facts
            ),
            "selected_late_positive_records": len(selected_late_cases),
            "first_nonpositive_later_positive_records": len(late_cases),
            "selected_nonpositive_later_positive_records": len(selected_bad_cases),
            "candidate_wide_negative_flags": negative_flags,
        },
        "late_positive_cases": late_cases,
        "selected_late_positive_cases": selected_late_cases,
        "by_target": by_target,
        "row_issues": sorted(set(issues)),
        "valid": not issues,
    }
    return summary


def write_outputs(out_dir: Path, summary: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "selection_coverage_audit.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Multi-state selection coverage audit",
        "",
        f"Valid: **{summary['valid']}**",
        f"Records: **{summary['record_count']}**",
        f"Sink-reached audited records: **{summary['audited_records']}**",
        f"Collected profiles: **{summary['profile_count_total']}**",
        f"First non-positive, later positive: **{summary['selection']['first_nonpositive_later_positive_records']}**",
        f"Selected later-positive records: **{summary['selection']['selected_late_positive_records']}**",
        f"Selected non-positive despite later positive: **{summary['selection']['selected_nonpositive_later_positive_records']}**",
        "",
        "The report is bounded selection evidence, not exhaustive multi-state or firmware ground truth.",
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    digest = hashlib.sha256(summary_path.read_bytes()).hexdigest()
    (out_dir / "SHA256SUMS").write_text(
        f"{digest}  selection_coverage_audit.json\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--expected-targets", type=int, default=None)
    args = parser.parse_args()
    try:
        summary = audit_campaign(args.campaign_dir, args.expected_targets)
        write_outputs(args.out_dir, summary)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"MULTISTATE_SELECTION_AUDIT_ERROR: {exc}")
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
