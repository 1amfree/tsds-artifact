#!/usr/bin/env python3
"""Audit a current bounded multi-state TSDS firmware campaign.

This audit is intentionally separate from the frozen V20 matrix audit.  The
current evaluator may leave incomplete collections as residual obligations and
therefore need not reproduce the historical 102-profile/1122-cell ledger.
The checks here validate conservation and internal ledger invariants; they do
not establish solver soundness, source realizability, or device exploitability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


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
STATUS_FIELDS = (
    "vulnerable",
    "filtered",
    "no_taint_sink",
    "static_source_inference",
    "static_warning_reduction",
    "residual",
    "unreachable",
    "timeout",
    "crashed",
    "eval_error",
    "state_error",
    "invalid_closure",
    "empty_trace",
)


def load_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: expected JSON object")
        yield value


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _row_issues(row: dict[str, Any]) -> list[str]:
    decisions = row.get("vector_decisions")
    if not isinstance(decisions, list):
        return []
    issues: list[str] = []
    if len(decisions) != len(VECTOR_IDS):
        issues.append("matrix_vector_count_not_11")
    ids = [str(item.get("vector_id") or "") for item in decisions if isinstance(item, dict)]
    if len(ids) != len(decisions) or not all(ids):
        issues.append("matrix_vector_id_missing")
    if len(set(ids)) != len(ids):
        issues.append("matrix_vector_id_duplicate")
    if set(ids) != VECTOR_IDS:
        issues.append("matrix_vector_id_set_mismatch")
    bad_decisions = [
        str(item.get("decision") or "")
        for item in decisions
        if not isinstance(item, dict) or str(item.get("decision") or "") not in DECISIONS
    ]
    if bad_decisions:
        issues.append("matrix_decision_unsupported")
    counts = Counter(
        str(item.get("decision") or "")
        for item in decisions
        if isinstance(item, dict)
    )
    expected = {
        "VECTOR_SAT": _int(row.get("vulnerable_vectors")),
        "MATRIX_UNSAT": _int(row.get("secure_vectors")),
        "INCONCLUSIVE": _int(row.get("inconclusive_vectors")),
    }
    if any(counts.get(key, 0) != value for key, value in expected.items()):
        issues.append("matrix_decision_counts_disagree")
    profile = row.get("sanitizer_gap_profile")
    if isinstance(profile, dict):
        if _int(profile.get("total_vectors")) != len(decisions):
            issues.append("sanitizer_gap_total_disagrees")
    return sorted(set(issues))


def _multi_state_facts(row: dict[str, Any]) -> dict[str, Any]:
    audit = row.get("multi_state_audit")
    if not isinstance(audit, dict):
        return {
            "present": False,
            "collection_complete": None,
            "candidate_wide_negative": False,
            "primary_selection_blocked": None,
            "aggregate_class": "missing",
            "capture_count": 0,
        }
    aggregate = audit.get("aggregate")
    if not isinstance(aggregate, dict):
        aggregate = {}
    collection_accounting = aggregate.get("collection_accounting")
    if not isinstance(collection_accounting, dict):
        collection_accounting = {}
    return {
        "present": True,
        "collection_complete": bool(
            audit.get("collection_complete")
            or aggregate.get("collection_complete")
            or collection_accounting.get("effective_complete")
        ),
        "candidate_wide_negative": bool(
            aggregate.get("candidate_wide_negative")
            or audit.get("candidate_wide_negative")
        ),
        "primary_selection_blocked": bool(
            audit.get("primary_selection_blocked")
            or row.get("multi_state_primary_selection_blocked")
        ),
        "aggregate_class": str(
            aggregate.get("aggregate_class")
            or aggregate.get("multi_state_aggregate_class")
            or audit.get("multi_state_aggregate_class")
            or "unspecified"
        ),
        "capture_count": _int(
            audit.get("captured_state_count")
            or audit.get("multi_state_capture_count")
            or audit.get("profile_count")
        ),
    }


def audit_campaign(campaign_dir: Path, expected_targets: int | None) -> dict[str, Any]:
    # Campaign downloads may preserve one directory per target, whereas the
    # live driver writes target files at the campaign root.  Discover both
    # layouts so the audit cannot silently under-count completed targets.
    result_paths = sorted(campaign_dir.rglob("*.results.jsonl"))
    if not result_paths:
        raise ValueError(f"no results JSONL files found under {campaign_dir}")

    rows: list[dict[str, Any]] = []
    target_counts: dict[str, int] = {}
    for path in result_paths:
        target = path.name[: -len(".results.jsonl")]
        target_rows = list(load_jsonl(path))
        target_counts[target] = len(target_rows)
        rows.extend(target_rows)

    status_counts = Counter(str(row.get("status") or "missing") for row in rows)
    evidence_counts = Counter(
        str(row.get("evidence_provenance") or "missing") for row in rows
    )
    claim_counts = Counter(str(row.get("admissible_claim") or "missing") for row in rows)
    profile_rows = [row for row in rows if isinstance(row.get("vector_decisions"), list)]
    decision_counts = Counter(
        str(item.get("decision") or "")
        for row in profile_rows
        for item in row.get("vector_decisions") or []
        if isinstance(item, dict)
    )
    profile_verdicts = Counter(str(row.get("verdict") or "missing") for row in profile_rows)
    row_issues = [
        {"ordinal": index, "issues": _row_issues(row)}
        for index, row in enumerate(rows)
        if _row_issues(row)
    ]

    multi_state = [_multi_state_facts(row) for row in rows]
    multi_state_present = sum(bool(item["present"]) for item in multi_state)
    complete_count = sum(item["collection_complete"] is True for item in multi_state)
    incomplete_count = sum(item["collection_complete"] is False for item in multi_state)
    negative_count = sum(bool(item["candidate_wide_negative"]) for item in multi_state)
    blocked_count = sum(bool(item["primary_selection_blocked"]) for item in multi_state)
    aggregate_classes = Counter(str(item["aggregate_class"]) for item in multi_state)
    capture_counts = Counter(str(item["capture_count"]) for item in multi_state)

    issues: list[str] = []
    if expected_targets is not None and len(result_paths) != expected_targets:
        issues.append("target_count_mismatch")
    if row_issues:
        issues.append("matrix_profile_integrity_issues")
    if sum(decision_counts.values()) != len(profile_rows) * 11:
        issues.append("matrix_cell_count_not_profile_count_times_11")
    if negative_count:
        issues.append("candidate_wide_negative_flag_present")
    sink_reached_rows = [row for row in rows if bool(row.get("sink_reached_observed"))]
    if sum(
        isinstance(row.get("multi_state_audit"), dict) for row in sink_reached_rows
    ) != len(sink_reached_rows):
        issues.append("multi_state_audit_missing_on_sink_reached_record")
    if any(status not in STATUS_FIELDS for status in status_counts):
        issues.append("unknown_status_present")

    summary = {
        "schema": "tsds-current-multistate-campaign-audit-v1",
        "claim_boundary": (
            "This audit checks record conservation, matrix-ledger integrity, and "
            "the bounded multi-state negative gate. It does not validate solver "
            "semantics, source realizability, or device exploitability."
        ),
        "campaign_dir": str(campaign_dir),
        "target_count": len(result_paths),
        "target_record_counts": target_counts,
        "record_count": len(rows),
        "status_counts": dict(sorted(status_counts.items())),
        "evidence_provenance_counts": dict(sorted(evidence_counts.items())),
        "admissible_claim_counts": dict(sorted(claim_counts.items())),
        "matrix_profile_count": len(profile_rows),
        "matrix_profile_verdicts": dict(sorted(profile_verdicts.items())),
        "matrix_cell_count": int(sum(decision_counts.values())),
        "matrix_cell_decisions": dict(sorted(decision_counts.items())),
        "matrix_profile_issues": row_issues,
        "multi_state": {
            "records_with_audit": multi_state_present,
            "sink_reached_records": len(sink_reached_rows),
            "collection_complete": complete_count,
            "collection_incomplete": incomplete_count,
            "candidate_wide_negative": negative_count,
            "primary_selection_blocked": blocked_count,
            "aggregate_classes": dict(sorted(aggregate_classes.items())),
            "capture_count_distribution": dict(sorted(capture_counts.items())),
        },
        "issues": sorted(set(issues)),
        "valid": not issues,
    }
    return summary


def write_outputs(out_dir: Path, summary: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "current_multistate_campaign_audit.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    multi = summary["multi_state"]
    lines = [
        "# Current bounded multi-state campaign audit",
        "",
        f"Valid: **{summary['valid']}**",
        f"Targets: **{summary['target_count']}**",
        f"Records: **{summary['record_count']}**",
        f"Complete matrix profiles: **{summary['matrix_profile_count']}**",
        f"Matrix cells: **{summary['matrix_cell_count']}**",
        f"Candidate-wide negative flags: **{multi['candidate_wide_negative']}**",
        "",
        "This is accounting and gate evidence, not solver or firmware ground truth.",
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    digest = hashlib.sha256(summary_path.read_bytes()).hexdigest()
    (out_dir / "SHA256SUMS").write_text(
        f"{digest}  current_multistate_campaign_audit.json\n", encoding="utf-8"
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
        print(f"CURRENT_MULTISTATE_AUDIT_ERROR: {exc}")
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
