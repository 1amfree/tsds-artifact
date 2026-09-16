#!/usr/bin/env python3
"""Audit the completeness and consistency of TSDS vector-decision ledgers.

TSDS intentionally separates solver outcomes from device-level claims. This
read-only audit checks a narrower reproducibility property: when a v14 ledger
records a shell-vector matrix, does it contain one well-formed decision for
each declared matrix vector, and do the per-record aggregate fields agree with
those decisions? It never executes rendered commands or firmware binaries.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


DEFAULT_INPUT = Path(
    "experiment_reports/full_firmware_campaign_current_tsds_20260627"
)
DEFAULT_OUTPUT = Path("experiment_reports/vector_decision_integrity_current")

# This set is the matrix-bounded contract described by the paper. Keeping it
# in the artifact audit makes a silent omission visible if a future evaluator
# changes its internal vector list without updating the experimental protocol.
MATRIX_VECTOR_IDS = (
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
)
EXPECTED_MATRIX_VECTOR_IDS = frozenset(MATRIX_VECTOR_IDS)
CANONICAL_DECISIONS = {
    "VECTOR_SAT",
    "MATRIX_UNSAT",
    "INCONCLUSIVE",
}
V14_WITNESS_SCHEMA = "tsds-shell-witness-v3"
V14_LEXICAL_GATE = "tsds-shell-lexical-gate-v1"
LEXICAL_MODEL_SOURCES = {
    "raw_solver_model",
    "escaped_witness_decode",
}


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _controlled_byte_count(record: dict[str, Any]) -> int:
    count = _as_int(record.get("tainted_byte_count"))
    if count:
        return count
    offsets = record.get("tainted_offsets") or record.get("controlled_offsets") or []
    return len(offsets) if isinstance(offsets, list) else 0


def _matrix_enabled(record: dict[str, Any]) -> bool:
    features = record.get("features") or {}
    if isinstance(features, dict) and "threat_matrix" in features:
        return bool(features.get("threat_matrix"))
    return bool(record.get("vector_decisions"))


def _is_v14_ledger(record: dict[str, Any]) -> bool:
    features = record.get("features") or {}
    return bool(
        isinstance(features, dict)
        and features.get("shell_lexical_gate") == V14_LEXICAL_GATE
    )


def _decision_counts(decisions: list[dict[str, Any]]) -> Counter[str]:
    return Counter(
        str(item.get("decision") or "")
        for item in decisions
        if isinstance(item, dict)
    )


def _record_issues(record: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    """Return non-mutating ledger-integrity issues and compact audit facts."""
    raw_decisions = record.get("vector_decisions")
    matrix_enabled = _matrix_enabled(record)
    v14_ledger = _is_v14_ledger(record)
    status = str(record.get("status") or "")
    controlled = _controlled_byte_count(record)
    issues: list[str] = []

    if raw_decisions is None:
        decisions: list[dict[str, Any]] = []
        if status in {"vulnerable", "filtered"}:
            issues.append("claim_without_vector_decisions")
    elif not isinstance(raw_decisions, list):
        decisions = []
        issues.append("vector_decisions_not_a_list")
    else:
        decisions = [item for item in raw_decisions if isinstance(item, dict)]
        if len(decisions) != len(raw_decisions):
            issues.append("vector_decisions_contain_non_object_entries")

    counts = _decision_counts(decisions)
    vector_ids = [str(item.get("vector_id") or "") for item in decisions]
    nonempty_ids = [value for value in vector_ids if value]
    if decisions and len(nonempty_ids) != len(decisions):
        issues.append("vector_decision_missing_vector_id")
    if len(nonempty_ids) != len(set(nonempty_ids)):
        issues.append("duplicate_vector_decision_id")

    # A no-source record intentionally has no matrix decisions. Once TSDS
    # observes controlled sink bytes under the full matrix, however, a v14
    # record must account for every matrix predicate.
    require_full_matrix = bool(
        matrix_enabled
        and controlled > 0
        and (decisions or status in {"vulnerable", "filtered"})
    )
    if require_full_matrix:
        actual_ids = set(nonempty_ids)
        if len(decisions) != len(MATRIX_VECTOR_IDS):
            issues.append("matrix_vector_count_mismatch")
        if actual_ids != EXPECTED_MATRIX_VECTOR_IDS:
            issues.append("matrix_vector_set_mismatch")

    unknown_decisions = sorted(
        decision
        for decision in counts
        if decision and decision not in CANONICAL_DECISIONS
    )
    if unknown_decisions:
        issues.append("unknown_vector_decision")

    expected_counts = {
        "VECTOR_SAT": _as_int(record.get("vulnerable_vectors")),
        "MATRIX_UNSAT": _as_int(record.get("secure_vectors")),
        "INCONCLUSIVE": _as_int(record.get("inconclusive_vectors")),
    }
    if decisions and any(
        counts.get(name, 0) != expected
        for name, expected in expected_counts.items()
    ):
        issues.append("vector_decision_count_disagrees_with_record")

    profile = record.get("sanitizer_gap_profile") or {}
    if decisions and isinstance(profile, dict):
        if _as_int(profile.get("total_vectors")) != len(decisions):
            issues.append("sanitizer_gap_total_disagrees_with_decisions")
        profile_counts = {
            "VECTOR_SAT": _as_int(profile.get("vulnerable_count")),
            "MATRIX_UNSAT": _as_int(profile.get("secure_count")),
            "INCONCLUSIVE": _as_int(profile.get("inconclusive_count")),
        }
        if any(
            counts.get(name, 0) != expected
            for name, expected in profile_counts.items()
        ):
            issues.append("sanitizer_gap_counts_disagree_with_decisions")

    lexical_reasons: Counter[str] = Counter()
    lexical_model_sources: Counter[str] = Counter()
    for item in decisions:
        decision = str(item.get("decision") or "")
        if v14_ledger:
            if item.get("schema") != V14_WITNESS_SCHEMA:
                issues.append("v14_decision_missing_witness_schema")
            if item.get("lexical_gate") != V14_LEXICAL_GATE:
                issues.append("v14_decision_missing_lexical_gate")

        if decision == "VECTOR_SAT":
            if not item.get("witness"):
                issues.append("sat_vector_without_witness")
            if not item.get("grammar_complete"):
                issues.append("sat_vector_without_grammar_complete_marker")
            if not item.get("parser_calibration"):
                issues.append("sat_vector_without_parser_calibration")
            if v14_ledger:
                lexical_reason = str(item.get("lexical_reason") or "")
                lexical_source = str(item.get("lexical_model_source") or "")
                lexical_reasons[lexical_reason] += 1
                lexical_model_sources[lexical_source] += 1
                if lexical_reason != "lexically_complete":
                    issues.append("sat_vector_without_lexically_complete_model")
                if lexical_source not in LEXICAL_MODEL_SOURCES:
                    issues.append("sat_vector_without_lexical_model_source")
        elif decision == "INCONCLUSIVE":
            reason = str(item.get("reason") or "")
            if not reason:
                issues.append("inconclusive_vector_without_reason")
            if v14_ledger:
                lexical_reason = str(item.get("lexical_reason") or "")
                lexical_source = str(item.get("lexical_model_source") or "")
                if lexical_reason:
                    lexical_reasons[lexical_reason] += 1
                if lexical_source:
                    lexical_model_sources[lexical_source] += 1
                if reason == "incomplete_shell_lexeme":
                    if not lexical_reason or lexical_reason == "lexically_complete":
                        issues.append("lexical_inconclusive_without_incomplete_reason")
                    if lexical_source not in LEXICAL_MODEL_SOURCES:
                        issues.append("lexical_inconclusive_without_model_source")
                    if not item.get("rejected_witness"):
                        issues.append("lexical_inconclusive_without_rejected_witness")

        if (
            decision == "MATRIX_UNSAT"
            and record.get("sink_snapshot_cstring_complete") is False
        ):
            issues.append("unsat_vector_from_incomplete_sink_snapshot")

    # Preserve one row-level issue of each kind so CSV reviewers can group
    # failures by record without being flooded by the same issue per vector.
    issues = sorted(set(issues))
    facts = {
        "matrix_enabled": matrix_enabled,
        "v14_ledger": v14_ledger,
        "decision_count": len(decisions),
        "controlled_bytes": controlled,
        "sat_vectors": counts.get("VECTOR_SAT", 0),
        "unsat_vectors": counts.get("MATRIX_UNSAT", 0),
        "inconclusive_vectors": counts.get("INCONCLUSIVE", 0),
        "lexical_reasons": dict(sorted(lexical_reasons.items())),
        "lexical_model_sources": dict(sorted(lexical_model_sources.items())),
    }
    return issues, facts


def iter_campaign_records(input_dir: Path) -> Iterable[dict[str, Any]]:
    files = sorted(input_dir.glob("*.results.jsonl"))
    if not files:
        raise FileNotFoundError(f"no *.results.jsonl files found under {input_dir}")
    for path in files:
        target = path.name.removesuffix(".results.jsonl")
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                record = json.loads(line)
                record["_audit_target"] = target
                record["_audit_source"] = str(path)
                record["_audit_line"] = line_no
                yield record


def audit_records(
    records: Iterable[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    issue_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    decision_counts: Counter[str] = Counter()
    lexical_reason_counts: Counter[str] = Counter()
    lexical_source_counts: Counter[str] = Counter()
    per_vector: dict[str, Counter[str]] = defaultdict(Counter)

    for record in records:
        issues, facts = _record_issues(record)
        decisions = record.get("vector_decisions") or []
        status = str(record.get("status") or "unknown")
        status_counts[status] += 1
        issue_counts.update(issues)
        for item in decisions:
            if not isinstance(item, dict):
                continue
            decision = str(item.get("decision") or "")
            decision_counts[decision] += 1
            per_vector[str(item.get("vector_id") or "")][decision] += 1
        lexical_reason_counts.update(facts["lexical_reasons"])
        lexical_source_counts.update(facts["lexical_model_sources"])
        rows.append(
            {
                "target": record.get("_audit_target"),
                "closure_idx": record.get("closure_idx"),
                "status": status,
                "matrix_enabled": facts["matrix_enabled"],
                "v14_ledger": facts["v14_ledger"],
                "controlled_bytes": facts["controlled_bytes"],
                "decision_count": facts["decision_count"],
                "sat_vectors": facts["sat_vectors"],
                "unsat_vectors": facts["unsat_vectors"],
                "inconclusive_vectors": facts["inconclusive_vectors"],
                "lexical_reasons": json.dumps(facts["lexical_reasons"], sort_keys=True),
                "lexical_model_sources": json.dumps(
                    facts["lexical_model_sources"], sort_keys=True
                ),
                "issues": ";".join(issues),
            }
        )

    records_with_decisions = sum(
        1 for row in rows if int(row["decision_count"] or 0) > 0
    )
    summary = {
        "schema": "tsds-vector-decision-integrity-audit-v1",
        "records": len(rows),
        "records_with_decisions": records_with_decisions,
        "records_with_integrity_issues": sum(1 for row in rows if row["issues"]),
        "current_statuses": dict(sorted(status_counts.items())),
        "decision_outcomes": dict(sorted(decision_counts.items())),
        "lexical_reasons": dict(sorted(lexical_reason_counts.items())),
        "lexical_model_sources": dict(sorted(lexical_source_counts.items())),
        "per_vector": {
            key: dict(sorted(value.items()))
            for key, value in sorted(per_vector.items())
        },
        "integrity_issue_counts": dict(sorted(issue_counts.items())),
        "claim_boundary": (
            "This audit checks ledger completeness and consistency only. It "
            "does not execute commands, validate reachability, or establish "
            "device-level exploitability."
        ),
    }
    return rows, summary


def write_outputs(
    out_dir: Path, rows: list[dict[str, Any]], summary: dict[str, Any]
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "vector_decision_integrity_audit.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    fields = list(rows[0]) if rows else []
    with (out_dir / "vector_decision_integrity_records.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# TSDS vector-decision integrity audit",
        "",
        summary["claim_boundary"],
        "",
        f"- Records: {summary['records']}",
        f"- Records with decisions: {summary['records_with_decisions']}",
        (
            "- Records with integrity issues: "
            f"{summary['records_with_integrity_issues']}"
        ),
        "",
        "## Decision outcomes",
        "",
        "| Outcome | Decisions |",
        "|---|---:|",
    ]
    for name, count in summary["decision_outcomes"].items():
        lines.append(f"| {name} | {count} |")
    lines.extend(["", "## Integrity issues", "", "| Issue | Records |", "|---|---:|"])
    for name, count in summary["integrity_issue_counts"].items():
        lines.append(f"| {name} | {count} |")
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--fail-on-issues",
        action="store_true",
        help="return exit code 2 if any ledger-integrity issue is observed",
    )
    args = parser.parse_args()

    rows, summary = audit_records(iter_campaign_records(args.input_dir))
    write_outputs(args.out_dir, rows, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    if args.fail_on_issues and summary["records_with_integrity_issues"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
