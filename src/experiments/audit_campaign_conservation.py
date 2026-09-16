#!/usr/bin/env python3
"""Audit record conservation across TSDS campaign artifacts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


STRICT_VERDICTS = {
    "VECTOR_SAT",
    "MATRIX_UNSAT",
    "NO_MODELED_SOURCE",
    "STATIC_SOURCE_INFERENCE",
    "STATIC_WARNING_REDUCTION",
    "RESIDUAL",
}


# The evaluator redirects library logging to per-target stderr logs. A reached
# firmware syslog call can therefore produce an angr INFO line even when the
# target exited successfully and every serialized evidence invariant holds.
# Keep that exception deliberately narrow: any other stderr content remains a
# conservation failure and is retained by hash and line number for audit.
ANGR_POSIX_SYSLOG_INFO_RE = re.compile(
    r"^INFO\s+\|\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3}\s+\|\s+"
    r"angr\.procedures\.posix\.syslog\s+\|\s+Syslog priority "
    r"<BV\d+ [^>\r\n]+>: b(?:'.*'|\".*\")$"
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_no, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_no}: record is not an object")
        rows.append(row)
    return rows


def record_identity(target: str, row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        target,
        row.get("closure_idx"),
        str(row.get("source_addr") or "").lower(),
        str(row.get("sink_addr") or "").lower(),
    )


def classify_stderr(stderr_path: Path) -> dict[str, Any]:
    """Classify redirected target stderr without hiding unexpected output.

    The accepted class is restricted to the known structured angr syslog INFO
    record. The returned metadata intentionally contains no raw firmware log
    payload; the original log remains available at ``path`` and is bound by its
    SHA-256 digest.
    """

    result: dict[str, Any] = {
        "path": str(stderr_path),
        "present": stderr_path.exists(),
        "bytes": 0,
        "sha256": None,
        "nonblank_lines": 0,
        "benign_structured_info_lines": 0,
        "unexpected_lines": 0,
        "unexpected_line_numbers": [],
        "classification": "missing",
    }
    if not stderr_path.exists():
        return result
    if not stderr_path.is_file():
        result["classification"] = "not_regular_file"
        result["unexpected_lines"] = 1
        result["unexpected_line_numbers"] = [0]
        return result
    try:
        raw = stderr_path.read_bytes()
    except OSError as exc:
        result["classification"] = "unreadable"
        result["read_error"] = f"{type(exc).__name__}:{exc}"
        result["unexpected_lines"] = 1
        result["unexpected_line_numbers"] = [0]
        return result

    result["bytes"] = len(raw)
    result["sha256"] = hashlib.sha256(raw).hexdigest()
    if not raw:
        result["classification"] = "empty"
        return result

    lines = raw.decode("utf-8", errors="replace").splitlines()
    nonblank = [
        (line_no, line.strip())
        for line_no, line in enumerate(lines, 1)
        if line.strip()
    ]
    result["nonblank_lines"] = len(nonblank)
    if not nonblank:
        result["classification"] = "empty"
        return result

    unexpected = [
        line_no
        for line_no, line in nonblank
        if ANGR_POSIX_SYSLOG_INFO_RE.fullmatch(line) is None
    ]
    result["benign_structured_info_lines"] = len(nonblank) - len(unexpected)
    result["unexpected_lines"] = len(unexpected)
    result["unexpected_line_numbers"] = unexpected
    result["classification"] = (
        "benign_angr_posix_syslog_info" if not unexpected else "unexpected"
    )
    return result


def audit_target(
    campaign_dir: Path, summary_path: Path, require_resource_metrics: bool
) -> dict[str, Any]:
    target = summary_path.name[: -len(".summary.json")]
    jsonl_path = campaign_dir / f"{target}.results.jsonl"
    report_path = campaign_dir / f"{target}.report.md"
    resource_path = campaign_dir / f"{target}.resource.txt"
    stderr_path = campaign_dir / f"{target}.stderr.log"
    issues = []
    summary = load_json(summary_path)
    if not jsonl_path.is_file():
        issues.append("missing_results_jsonl")
        records: list[dict[str, Any]] = []
    else:
        try:
            records = load_jsonl(jsonl_path)
        except ValueError as exc:
            issues.append(str(exc))
            records = []

    if not report_path.is_file():
        issues.append("missing_markdown_report")
    if require_resource_metrics and not resource_path.is_file():
        issues.append("missing_resource_metrics")
    stderr = classify_stderr(stderr_path)
    if stderr["classification"] in {"not_regular_file", "unreadable", "unexpected"}:
        issues.append("unexpected_stderr")

    expected = int(summary.get("unique_pairs_analyzed") or 0)
    ledger = summary.get("evidence_contract_ledger") or {}
    ledger_records = int(ledger.get("records") or 0)
    verdicts = {
        str(key): int(value or 0)
        for key, value in (ledger.get("verdicts") or {}).items()
    }
    verdict_sum = sum(verdicts.values())
    if len(records) != expected:
        issues.append("jsonl_vs_unique_pairs_mismatch")
    if ledger_records != expected:
        issues.append("ledger_vs_unique_pairs_mismatch")
    if verdict_sum != expected:
        issues.append("verdict_sum_vs_unique_pairs_mismatch")
    unknown_verdicts = sorted(set(verdicts) - STRICT_VERDICTS)
    if unknown_verdicts:
        issues.append("unknown_summary_verdict:" + ",".join(unknown_verdicts))

    identities = [record_identity(target, row) for row in records]
    duplicate_identities = sum(
        count - 1 for count in Counter(identities).values() if count > 1
    )
    if duplicate_identities:
        issues.append("duplicate_record_identity")
    missing_identity = sum(
        identity[1] is None or not identity[2] or not identity[3]
        for identity in identities
    )
    if missing_identity:
        issues.append("record_identity_incomplete")

    record_verdicts = Counter(str(row.get("verdict") or "") for row in records)
    if dict(sorted(record_verdicts.items())) != dict(sorted(verdicts.items())):
        issues.append("jsonl_vs_summary_verdict_mismatch")
    invalid_contract = sum(
        row.get("evidence_contract_valid") is not True for row in records
    )
    if invalid_contract:
        issues.append("contract_invalid_jsonl_record")
    unknown_record_verdicts = sorted(set(record_verdicts) - STRICT_VERDICTS)
    if unknown_record_verdicts:
        issues.append("unknown_jsonl_verdict:" + ",".join(unknown_record_verdicts))

    versions = sorted(
        {str(row.get("analysis_version")) for row in records if row.get("analysis_version")}
    )
    if len(versions) > 1:
        issues.append("mixed_analysis_versions")
    candidate_closures = int(summary.get("total_closures") or 0)
    if candidate_closures < expected:
        issues.append("unique_pairs_exceed_total_closures")

    return {
        "target": target,
        "total_closures": candidate_closures,
        "candidate_closures": candidate_closures,
        "selected_closures": expected,
        "unique_pairs": expected,
        "jsonl_records": len(records),
        "ledger_records": ledger_records,
        "verdict_sum": verdict_sum,
        "contract_invalid_records": invalid_contract,
        "duplicate_identities": duplicate_identities,
        "analysis_versions": versions,
        "stderr": stderr,
        "issues": sorted(set(issues)),
        "valid": not issues,
    }


def audit_campaign(
    campaign_dir: Path,
    expected_targets: int | None = None,
    require_resource_metrics: bool = False,
) -> dict[str, Any]:
    summaries = sorted(campaign_dir.glob("*.summary.json"))
    targets = [
        audit_target(campaign_dir, path, require_resource_metrics)
        for path in summaries
    ]
    campaign_issues = []
    if expected_targets is not None and len(targets) != expected_targets:
        campaign_issues.append("target_count_mismatch")
    if not targets:
        campaign_issues.append("no_target_summaries")
    if any(not row["valid"] for row in targets):
        campaign_issues.append("target_conservation_failure")

    aggregate_path = campaign_dir / "full_campaign_aggregate.json"
    if aggregate_path.is_file():
        aggregate = load_json(aggregate_path)
        total = aggregate.get("total") or {}
        checks = {
            "evaluated": sum(row["unique_pairs"] for row in targets),
            "contract_valid": sum(
                row["jsonl_records"] - row["contract_invalid_records"]
                for row in targets
            ),
        }
        for key, expected in checks.items():
            if int(total.get(key) or 0) != expected:
                campaign_issues.append(f"aggregate_{key}_mismatch")
        candidate_total = sum(row["candidate_closures"] for row in targets)
        selected_total = sum(row["selected_closures"] for row in targets)
        # Existing artifacts only exposed the compatibility alias closures.
        # New artifacts also expose explicit candidate and selected counts.
        if int(total.get("closures") or 0) != candidate_total:
            campaign_issues.append("aggregate_candidate_closures_mismatch")
        if (
            "candidate_closures" in total
            and int(total.get("candidate_closures") or 0) != candidate_total
        ):
            campaign_issues.append("aggregate_explicit_candidate_closures_mismatch")
        if (
            "selected_closures" in total
            and int(total.get("selected_closures") or 0) != selected_total
        ):
            campaign_issues.append("aggregate_selected_closures_mismatch")
        aggregate_verdicts = {
            "vector_sat": "VECTOR_SAT",
            "matrix_unsat": "MATRIX_UNSAT",
            "no_modeled_source": "NO_MODELED_SOURCE",
            "static_source_inference": "STATIC_SOURCE_INFERENCE",
            "static_warning_reduction": "STATIC_WARNING_REDUCTION",
            "contract_residual": "RESIDUAL",
        }
        summary_verdicts = Counter()
        for path in summaries:
            ledger = load_json(path).get("evidence_contract_ledger") or {}
            summary_verdicts.update(ledger.get("verdicts") or {})
        for aggregate_key, verdict in aggregate_verdicts.items():
            if int(total.get(aggregate_key) or 0) != int(summary_verdicts[verdict]):
                campaign_issues.append(f"aggregate_{aggregate_key}_mismatch")
    else:
        campaign_issues.append("missing_campaign_aggregate")

    totals = {
        "targets": len(targets),
        "total_closures": sum(row["total_closures"] for row in targets),
        "candidate_closures": sum(row["candidate_closures"] for row in targets),
        "selected_closures": sum(row["selected_closures"] for row in targets),
        "unique_pairs": sum(row["unique_pairs"] for row in targets),
        "jsonl_records": sum(row["jsonl_records"] for row in targets),
        "ledger_records": sum(row["ledger_records"] for row in targets),
        "contract_invalid_records": sum(
            row["contract_invalid_records"] for row in targets
        ),
        "duplicate_identities": sum(row["duplicate_identities"] for row in targets),
        "benign_structured_stderr_lines": sum(
            int((row.get("stderr") or {}).get("benign_structured_info_lines") or 0)
            for row in targets
        ),
        "unexpected_stderr_lines": sum(
            int((row.get("stderr") or {}).get("unexpected_lines") or 0)
            for row in targets
        ),
    }
    return {
        "schema": "tsds-campaign-conservation-audit-v1",
        "campaign_dir": str(campaign_dir),
        "targets": targets,
        "total": totals,
        "issues": sorted(set(campaign_issues)),
        "valid": not campaign_issues,
    }


def write_outputs(out_dir: Path, summary: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty audit directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "campaign_conservation_audit.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    rows = []
    for target in summary["targets"]:
        row = dict(target)
        row["analysis_versions"] = json.dumps(row["analysis_versions"])
        row["stderr"] = json.dumps(row["stderr"], sort_keys=True)
        row["issues"] = json.dumps(row["issues"])
        rows.append(row)
    if rows:
        with (out_dir / "campaign_conservation_per_target.csv").open(
            "w", newline="", encoding="utf-8"
        ) as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
    lines = [
        "# TSDS campaign conservation audit",
        "",
        f"Valid: **{summary['valid']}**",
        f"Targets: **{summary['total']['targets']}**",
        f"Candidate closures: **{summary['total']['candidate_closures']}**",
        f"Selected records: **{summary['total']['selected_closures']}**",
        f"JSONL records: **{summary['total']['jsonl_records']}**",
        f"Ledger records: **{summary['total']['ledger_records']}**",
        f"Duplicate identities: **{summary['total']['duplicate_identities']}**",
        "Benign structured stderr lines: "
        f"**{summary['total']['benign_structured_stderr_lines']}**",
        f"Unexpected stderr lines: **{summary['total']['unexpected_stderr_lines']}**",
        "",
        "Every paper-facing record must be conserved across JSONL, target "
        "summary, verdict ledger, and campaign aggregate. Only exact angr "
        "posix.syslog INFO records are non-fatal stderr metadata; every other "
        "stderr line is a conservation failure.",
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--expected-targets", type=int)
    parser.add_argument("--require-resource-metrics", action="store_true")
    parser.add_argument("--fail-on-issues", action="store_true")
    args = parser.parse_args()
    summary = audit_campaign(
        args.campaign_dir,
        expected_targets=args.expected_targets,
        require_resource_metrics=args.require_resource_metrics,
    )
    write_outputs(args.out_dir, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.fail_on_issues and not summary["valid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
