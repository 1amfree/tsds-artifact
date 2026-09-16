#!/usr/bin/env python3
"""Build a reproducible performance and resource ledger for one TSDS campaign.

This is an evidence-only postprocessor.  It reports analyzer cost and resource
observations from serialized campaign records; it does not infer semantic
completeness, source realizability, exploitability, or concurrent scalability.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

# Permit both ``python -m`` and direct script invocation from any directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.performance_diagnostics import summarize_performance
from tsds.resource_envelopes import summarize_resource_envelope


SCHEMA = "tsds-current-campaign-performance-v1"
CLAIM_BOUNDARY = (
    "Descriptive accounting of the recorded per-closure analyzer run and its "
    "resource envelope.  The aggregate rate is an amortized sequential "
    "campaign rate, not a concurrent throughput benchmark.  These observations "
    "do not establish semantic completeness, source realizability, firmware "
    "ground truth, or device-level exploitability."
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def load_jsonl(path: Path, target: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_no}: expected a JSON object")
        row = dict(value)
        row["_target"] = target
        row["_source_path"] = path.as_posix()
        row["_source_line"] = line_no
        rows.append(row)
    return rows


def target_name_for_results(path: Path) -> str:
    suffix = ".results.jsonl"
    if not path.name.endswith(suffix):
        raise ValueError(f"unexpected results filename: {path}")
    return path.name[: -len(suffix)]


def find_summary(results_path: Path, target: str) -> Path:
    local = results_path.with_name(f"{target}.summary.json")
    if local.is_file():
        return local
    candidates = sorted(results_path.parent.rglob(f"{target}.summary.json"))
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise FileNotFoundError(f"no summary found for {results_path}")
    raise ValueError(f"multiple summaries found for {results_path}: {candidates}")


def finite_nonnegative(value: Any, label: str, issues: list[str]) -> float | None:
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        issues.append(f"non_numeric:{label}")
        return None
    if not math.isfinite(number) or number < 0:
        issues.append(f"invalid_nonnegative:{label}")
        return None
    return number


def distribution(values: Iterable[float]) -> dict[str, float | int | None]:
    rows = sorted(float(value) for value in values)
    if not rows:
        return {
            "records": 0,
            "min": None,
            "p50": None,
            "p95": None,
            "max": None,
            "mean": None,
        }

    def percentile(probability: float) -> float:
        if len(rows) == 1:
            return rows[0]
        position = probability * (len(rows) - 1)
        lower = math.floor(position)
        upper = math.ceil(position)
        if lower == upper:
            return rows[lower]
        weight = position - lower
        return rows[lower] * (1.0 - weight) + rows[upper] * weight

    return {
        "records": len(rows),
        "min": round(rows[0], 4),
        "p50": round(percentile(0.50), 4),
        "p95": round(percentile(0.95), 4),
        "max": round(rows[-1], 4),
        "mean": round(statistics.mean(rows), 4),
    }


def compact_performance(summary: dict[str, Any]) -> dict[str, Any]:
    overall = summary.get("overall") or {}
    return {
        "records": int(summary.get("records") or 0),
        "elapsed_sec": overall.get("elapsed_sec") or {},
        "peak_rss_mib": overall.get("peak_rss_mib") or {},
        "engine_steps_total": overall.get("engine_steps_total") or {},
        "tail_thresholds": summary.get("tail_thresholds") or {},
        "tail_records": int(summary.get("tail_records") or 0),
        "tail_by_verdict": summary.get("tail_by_verdict") or {},
        "missing_metrics": summary.get("missing_metrics") or {},
        "structurally_not_applicable_metrics": (
            summary.get("structurally_not_applicable_metrics") or {}
        ),
        "memory_limit_mib_counts": summary.get("memory_limit_mib_counts") or {},
        "resource_limit_hits": int(summary.get("resource_limit_hits") or 0),
        "timeout_records": int(summary.get("timeout_records") or 0),
        "total_worker_elapsed_sec": float(summary.get("total_worker_elapsed_sec") or 0.0),
        "rank_correlations": summary.get("rank_correlations") or {},
    }


def target_row(
    campaign_dir: Path,
    results_path: Path,
    summary_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    target = target_name_for_results(results_path)
    rows = load_jsonl(results_path, target)
    summary = load_json(summary_path)
    issues: list[str] = []
    expected = int(summary.get("unique_pairs_analyzed") or 0)
    expected_input = int(summary.get("unique_pairs_expected") or 0)
    if expected != len(rows):
        issues.append(f"record_count_mismatch:{target}:{len(rows)}!={expected}")
    if expected_input and expected_input != expected:
        issues.append(f"summary_pair_count_mismatch:{target}:{expected_input}!={expected}")

    wall_time = finite_nonnegative(summary.get("wall_time_sec"), f"{target}.wall_time_sec", issues)
    elapsed = [
        value
        for row in rows
        if (value := finite_nonnegative(row.get("elapsed_sec"), f"{target}.elapsed_sec", issues))
        is not None
    ]
    worker_rss = [
        value
        for row in rows
        if (value := finite_nonnegative(row.get("process_peak_rss_mib"), f"{target}.rss", issues))
        is not None
    ]
    statuses = Counter(str(row.get("status") or "unknown") for row in rows)
    verdicts = Counter(str(row.get("verdict") or "unknown") for row in rows)
    matrix_records = sum(
        1
        for row in rows
        if int(row.get("solver_query_bundle_count") or 0) > 0
        or bool(row.get("vector_decisions") or row.get("threat_matrix_decisions"))
    )
    matrix_manifests = sum(int(row.get("solver_query_bundle_count") or 0) for row in rows)
    resource_ledger = summary.get("resource_limit_enforcement_ledger") or {}
    worker_summary = summarize_resource_envelope(rows)
    campaign_wall = wall_time or 0.0
    record_rate = len(rows) / campaign_wall if campaign_wall else None
    analysis_timer = sum(elapsed)
    return (
        {
            "target": target,
            "results_path": results_path.relative_to(campaign_dir).as_posix(),
            "summary_path": summary_path.relative_to(campaign_dir).as_posix(),
            "input_closures": int(summary.get("total_closures") or 0),
            "expected_records": expected,
            "records": len(rows),
            "closure_to_record_gap": max(0, int(summary.get("total_closures") or 0) - len(rows)),
            "wall_time_sec": round(campaign_wall, 4) if wall_time is not None else None,
            "amortized_records_per_wall_sec": round(record_rate, 8) if record_rate is not None else None,
            "amortized_records_per_wall_hour": round(record_rate * 3600.0, 4) if record_rate is not None else None,
            "record_timer_sec": round(analysis_timer, 4),
            "record_timer_coverage_pct": round(100.0 * analysis_timer / campaign_wall, 4)
            if campaign_wall
            else None,
            "orchestration_overhead_sec": round(max(0.0, campaign_wall - analysis_timer), 4)
            if wall_time is not None
            else None,
            "elapsed_sec": distribution(elapsed),
            "peak_rss_mib": distribution(worker_rss),
            "status_counts": dict(sorted(statuses.items())),
            "verdict_counts": dict(sorted(verdicts.items())),
            "matrix_profile_records": matrix_records,
            "matrix_query_manifest_count": matrix_manifests,
            "avg_closure_time_sec_from_summary": summary.get("avg_closure_time_sec"),
            "avg_matrix_time_sec_from_summary": summary.get("avg_matrix_time_sec"),
            "avg_engine_steps_from_summary": summary.get("avg_engine_steps"),
            "resource_limit": {
                "configured_limit_mib": resource_ledger.get("configured_limit_mib"),
                "executed_records": resource_ledger.get("executed_records"),
                "records_with_limit_requested": resource_ledger.get("records_with_limit_requested"),
                "records_with_limit_enforced": resource_ledger.get("records_with_limit_enforced"),
                "records_with_unavailable_worker_metrics": resource_ledger.get(
                    "records_with_unavailable_worker_metrics"
                ),
                "resource_limit_hits": resource_ledger.get("resource_limit_hits"),
                "all_executed_workers_enforced": resource_ledger.get(
                    "all_executed_workers_enforced"
                ),
            },
            "resource_observation_summary": worker_summary,
            "performance_diagnostics": compact_performance(
                summarize_performance(rows)[1]
            ),
        },
        rows,
        issues,
    )


def build_ledger(campaign_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    results_paths = sorted(campaign_dir.rglob("*.results.jsonl"))
    if not results_paths:
        raise ValueError(f"no results JSONL files under {campaign_dir}")
    target_rows: list[dict[str, Any]] = []
    all_rows: list[dict[str, Any]] = []
    issues: list[str] = []
    seen_targets: set[str] = set()
    source_files: list[dict[str, Any]] = []
    for results_path in results_paths:
        target = target_name_for_results(results_path)
        if target in seen_targets:
            issues.append(f"duplicate_target_results:{target}")
        seen_targets.add(target)
        summary_path = find_summary(results_path, target)
        row, records, row_issues = target_row(campaign_dir, results_path, summary_path)
        target_rows.append(row)
        all_rows.extend(records)
        issues.extend(row_issues)
        for path in (results_path, summary_path):
            source_files.append(
                {
                    "path": path.relative_to(campaign_dir).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )

    performance = summarize_performance(all_rows)[1]
    resource = summarize_resource_envelope(all_rows)
    campaign_wall = sum(float(row["wall_time_sec"] or 0.0) for row in target_rows)
    analysis_timer = sum(float(row["record_timer_sec"] or 0.0) for row in target_rows)
    total_records = len(all_rows)
    rate = total_records / campaign_wall if campaign_wall else None
    if sum(int(row["records"]) for row in target_rows) != total_records:
        issues.append("aggregate_record_count_mismatch")
    if any(int(row["records"]) != int(row["expected_records"]) for row in target_rows):
        issues.append("one_or_more_target_record_count_mismatches")

    aggregate = {
        "schema": SCHEMA,
        "campaign": str(campaign_dir.resolve()),
        "target_count": len(target_rows),
        "input_closures": sum(int(row["input_closures"]) for row in target_rows),
        "records": total_records,
        "closure_to_record_gap": sum(int(row["closure_to_record_gap"]) for row in target_rows),
        "campaign_wall_time_sec_sum": round(campaign_wall, 4),
        "amortized_records_per_wall_sec": round(rate, 8) if rate is not None else None,
        "amortized_records_per_wall_hour": round(rate * 3600.0, 4) if rate is not None else None,
        "record_timer_sec_sum": round(analysis_timer, 4),
        "record_timer_coverage_pct": round(100.0 * analysis_timer / campaign_wall, 4)
        if campaign_wall
        else None,
        "orchestration_overhead_sec_sum": round(max(0.0, campaign_wall - analysis_timer), 4),
        "status_counts": dict(sorted(Counter(str(row.get("status") or "unknown") for row in all_rows).items())),
        "verdict_counts": dict(sorted(Counter(str(row.get("verdict") or "unknown") for row in all_rows).items())),
        "matrix_profile_records": sum(int(row["matrix_profile_records"]) for row in target_rows),
        "matrix_query_manifest_count": sum(int(row["matrix_query_manifest_count"]) for row in target_rows),
        "elapsed_sec": performance.get("overall", {}).get("elapsed_sec") or {},
        "peak_rss_mib": performance.get("overall", {}).get("peak_rss_mib") or {},
        "engine_steps_total": performance.get("overall", {}).get("engine_steps_total") or {},
        "performance_diagnostics": compact_performance(performance),
        "resource_observation_summary": resource,
    }
    ledger = {
        "schema": SCHEMA,
        "claim_boundary": CLAIM_BOUNDARY,
        "campaign": aggregate,
        "targets": sorted(target_rows, key=lambda row: row["target"]),
        "source_files": sorted(source_files, key=lambda row: row["path"]),
        "issues": sorted(set(issues)),
        "valid": not issues,
    }
    return ledger, all_rows, issues


def write_outputs(out_dir: Path, ledger: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "current_campaign_performance.json").write_text(
        json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (out_dir / "current_campaign_performance_by_target.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        fields = [
            "target",
            "input_closures",
            "expected_records",
            "records",
            "closure_to_record_gap",
            "wall_time_sec",
            "amortized_records_per_wall_hour",
            "record_timer_coverage_pct",
            "matrix_profile_records",
            "matrix_query_manifest_count",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(
            {field: row.get(field) for field in fields}
            for row in ledger["targets"]
        )
    with (out_dir / "current_campaign_resource_records.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        fields = [
            "target",
            "closure_idx",
            "status",
            "verdict",
            "elapsed_sec",
            "process_peak_rss_mib",
            "process_resource_metric_scope",
            "subprocess_memory_limit_mib",
            "resource_limit_enforcement",
            "resource_limit_hit",
            "engine_steps_total",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})
    (out_dir / "README.md").write_text(
        "# Current TSDS campaign performance ledger\n\n"
        "This directory contains evidence-only accounting generated from the "
        "current eight-target campaign.\n\n"
        f"{ledger['claim_boundary']}\n\n"
        f"Validation issues: **{len(ledger['issues'])}**; valid: **{ledger['valid']}**.\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    campaign = args.campaign.resolve()
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(f"refusing to reuse non-empty output directory: {out_dir}")
    ledger, rows, _ = build_ledger(campaign)
    write_outputs(out_dir, ledger, rows)
    print(json.dumps(ledger, indent=2, sort_keys=True))
    return 0 if ledger["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
