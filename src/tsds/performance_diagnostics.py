"""Distribution-aware performance diagnostics for per-closure TSDS workers."""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from typing import Any, Iterable, Mapping, Sequence


PERFORMANCE_SCHEMA = "tsds-performance-diagnostics-v1"


def percentile(values: Sequence[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(float(value) for value in values)
    position = probability * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def distribution(values: Iterable[float]) -> dict[str, Any]:
    rows = [float(value) for value in values if math.isfinite(float(value))]
    if not rows:
        return {
            "records": 0,
            "min": None,
            "p50": None,
            "p90": None,
            "p95": None,
            "p99": None,
            "max": None,
            "mean": None,
            "mad": None,
        }
    median = statistics.median(rows)
    mad = statistics.median(abs(value - median) for value in rows)
    return {
        "records": len(rows),
        "min": round(min(rows), 4),
        "p50": round(median, 4),
        "p90": round(percentile(rows, 0.90), 4),
        "p95": round(percentile(rows, 0.95), 4),
        "p99": round(percentile(rows, 0.99), 4),
        "max": round(max(rows), 4),
        "mean": round(statistics.mean(rows), 4),
        "mad": round(mad, 4),
    }


def _average_ranks(values: Sequence[float]) -> list[float]:
    ordered = sorted(enumerate(values), key=lambda item: item[1])
    ranks = [0.0] * len(values)
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][1] == ordered[index][1]:
            end += 1
        rank = (index + 1 + end) / 2.0
        for offset in range(index, end):
            ranks[ordered[offset][0]] = rank
        index = end
    return ranks


def spearman_correlation(pairs: Iterable[tuple[float, float]]) -> float | None:
    rows = [
        (float(left), float(right))
        for left, right in pairs
        if math.isfinite(float(left)) and math.isfinite(float(right))
    ]
    if len(rows) < 3:
        return None
    left_ranks = _average_ranks([left for left, _ in rows])
    right_ranks = _average_ranks([right for _, right in rows])
    left_mean = statistics.mean(left_ranks)
    right_mean = statistics.mean(right_ranks)
    numerator = sum(
        (left - left_mean) * (right - right_mean)
        for left, right in zip(left_ranks, right_ranks)
    )
    denominator = math.sqrt(
        sum((value - left_mean) ** 2 for value in left_ranks)
        * sum((value - right_mean) ** 2 for value in right_ranks)
    )
    return round(numerator / denominator, 4) if denominator else None


def _number(record: Mapping[str, Any], key: str) -> float | None:
    try:
        value = float(record.get(key))
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) and value >= 0 else None


def _group_summary(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    elapsed = [value for row in records if (value := _number(row, "elapsed_sec")) is not None]
    rss = [value for row in records if (value := _number(row, "process_peak_rss_mib")) is not None]
    steps = [value for row in records if (value := _number(row, "engine_steps_total")) is not None]
    return {
        "records": len(records),
        "elapsed_sec": distribution(elapsed),
        "peak_rss_mib": distribution(rss),
        "engine_steps_total": distribution(steps),
    }


def summarize_performance(
    records: Iterable[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = [dict(record) for record in records]
    elapsed_values = [
        value for row in rows if (value := _number(row, "elapsed_sec")) is not None
    ]
    rss_values = [
        value for row in rows if (value := _number(row, "process_peak_rss_mib")) is not None
    ]
    elapsed_p95 = percentile(elapsed_values, 0.95)
    rss_p95 = percentile(rss_values, 0.95)
    tails = []
    for row in rows:
        elapsed = _number(row, "elapsed_sec")
        rss = _number(row, "process_peak_rss_mib")
        elapsed_tail = elapsed is not None and elapsed_p95 is not None and elapsed >= elapsed_p95
        rss_tail = rss is not None and rss_p95 is not None and rss >= rss_p95
        if elapsed_tail or rss_tail:
            tails.append(
                {
                    "target": row.get("_target") or row.get("target"),
                    "closure_idx": row.get("closure_idx"),
                    "verdict": row.get("verdict"),
                    "engine_stop_reason": row.get("engine_stop_reason"),
                    "elapsed_sec": elapsed,
                    "process_peak_rss_mib": rss,
                    "engine_steps_total": _number(row, "engine_steps_total"),
                    "elapsed_tail": elapsed_tail,
                    "rss_tail": rss_tail,
                }
            )
    grouped_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    grouped_verdict: dict[str, list[dict[str, Any]]] = defaultdict(list)
    grouped_provenance: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped_target[str(row.get("_target") or row.get("target") or "unknown")].append(row)
        grouped_verdict[str(row.get("verdict") or "unknown")].append(row)
        grouped_provenance[str(row.get("evidence_provenance") or "unknown")].append(row)

    elapsed_steps = []
    elapsed_rss = []
    steps_rss = []
    for row in rows:
        elapsed = _number(row, "elapsed_sec")
        rss = _number(row, "process_peak_rss_mib")
        steps = _number(row, "engine_steps_total")
        if elapsed is not None and steps is not None:
            elapsed_steps.append((elapsed, steps))
        if elapsed is not None and rss is not None:
            elapsed_rss.append((elapsed, rss))
        if steps is not None and rss is not None:
            steps_rss.append((steps, rss))
    missing = Counter()
    structurally_not_applicable = Counter()
    for row in rows:
        for key in ("elapsed_sec", "process_peak_rss_mib"):
            if _number(row, key) is None:
                missing[key] += 1
        if _number(row, "engine_steps_total") is None:
            if str(row.get("verdict") or "") == "STATIC_WARNING_REDUCTION":
                structurally_not_applicable["engine_steps_total"] += 1
            else:
                missing["engine_steps_total"] += 1
    limits = Counter(str(row.get("subprocess_memory_limit_mib") or "missing") for row in rows)
    hits = sum(bool(row.get("resource_limit_hit")) for row in rows)
    summary = {
        "schema": PERFORMANCE_SCHEMA,
        "records": len(rows),
        "overall": _group_summary(rows),
        "per_target": {key: _group_summary(value) for key, value in sorted(grouped_target.items())},
        "per_verdict": {key: _group_summary(value) for key, value in sorted(grouped_verdict.items())},
        "per_provenance": {key: _group_summary(value) for key, value in sorted(grouped_provenance.items())},
        "tail_thresholds": {
            "elapsed_p95_sec": round(elapsed_p95, 4) if elapsed_p95 is not None else None,
            "rss_p95_mib": round(rss_p95, 4) if rss_p95 is not None else None,
        },
        "tail_records": len(tails),
        "tail_by_verdict": dict(sorted(Counter(str(row["verdict"]) for row in tails).items())),
        "rank_correlations": {
            "elapsed_vs_steps": spearman_correlation(elapsed_steps),
            "elapsed_vs_rss": spearman_correlation(elapsed_rss),
            "steps_vs_rss": spearman_correlation(steps_rss),
        },
        "missing_metrics": dict(sorted(missing.items())),
        "structurally_not_applicable_metrics": dict(
            sorted(structurally_not_applicable.items())
        ),
        "memory_limit_mib_counts": dict(sorted(limits.items())),
        "resource_limit_hits": hits,
        "timeout_records": sum(str(row.get("status") or "") == "timeout" for row in rows),
        "total_worker_elapsed_sec": round(sum(elapsed_values), 4),
        "claim_boundary": (
            "Metrics describe per-closure worker observations under the recorded resource envelope; "
            "they are not a cross-tool performance comparison."
        ),
    }
    return tails, summary
