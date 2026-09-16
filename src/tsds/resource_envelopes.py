"""Resource-envelope accounting for isolated TSDS closure analyses.

The functions are intentionally pure and operate on serialized records.  The
evaluator can emit per-closure peak RSS/CPU fields, while this module turns
them into an auditable admission and regression envelope.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any, Iterable, Mapping


RESOURCE_ENVELOPE_SCHEMA = "tsds-resource-envelope-v1"


def _float(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and number >= 0 else None


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    if len(values) == 1:
        return values[0]
    rank = (len(values) - 1) * percentile
    low = int(math.floor(rank))
    high = int(math.ceil(rank))
    if low == high:
        return values[low]
    fraction = rank - low
    return values[low] * (1.0 - fraction) + values[high] * fraction


def record_resource_view(record: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize resource fields emitted by the isolated closure process."""

    record = record or {}
    rss_kb = _float(record.get("process_peak_rss_kb"))
    if rss_kb is None:
        rss_mib = _float(record.get("process_peak_rss_mib"))
    else:
        rss_mib = rss_kb / 1024.0
    return {
        "closure_idx": record.get("closure_idx"),
        "status": record.get("status"),
        "memoized": bool(record.get("memoized")),
        "elapsed_sec": _float(record.get("elapsed_sec")),
        "peak_rss_mib": rss_mib,
        "user_cpu_sec": _float(record.get("process_user_cpu_sec")),
        "system_cpu_sec": _float(record.get("process_system_cpu_sec")),
        "resource_limit_mib": _float(record.get("subprocess_memory_limit_mib")),
        "resource_limit_enforcement": str(record.get("resource_limit_enforcement") or "missing"),
        "resource_limit_hit": bool(record.get("resource_limit_hit")),
        "resource_metric_scope": str(record.get("process_resource_metric_scope") or "worker_recorded"),
    }


def summarize_resource_envelope(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = [record_resource_view(record) for record in records or []]
    executed_rows = [row for row in rows if not row.get("memoized")]
    rss = [row["peak_rss_mib"] for row in executed_rows if row["peak_rss_mib"] is not None]
    elapsed = [row["elapsed_sec"] for row in executed_rows if row["elapsed_sec"] is not None]
    cpu = [
        (row["user_cpu_sec"] or 0.0) + (row["system_cpu_sec"] or 0.0)
        for row in executed_rows
        if row["user_cpu_sec"] is not None or row["system_cpu_sec"] is not None
    ]
    statuses = Counter(str(row.get("status") or "unknown") for row in rows)
    unavailable_worker_metrics = [
        row for row in rows
        if row.get("resource_metric_scope") == "unavailable_worker_terminated"
    ]
    required_rss = [
        row for row in rows
        if not row.get("memoized")
        and row.get("resource_metric_scope") != "unavailable_worker_terminated"
    ]
    missing_required_rss = sum(1 for row in required_rss if row["peak_rss_mib"] is None)
    limit_requested = [
        row for row in executed_rows if (row.get("resource_limit_mib") or 0.0) > 0.0
    ]
    limit_not_enforced = [
        row for row in limit_requested if row.get("resource_limit_enforcement") != "enforced"
    ]
    enforcement = Counter(str(row.get("resource_limit_enforcement") or "missing") for row in rows)
    return {
        "schema": RESOURCE_ENVELOPE_SCHEMA,
        "records": len(rows),
        "records_with_rss": len(rss),
        "records_requiring_rss": len(required_rss),
        "records_missing_required_rss": missing_required_rss,
        "records_with_unavailable_worker_metrics": len(unavailable_worker_metrics),
        "records_with_elapsed": len(elapsed),
        "records_with_cpu": len(cpu),
        "peak_rss_mib": round(max(rss), 4) if rss else None,
        "p50_rss_mib": round(_percentile(rss, 0.50), 4) if rss else None,
        "p95_rss_mib": round(_percentile(rss, 0.95), 4) if rss else None,
        "p50_elapsed_sec": round(_percentile(elapsed, 0.50), 4) if elapsed else None,
        "p95_elapsed_sec": round(_percentile(elapsed, 0.95), 4) if elapsed else None,
        "p95_cpu_sec": round(_percentile(cpu, 0.95), 4) if cpu else None,
        "resource_limit_hits": sum(1 for row in rows if row["resource_limit_hit"]),
        "records_with_memory_limit_requested": len(limit_requested),
        "records_with_memory_limit_enforced": len(limit_requested) - len(limit_not_enforced),
        "records_with_memory_limit_not_enforced": len(limit_not_enforced),
        "resource_limit_enforcement_counts": dict(sorted(enforcement.items())),
        "status_counts": dict(sorted(statuses.items())),
        "claim_boundary": (
            "Resource metrics describe analyzer cost and isolation behavior; "
            "they do not establish semantic completeness or exploitability."
        ),
    }


def envelope_violations(
    summary: Mapping[str, Any],
    *,
    require_per_record_rss: bool = False,
    require_memory_limit_enforced: bool = False,
    fail_on_resource_limit_hits: bool = False,
    fail_on_unavailable_worker_metrics: bool = False,
    max_p95_rss_mib: float | None = None,
    max_p95_elapsed_sec: float | None = None,
) -> list[str]:
    """Evaluate optional experiment-budget gates without inventing a budget."""

    summary = summary or {}
    issues: list[str] = []
    if require_per_record_rss and int(summary.get("records_missing_required_rss") or 0):
        issues.append("missing_per_record_rss")
    if require_memory_limit_enforced:
        requested = int(summary.get("records_with_memory_limit_requested") or 0)
        executed = int(summary.get("records_requiring_rss") or 0)
        not_enforced = int(summary.get("records_with_memory_limit_not_enforced") or 0)
        if requested != executed:
            issues.append("memory_limit_not_requested_for_all_executed_records")
        if not_enforced:
            issues.append("memory_limit_not_enforced")
    if fail_on_resource_limit_hits and int(summary.get("resource_limit_hits") or 0):
        issues.append("resource_limit_hit")
    if fail_on_unavailable_worker_metrics and int(summary.get("records_with_unavailable_worker_metrics") or 0):
        issues.append("unavailable_worker_resource_metrics")
    p95_rss = _float(summary.get("p95_rss_mib"))
    p95_elapsed = _float(summary.get("p95_elapsed_sec"))
    if max_p95_rss_mib is not None and (p95_rss is None or p95_rss > max_p95_rss_mib):
        issues.append("p95_rss_budget_exceeded")
    if max_p95_elapsed_sec is not None and (p95_elapsed is None or p95_elapsed > max_p95_elapsed_sec):
        issues.append("p95_elapsed_budget_exceeded")
    return issues
