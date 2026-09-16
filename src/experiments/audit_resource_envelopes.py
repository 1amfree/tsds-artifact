#!/usr/bin/env python3
"""Audit per-closure TSDS resource metrics from campaign JSONL ledgers."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.resource_envelopes import (  # noqa: E402
    envelope_violations,
    record_resource_view,
    summarize_resource_envelope,
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
            if isinstance(row, dict):
                rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--require-per-record-rss", action="store_true")
    parser.add_argument("--require-memory-limit-enforced", action="store_true")
    parser.add_argument("--fail-on-resource-limit-hits", action="store_true")
    parser.add_argument("--fail-on-unavailable-worker-metrics", action="store_true")
    parser.add_argument("--max-p95-rss-mib", type=float)
    parser.add_argument("--max-p95-elapsed-sec", type=float)
    parser.add_argument("--fail-on-issues", action="store_true")
    args = parser.parse_args()

    paths = sorted(args.input_dir.resolve().glob("*.results.jsonl"))
    if not paths:
        print(f"no campaign JSONL files found in {args.input_dir}", file=sys.stderr)
        return 2
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to reuse non-empty output directory: {out_dir}", file=sys.stderr)
        return 3
    out_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    resource_rows: list[dict[str, Any]] = []
    for path in paths:
        target = path.name.removesuffix(".results.jsonl")
        for record in load_jsonl(path):
            row = record_resource_view(record)
            row["target"] = target
            resource_rows.append(row)
            rows.append(record)
    summary = summarize_resource_envelope(rows)
    summary["input_files"] = [str(path) for path in paths]
    issues = envelope_violations(
        summary,
        require_per_record_rss=args.require_per_record_rss,
        require_memory_limit_enforced=args.require_memory_limit_enforced,
        fail_on_resource_limit_hits=args.fail_on_resource_limit_hits,
        fail_on_unavailable_worker_metrics=args.fail_on_unavailable_worker_metrics,
        max_p95_rss_mib=args.max_p95_rss_mib,
        max_p95_elapsed_sec=args.max_p95_elapsed_sec,
    )
    summary["issues"] = issues
    with (out_dir / "resource_envelope_records.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = [
            "target", "closure_idx", "status", "memoized", "elapsed_sec", "peak_rss_mib",
            "user_cpu_sec", "system_cpu_sec", "resource_limit_mib", "resource_limit_enforcement",
            "resource_limit_hit", "resource_metric_scope",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(resource_rows)
    (out_dir / "resource_envelope_audit.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        "# TSDS resource envelope audit\n\n"
        f"Records: **{summary['records']}**; records with per-closure RSS: "
        f"**{summary['records_with_rss']}**; issues: **{len(issues)}**.\n\n"
        + summary["claim_boundary"]
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.fail_on_issues and issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
