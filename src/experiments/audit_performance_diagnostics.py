#!/usr/bin/env python3
"""Export distribution- and tail-aware diagnostics from a TSDS campaign."""

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

from tsds.performance_diagnostics import summarize_performance  # noqa: E402


def load_records(campaign: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(campaign.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        with path.open("r", encoding="utf-8") as stream:
            for line_no, line in enumerate(stream, 1):
                if line.strip():
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ValueError(f"{path}:{line_no}: record is not an object")
                    row["_target"] = target
                    rows.append(row)
    if not rows:
        raise ValueError(f"no campaign records under {campaign}")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--expected-records", type=int)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    records = load_records(args.campaign.resolve())
    tails, summary = summarize_performance(records)
    issues = []
    if args.expected_records is not None and len(records) != args.expected_records:
        issues.append(f"record_count_mismatch:{len(records)}!={args.expected_records}")
    if summary["missing_metrics"]:
        issues.append("worker_metrics_missing")
    if summary["resource_limit_hits"]:
        issues.append("resource_limit_hits_observed")
    summary["issues"] = issues
    summary["valid"] = bool(records) and not issues
    summary["campaign"] = str(args.campaign.resolve())
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"output directory is non-empty: {out_dir}", file=sys.stderr)
        return 3
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "performance_tail_records.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        fields = list(tails[0]) if tails else ["target", "closure_idx"]
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(tails)
    (out_dir / "performance_diagnostics.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.require_complete and not summary["valid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
