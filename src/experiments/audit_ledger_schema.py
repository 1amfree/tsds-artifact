#!/usr/bin/env python3
"""Validate v16+ TSDS ledger structure independently of the evaluator."""

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

from tsds.ledger_schema import schema_summary, validate_ledger_record  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--fail-on-issues", action="store_true")
    args = parser.parse_args()
    paths = sorted(args.input_dir.resolve().glob("*.results.jsonl"))
    if not paths:
        print("no campaign JSONL files found", file=sys.stderr)
        return 2
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to reuse non-empty output directory: {out_dir}", file=sys.stderr)
        return 3
    out_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for path in paths:
        target = path.name.removesuffix(".results.jsonl")
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            records.append(record)
            rows.append({
                "target": target,
                "closure_idx": record.get("closure_idx"),
                "status": record.get("status"),
                "analysis_version": record.get("analysis_version"),
                "issues": ";".join(validate_ledger_record(record)),
            })
    summary = schema_summary(records)
    with (out_dir / "ledger_schema_records.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["target", "closure_idx", "status", "analysis_version", "issues"], lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "ledger_schema_audit.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "README.md").write_text("# TSDS ledger schema audit\n\n" + summary["claim_boundary"] + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.fail_on_issues and summary["records_with_issues"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
