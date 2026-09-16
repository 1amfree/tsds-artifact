#!/usr/bin/env python3
"""Audit TSDS vector decisions against conservative shell-dialect profiles."""

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

from tsds.shell_dialects import DIALECTS, audit_records  # noqa: E402


def load_records(input_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(input_dir.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            record["target"] = target
            records.append(record)
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--dialect", action="append", default=[])
    parser.add_argument("--fail-on-sat-issues", action="store_true")
    args = parser.parse_args()
    selected = args.dialect or list(DIALECTS)
    unknown = sorted(set(selected) - set(DIALECTS))
    if unknown:
        print(f"unknown dialect profile(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    records = load_records(args.input_dir.resolve())
    if not records:
        print("no campaign JSONL records found", file=sys.stderr)
        return 2
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to reuse non-empty output directory: {out_dir}", file=sys.stderr)
        return 3
    out_dir.mkdir(parents=True, exist_ok=True)
    rows, summary = audit_records(records, selected)
    with (out_dir / "shell_dialect_profile_records.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = [
            "closure_idx", "status", "dialect", "vector_id", "decision",
            "quote_context", "effective_quote_context", "witness_kind",
            "lexically_active", "portable_sat", "issues",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows([{**row, "issues": ";".join(row["issues"])} for row in rows])
    (out_dir / "shell_dialect_profile_audit.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        "# TSDS shell dialect profile audit\n\n" + summary["claim_boundary"] + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    sat_issues = int(summary["outcomes"].get("sat_issue", 0))
    return 2 if args.fail_on_sat_issues and sat_issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
