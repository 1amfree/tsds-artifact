#!/usr/bin/env python3
"""Audit TSDS v1 evidence-scope records and abstention-aware statistics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tsds.evidence_scope import conservation_summary


def load_records(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".jsonl":
        values = [json.loads(line) for line in raw.splitlines() if line.strip()]
    else:
        values = json.loads(raw)
    if not isinstance(values, list):
        raise ValueError("input must contain a JSON list or JSONL records")
    if any(not isinstance(value, dict) for value in values):
        raise ValueError("every evidence-scope row must be a JSON object")
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-total", type=int)
    args = parser.parse_args()
    try:
        summary = conservation_summary(
            load_records(args.input), expected_total=args.expected_total
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.output.exists():
            raise ValueError(f"refusing to overwrite output: {args.output}")
        args.output.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"EVIDENCE_SCOPE_AUDIT_ERROR: {exc}")
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
