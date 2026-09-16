#!/usr/bin/env python3
"""Validate a normalized front-end candidate corpus and emit a neutral ledger."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.candidate_contract import audit_candidate_document  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--require-valid", action="store_true")
    args = parser.parse_args()
    raw = args.input.read_bytes()
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError("candidate document is not an object")
    rows, summary = audit_candidate_document(document)
    summary["input"] = {
        "path": str(args.input.resolve()),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"output directory is non-empty: {out_dir}", file=sys.stderr)
        return 3
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "normalized_candidates.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        fields = list(rows[0]) if rows else ["candidate_id"]
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "candidate_contract_audit.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.require_valid and not summary["valid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
