#!/usr/bin/env python3
"""Summarize shell-differential outcomes without reclassifying failures."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def analyze(path: Path) -> dict[str, Any]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    shared_rejections: list[dict[str, Any]] = []
    disagreements: list[dict[str, Any]] = []
    fail_by_vector: Counter[str] = Counter()
    fail_by_context: Counter[str] = Counter()
    for row in rows:
        results = row.get("shell_results") or []
        statuses = [str(item.get("status") or "UNKNOWN") for item in results]
        if row.get("status") == "FAIL":
            parts = str(row.get("probe_id") or "").split(":")
            if parts:
                fail_by_vector[parts[0]] += 1
            if len(parts) > 1:
                fail_by_context[parts[1]] += 1
            if results and all(status == "FAIL" for status in statuses):
                shared_rejections.append({
                    "probe_id": row.get("probe_id"),
                    "shell_statuses": statuses,
                    "returncodes": [item.get("returncode") for item in results],
                })
        if len(set(statuses)) > 1:
            disagreements.append({"probe_id": row.get("probe_id"), "shell_statuses": statuses})
    return {
        "schema": "tsds-shell-differential-analysis-v1",
        "input": str(path),
        "probe_count": len(rows),
        "status_counts": dict(sorted(Counter(str(row.get("status") or "UNKNOWN") for row in rows).items())),
        "fail_count": sum(row.get("status") == "FAIL" for row in rows),
        "shared_rejection_count": len(shared_rejections),
        "shell_status_disagreement_count": len(disagreements),
        "fail_by_vector": dict(sorted(fail_by_vector.items())),
        "fail_by_context": dict(sorted(fail_by_context.items())),
        "shared_rejection_examples": shared_rejections[:10],
        "disagreement_examples": disagreements[:10],
        "interpretation": (
            "The reported FAIL rows are preserved as failures. In this receipt, "
            "a shared rejection means every requested shell rejected the same "
            "probe; it is not reclassified as PASS or as a dialect agreement."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.input)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("probe_count", "fail_count", "shared_rejection_count", "shell_status_disagreement_count")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
