#!/usr/bin/env python3
"""Independently verify replay-receipt accounting against its summary.

This checker does not run a solver.  It validates that a replay receipt stream
is well formed and that its published counts are exactly derivable from the
receipts, keeping solver execution, receipt accounting, and semantic claims as
separate evidence layers.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


COMPARISONS = ("MATCH", "MISMATCH", "UNKNOWN", "NOT_APPLICABLE")
STATUSES = ("OK", "UNKNOWN", "UNAVAILABLE")


def _load_receipts(path: Path) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: receipt is not an object")
        receipts.append(value)
    return receipts


def verify(receipts_path: Path, summary_path: Path) -> dict[str, Any]:
    receipts = _load_receipts(receipts_path)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if not isinstance(summary, dict):
        raise ValueError("summary is not an object")

    issues: list[str] = []
    all_replays: list[dict[str, Any]] = []
    invalid_receipts = 0
    manifest_ids: set[str] = set()
    for index, receipt in enumerate(receipts):
        if receipt.get("status") != "OK" or receipt.get("issues"):
            invalid_receipts += 1
            issues.append(f"receipt_{index}_not_ok")
        manifest = str(receipt.get("manifest") or "")
        if not manifest:
            issues.append(f"receipt_{index}_manifest_missing")
        if manifest in manifest_ids:
            issues.append(f"receipt_{index}_duplicate_manifest")
        manifest_ids.add(manifest)
        replays = receipt.get("replays")
        if not isinstance(replays, list) or not replays:
            issues.append(f"receipt_{index}_replays_missing")
            continue
        for replay in replays:
            if not isinstance(replay, dict):
                issues.append(f"receipt_{index}_replay_not_object")
                continue
            all_replays.append(replay)

    comparison_counts = Counter(str(row.get("comparison") or "") for row in all_replays)
    status_counts = Counter(str(row.get("status") or "") for row in all_replays)
    model_comparison_counts = Counter(
        str((row.get("model_check") or {}).get("comparison") or "")
        for row in all_replays
        if isinstance(row.get("model_check"), dict)
    )
    observed_comparison_counts = {
        key: int(comparison_counts.get(key, 0)) for key in COMPARISONS
    }
    observed_status_counts = {key: int(status_counts.get(key, 0)) for key in STATUSES}
    observed_model_counts = {
        key: int(model_comparison_counts.get(key, 0)) for key in COMPARISONS
    }
    if len(receipts) != int(summary.get("manifest_count") or 0):
        issues.append("manifest_count_disagrees")
    if len(all_replays) != int(summary.get("replay_count") or 0):
        issues.append("replay_count_disagrees")
    if invalid_receipts != int(summary.get("invalid_manifest_count") or 0):
        issues.append("invalid_manifest_count_disagrees")
    if observed_comparison_counts != summary.get("comparison_counts"):
        issues.append("comparison_counts_disagree")
    if observed_status_counts != summary.get("status_counts"):
        issues.append("status_counts_disagree")
    if observed_model_counts != summary.get("model_comparison_counts"):
        issues.append("model_comparison_counts_disagree")

    return {
        "schema": "tsds-replay-receipt-verification-v1",
        "receipts": str(receipts_path),
        "summary": str(summary_path),
        "receipt_count": len(receipts),
        "replay_count": len(all_replays),
        "invalid_receipt_count": invalid_receipts,
        "comparison_counts": observed_comparison_counts,
        "status_counts": observed_status_counts,
        "model_comparison_counts": observed_model_counts,
        "issues": sorted(set(issues)),
        "valid": not issues,
        "claim_boundary": (
            "This checker validates receipt accounting and does not establish "
            "solver soundness, source realizability, or device exploitability."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipts", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.receipts, args.summary)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"REPLAY_RECEIPT_VERIFICATION_ERROR: {exc}")
        return 2
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
