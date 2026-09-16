#!/usr/bin/env python3
"""Compare two independently generated replay receipt streams.

The comparison is deliberately narrower than solver validation: it checks
that the two external replay runs cover the same manifest/kind pairs and emit
the same observed status.  It does not turn agreement into device-level
validity.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def _load(path: Path) -> tuple[dict[str, dict[str, dict[str, Any]]], list[str]]:
    entries: dict[str, dict[str, dict[str, Any]]] = {}
    issues: list[str] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            try:
                receipt = json.loads(line)
            except json.JSONDecodeError:
                issues.append(f"line_{line_number}_invalid_json")
                continue
            if not isinstance(receipt, dict):
                issues.append(f"line_{line_number}_not_object")
                continue
            manifest = receipt.get("manifest")
            if not isinstance(manifest, str) or not manifest:
                issues.append(f"line_{line_number}_missing_manifest")
                continue
            if manifest in entries:
                issues.append(f"duplicate_manifest:{manifest}")
                continue
            rows: dict[str, dict[str, Any]] = {}
            for row_index, row in enumerate(receipt.get("replays", [])):
                if not isinstance(row, dict):
                    issues.append(f"{manifest}:row_{row_index}_not_object")
                    continue
                kind = row.get("kind")
                if not isinstance(kind, str) or not kind:
                    issues.append(f"{manifest}:row_{row_index}_missing_kind")
                    continue
                if kind in rows:
                    issues.append(f"{manifest}:duplicate_kind:{kind}")
                    continue
                rows[kind] = row
            entries[manifest] = rows
    return entries, issues


def compare(left_path: Path, right_path: Path) -> dict[str, Any]:
    left, left_issues = _load(left_path)
    right, right_issues = _load(right_path)
    paired = 0
    observed_agreement = 0
    observed_disagreement = 0
    expected_disagreement = 0
    missing_left = 0
    missing_right = 0
    status_pairs: Counter[str] = Counter()

    for manifest in sorted(set(left) | set(right)):
        left_rows = left.get(manifest, {})
        right_rows = right.get(manifest, {})
        for kind in sorted(set(left_rows) | set(right_rows)):
            left_row = left_rows.get(kind)
            right_row = right_rows.get(kind)
            if left_row is None:
                missing_left += 1
                continue
            if right_row is None:
                missing_right += 1
                continue
            paired += 1
            left_observed = left_row.get("observed")
            right_observed = right_row.get("observed")
            status_pairs[f"{left_observed}|{right_observed}"] += 1
            if left_observed == right_observed:
                observed_agreement += 1
            else:
                observed_disagreement += 1
            if left_row.get("expected") != right_row.get("expected"):
                expected_disagreement += 1

    issues = [*left_issues, *right_issues]
    valid = not issues and not missing_left and not missing_right and not expected_disagreement and not observed_disagreement
    return {
        "schema": "tsds-solver-cross-replay-v1",
        "left_receipt_file": str(left_path),
        "right_receipt_file": str(right_path),
        "left_manifest_count": len(left),
        "right_manifest_count": len(right),
        "paired_replay_count": paired,
        "observed_agreement_count": observed_agreement,
        "observed_disagreement_count": observed_disagreement,
        "expected_disagreement_count": expected_disagreement,
        "missing_left_count": missing_left,
        "missing_right_count": missing_right,
        "status_pairs": dict(sorted(status_pairs.items())),
        "issues": sorted(set(issues)),
        "valid": valid,
        "claim_boundary": (
            "Cross-replay agreement checks coverage and observed solver status between two "
            "external runs. It does not prove source realizability, solver soundness, or "
            "device-level exploitability."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--left", type=Path, required=True)
    parser.add_argument("--right", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.left, args.right)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
