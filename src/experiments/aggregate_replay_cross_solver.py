#!/usr/bin/env python3
"""Aggregate per-target cross-solver replay comparisons."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from .compare_replay_receipts import compare
except ImportError:  # pragma: no cover - exercised by the script entrypoint
    from compare_replay_receipts import compare


def aggregate(pairs: dict[str, tuple[Path, Path]]) -> dict[str, Any]:
    results = {name: compare(left, right) for name, (left, right) in sorted(pairs.items())}
    totals: Counter[str] = Counter()
    for result in results.values():
        for key in (
            "paired_replay_count",
            "observed_agreement_count",
            "observed_disagreement_count",
            "expected_disagreement_count",
            "missing_left_count",
            "missing_right_count",
        ):
            totals[key] += int(result[key])
    return {
        "schema": "tsds-solver-cross-replay-aggregate-v1",
        "target_count": len(results),
        "targets": results,
        "totals": dict(sorted(totals.items())),
        "valid": all(result["valid"] for result in results.values()),
        "claim_boundary": (
            "This aggregate checks manifest/kind coverage and observed-status agreement "
            "between external solver runs for each listed target. It does not prove "
            "source realizability, solver soundness, or device-level exploitability."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--pair",
        action="append",
        required=True,
        help="NAME|LEFT_RECEIPTS|RIGHT_RECEIPTS; repeat per target.",
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    pairs: dict[str, tuple[Path, Path]] = {}
    for raw in args.pair:
        name, left, right = raw.split("|", 2)
        if not name or name in pairs:
            raise SystemExit(f"invalid or duplicate target name: {name!r}")
        pairs[name] = (Path(left), Path(right))
    result = aggregate(pairs)
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
