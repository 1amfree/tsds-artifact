#!/usr/bin/env python3
"""Export matrix-bounded TSDS counterfactual repair explanations."""

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

from tsds.sanitizer_repair import (  # noqa: E402
    aggregate_counterfactual_repairs,
    counterfactual_repair_plan,
)


def load_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for jsonl in sorted(path.glob("*.results.jsonl")):
        target = jsonl.name.removesuffix(".results.jsonl")
        for line in jsonl.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("status") == "vulnerable":
                rows.append({"target": target, "record": record})
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to reuse non-empty output directory: {out_dir}", file=sys.stderr)
        return 3
    out_dir.mkdir(parents=True, exist_ok=True)
    inputs = load_rows(args.input_dir.resolve())
    rows: list[dict[str, Any]] = []
    plans: list[dict[str, Any]] = []
    for item in inputs:
        plan = counterfactual_repair_plan(item["record"])
        plan["target"] = item["target"]
        plans.append(plan)
        rows.append(
            {
                "target": item["target"],
                "closure_idx": plan.get("closure_idx"),
                "sat_vectors": ";".join(plan["modeled_sat_vectors"]),
                "inconclusive_vectors": ";".join(plan["inconclusive_vectors"]),
                "safeguards": ";".join(item["id"] for item in plan["counterfactual_safeguards"]),
                "complete_under_matrix": plan["complete_under_matrix"],
            }
        )
    summary = aggregate_counterfactual_repairs([item["record"] for item in inputs])
    summary["input_dir"] = str(args.input_dir.resolve())
    (out_dir / "counterfactual_repairs.jsonl").write_text(
        "".join(json.dumps(plan, sort_keys=True) + "\n" for plan in plans), encoding="utf-8"
    )
    with (out_dir / "counterfactual_repairs.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = ["target", "closure_idx", "sat_vectors", "inconclusive_vectors", "safeguards", "complete_under_matrix"]
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "counterfactual_repair_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        "# TSDS counterfactual repair pack\n\n" + summary["claim_boundary"] + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
