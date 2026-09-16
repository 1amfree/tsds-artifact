#!/usr/bin/env python3
"""Build a deterministic, fixture-conditioned TSDS residual replay plan.

This planner only emits manifests and synthetic branch fixtures.  It does not
run firmware, execute commands, or upgrade any evidence verdict.  A separate
replay driver must preserve the fixture-conditioned scope when consuming this
plan.
"""

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

from tsds.residual_refinement import build_refinement_plan  # noqa: E402


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: row is not an object")
            rows.append(value)
    return rows


def target_from_path(path: Path) -> str:
    suffix = ".results.jsonl"
    return path.name[: -len(suffix)] if path.name.endswith(suffix) else path.stem


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = [
        "target",
        "closure_idx",
        "closure_ordinal",
        "old_status",
        "strategy",
        "priority",
        "fixture_variants",
        "fixture_requests",
        "claim_scope",
    ]
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--max-records-per-target", type=int, default=0)
    parser.add_argument("--max-variants", type=int, default=3)
    parser.add_argument("--priority", action="append", default=[])
    parser.add_argument("--strategy", action="append", default=[])
    args = parser.parse_args()

    input_dir = args.input_dir.resolve()
    paths = sorted(input_dir.glob("*.results.jsonl"))
    if not paths:
        print(f"no campaign JSONL files found in {input_dir}", file=sys.stderr)
        return 2
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to reuse non-empty output directory: {out_dir}", file=sys.stderr)
        return 3
    out_dir.mkdir(parents=True, exist_ok=True)

    target_plans: dict[str, dict[str, Any]] = {}
    manifest_rows: list[dict[str, Any]] = []
    for path in paths:
        target = target_from_path(path)
        plan = build_refinement_plan(
            load_jsonl(path),
            max_records=args.max_records_per_target,
            max_variants=args.max_variants,
            priorities=args.priority,
            strategies=args.strategy,
        )
        target_plans[target] = plan
        fixtures_dir = out_dir / "fixtures" / target
        for row in plan["records"]:
            closure_idx = row.get("closure_idx")
            for variant in row.get("fixture_variants") or []:
                fixtures_dir.mkdir(parents=True, exist_ok=True)
                filename = f"closure_{closure_idx}_{variant['variant']}.json"
                fixture_path = fixtures_dir / filename
                fixture_path.write_text(
                    json.dumps(variant["fixture"], indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            manifest_rows.append(
                {
                    "target": target,
                    "closure_idx": closure_idx,
                    "closure_ordinal": row.get("closure_ordinal"),
                    "old_status": row.get("old_status"),
                    "strategy": row.get("strategy"),
                    "priority": row.get("priority"),
                    "fixture_variants": len(row.get("fixture_variants") or []),
                    "fixture_requests": len(row.get("model_gap_requests") or []),
                    "claim_scope": row.get("claim_scope"),
                }
            )

    aggregate = {
        "schema": "tsds-residual-refinement-plan-pack-v2",
        "input_dir": str(input_dir),
        "targets": target_plans,
        "selected_records": len(manifest_rows),
        "fixture_variants": sum(int(row["fixture_variants"]) for row in manifest_rows),
        "claim_boundary": (
            "Fixtures in this pack are synthetic branch-enabling assumptions. "
            "Any replay using them remains fixture-conditioned and is excluded from primary evidence aggregates."
        ),
    }
    (out_dir / "residual_refinement_plan.json").write_text(
        json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_csv(out_dir / "residual_refinement_manifest.csv", manifest_rows)
    (out_dir / "README.md").write_text(
        "# TSDS residual refinement v2 plan\n\n"
        f"Selected residual records: **{aggregate['selected_records']}**; "
        f"synthetic fixture variants: **{aggregate['fixture_variants']}**.\n\n"
        + aggregate["claim_boundary"]
        + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "out_dir": str(out_dir),
                "schema": aggregate["schema"],
                "selected_records": aggregate["selected_records"],
                "fixture_variants": aggregate["fixture_variants"],
                "targets": {
                    target: plan["summary"]
                    for target, plan in sorted(target_plans.items())
                },
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
