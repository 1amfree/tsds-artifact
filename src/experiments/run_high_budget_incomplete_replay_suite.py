#!/usr/bin/env python3
"""Replay every current record with an explicitly incomplete collection.

This is an evidence-only runner.  It selects the  records whose current
multi-state receipt declares ``collection_complete == false`` and reruns the
same closure with the higher bounded budget used by the positive replay
suite.  It records raw execution receipts but never changes a TSDS class or
promotes a residual.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.run_high_budget_positive_replay_suite import (  # noqa: E402
    SETTINGS,
    TARGETS,
    command_for,
    run_case,
    sha256_file,
    write_json,
)


SCHEMA = "tsds-high-budget-incomplete-replay-suite-v1"
CONFIG_SCHEMA = "tsds-high-budget-incomplete-replay-suite-config-v1"


def load_incomplete_rows(baseline: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(baseline.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        if target not in TARGETS:
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            audit = row.get("multi_state_audit") or {}
            if audit.get("collection_complete") is not False:
                continue
            rows.append(
                {
                    "target": target,
                    "closure_idx": int(row["closure_idx"]),
                    "baseline_status": row.get("status"),
                    "baseline_verdict": row.get("verdict"),
                    "baseline_source_addr": row.get("source_addr"),
                    "baseline_sink_addr": row.get("sink_addr"),
                    "baseline_sink_function": row.get("sink_function"),
                    "baseline_snapshot_digest": row.get("sink_snapshot_digest"),
                    "baseline_profile_count": len(audit.get("profiles") or []),
                    "baseline_collection_blockers": list(
                        audit.get("collection_accounting", {}).get("blockers") or []
                    ),
                    "baseline_row_sha256": hashlib.sha256(
                        (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    ).hexdigest(),
                }
            )
    rows.sort(key=lambda item: (item["target"], item["closure_idx"]))
    return rows


def manifest_for(out_dir: Path, cases: list[dict[str, Any]]) -> dict[str, Any]:
    artifacts: dict[str, dict[str, Any]] = {}
    for path in sorted(out_dir.rglob("*")):
        if not path.is_file() or path.name in {"run_manifest.json", "suite_config.json", "progress.json"}:
            continue
        artifacts[str(path.relative_to(out_dir)).replace("\\", "/")] = {
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_count": len(cases),
        "receipt_count": sum(bool(case["receipt_present"]) for case in cases),
        "complete_count": sum(case["collection_complete"] is True for case in cases),
        "incomplete_count": sum(case["collection_complete"] is not True for case in cases),
        "outcome_stability_count": sum(
            case["result_verdict"] == case["baseline_verdict"]
            and case["result_sink_addr"] == case["baseline_sink_addr"]
            for case in cases
        ),
        "cases": cases,
        "artifacts": artifacts,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--evaluator", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    baseline = args.baseline if args.baseline.is_absolute() else root / args.baseline
    out_dir = args.out_dir if args.out_dir.is_absolute() else root / args.out_dir
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)

    cases = load_incomplete_rows(baseline)
    if not cases:
        raise SystemExit("baseline contains no explicitly incomplete multi-state rows")
    config = {
        "schema": CONFIG_SCHEMA,
        "baseline": str(baseline),
        "baseline_sha256": sha256_file(baseline / "full_campaign_aggregate.json")
        if (baseline / "full_campaign_aggregate.json").is_file()
        else None,
        "evaluator": str(args.evaluator),
        "evaluator_sha256": sha256_file(args.evaluator),
        "runner_sha256": sha256_file(Path(__file__).resolve()),
        "settings": SETTINGS,
        "selection": "multi_state_audit.collection_complete == false",
        "cases": cases,
        "claim_boundary": (
            "Finite identity-bound higher-budget replay of records whose baseline "
            "collection was explicitly incomplete.  The run reports recovered "
            "bounded profiles and outcome identity only; it does not establish "
            "exhaustive sink-state coverage, candidate-wide negative conclusions, "
            "solver soundness, source realizability, firmware ground truth, or "
            "device exploitability."
        ),
    }
    write_json(out_dir / "suite_config.json", config)

    completed_cases: list[dict[str, Any]] = []
    for ordinal, case in enumerate(cases, start=1):
        print(f"[{ordinal}/{len(cases)}] {case['target']} closure {case['closure_idx']}", flush=True)
        completed_cases.append(
            run_case(
                root=root,
                python=args.python,
                evaluator=args.evaluator,
                case=case,
                out_dir=out_dir,
            )
        )
        write_json(
            out_dir / "progress.json",
            {"completed": ordinal, "total": len(cases), "cases": completed_cases},
        )

    write_json(out_dir / "run_manifest.json", manifest_for(out_dir, completed_cases))
    (out_dir / "progress.json").unlink(missing_ok=True)
    print(
        json.dumps(
            {
                "cases": len(completed_cases),
                "receipts": sum(c["receipt_present"] for c in completed_cases),
                "complete": sum(c["collection_complete"] is True for c in completed_cases),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
