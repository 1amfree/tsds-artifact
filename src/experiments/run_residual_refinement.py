#!/usr/bin/env python3
"""Execute TSDS residual recovery plans and summarize resolution deltas.

This script operationalizes the residual recovery plan emitted by
advanced_sanitizer_evaluator.py. It reads per-closure JSONL records, selects
residual records, reruns the evaluator with each record's suggested overrides,
and writes a machine-readable delta report.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from advanced_sanitizer_evaluator import (
    parse_result_json_marker,
    residual_refinement_status_group,
    select_residual_refinement_candidates,
    summarize_residual_refinement,
)


TARGETS = {
    "ac18": {
        "name": "Tenda AC18",
        "binary": "Tenda_AC18/httpd",
        "mango": "Tenda_AC18/results/cmdi_results.json",
        "jsonl": "Tenda_AC18/reports/ac18_results_v2.jsonl",
    },
    "w20e": {
        "name": "Tenda W20E",
        "binary": "Tenda_W20E/httpd",
        "mango": "Tenda_W20E/results/cmdi_results.json",
        "jsonl": "Tenda_W20E/reports/w20e_results.jsonl",
    },
    "xr300": {
        "name": "Netgear XR300",
        "binary": "XR300/httpd",
        "mango": "XR300/results/cmdi_results.json",
        "jsonl": "XR300/reports/xr300_results.jsonl",
    },
}


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records
def cli_flag(name: str) -> str:
    return "--" + name.replace("_", "-")


def build_command(
    python_bin: Path,
    evaluator: Path,
    binary: Path,
    mango: Path,
    closure_idx: int,
    overrides: Dict[str, Any],
    no_evidence_cache: bool,
) -> List[str]:
    cmd = [
        str(python_bin),
        str(evaluator),
        str(binary),
        str(mango),
        "--closure-idx",
        str(closure_idx),
    ]
    for key, value in sorted(overrides.items()):
        if value is None:
            continue
        if key == "no_reconciliation":
            if str(value).lower() in {"1", "true", "yes"}:
                cmd.append("--no-reconciliation")
            continue
        if key == "loop_semantic_weak_static":
            if str(value).lower() in {"1", "true", "yes"}:
                cmd.append("--loop-semantic-weak-static")
            continue
        cmd.extend([cli_flag(key), str(value)])
    if no_evidence_cache:
        cmd.append("--no-evidence-cache")
    return cmd
def run_one(
    cmd: List[str],
    timeout: int,
    log_path: Path,
) -> Tuple[Dict[str, Any], float]:
    start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    elapsed = time.perf_counter() - start
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(proc.stdout, encoding="utf-8", errors="replace")
    result = parse_result_json_marker(proc.stdout)
    if not result:
        result = {
            "status": "eval_error",
            "error": "missing RESULT_JSON marker",
            "returncode": proc.returncode,
        }
    result["refinement_returncode"] = proc.returncode
    return result, elapsed


def write_jsonl(path: Path, records: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, sort_keys=True) + "\n")


def write_markdown(path: Path, records: List[Dict[str, Any]], dry_run: bool) -> None:
    total = len(records)
    resolved = sum(1 for r in records if r.get("new_status_group") == "resolved")
    unchanged = sum(1 for r in records if r.get("old_status") == r.get("new_status"))
    lines = [
        "# Residual Refinement Report",
        "",
        f"- Dry run: `{dry_run}`",
        f"- Records: {total}",
        f"- Resolved after refinement: {resolved}",
        f"- Unchanged status: {unchanged}",
        "",
        "| Target | Closure | Strategy | Priority | Old | New | Delta | Time(s) |",
        "|---|---:|---|---|---|---|---|---:|",
    ]
    for r in records:
        lines.append(
            "| {target} | {idx} | {strategy} | {priority} | {old} | {new} | {delta} | {elapsed:.2f} |".format(
                target=r.get("target"),
                idx=r.get("closure_idx"),
                strategy=r.get("strategy"),
                priority=r.get("priority"),
                old=r.get("old_status"),
                new=r.get("new_status"),
                delta=r.get("delta"),
                elapsed=float(r.get("elapsed_sec") or 0.0),
            )
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="/home/ubuntu/work/sanitizer")
    parser.add_argument("--target", action="append", choices=sorted(TARGETS), help="Target key; repeatable")
    parser.add_argument("--python", default="/home/ubuntu/work/sanitizer/operation-mango-public/.venv/bin/python")
    parser.add_argument("--evaluator", default="/home/ubuntu/work/sanitizer/Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py")
    parser.add_argument("--out-dir", default="experiment_reports/residual_refinement_20260624")
    parser.add_argument("--strategy", action="append", help="Residual plan strategy filter; repeatable")
    parser.add_argument("--priority", action="append", help="Priority filter; repeatable")
    parser.add_argument("--max-records", type=int, default=0)
    parser.add_argument("--timeout", type=int, default=260)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--use-evidence-cache", action="store_true")
    args = parser.parse_args()

    root = Path(args.root)
    out_dir = root / args.out_dir
    python_bin = Path(args.python)
    evaluator = Path(args.evaluator)
    target_keys = args.target or sorted(TARGETS)
    strategies = set(args.strategy or [])
    priorities = set(args.priority or [])
    outputs: List[Dict[str, Any]] = []

    for key in target_keys:
        meta = TARGETS[key]
        jsonl_path = root / meta["jsonl"]
        if not jsonl_path.exists():
            raise FileNotFoundError(f"Missing JSONL for {meta['name']}: {jsonl_path}")
        selected = select_residual_refinement_candidates(
            load_jsonl(jsonl_path),
            strategies=strategies or None,
            priorities=priorities or None,
            max_records=args.max_records,
        )
        for record in selected:
            closure_idx = int(record.get("closure_idx"))
            overrides = record.get("residual_plan_config_overrides") or {}
            cmd = build_command(
                python_bin=python_bin,
                evaluator=evaluator,
                binary=root / meta["binary"],
                mango=root / meta["mango"],
                closure_idx=closure_idx,
                overrides=overrides,
                no_evidence_cache=not args.use_evidence_cache,
            )
            log_path = out_dir / "logs" / f"{key}_closure_{closure_idx}.log"
            base = {
                "target_key": key,
                "target": meta["name"],
                "closure_idx": closure_idx,
                "strategy": record.get("residual_plan_strategy") or "manual_review",
                "priority": record.get("residual_plan_priority") or "medium",
                "old_status": record.get("status"),
                "old_stop_reason": record.get("engine_stop_reason"),
                "command": cmd,
                "log_path": str(log_path.relative_to(root)),
            }
            if args.dry_run:
                base.update({
                    "new_status": "<dry-run>",
                    "new_status_group": "<dry-run>",
                    "delta": "planned",
                    "elapsed_sec": 0.0,
                })
                outputs.append(base)
                continue
            try:
                result, elapsed = run_one(cmd, args.timeout, log_path)
            except subprocess.TimeoutExpired as exc:
                elapsed = float(args.timeout)
                result = {
                    "status": "timeout",
                    "timeout_kind": "refinement_driver_timeout",
                    "error": str(exc),
                }
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.write_text(str(exc), encoding="utf-8", errors="replace")
            new_status = result.get("status") or "unknown"
            old_status = str(record.get("status") or "unknown")
            old_group = residual_refinement_status_group(old_status)
            new_group = residual_refinement_status_group(str(new_status))
            if new_group == "resolved" and old_group != "resolved":
                delta = "resolved"
            elif str(new_status) != old_status:
                delta = "changed"
            else:
                delta = "unchanged"
            base.update({
                "new_status": new_status,
                "new_status_group": new_group,
                "new_stop_reason": result.get("engine_stop_reason"),
                "delta": delta,
                "elapsed_sec": round(elapsed, 4),
                "result": result,
            })
            outputs.append(base)

    write_jsonl(out_dir / "residual_refinement_results.jsonl", outputs)
    summary = summarize_residual_refinement(outputs)
    summary["dry_run"] = args.dry_run
    (out_dir / "residual_refinement_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    write_markdown(out_dir / "residual_refinement_report.md", outputs, args.dry_run)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
