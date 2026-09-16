#!/usr/bin/env python3
"""Retry the four incomplete replays that lacked a usable multistate receipt.

This is an evidence-only recovery run.  It records higher-budget evaluator
receipts, but never changes a ledger class or promotes a residual.
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

from experiments.run_high_budget_positive_replay_suite import TARGETS, sha256_file, write_json  # noqa: E402


SCHEMA = "tsds-targeted-multistate-timeout-recovery-v1"
CONFIG_SCHEMA = "tsds-targeted-multistate-timeout-recovery-config-v1"
CASES = (
    ("dir878", 2),
    ("r6400v2", 6),
    ("tenda_ac15", 34),
    ("xr300", 5),
)
SETTINGS: dict[str, Any] = {
    "engine_timeout": 300,
    "max_steps": 5000,
    "closure_timeout": 600,
    "subprocess_timeout": 660,
    "execution_backend": "forkserver",
    "multi_state_audit": True,
    "multi_state_settle_steps": 128,
    "no_evidence_cache": True,
    "no_evidence_aware_scheduler": True,
    "no_semantic_frontier": True,
    "no_loop_semantic_summary": True,
    "stagnation_limit": 0,
    "source_liveness_limit": 0,
    "source_dead_state_cap": 750,
    "scheduler_base_active_cap": 750,
    "scheduler_min_active_cap": 750,
    "scheduler_max_active_cap": 750,
    "scheduler_constraint_soft_limit": 6000,
    "scheduler_escape_quota": 48,
    "constraint_projection_cache_size": 8192,
    "online_refinement_rounds": 1,
    "online_refinement_candidates": 3,
}


def load_baseline_cases(baseline: Path) -> list[dict[str, Any]]:
    wanted = set(CASES)
    found: dict[tuple[str, int], dict[str, Any]] = {}
    for path in sorted(baseline.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        if target not in TARGETS:
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            key = (target, int(row["closure_idx"]))
            if key not in wanted:
                continue
            audit = row.get("multi_state_audit") or {}
            if audit.get("collection_complete") is not False:
                raise ValueError(f"targeted case is not baseline-incomplete: {key}")
            found[key] = {
                "target": target,
                "closure_idx": int(row["closure_idx"]),
                "baseline_status": row.get("status"),
                "baseline_verdict": row.get("verdict"),
                "baseline_source_addr": row.get("source_addr"),
                "baseline_sink_addr": row.get("sink_addr"),
                "baseline_sink_function": row.get("sink_function"),
                "baseline_row_sha256": hashlib.sha256(
                    (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
                ).hexdigest(),
            }
    missing = wanted - set(found)
    if missing:
        raise ValueError(f"targeted baseline cases missing: {sorted(missing)}")
    return [found[key] for key in CASES]


def command_for(*, python: Path, evaluator: Path, binary: Path, mango: Path, case_dir: Path, closure_idx: int) -> list[str]:
    s = SETTINGS
    return [
        str(python), str(evaluator), str(binary), str(mango),
        "--closure-idx", str(closure_idx),
        "--engine-timeout", str(s["engine_timeout"]),
        "--max-steps", str(s["max_steps"]),
        "--closure-timeout", str(s["closure_timeout"]),
        "--subprocess-timeout", str(s["subprocess_timeout"]),
        "--execution-backend", str(s["execution_backend"]),
        "--multi-state-audit", "--multi-state-settle-steps", str(s["multi_state_settle_steps"]),
        "--no-evidence-cache", "--no-evidence-aware-scheduler", "--no-semantic-frontier", "--no-loop-semantic-summary",
        "--stagnation-limit", str(s["stagnation_limit"]),
        "--source-liveness-limit", str(s["source_liveness_limit"]),
        "--source-dead-state-cap", str(s["source_dead_state_cap"]),
        "--scheduler-base-active-cap", str(s["scheduler_base_active_cap"]),
        "--scheduler-min-active-cap", str(s["scheduler_min_active_cap"]),
        "--scheduler-max-active-cap", str(s["scheduler_max_active_cap"]),
        "--scheduler-constraint-soft-limit", str(s["scheduler_constraint_soft_limit"]),
        "--scheduler-escape-quota", str(s["scheduler_escape_quota"]),
        "--constraint-projection-cache-size", str(s["constraint_projection_cache_size"]),
        "--online-refinement-rounds", str(s["online_refinement_rounds"]),
        "--online-refinement-candidates", str(s["online_refinement_candidates"]),
        "--summary-json", str(case_dir / "summary.json"),
        "--results-jsonl", str(case_dir / "results.jsonl"),
        "--report-file", str(case_dir / "report.md"),
    ]


def run_case(*, root: Path, python: Path, evaluator: Path, case: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    target = case["target"]
    binary_rel, mango_rel = TARGETS[target]
    case_dir = out_dir / f"{target}_idx{case['closure_idx']}"
    case_dir.mkdir(parents=True, exist_ok=False)
    command = command_for(
        python=python,
        evaluator=evaluator,
        binary=root / binary_rel,
        mango=root / mango_rel,
        case_dir=case_dir,
        closure_idx=case["closure_idx"],
    )
    write_json(case_dir / "command.json", command)
    env = os.environ.copy()
    env.update({"PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    started = time.time()
    returncode: int | None = None
    timed_out = False
    error: str | None = None
    with (case_dir / "stdout.log").open("w", encoding="utf-8") as stdout, (case_dir / "stderr.log").open("w", encoding="utf-8") as stderr:
        try:
            completed = subprocess.run(
                command,
                cwd=str(root),
                env=env,
                stdout=stdout,
                stderr=stderr,
                timeout=int(SETTINGS["subprocess_timeout"]) + 120,
                check=False,
            )
            returncode = int(completed.returncode)
        except subprocess.TimeoutExpired:
            timed_out = True
            error = "runner_timeout"
        except OSError as exc:
            error = f"{type(exc).__name__}: {exc}"
    write_text = case_dir.joinpath("returncode").write_text
    write_text(("TIMEOUT" if timed_out else str(returncode) if returncode is not None else "ERROR") + "\n", encoding="utf-8")
    lines = []
    result_path = case_dir / "results.jsonl"
    if result_path.is_file():
        lines = [line for line in result_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    row = json.loads(lines[0]) if len(lines) == 1 else None
    audit = (row or {}).get("multi_state_audit") or {}
    return {
        **case,
        "returncode": returncode,
        "runner_timeout": timed_out,
        "runner_error": error,
        "elapsed_sec": round(time.time() - started, 3),
        "receipt_present": row is not None,
        "result_status": (row or {}).get("status"),
        "result_verdict": (row or {}).get("verdict"),
        "result_source_addr": (row or {}).get("source_addr"),
        "result_sink_addr": (row or {}).get("sink_addr"),
        "collection_complete": audit.get("collection_complete"),
        "profile_count": len(audit.get("profiles") or []),
        "candidate_wide_negative": (audit.get("aggregate") or {}).get("candidate_wide_negative", audit.get("candidate_wide_negative")),
        "case_dir": str(case_dir),
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
    baseline = args.baseline.resolve()
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    cases = load_baseline_cases(baseline)
    config = {
        "schema": CONFIG_SCHEMA,
        "baseline": str(baseline),
        "baseline_sha256": sha256_file(baseline / "full_campaign_aggregate.json"),
        "evaluator": str(args.evaluator),
        "evaluator_sha256": sha256_file(args.evaluator),
        "runner_sha256": sha256_file(Path(__file__).resolve()),
        "settings": SETTINGS,
        "cases": cases,
        "claim_boundary": "Finite targeted timeout recovery.  Receipts and recovered profiles are observations only; no class is promoted and no exhaustive coverage, candidate-wide negative conclusion, solver soundness, source realizability, firmware ground truth, or device exploitability claim is made.",
    }
    write_json(out_dir / "suite_config.json", config)
    results = []
    for ordinal, case in enumerate(cases, start=1):
        print(f"[{ordinal}/{len(cases)}] {case['target']} closure {case['closure_idx']}", flush=True)
        # Preserve the venv launcher path; resolving the symlink would switch
        # to the system interpreter and drop the evaluator dependencies.
        results.append(run_case(root=root, python=args.python, evaluator=args.evaluator, case=case, out_dir=out_dir))
        write_json(out_dir / "progress.json", {"completed": ordinal, "total": len(cases), "cases": results})
    artifacts = {}
    for path in sorted(out_dir.rglob("*")):
        if path.is_file() and path.name not in {"progress.json", "run_manifest.json", "suite_config.json"}:
            artifacts[str(path.relative_to(out_dir)).replace("\\", "/")] = {"bytes": path.stat().st_size, "sha256": sha256_file(path)}
    write_json(out_dir / "run_manifest.json", {"schema": SCHEMA, "generated_at": datetime.now(timezone.utc).isoformat(), "case_count": len(results), "receipt_count": sum(r["receipt_present"] for r in results), "cases": results, "artifacts": artifacts})
    (out_dir / "progress.json").unlink(missing_ok=True)
    print(json.dumps({"cases": len(results), "receipts": sum(r["receipt_present"] for r in results), "complete": sum(r["collection_complete"] is True for r in results)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
