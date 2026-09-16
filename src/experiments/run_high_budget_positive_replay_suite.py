#!/usr/bin/env python3
"""Replay every direct positive row from the current TSDS campaign.

This is an evidence-only runner.  It discovers the positive rows from the
immutable baseline ledger, reruns each exact closure with a larger bounded
multi-state budget, and records the raw evaluator return code together with
the normalized receipt.  The runner deliberately makes no classification
decision and never edits manuscript artifacts.
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


TARGETS: dict[str, tuple[str, str]] = {
    "asus_rt_be57": ("ASUS_RT-BE57/httpd", "ASUS_RT-BE57/result/cmdi_results.json"),
    "dir878": ("DIR-878/rc", "DIR-878/DIR_878_results/cmdi_results.json"),
    "r6400v2": ("R6400v2/httpd", "R6400v2/R6400v2_result/cmdi_results.json"),
    "r7000": ("R7000/httpd", "R7000/R7000_result/cmdi_results.json"),
    "tenda_ac15": ("Tenda_AC15/httpd", "Tenda_AC15/Tenda_AC15_results/cmdi_results.json"),
    "tenda_ac18": ("Tenda_AC18/httpd", "Tenda_AC18/results/cmdi_results.json"),
    "tenda_w20e": ("Tenda_W20E/httpd", "Tenda_W20E/results/cmdi_results.json"),
    "xr300": ("XR300/httpd", "XR300/results/cmdi_results.json"),
}


SETTINGS: dict[str, Any] = {
    "engine_timeout": 180,
    "max_steps": 3000,
    "closure_timeout": 360,
    "subprocess_timeout": 420,
    "execution_backend": "forkserver",
    "multi_state_audit": True,
    "multi_state_settle_steps": 96,
    "no_evidence_cache": True,
    "no_evidence_aware_scheduler": True,
    "no_semantic_frontier": True,
    "no_loop_semantic_summary": True,
    "stagnation_limit": 0,
    "source_liveness_limit": 0,
    "source_dead_state_cap": 500,
    "scheduler_base_active_cap": 500,
    "scheduler_min_active_cap": 500,
    "scheduler_max_active_cap": 500,
    "scheduler_constraint_soft_limit": 4000,
    "scheduler_escape_quota": 32,
    "constraint_projection_cache_size": 4096,
    "online_refinement_rounds": 1,
    "online_refinement_candidates": 3,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_positive_rows(baseline: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(baseline.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("verdict") == "VECTOR_SAT" or row.get("status") == "vulnerable":
                rows.append(
                    {
                        "target": target,
                        "closure_idx": int(row["closure_idx"]),
                        "baseline_status": row.get("status"),
                        "baseline_verdict": row.get("verdict"),
                        "baseline_source_addr": row.get("source_addr"),
                        "baseline_sink_addr": row.get("sink_addr"),
                        "baseline_snapshot_digest": row.get("sink_snapshot_digest"),
                        "baseline_row_sha256": hashlib.sha256(
                            (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
                        ).hexdigest(),
                    }
                )
    rows.sort(key=lambda item: (item["target"], item["closure_idx"]))
    return rows


def command_for(
    *,
    python: Path,
    evaluator: Path,
    binary: Path,
    mango: Path,
    case_dir: Path,
    closure_idx: int,
) -> list[str]:
    values = SETTINGS
    command = [
        str(python),
        str(evaluator),
        str(binary),
        str(mango),
        "--closure-idx",
        str(closure_idx),
        "--engine-timeout",
        str(values["engine_timeout"]),
        "--max-steps",
        str(values["max_steps"]),
        "--closure-timeout",
        str(values["closure_timeout"]),
        "--subprocess-timeout",
        str(values["subprocess_timeout"]),
        "--execution-backend",
        str(values["execution_backend"]),
        "--multi-state-audit",
        "--multi-state-settle-steps",
        str(values["multi_state_settle_steps"]),
        "--no-evidence-cache",
        "--no-evidence-aware-scheduler",
        "--no-semantic-frontier",
        "--no-loop-semantic-summary",
        "--stagnation-limit",
        str(values["stagnation_limit"]),
        "--source-liveness-limit",
        str(values["source_liveness_limit"]),
        "--source-dead-state-cap",
        str(values["source_dead_state_cap"]),
        "--scheduler-base-active-cap",
        str(values["scheduler_base_active_cap"]),
        "--scheduler-min-active-cap",
        str(values["scheduler_min_active_cap"]),
        "--scheduler-max-active-cap",
        str(values["scheduler_max_active_cap"]),
        "--scheduler-constraint-soft-limit",
        str(values["scheduler_constraint_soft_limit"]),
        "--scheduler-escape-quota",
        str(values["scheduler_escape_quota"]),
        "--constraint-projection-cache-size",
        str(values["constraint_projection_cache_size"]),
        "--online-refinement-rounds",
        str(values["online_refinement_rounds"]),
        "--online-refinement-candidates",
        str(values["online_refinement_candidates"]),
        "--summary-json",
        str(case_dir / "summary.json"),
        "--results-jsonl",
        str(case_dir / "results.jsonl"),
        "--report-file",
        str(case_dir / "report.md"),
    ]
    return command


def run_case(
    *,
    root: Path,
    python: Path,
    evaluator: Path,
    case: dict[str, Any],
    out_dir: Path,
) -> dict[str, Any]:
    target = str(case["target"])
    binary_rel, mango_rel = TARGETS[target]
    case_dir = out_dir / f"{target}_idx{int(case['closure_idx'])}"
    case_dir.mkdir(parents=True, exist_ok=False)
    command = command_for(
        python=python,
        evaluator=evaluator,
        binary=root / binary_rel,
        mango=root / mango_rel,
        case_dir=case_dir,
        closure_idx=int(case["closure_idx"]),
    )
    (case_dir / "command.json").write_text(
        json.dumps(command, indent=2) + "\n", encoding="utf-8"
    )
    env = os.environ.copy()
    env.update({"PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    started = time.time()
    returncode: int | None = None
    timed_out = False
    error: str | None = None
    try:
        with (case_dir / "stdout.log").open("w", encoding="utf-8") as stdout, (case_dir / "stderr.log").open("w", encoding="utf-8") as stderr:
            try:
                completed = subprocess.run(
                    command,
                    cwd=str(root),
                    env=env,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=int(SETTINGS["subprocess_timeout"]) + 60,
                    check=False,
                )
                returncode = int(completed.returncode)
            except subprocess.TimeoutExpired:
                timed_out = True
                error = "runner_timeout"
            except OSError as exc:
                error = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # pragma: no cover - operational guard
        error = f"{type(exc).__name__}: {exc}"
    (case_dir / "returncode").write_text(
        ("TIMEOUT" if timed_out else str(returncode) if returncode is not None else "ERROR") + "\n",
        encoding="utf-8",
    )
    elapsed = round(time.time() - started, 3)
    normalized: dict[str, Any] | None = None
    result_path = case_dir / "results.jsonl"
    if result_path.is_file():
        lines = [line for line in result_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
        if len(lines) == 1:
            try:
                normalized = json.loads(lines[0])
            except json.JSONDecodeError:
                normalized = None
    return {
        **case,
        "returncode": returncode,
        "runner_timeout": timed_out,
        "runner_error": error,
        "elapsed_sec": elapsed,
        "receipt_present": normalized is not None,
        "result_status": normalized.get("status") if normalized else None,
        "result_verdict": normalized.get("verdict") if normalized else None,
        "result_source_addr": normalized.get("source_addr") if normalized else None,
        "result_sink_addr": normalized.get("sink_addr") if normalized else None,
        "result_snapshot_digest": normalized.get("sink_snapshot_digest") if normalized else None,
        "collection_complete": (
            ((normalized or {}).get("multi_state_audit") or {}).get("collection_complete")
            if normalized
            else None
        ),
        "profile_count": len(((normalized or {}).get("multi_state_audit") or {}).get("profiles") or []) if normalized else 0,
        "case_dir": str(case_dir),
    }


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
        "schema": "tsds-high-budget-positive-replay-suite-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_count": len(cases),
        "receipt_count": sum(bool(case["receipt_present"]) for case in cases),
        "complete_count": sum(case["collection_complete"] is True for case in cases),
        "incomplete_count": sum(case["collection_complete"] is not True for case in cases),
        "positive_outcome_count": sum(case["result_verdict"] == "VECTOR_SAT" for case in cases),
        "outcome_stability_count": sum(
            case["result_verdict"] == case["baseline_verdict"] and case["result_sink_addr"] == case["baseline_sink_addr"]
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
    cases = load_positive_rows(baseline)
    if not cases:
        raise SystemExit("baseline contains no direct positive rows")
    config = {
        "schema": "tsds-high-budget-positive-replay-suite-config-v1",
        "baseline": str(baseline),
        "baseline_sha256": sha256_file(baseline / "full_campaign_aggregate.json") if (baseline / "full_campaign_aggregate.json").is_file() else None,
        "evaluator": str(args.evaluator),
        "evaluator_sha256": sha256_file(args.evaluator),
        "runner_sha256": sha256_file(Path(__file__).resolve()),
        "settings": SETTINGS,
        "cases": cases,
        "claim_boundary": "Finite identity-bound high-budget replay of direct positive rows. Positive receipts are interpreted existentially over the sink instances actually collected; collection completeness is reported separately and never authorizes a candidate-wide negative conclusion. No exhaustive coverage, source-realizability, firmware ground truth, solver soundness, or device exploitability claim.",
    }
    write_json(out_dir / "suite_config.json", config)
    completed_cases: list[dict[str, Any]] = []
    for ordinal, case in enumerate(cases, start=1):
        print(f"[{ordinal}/{len(cases)}] {case['target']} closure {case['closure_idx']}", flush=True)
        completed_cases.append(run_case(root=root, python=args.python, evaluator=args.evaluator, case=case, out_dir=out_dir))
        write_json(out_dir / "progress.json", {"completed": ordinal, "total": len(cases), "cases": completed_cases})
    write_json(out_dir / "run_manifest.json", manifest_for(out_dir, completed_cases))
    (out_dir / "progress.json").unlink(missing_ok=True)
    print(json.dumps({"cases": len(completed_cases), "receipts": sum(c["receipt_present"] for c in completed_cases)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
