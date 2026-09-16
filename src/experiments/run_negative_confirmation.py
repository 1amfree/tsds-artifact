#!/usr/bin/env python3
"""Replay path-control-sensitive negative TSDS records without pruning.

The driver is intentionally post-campaign.  It never overwrites campaign
ledgers and never converts a failed replay into a negative claim.  Stable,
changed, and unresolved confirmations are emitted as separate artifact rows.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.run_full_firmware_campaign import TARGETS


DEFAULT_CAMPAIGN = Path(
    "experiment_reports/full_firmware_campaign_current_tsds_20260627"
)

DETERMINISTIC_CONFIRMATION_ENVIRONMENT = {
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "LC_ALL": "C",
    "LANG": "C",
    "TZ": "UTC",
}

PATH_CONTROL_FIELDS = (
    "engine_semantic_frontier_pruned",
    "engine_semantic_frontier_pruned_total",
    "engine_loop_semantic_pruned",
    "engine_loop_semantic_pruned_total",
    "engine_loop_semantic_cap_pruned",
    "engine_loop_semantic_cap_pruned_total",
    "seed_states_pruned",
)


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def path_control_events(record: dict[str, Any]) -> int:
    return sum(_as_int(record.get(field)) for field in PATH_CONTROL_FIELDS)


def needs_confirmation(record: dict[str, Any]) -> bool:
    return (
        str(record.get("status") or "") in {"filtered", "no_taint_sink"}
        and bool(
            record.get("negative_confirmation_required")
            or path_control_events(record)
        )
    )


def iter_candidates(
    campaign_dir: Path, targets: set[str] | None = None
) -> Iterable[dict[str, Any]]:
    for path in sorted(campaign_dir.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        if targets and target not in targets:
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                record = json.loads(line)
                if needs_confirmation(record):
                    record["_confirmation_target"] = target
                    record["_confirmation_source"] = str(path)
                    record["_confirmation_line"] = line_no
                    yield record


def parse_result_marker(output: str) -> dict[str, Any] | None:
    for line in reversed(output.splitlines()):
        if line.startswith("RESULT_JSON: "):
            try:
                return json.loads(line.split("RESULT_JSON: ", 1)[1])
            except json.JSONDecodeError:
                return None
    return None


def vector_signature(record: dict[str, Any]) -> tuple[Any, ...]:
    decisions = record.get("vector_decisions") or []
    if decisions:
        profile = tuple(
            sorted(
                (
                    str(item.get("vector_id") or item.get("vector") or ""),
                    str(item.get("decision") or ""),
                    str(item.get("witness_kind") or ""),
                    str(item.get("quote_context") or ""),
                )
                for item in decisions
            )
        )
    else:
        profile = (
            ("sat_count", _as_int(record.get("vulnerable_vectors")), "", ""),
            ("unsat_count", _as_int(record.get("secure_vectors")), "", ""),
            (
                "inconclusive_count",
                _as_int(record.get("inconclusive_vectors")),
                "",
                "",
            ),
        )
    return (str(record.get("status") or ""), profile)


def compare_result(
    baseline: dict[str, Any], confirmation: dict[str, Any] | None
) -> str:
    if confirmation is None:
        return "replay_error"
    status = str(confirmation.get("status") or "")
    if (
        baseline.get("analysis_recovery")
        == "binary_static_fixed_command_template"
        and status == "static_warning_reduction"
    ):
        return "contract_reclassified_static_reduction"
    if status in {
        "timeout",
        "unreachable",
        "residual",
        "crashed",
        "eval_error",
        "state_error",
    }:
        return "confirmation_residual"
    if baseline.get("vector_decisions") and confirmation.get("vector_decisions"):
        same_signature = vector_signature(baseline) == vector_signature(confirmation)
    else:
        same_signature = (
            str(baseline.get("status") or ""),
            _as_int(baseline.get("vulnerable_vectors")),
            _as_int(baseline.get("secure_vectors")),
            _as_int(baseline.get("inconclusive_vectors")),
        ) == (
            str(confirmation.get("status") or ""),
            _as_int(confirmation.get("vulnerable_vectors")),
            _as_int(confirmation.get("secure_vectors")),
            _as_int(confirmation.get("inconclusive_vectors")),
        )
    if same_signature:
        return "stable"
    if status == "vulnerable":
        return "changed_to_vector_sat"
    return "changed"


def target_index(root: Path) -> dict[str, dict[str, Path]]:
    return {
        item["name"]: {
            "binary": root / item["binary"],
            "mango": root / item["mango"],
        }
        for item in TARGETS
    }


def build_command(
    python: Path,
    evaluator: Path,
    binary: Path,
    mango: Path,
    closure_idx: int,
    args: argparse.Namespace,
) -> list[str]:
    command = [
        str(python),
        str(evaluator),
        str(binary),
        str(mango),
        "--closure-idx",
        str(closure_idx),
        "--mode",
        "full",
        "--engine-timeout",
        str(args.engine_timeout),
        "--max-steps",
        str(args.max_steps),
        "--closure-timeout",
        str(args.closure_timeout),
        "--no-semantic-frontier",
        "--no-loop-semantic-summary",
        "--source-liveness-limit",
        "0",
        "--seed-equiv-limit",
        "0",
        "--no-taint-equiv-limit",
        "0",
        "--stagnation-limit",
        "0",
        "--closure-memo-limit",
        "0",
        "--no-evidence-cache",
    ]
    memory_limit_mib = int(getattr(args, "memory_limit_mib", 0) or 0)
    if memory_limit_mib > 0:
        command.extend(["--subprocess-memory-limit-mib", str(memory_limit_mib)])
    return command


def run_confirmation(
    record: dict[str, Any],
    paths: dict[str, Path],
    args: argparse.Namespace,
    logs_dir: Path,
) -> dict[str, Any]:
    target = str(record["_confirmation_target"])
    closure_idx = _as_int(record.get("closure_idx"))
    command = build_command(
        args.python,
        args.evaluator,
        paths["binary"],
        paths["mango"],
        closure_idx,
        args,
    )
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            command,
            cwd=args.root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=args.replay_timeout,
            check=False,
            env={**os.environ, **DETERMINISTIC_CONFIRMATION_ENVIRONMENT},
        )
        output = proc.stdout
        returncode = proc.returncode
        confirmation = parse_result_marker(output)
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + "\nREPLAY_TIMEOUT"
        returncode = 124
        confirmation = None

    log_path = logs_dir / f"{target}.closure_{closure_idx:04d}.log"
    log_path.write_text(output, encoding="utf-8", errors="replace")
    outcome = compare_result(record, confirmation)
    if returncode != 0:
        outcome = "replay_error"
    return {
        "target": target,
        "closure_idx": closure_idx,
        "baseline_status": record.get("status"),
        "confirmation_status": (
            confirmation.get("status") if confirmation else ""
        ),
        "outcome": outcome,
        "path_control_events": path_control_events(record),
        "baseline_signature": repr(vector_signature(record)),
        "confirmation_signature": (
            repr(vector_signature(confirmation)) if confirmation else ""
        ),
        "returncode": returncode,
        "elapsed_sec": round(time.perf_counter() - start, 4),
        "log": str(log_path),
        "confirmation_record": confirmation or {},
    }


def write_outputs(out_dir: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(str(row.get("outcome") or "unknown") for row in rows)
    summary = {
        "schema": "tsds-negative-confirmation-v1",
        "records": len(rows),
        "outcomes": dict(sorted(counts.items())),
        "claim_boundary": (
            "A stable row confirms the same analyzer verdict without TSDS path "
            "control for that closure. Changed or incomplete replays remain "
            "sensitivity/residual evidence, not negative conclusions."
        ),
    }
    (out_dir / "negative_confirmation_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "negative_confirmation_records.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    csv_fields = [
        "target",
        "closure_idx",
        "baseline_status",
        "confirmation_status",
        "outcome",
        "path_control_events",
        "returncode",
        "elapsed_sec",
        "log",
    ]
    with (out_dir / "negative_confirmation_records.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(
            handle, fieldnames=csv_fields, extrasaction="ignore", lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)
    lines = [
        "# TSDS negative-evidence confirmation",
        "",
        summary["claim_boundary"],
        "",
        f"- Replayed records: {summary['records']}",
        "",
        "| Outcome | Records |",
        "|---|---:|",
    ]
    for name, count in summary["outcomes"].items():
        lines.append(f"| {name} | {count} |")
    (out_dir / "README.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    return summary


def confirmation_gate_issues(
    summary: dict[str, Any],
    *,
    fail_on_replay_errors: bool = False,
    fail_on_positive_change: bool = False,
    minimum_records: int = 0,
) -> list[str]:
    """验证负向重放是否满足错误、漂移和最小样本数门禁。"""

    outcomes = summary.get("outcomes") or {}
    issues: list[str] = []
    # 显式拒绝空重放，避免把没有执行样本误写成负向确认结果。
    if int(summary.get("records") or 0) < minimum_records:
        issues.append("negative_confirmation_insufficient_records")
    if fail_on_replay_errors and (
        int(outcomes.get("replay_error") or 0)
        or int(outcomes.get("target_manifest_missing") or 0)
    ):
        issues.append("negative_confirmation_replay_error")
    if fail_on_positive_change and int(outcomes.get("changed_to_vector_sat") or 0):
        issues.append("negative_confirmation_changed_to_vector_sat")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--campaign-dir", type=Path, default=DEFAULT_CAMPAIGN)
    parser.add_argument(
        "--python",
        type=Path,
        default=Path(
            "/home/ubuntu/work/sanitizer/operation-mango-public/.venv/bin/python"
        ),
    )
    parser.add_argument(
        "--evaluator",
        type=Path,
        default=Path(
            "/home/ubuntu/work/sanitizer/Taint_demo/sanitizer_demo/"
            "advanced_sanitizer_evaluator.py"
        ),
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--target", action="append", dest="targets")
    parser.add_argument("--max-records", type=int, default=0)
    parser.add_argument("--engine-timeout", type=int, default=90)
    parser.add_argument("--max-steps", type=int, default=1000)
    parser.add_argument("--closure-timeout", type=int, default=180)
    parser.add_argument("--replay-timeout", type=int, default=240)
    parser.add_argument("--memory-limit-mib", type=int, default=0)
    parser.add_argument("--fail-on-replay-errors", action="store_true")
    parser.add_argument("--fail-on-positive-change", action="store_true")
    parser.add_argument(
        "--minimum-records",
        type=int,
        default=0,
        help="Fail when fewer than this many confirmation records are replayed.",
    )
    args = parser.parse_args()

    args.root = args.root.resolve()
    args.campaign_dir = (
        args.campaign_dir
        if args.campaign_dir.is_absolute()
        else args.root / args.campaign_dir
    ).resolve()
    if args.memory_limit_mib < 0:
        parser.error("--memory-limit-mib must be non-negative")
    if args.minimum_records < 0:
        parser.error("--minimum-records must be non-negative")
    args.out_dir = args.out_dir.resolve()
    if args.out_dir.exists() and any(args.out_dir.iterdir()):
        print(f"refusing to reuse non-empty output directory: {args.out_dir}", file=sys.stderr)
        return 3
    args.out_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = args.out_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    selected = list(
        iter_candidates(
            args.campaign_dir,
            set(args.targets or []) or None,
        )
    )
    if args.max_records:
        selected = selected[: args.max_records]
    paths = target_index(args.root)
    rows = []
    for record in selected:
        target = str(record["_confirmation_target"])
        if target not in paths:
            rows.append(
                {
                    "target": target,
                    "closure_idx": record.get("closure_idx"),
                    "baseline_status": record.get("status"),
                    "confirmation_status": "",
                    "outcome": "target_manifest_missing",
                    "path_control_events": path_control_events(record),
                    "returncode": 127,
                    "elapsed_sec": 0.0,
                    "log": "",
                }
            )
            continue
        rows.append(
            run_confirmation(record, paths[target], args, logs_dir)
        )
    summary = write_outputs(args.out_dir, rows)
    gate_issues = confirmation_gate_issues(
        summary,
        fail_on_replay_errors=args.fail_on_replay_errors,
        fail_on_positive_change=args.fail_on_positive_change,
        minimum_records=args.minimum_records,
    )
    summary["gate_issues"] = gate_issues
    (args.out_dir / "negative_confirmation_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if gate_issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
