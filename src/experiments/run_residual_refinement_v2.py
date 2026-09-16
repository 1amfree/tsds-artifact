#!/usr/bin/env python3
"""Run bounded, fail-closed TSDS v16 residual refinement replays.

The driver consumes an immutable baseline campaign and emits a separate replay
ledger.  It never mutates the baseline campaign and never merges a replay
result into its primary aggregates.  Synthetic-fixture replays are explicitly
fixture-conditioned.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.residual_refinement import (  # noqa: E402
    build_refinement_plan,
    classify_transition,
    transition_summary,
)


DETERMINISTIC_REPLAY_ENVIRONMENT = {
    "PYTHONHASHSEED": "0",
    "LC_ALL": "C",
    "LANG": "C",
    "TZ": "UTC",
}
REPLAY_IDENTITY_SOURCES = (
    "advanced_sanitizer_evaluator.py",
    "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py",
    "experiments/run_residual_refinement_v2.py",
    "tsds/residual_refinement.py",
)


def file_identity(path: Path, base: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    resolved = path.resolve()
    try:
        display = str(resolved.relative_to(base.resolve()))
    except ValueError:
        display = str(resolved)
    return {"path": display, "size": resolved.stat().st_size, "sha256": digest.hexdigest()}


def identity_drift(
    before: list[dict[str, Any]], after: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    baseline = {str(row["path"]): row for row in before}
    observed = {str(row["path"]): row for row in after}
    drift: list[dict[str, Any]] = []
    for key in sorted(set(baseline) | set(observed)):
        old = baseline.get(key)
        new = observed.get(key)
        if old != new:
            drift.append({"path": key, "before": old, "after": new})
    return drift


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_no}: row is not an object")
        rows.append(value)
    return rows


def parse_result_marker(output: str) -> dict[str, Any]:
    for line in reversed(output.splitlines()):
        if line.startswith("RESULT_JSON: "):
            try:
                value = json.loads(line[len("RESULT_JSON: "):])
            except json.JSONDecodeError:
                break
            if isinstance(value, dict):
                return value
    return {"status": "eval_error", "error": "missing RESULT_JSON marker"}


def command_for_replay(
    python: Path,
    root: Path,
    binary_path: str,
    json_path: str,
    closure_idx: int,
    overrides: Mapping[str, Any],
    *,
    fixture_path: Path | None = None,
    memory_limit_mib: int = 0,
) -> list[str]:
    """Build a list-form command; no shell interpolation is used."""

    config = {
        "engine_timeout": 45,
        "max_steps": 500,
        "closure_timeout": 90,
        "seed_equiv_limit": 2,
        "no_taint_equiv_limit": 3,
        "stagnation_limit": 10,
        "semantic_frontier_min_states": 12,
        "semantic_frontier_bucket_limit": 2,
        "semantic_frontier_period": 2,
        "source_liveness_limit": 4,
        "source_dead_state_cap": 20,
        "loop_semantic_min_states": 50,
        "loop_semantic_min_visits": 3,
        "loop_semantic_bucket_limit": 1,
        "loop_semantic_period": 1,
        "loop_semantic_near_sink_window": 0x80,
        "loop_semantic_saturation_limit": 3,
        "weak_evidence_equiv_limit": 2,
    }
    config.update({key: value for key, value in dict(overrides or {}).items() if value is not None})
    command = [
        str(python),
        str(root / "advanced_sanitizer_evaluator.py"),
        str(binary_path),
        str(json_path),
        "--closure-idx", str(closure_idx),
        "--mode", "full",
        "--no-evidence-cache",
    ]
    for key, value in sorted(config.items()):
        if isinstance(value, bool):
            if value:
                command.append("--" + key.replace("_", "-"))
            continue
        command.extend(["--" + key.replace("_", "-"), str(value)])
    if fixture_path:
        command.extend(["--env-fixture-json", str(fixture_path)])
    if memory_limit_mib:
        command.extend(["--subprocess-memory-limit-mib", str(memory_limit_mib)])
    return command


def run_one(command: list[str], cwd: Path, timeout: int) -> tuple[dict[str, Any], int, float, str]:
    start = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, **DETERMINISTIC_REPLAY_ENVIRONMENT},
        )
        output = result.stdout
        parsed = parse_result_marker(output)
        return parsed, result.returncode, round(time.perf_counter() - start, 4), output[-4000:]
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "")
        if isinstance(output, bytes):
            output = output.decode("utf-8", "replace")
        return (
            {"status": "timeout", "timeout_kind": "refinement_driver_timeout", "error": str(exc)},
            124,
            round(time.perf_counter() - start, 4),
            str(output)[-4000:],
        )


def campaign_inputs(campaign_dir: Path, target: str) -> tuple[str, str]:
    summary_path = campaign_dir / f"{target}.summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    binary = summary.get("binary_path")
    mango = summary.get("json_path")
    if not binary or not mango:
        raise ValueError(f"{summary_path}: missing binary_path/json_path")
    return str(binary), str(mango)


def resolve_replay_python(value: Path | None) -> Path:
    """Keep a virtual-environment interpreter path without resolving symlinks."""
    return value.absolute() if value is not None else Path(sys.executable)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--python", type=Path, default=None)
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--max-records-per-target", type=int, default=0)
    parser.add_argument("--max-fixture-variants", type=int, default=3)
    parser.add_argument("--priority", action="append", default=[])
    parser.add_argument("--strategy", action="append", default=[])
    parser.add_argument("--include-fixture-variants", action="store_true")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--memory-limit-mib", type=int, default=0)
    parser.add_argument("--fail-on-run-errors", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    root = args.root.resolve()
    # Do not resolve the interpreter symlink: virtual-environment ``python``
    # commonly points at the system binary, and resolving it would silently
    # drop angr/claripy from the replay environment.
    python = resolve_replay_python(args.python)
    campaign_dir = args.campaign_dir.resolve()
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to reuse non-empty output directory: {out_dir}", file=sys.stderr)
        return 3
    paths = sorted(campaign_dir.glob("*.results.jsonl"))
    if args.target:
        selected = set(args.target)
        paths = [path for path in paths if path.name.removesuffix(".results.jsonl") in selected]
    if not paths:
        print("no selected campaign JSONL files found", file=sys.stderr)
        return 2
    if args.memory_limit_mib < 0:
        parser.error("--memory-limit-mib must be non-negative")
    out_dir.mkdir(parents=True, exist_ok=True)

    output_rows: list[dict[str, Any]] = []
    plan_manifest: dict[str, Any] = {"targets": {}}
    identity_paths = [root / relative for relative in REPLAY_IDENTITY_SOURCES]
    for path in paths:
        target = path.name.removesuffix(".results.jsonl")
        summary_path = campaign_dir / f"{target}.summary.json"
        binary_path, json_path = campaign_inputs(campaign_dir, target)
        binary_identity_path = Path(binary_path)
        mango_identity_path = Path(json_path)
        if not binary_identity_path.is_absolute():
            binary_identity_path = root / binary_identity_path
        if not mango_identity_path.is_absolute():
            mango_identity_path = root / mango_identity_path
        identity_paths.extend(
            [path, summary_path, binary_identity_path, mango_identity_path]
        )
    missing_identity_paths = [str(path) for path in identity_paths if not path.is_file()]
    if missing_identity_paths:
        print("missing replay identity input(s): " + ", ".join(missing_identity_paths), file=sys.stderr)
        return 2
    identity_paths = sorted(set(path.resolve() for path in identity_paths), key=str)
    preflight_identities = [file_identity(path, root) for path in identity_paths]
    fixtures_root = out_dir / "fixtures"
    logs_root = out_dir / "logs"
    for path in paths:
        target = path.name.removesuffix(".results.jsonl")
        baseline_rows = load_jsonl(path)
        by_closure = {int(row.get("closure_idx")): row for row in baseline_rows if row.get("closure_idx") is not None}
        plan = build_refinement_plan(
            baseline_rows,
            max_records=args.max_records_per_target,
            max_variants=args.max_fixture_variants,
            priorities=args.priority,
            strategies=args.strategy,
        )
        plan_manifest["targets"][target] = plan
        binary_path, json_path = campaign_inputs(campaign_dir, target)
        for planned in plan["records"]:
            closure_idx = int(planned["closure_idx"])
            baseline = by_closure[closure_idx]
            attempts: list[tuple[str, dict[str, Any] | None, Path | None]] = [("budget_only", None, None)]
            if args.include_fixture_variants:
                for variant in planned.get("fixture_variants") or []:
                    fixture_path = fixtures_root / target / f"closure_{closure_idx}_{variant['variant']}.json"
                    fixture_path.parent.mkdir(parents=True, exist_ok=True)
                    fixture_path.write_text(json.dumps(variant["fixture"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
                    attempts.append(("fixture_variant", variant, fixture_path))
            for attempt_kind, variant, fixture_path in attempts:
                command = command_for_replay(
                    python,
                    root,
                    binary_path,
                    json_path,
                    closure_idx,
                    planned.get("config_overrides") or {},
                    fixture_path=fixture_path,
                    memory_limit_mib=args.memory_limit_mib,
                )
                if args.dry_run:
                    result_obj, returncode, elapsed, output = ({"status": "not_run"}, 0, 0.0, "")
                else:
                    result_obj, returncode, elapsed, output = run_one(command, root, args.timeout)
                transition = classify_transition(baseline, result_obj, fixture_variant=variant)
                row = {
                    "target": target,
                    "attempt_kind": attempt_kind,
                    "closure_idx": closure_idx,
                    "strategy": planned.get("strategy"),
                    "priority": planned.get("priority"),
                    "fixture_path": str(fixture_path) if fixture_path else "",
                    "returncode": returncode,
                    "result_marker_present": not (
                        result_obj.get("status") == "eval_error"
                        and result_obj.get("error") == "missing RESULT_JSON marker"
                    ),
                    "elapsed_sec": elapsed,
                    "command": command,
                    "result": result_obj,
                    "transition": transition,
                }
                output_rows.append(row)
                log_path = logs_root / target / f"closure_{closure_idx}_{attempt_kind}_{variant.get('variant') if variant else 'none'}.log"
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.write_text(output, encoding="utf-8", errors="replace")

    transitions = [row["transition"] for row in output_rows]
    summary = transition_summary(transitions)
    postflight_identities = [file_identity(path, root) for path in identity_paths]
    drift = identity_drift(preflight_identities, postflight_identities)
    run_errors = sum(
        1
        for row in output_rows
        if (
            int(row.get("returncode") or 0) != 0
            or not row.get("result_marker_present")
            or str((row.get("result") or {}).get("status") or "")
            in {"timeout", "crashed", "eval_error", "state_error"}
        )
    )
    summary.update(
        {
            "schema": "tsds-residual-refinement-replay-v2",
            "campaign_dir": str(campaign_dir),
            "attempts": len(output_rows),
            "dry_run": bool(args.dry_run),
            "fixture_variants_enabled": bool(args.include_fixture_variants),
            "run_errors": run_errors,
            "identity_drift_count": len(drift),
            "identity_stable": not drift,
            "claim_boundary": (
                "Replays are separate from the baseline campaign. Fixture-conditioned results cannot enter primary evidence aggregates; "
                "unconditional results remain candidates pending the normal contract and artifact audits."
            ),
        }
    )
    (out_dir / "refinement_plan.json").write_text(json.dumps(plan_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    replay_identity_manifest = {
        "schema": "tsds-residual-replay-identity-v1",
        "deterministic_environment": DETERMINISTIC_REPLAY_ENVIRONMENT,
        "preflight": preflight_identities,
        "postflight": postflight_identities,
        "drift": drift,
        "stable": not drift,
    }
    (out_dir / "replay_identity_manifest.json").write_text(
        json.dumps(replay_identity_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "refinement_replays.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in output_rows), encoding="utf-8")
    (out_dir / "refinement_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "README.md").write_text("# TSDS residual refinement v2 replays\n\n" + summary["claim_boundary"] + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    failed = bool(
        summary["records_with_issues"]
        or drift
        or (args.fail_on_run_errors and run_errors)
    )
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
