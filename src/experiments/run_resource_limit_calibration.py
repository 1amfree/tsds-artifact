#!/usr/bin/env python3
"""Calibrate per-closure TSDS memory limits on selected stress records.

The runner never merges calibration outcomes into a primary campaign.  It
replays an explicit closure/limit matrix, preserves raw logs, and reports
whether each isolated worker emitted a complete resource-bearing ledger row.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CALIBRATION_SCHEMA = "tsds-resource-limit-calibration-v2"
DETERMINISTIC_CALIBRATION_ENVIRONMENT = {
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "LC_ALL": "C",
    "LANG": "C",
    "TZ": "UTC",
}


def file_identity(path: Path, root: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    resolved = path.resolve()
    try:
        display = str(resolved.relative_to(root.resolve()))
    except ValueError:
        display = str(resolved)
    return {"path": display, "size": resolved.stat().st_size, "sha256": digest.hexdigest()}


def query_python_environment(python: Path, cwd: Path) -> dict[str, Any]:
    code = r'''
import importlib.metadata as md, json, platform, sys
packages = {}
for name in ("angr", "claripy", "unicorn", "z3-solver"):
    try:
        packages[name] = md.version(name)
    except md.PackageNotFoundError:
        packages[name] = None
print(json.dumps({
    "executable": sys.executable,
    "python": platform.python_version(),
    "implementation": platform.python_implementation(),
    "packages": packages,
}, sort_keys=True))
'''
    proc = subprocess.run(
        [str(python), "-c", code],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env={**os.environ, **DETERMINISTIC_CALIBRATION_ENVIRONMENT},
    )
    if proc.returncode:
        return {"query_returncode": proc.returncode, "query_stderr": proc.stderr.strip()}
    return json.loads(proc.stdout)


def parse_result_marker(output: str) -> dict[str, Any] | None:
    for line in reversed(str(output or "").splitlines()):
        if not line.startswith("RESULT_JSON: "):
            continue
        try:
            value = json.loads(line[len("RESULT_JSON: "):])
        except json.JSONDecodeError:
            return None
        return value if isinstance(value, dict) else None
    return None


def build_calibration_command(
    python: Path,
    evaluator: Path,
    binary: Path,
    mango: Path,
    closure_idx: int,
    limit_mib: int,
) -> list[str]:
    return [
        str(python), "-u", str(evaluator), str(binary), str(mango),
        "--closure-idx", str(closure_idx),
        "--mode", "full",
        "--engine-timeout", "45",
        "--max-steps", "500",
        "--closure-timeout", "90",
        "--seed-equiv-limit", "2",
        "--no-taint-equiv-limit", "3",
        "--stagnation-limit", "10",
        "--semantic-frontier-min-states", "12",
        "--semantic-frontier-bucket-limit", "2",
        "--semantic-frontier-period", "2",
        "--source-liveness-limit", "4",
        "--source-dead-state-cap", "20",
        "--loop-semantic-min-states", "50",
        "--loop-semantic-min-visits", "3",
        "--loop-semantic-bucket-limit", "1",
        "--loop-semantic-period", "1",
        "--loop-semantic-near-sink-window", "128",
        "--loop-semantic-saturation-limit", "3",
        "--weak-evidence-equiv-limit", "2",
        "--subprocess-memory-limit-mib", str(limit_mib),
        "--no-evidence-cache",
    ]


def run_case(command: list[str], cwd: Path, timeout: int) -> tuple[dict[str, Any], str]:
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, **DETERMINISTIC_CALIBRATION_ENVIRONMENT},
        )
        output = proc.stdout
        result = parse_result_marker(output)
        row = {
            "returncode": proc.returncode,
            "driver_timeout": False,
            "elapsed_sec": round(time.perf_counter() - started, 4),
            "marker_present": result is not None,
            "result": result,
            "memory_error_observed": "MemoryError" in output,
        }
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", "replace")
        row = {
            "returncode": 124,
            "driver_timeout": True,
            "elapsed_sec": round(time.perf_counter() - started, 4),
            "marker_present": False,
            "result": None,
            "memory_error_observed": "MemoryError" in output,
        }
    return row, str(output)


def accepted_case(row: dict[str, Any], limit_mib: int) -> bool:
    result = row.get("result") or {}
    return bool(
        row.get("returncode") == 0
        and row.get("marker_present")
        and result.get("subprocess_memory_limit_mib") == limit_mib
        and result.get("resource_limit_enforcement") == "enforced"
        and not result.get("resource_limit_hit")
        and result.get("process_peak_rss_mib") is not None
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--python", type=Path)
    parser.add_argument("--evaluator", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--mango", type=Path, required=True)
    parser.add_argument("--closure-idx", type=int, action="append", required=True)
    parser.add_argument("--limit-mib", type=int, action="append", required=True)
    parser.add_argument(
        "--required-limit-mib",
        type=int,
        action="append",
        default=[],
        help="Limit whose cases must all pass when --fail-on-unaccepted is set; repeatable. Defaults to every tested limit.",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--fail-on-unaccepted", action="store_true")
    args = parser.parse_args()

    root = args.root.resolve()
    python = args.python.absolute() if args.python else root / "operation-mango-public/.venv/bin/python"
    evaluator = args.evaluator.resolve() if args.evaluator else root / "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py"
    binary = args.binary if args.binary.is_absolute() else root / args.binary
    mango = args.mango if args.mango.is_absolute() else root / args.mango
    limits = sorted(set(args.limit_mib))
    required_limits = sorted(set(args.required_limit_mib or limits))
    closures = sorted(set(args.closure_idx))
    if any(limit <= 0 for limit in limits) or any(idx < 0 for idx in closures):
        parser.error("limits must be positive and closure indices non-negative")
    if not set(required_limits).issubset(limits):
        parser.error("--required-limit-mib must also be selected with --limit-mib")
    for path in (python, evaluator, binary, mango):
        if not path.is_file():
            parser.error(f"missing input: {path}")
    identity_paths = [
        python,
        evaluator,
        binary,
        mango,
        Path(__file__).resolve(),
    ]
    preflight_identities = [file_identity(path, root) for path in identity_paths]
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to reuse non-empty output directory: {out_dir}", file=sys.stderr)
        return 3
    logs = out_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    for limit_mib in limits:
        for closure_idx in closures:
            command = build_calibration_command(
                python, evaluator, binary, mango, closure_idx, limit_mib
            )
            outcome, output = run_case(command, root, args.timeout)
            outcome.update({
                "schema": CALIBRATION_SCHEMA,
                "closure_idx": closure_idx,
                "limit_mib": limit_mib,
                "command": command,
            })
            outcome["accepted"] = accepted_case(outcome, limit_mib)
            rows.append(outcome)
            (logs / f"closure_{closure_idx}_limit_{limit_mib}.log").write_text(
                output, encoding="utf-8", errors="replace"
            )

    accepted_by_limit = Counter({str(limit): 0 for limit in limits})
    cases_by_limit = Counter({str(limit): 0 for limit in limits})
    markers_by_limit = Counter({str(limit): 0 for limit in limits})
    memory_errors_by_limit = Counter({str(limit): 0 for limit in limits})
    for row in rows:
        key = str(row["limit_mib"])
        cases_by_limit[key] += 1
        if row["accepted"]:
            accepted_by_limit[key] += 1
        if row["marker_present"]:
            markers_by_limit[key] += 1
        if row["memory_error_observed"]:
            memory_errors_by_limit[key] += 1
    required_rows = [row for row in rows if row["limit_mib"] in required_limits]
    required_cases_accepted = bool(required_rows) and all(row["accepted"] for row in required_rows)
    postflight_identities = [file_identity(path, root) for path in identity_paths]
    input_identity_stable = preflight_identities == postflight_identities
    summary = {
        "schema": CALIBRATION_SCHEMA,
        "cases": len(rows),
        "closures": closures,
        "limits_mib": limits,
        "required_limits_mib": required_limits,
        "accepted_cases": sum(int(row["accepted"]) for row in rows),
        "accepted_by_limit": dict(sorted(accepted_by_limit.items(), key=lambda item: int(item[0]))),
        "cases_by_limit": dict(sorted(cases_by_limit.items(), key=lambda item: int(item[0]))),
        "markers_by_limit": dict(sorted(markers_by_limit.items(), key=lambda item: int(item[0]))),
        "memory_errors_by_limit": dict(sorted(memory_errors_by_limit.items(), key=lambda item: int(item[0]))),
        "all_cases_accepted": all(row["accepted"] for row in rows),
        "required_cases_accepted": required_cases_accepted,
        "input_identity_stable": input_identity_stable,
        "reproducibility": {
            "host": {
                "platform": platform.platform(),
                "machine": platform.machine(),
                "processor": platform.processor(),
            },
            "python_version": platform.python_version(),
            "requested_python": str(python),
            "python_environment": query_python_environment(python, root),
            "deterministic_environment": DETERMINISTIC_CALIBRATION_ENVIRONMENT,
            "preflight_identities": preflight_identities,
            "postflight_identities": postflight_identities,
        },
        "claim_boundary": (
            "Calibration selects a process resource envelope for the tested stress records. "
            "It does not alter or promote sink-byte evidence claims."
        ),
    }
    (out_dir / "resource_limit_calibration.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
    )
    (out_dir / "resource_limit_calibration_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        "# TSDS resource-limit calibration\n\n" + summary["claim_boundary"] + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.fail_on_unaccepted and not (
        required_cases_accepted and input_identity_stable
    ) else 0


if __name__ == "__main__":
    raise SystemExit(main())
