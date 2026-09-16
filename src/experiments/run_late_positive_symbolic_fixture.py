#!/usr/bin/env python3
"""Run a same-callsite symbolic fixture with a deliberately late positive."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SANITIZER_ROOT = ROOT / "Taint_demo" / "sanitizer_demo"
EVALUATOR = SANITIZER_ROOT / "advanced_sanitizer_evaluator.py"
SOURCE = ROOT / "experiments" / "fixtures" / "tsds_late_positive_fixture.c"
if str(SANITIZER_ROOT) not in sys.path:
    sys.path.insert(0, str(SANITIZER_ROOT))


def _symbol_address(binary: Path, symbol: str) -> int:
    output = subprocess.check_output(["nm", "-n", str(binary)], text=True)
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] == symbol:
            return int(fields[0], 16)
    raise RuntimeError(f"symbol not found: {symbol}")


def _system_callsite(binary: Path) -> int:
    output = subprocess.check_output(
        ["objdump", "-d", "-M", "intel", str(binary)], text=True
    )
    for line in output.splitlines():
        if "call" not in line or "<system@plt>" not in line:
            continue
        match = re.match(r"\s*([0-9a-fA-F]+):", line)
        if match:
            return int(match.group(1), 16)
    raise RuntimeError("system callsite not found")


def run(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / "tsds_late_positive_fixture"
    closure_json = out_dir / "closure.json"
    subprocess.run(
        [
            "gcc",
            "-O0",
            "-fno-inline",
            "-fno-builtin",
            "-fno-omit-frame-pointer",
            "-no-pie",
            str(SOURCE),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    source_addr = _symbol_address(binary, "tsds_late_positive_dispatch")
    sink_addr = _system_callsite(binary)
    closure_json.write_text(
        json.dumps(
            {
                "closures": [
                    {
                        "trace": [
                            {
                                "function": "tsds_late_positive_dispatch",
                                "ins_addr": hex(source_addr),
                                "string": "tsds_late_positive_dispatch(<symbolic-input>)",
                            }
                        ],
                        "sink": {
                            "function": "system",
                            "ins_addr": hex(sink_addr),
                            "string": "system(<symbolic-command>)",
                        },
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    summary_json = out_dir / "summary.json"
    results_jsonl = out_dir / "results.jsonl"
    command = [
        sys.executable,
        str(EVALUATOR),
        str(binary),
        str(closure_json),
        "--closure-idx",
        "0",
        "--multi-state-audit",
        "--multi-state-settle-steps",
        "64",
        "--engine-timeout",
        "45",
        "--max-steps",
        "300",
        "--closure-timeout",
        "240",
        "--no-evidence-cache",
        "--summary-json",
        str(summary_json),
        "--results-jsonl",
        str(results_jsonl),
    ]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    completed = subprocess.run(
        command,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    (out_dir / "stdout.log").write_text(
        completed.stdout + "\n--- STDERR ---\n" + completed.stderr,
        encoding="utf-8",
    )
    record: dict[str, Any] = {}
    if results_jsonl.exists():
        rows = [line for line in results_jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
        if rows:
            record = json.loads(rows[-1])
    audit = record.get("multi_state_audit") or {}
    profiles = audit.get("profiles") or []
    aggregate = audit.get("aggregate") or {}
    statuses = [str(profile.get("status") or "") for profile in profiles]
    late_positive = any(index > 0 and status == "VECTOR_SAT" for index, status in enumerate(statuses))
    first_nonpositive = bool(statuses) and statuses[0] != "VECTOR_SAT"
    result = {
        "schema": "tsds-late-positive-symbolic-fixture-v1",
        "returncode": completed.returncode,
        "source_addr": hex(source_addr),
        "sink_addr": hex(sink_addr),
        "profile_count": len(profiles),
        "statuses_in_collection_order": statuses,
        "first_observed_status": statuses[0] if statuses else None,
        "legacy_first_hit_status": statuses[0] if statuses else None,
        "later_positive_observed": late_positive,
        "first_profile_nonpositive": first_nonpositive,
        "collection_complete": bool(audit.get("collection_complete")),
        "aggregate_class": aggregate.get("aggregate_class"),
        "candidate_wide_negative": aggregate.get("candidate_wide_negative"),
        "primary_selection": audit.get("primary_selection"),
        "claim_boundary": (
            "Same-callsite synthetic ELF with a fixed-command and source-bearing "
            "branch; this tests bounded aggregation behavior only, not firmware "
            "ground truth or exploitability."
        ),
    }
    result["pass"] = bool(
        completed.returncode == 0
        and result["profile_count"] >= 2
        and result["later_positive_observed"]
        and result["first_profile_nonpositive"]
        and result["collection_complete"]
        and result["aggregate_class"] == "exists_positive"
        and result["candidate_wide_negative"] is False
    )
    (out_dir / "audit_summary.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.out_dir.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
