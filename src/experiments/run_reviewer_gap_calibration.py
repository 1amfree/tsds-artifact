#!/usr/bin/env python3
"""Bounded calibration for the reviewer-identified TSDS evidence gaps.

The script has two independent tracks:

* a closed, synthetic matrix oracle with fresh Z3 replay and SMT-LIB output;
* an opt-in multi-state run over one same-callsite synthetic ELF.

Neither track is a firmware vulnerability benchmark.  The result is useful
only for the stated calibration scopes and is deliberately written with those
boundaries in the output metadata.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SANITIZER_ROOT = PROJECT_ROOT / "Taint_demo" / "sanitizer_demo"
EVALUATOR = SANITIZER_ROOT / "advanced_sanitizer_evaluator.py"
FIXTURE_SOURCE = PROJECT_ROOT / "experiments" / "fixtures" / "tsds_multistate_fixture.c"

if str(SANITIZER_ROOT) not in sys.path:
    sys.path.insert(0, str(SANITIZER_ROOT))


def _state() -> Any:
    import claripy

    return SimpleNamespace(solver=claripy.Solver(), globals={})


def _symbolic_source(state: Any, count: int, prefix: str, alnum_only: bool = False) -> list[Any]:
    import claripy
    from advanced_sanitizer_evaluator import _symbolic_token_byte_constraints

    source = [claripy.BVS(f"{prefix}_{index}", 8) for index in range(count)]
    for byte in source:
        state.solver.add(_symbolic_token_byte_constraints(byte))
        state.solver.add(byte != 0)
        if alnum_only:
            state.solver.add(
                claripy.Or(
                    claripy.And(byte >= ord("A"), byte <= ord("Z")),
                    claripy.And(byte >= ord("a"), byte <= ord("z")),
                    claripy.And(byte >= ord("0"), byte <= ord("9")),
                    byte == ord("_"),
                )
            )
    return source


def _fixed(text: str) -> list[Any]:
    import claripy

    return [claripy.BVV(ord(char) & 0xFF, 8) for char in text]


def _nul() -> Any:
    import claripy

    return claripy.BVV(0, 8)


def _matrix_case(case_id: str, kind: str, *, vector: str = "", prefix: str = "", suffix: str = "", alnum_only: bool = False, unknown_prefix: bool = False, leading_nul: bool = False) -> dict[str, Any]:
    import claripy
    from advanced_sanitizer_evaluator import ThreatMatrixEvaluator

    state = _state()
    source_len = max(24, len(vector) + 16)
    source = _symbolic_source(state, source_len, f"calibration_{case_id}", alnum_only=alnum_only)
    before = []
    if leading_nul:
        before.append(_nul())
    before.extend(_fixed(prefix))
    if unknown_prefix:
        before.append(claripy.BVS(f"unknown_quote_{case_id}", 8))
    target = before + source + _fixed(suffix) + [_nul()]
    ThreatMatrixEvaluator.evaluate(
        state,
        source,
        target_bytes=target,
        use_threat_matrix=True,
    )
    decisions = list(state.globals.get("threat_matrix_decisions", []) or [])
    expected = {
        "positive": "VECTOR_SAT",
        "quote_breakout": "VECTOR_SAT",
        "alnum_only": "MATRIX_UNSAT",
        "fixed_metachar": "MATRIX_UNSAT",
        "after_nul": "MATRIX_UNSAT",
        "unknown_quote": "INCONCLUSIVE",
    }[kind]
    return {
        "case_id": case_id,
        "kind": kind,
        "state": state,
        "source": source,
        "target": target,
        "decisions": decisions,
        "expected": expected,
        "vector": vector,
    }


def _z3_replay(state: Any, extra: list[Any], out_path: Path) -> dict[str, Any]:
    import claripy
    import z3

    solver = z3.Solver()
    converted = [
        claripy.backends.z3.convert(expression)
        for expression in list(state.solver.constraints) + list(extra)
    ]
    solver.add(*converted)
    smt2 = solver.sexpr() + "\n"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(smt2, encoding="utf-8")
    check = solver.check()
    return {
        "independent_decision": "SAT" if check == z3.sat else "UNSAT" if check == z3.unsat else "UNKNOWN",
        "query_sha256": hashlib.sha256(smt2.encode("utf-8")).hexdigest(),
        "constraint_count": len(converted),
        "smt2_path": str(out_path),
    }


def run_matrix_replay(out_dir: Path) -> dict[str, Any]:
    from advanced_sanitizer_evaluator import ThreatMatrixEvaluator

    cases: list[dict[str, Any]] = []
    for spec in ThreatMatrixEvaluator.VECTOR_SPECS:
        cases.append(
            _matrix_case(
                f"positive_{spec['id']}",
                "positive",
                vector=spec["token"],
            )
        )
    cases.extend(
        [
            _matrix_case("boundary_alnum_only", "alnum_only", prefix="ping ", alnum_only=True),
            _matrix_case(
                "boundary_fixed_metachar",
                "fixed_metachar",
                prefix="ping ;id ",
                alnum_only=True,
            ),
            _matrix_case("boundary_after_nul", "after_nul", leading_nul=True),
            _matrix_case(
                "boundary_unknown_quote",
                "unknown_quote",
                prefix="echo ",
                unknown_prefix=True,
            ),
            _matrix_case(
                "quote_breakout",
                "quote_breakout",
                prefix="echo '",
                suffix="'",
            ),
        ]
    )

    rows: list[dict[str, Any]] = []
    replay_cells = 0
    replay_matches = 0
    ground_truth_matches = 0
    query_dir = out_dir / "smt2"
    for case in cases:
        decisions_by_id = {
            str(row.get("vector_id")): row for row in case["decisions"]
        }
        for spec in ThreatMatrixEvaluator.VECTOR_SPECS:
            observed_row = decisions_by_id.get(spec["id"], {})
            observed = str(observed_row.get("decision") or "MISSING")
            ground_truth = case["expected"]
            ground_truth_ok = observed == ground_truth
            ground_truth_matches += int(ground_truth_ok)

            replay = None
            replay_ok = None
            if case["kind"] not in {"after_nul", "unknown_quote"}:
                controlled = list(
                    case["state"].globals.get(
                        "threat_matrix_controlled_offsets", []
                    )
                    or []
                )
                candidates, _ = ThreatMatrixEvaluator._candidate_descriptors(
                    case["state"],
                    case["target"],
                    controlled,
                    spec,
                )
                candidate_constraints = [candidate["constraint"] for candidate in candidates]
                if candidate_constraints:
                    import claripy

                    aggregate = claripy.Or(*candidate_constraints)
                    replay = _z3_replay(
                        case["state"],
                        [aggregate],
                        query_dir / f"{case['case_id']}__{spec['id']}.smt2",
                    )
                    expected_replay = "SAT" if ground_truth == "VECTOR_SAT" else "UNSAT"
                    replay_ok = (
                        replay["independent_decision"] == expected_replay
                        and ((observed == "VECTOR_SAT") == (expected_replay == "SAT"))
                    )
                    replay_cells += 1
                    replay_matches += int(replay_ok)

            rows.append(
                {
                    "case_id": case["case_id"],
                    "kind": case["kind"],
                    "vector_id": spec["id"],
                    "observed": observed,
                    "ground_truth": ground_truth,
                    "ground_truth_pass": ground_truth_ok,
                    "solver_replay": replay["independent_decision"] if replay else "NOT_APPLICABLE",
                    "solver_replay_pass": replay_ok,
                    "query_sha256": replay["query_sha256"] if replay else "",
                }
            )

    summary = {
        "schema": "tsds-reviewer-gap-matrix-replay-v1",
        "cases": len(cases),
        "vectors": len(ThreatMatrixEvaluator.VECTOR_SPECS),
        "cells": len(rows),
        "ground_truth_passed": ground_truth_matches,
        "ground_truth_total": len(rows),
        "solver_replay_cells": replay_cells,
        "solver_replay_passed": replay_matches,
        "solver_replay_total": replay_cells,
        "all_ground_truth_pass": ground_truth_matches == len(rows),
        "all_solver_replay_pass": replay_matches == replay_cells,
        "claim_boundary": (
            "Closed synthetic matrix semantic calibration with hand-specified "
            "construction labels and fresh Z3 replay; not firmware accuracy, "
            "vulnerability ground truth, or exploitability."
        ),
    }
    (out_dir / "matrix_replay_cases.json").write_text(
        json.dumps(rows, indent=2, sort_keys=True), encoding="utf-8"
    )
    (out_dir / "matrix_replay_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    return summary


def _symbol_address(binary: Path, symbol: str) -> int:
    output = subprocess.check_output(["nm", "-an", str(binary)], text=True)
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
        if "call" not in line or (
            "<system@plt>" not in line and "<system>" not in line
        ):
            continue
        match = re.match(r"\s*([0-9a-fA-F]+):", line)
        if match:
            return int(match.group(1), 16)
    raise RuntimeError("system callsite not found")


def run_multistate_audit(out_dir: Path) -> dict[str, Any]:
    fixture_dir = out_dir / "fixture"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    binary = fixture_dir / (
        "tsds_multistate_fixture.exe" if os.name == "nt" else "tsds_multistate_fixture"
    )
    closure_json = fixture_dir / "closure.json"
    compile_command = [
        "gcc",
        "-O0",
        "-fno-inline",
        "-fno-builtin",
        "-fno-omit-frame-pointer",
        "-no-pie",
        str(FIXTURE_SOURCE),
        "-o",
        str(binary),
    ]
    subprocess.run(compile_command, check=True, capture_output=True, text=True)
    source_addr = _symbol_address(binary, "tsds_multistate_dispatch")
    sink_addr = _system_callsite(binary)
    closure_json.write_text(
        json.dumps(
            {
                "closures": [
                    {
                        "trace": [
                            {
                                "function": "tsds_multistate_dispatch",
                                "ins_addr": hex(source_addr),
                                "string": "tsds_multistate_dispatch(<symbolic-input>)",
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

    summary_json = out_dir / "multistate_summary.json"
    results_jsonl = out_dir / "multistate_results.jsonl"
    log_path = out_dir / "multistate_stdout.log"
    command = [
        sys.executable,
        str(EVALUATOR),
        str(binary),
        str(closure_json),
        "--closure-idx",
        "0",
        "--multi-state-audit",
        "--multi-state-settle-steps",
        "32",
        "--engine-timeout",
        "40",
        "--max-steps",
        "240",
        "--closure-timeout",
        "180",
        "--no-evidence-cache",
        "--summary-json",
        str(summary_json),
        "--results-jsonl",
        str(results_jsonl),
    ]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SANITIZER_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    completed = subprocess.run(
        command,
        env=env,
        capture_output=True,
        text=True,
        timeout=240,
    )
    log_path.write_text(
        completed.stdout + "\n--- STDERR ---\n" + completed.stderr,
        encoding="utf-8",
    )
    result_record: dict[str, Any] = {}
    if results_jsonl.exists():
        lines = [line for line in results_jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            result_record = json.loads(lines[-1])
    audit = result_record.get("multi_state_audit") or {}
    aggregate = audit.get("aggregate") or {}
    profiles = audit.get("profiles") or []
    distinct_profiles = len({profile.get("profile_fingerprint") for profile in profiles})
    summary = {
        "schema": "tsds-reviewer-gap-multistate-v1",
        "returncode": completed.returncode,
        "source_addr": hex(source_addr),
        "sink_addr": hex(sink_addr),
        "profile_count": len(profiles),
        "distinct_profile_count": distinct_profiles,
        "engine_run_count": audit.get("engine_run_count", 0),
        "collection_complete": bool(audit.get("collection_complete")),
        "aggregate_class": aggregate.get("aggregate_class", "missing"),
        "candidate_wide_negative": aggregate.get("candidate_wide_negative"),
        "statuses": sorted({str(profile.get("status")) for profile in profiles}),
        "pass": bool(
            completed.returncode == 0
            and len(profiles) >= 2
            and distinct_profiles >= 2
            and aggregate.get("aggregate_class") == "exists_positive"
            and aggregate.get("candidate_wide_negative") is False
        ),
        "claim_boundary": (
            "One same-callsite synthetic ELF; bounded sink-instance collection "
            "and existential aggregation only. It does not establish exhaustive "
            "multi-state coverage or firmware exploitability."
        ),
    }
    (out_dir / "multistate_audit_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    return summary


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    fields = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("experiment_reports/saner2027_reviewer_gap_calibration_20260913"),
    )
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    matrix = run_matrix_replay(args.out_dir / "matrix")
    multistate = run_multistate_audit(args.out_dir / "multistate")
    (args.out_dir / "summary.json").write_text(
        json.dumps(
            {
                "schema": "tsds-reviewer-gap-calibration-v1",
                "matrix": matrix,
                "multistate": multistate,
                "overall_pass": bool(
                    matrix["all_ground_truth_pass"]
                    and matrix["all_solver_replay_pass"]
                    and multistate["pass"]
                ),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    _write_csv(
        args.out_dir / "matrix" / "matrix_replay_cases.csv",
        json.loads((args.out_dir / "matrix" / "matrix_replay_cases.json").read_text(encoding="utf-8")),
    )
    print(json.dumps({"matrix": matrix, "multistate": multistate}, indent=2, sort_keys=True))
    return 0 if matrix["all_ground_truth_pass"] and matrix["all_solver_replay_pass"] and multistate["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
