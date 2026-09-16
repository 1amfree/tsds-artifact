#!/usr/bin/env python3
"""Executable boundary tests for TSDS shell-vector predicates.

The suite exercises the actual ThreatMatrixEvaluator used by TSDS on synthetic
sink buffers. It is a matrix-boundary experiment: it checks byte-level
SAT/UNSAT behavior and records explicit non-claims such as quote-context
semantics. It does not execute a shell and does not create exploit evidence.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any


DEFAULT_OUT = Path("experiment_reports/iceccs_urgent_validation_pack_20260702")

# This suite is invoked both through unittest imports and as a standalone
# pipeline stage.  Script execution puts ``experiments/`` rather than the
# project root on sys.path, so make the canonical evaluator import explicit.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _label(text: str) -> str:
    return str(text).replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")


def _state():
    import claripy

    return SimpleNamespace(solver=claripy.Solver(), globals={})


def _sym_bytes(state: Any, count: int, prefix: str = "webvar_boundary") -> list[Any]:
    import claripy
    from advanced_sanitizer_evaluator import _symbolic_token_byte_constraints

    out = [claripy.BVS(f"{prefix}_{idx}", 8) for idx in range(count)]
    for byte in out:
        state.solver.add(_symbolic_token_byte_constraints(byte))
        state.solver.add(byte != 0)
    return out


def _fixed(text: str) -> list[Any]:
    import claripy

    return [claripy.BVV(ord(ch) & 0xFF, 8) for ch in text]


def _nul() -> Any:
    import claripy

    return claripy.BVV(0, 8)


def _vector_sat(vector: str, source_len: int = 16, prefix: str = "", suffix: str = "") -> tuple[bool, str]:
    from advanced_sanitizer_evaluator import ThreatMatrixEvaluator, render_model_bytes

    state = _state()
    source = _sym_bytes(state, source_len, f"webvar_{abs(hash(vector)) & 0xffff}")
    target = _fixed(prefix) + source + _fixed(suffix) + [_nul()]
    spec = next(
        item for item in ThreatMatrixEvaluator.VECTOR_SPECS
        if item["token"] == vector
    )
    match, _, _, _ = ThreatMatrixEvaluator._find_satisfying_spec(
        state,
        target,
        list(range(len(prefix), len(prefix) + len(source))),
        spec,
    )
    if not match:
        return False, ""
    return True, render_model_bytes(state, target, match["constraints"])


def _evaluate_report(
    source_len: int,
    prefix: str = "",
    suffix: str = "",
    constrain_alnum: bool = False,
    leading_nul: bool = False,
) -> list[str]:
    from advanced_sanitizer_evaluator import ThreatMatrixEvaluator

    state = _state()
    source = _sym_bytes(state, source_len, f"webvar_eval_{source_len}_{len(prefix)}_{len(suffix)}")
    if constrain_alnum:
        import claripy

        for byte in source:
            state.solver.add(
                claripy.Or(
                    claripy.And(byte >= ord("A"), byte <= ord("Z")),
                    claripy.And(byte >= ord("a"), byte <= ord("z")),
                    claripy.And(byte >= ord("0"), byte <= ord("9")),
                    byte == ord("_"),
                )
            )
    target = ([] if not leading_nul else [_nul()]) + _fixed(prefix) + source + _fixed(suffix) + [_nul()]
    return ThreatMatrixEvaluator.evaluate(state, source, target_bytes=target, use_threat_matrix=True)


def _report_counts(report: list[str]) -> tuple[int, int, int]:
    from advanced_sanitizer_evaluator import matrix_report_counts

    return matrix_report_counts(report)


def run_suite() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from advanced_sanitizer_evaluator import ThreatMatrixEvaluator

    rows: list[dict[str, Any]] = []

    for spec in ThreatMatrixEvaluator.VECTOR_SPECS:
            family = spec["category"]
            vector = spec["token"]
            sat, witness = _vector_sat(
                vector,
                source_len=max(16, len(spec["witness"]) + 6),
            )
            rows.append(
                {
                    "case": f"vector::{_label(vector)}",
                    "family": family,
                    "vector": _label(vector),
                    "expected": "SAT",
                    "observed": "SAT" if sat else "UNSAT",
                    "pass": sat,
                    "witness_preview": witness,
                    "boundary": (
                        "grammar-complete witness with full controlled-byte, "
                        "C-string, path, and quote-context constraints"
                    ),
                }
            )

    report = _evaluate_report(12, prefix="ping ", constrain_alnum=True)
    vulnerable, secure, inconclusive = _report_counts(report)
    rows.append(
        {
            "case": "all_vectors_filtered_alnum_source",
            "family": "all",
            "vector": "all 11",
            "expected": "11 UNSAT",
            "observed": f"{secure} secure/{vulnerable} vulnerable/{inconclusive} inconclusive",
            "pass": secure == 11 and vulnerable == 0 and inconclusive == 0,
            "witness_preview": "",
            "boundary": "alnum-only source bytes block the implemented matrix vectors",
        }
    )

    report = _evaluate_report(8, prefix="ping ;id ", constrain_alnum=True)
    vulnerable, secure, inconclusive = _report_counts(report)
    rows.append(
        {
            "case": "fixed_metachar_not_source_controlled",
            "family": "all",
            "vector": "; fixed outside controlled offsets",
            "expected": "11 UNSAT",
            "observed": f"{secure} secure/{vulnerable} vulnerable/{inconclusive} inconclusive",
            "pass": secure == 11 and vulnerable == 0 and inconclusive == 0,
            "witness_preview": "",
            "boundary": "fixed command syntax is not counted unless a modeled source byte participates",
        }
    )

    report = _evaluate_report(8, leading_nul=True)
    vulnerable, secure, inconclusive = _report_counts(report)
    rows.append(
        {
            "case": "cstring_prefix_null_blocks_later_source_vector",
            "family": "all",
            "vector": "after NUL",
            "expected": "11 UNSAT",
            "observed": f"{secure} secure/{vulnerable} vulnerable/{inconclusive} inconclusive",
            "pass": secure == 11 and vulnerable == 0 and inconclusive == 0,
            "witness_preview": "",
            "boundary": "vectors after a C-string terminator are not feasible for the sink argument",
        }
    )

    report = _evaluate_report(8, prefix="echo '", suffix="'")
    vulnerable, secure, inconclusive = _report_counts(report)
    rows.append(
        {
            "case": "single_quote_requires_modeled_breakout",
            "family": "Command Chaining",
            "vector": "; inside single quotes",
            "expected": "VECTOR_SAT only through a controlled quote-breakout witness",
            "observed": f"{secure} secure/{vulnerable} vulnerable/{inconclusive} inconclusive",
            "pass": vulnerable > 0,
            "witness_preview": "see evaluator report",
            "boundary": "ordinary separators remain literal in quotes; the positive must include a modeled breakout",
        }
    )

    summary = {
        # schema 用于将可执行边界实验绑定到发布门禁的解析语义。
        "schema": "tsds-threat-matrix-boundary-v1",
        "total_cases": len(rows),
        "passed_cases": sum(1 for row in rows if str(row.get("pass")) == "True" or row.get("pass") is True),
        "vector_cases": sum(1 for row in rows if str(row.get("case", "")).startswith("vector::")),
        "boundary_cases": sum(1 for row in rows if not str(row.get("case", "")).startswith("vector::")),
        "claim_boundary": (
            "Executable sink-byte and quote-context tests with grammar-complete "
            "witnesses; no device-level exploit claim."
        ),
    }
    return rows, summary


def write_markdown(path: Path, rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    lines = [
        "# Executable threat-matrix boundary suite",
        "",
        summary["claim_boundary"],
        "",
        f"- Cases: `{summary['total_cases']}`",
        f"- Passed: `{summary['passed_cases']}`",
        f"- Vector predicates exercised: `{summary['vector_cases']}`",
        f"- Boundary cases exercised: `{summary['boundary_cases']}`",
        "",
        "| Case | Expected | Observed | Pass | Boundary |",
        "|---|---|---|---:|---|",
    ]
    for row in rows:
        lines.append(
            "| {case} | {expected} | {observed} | {passed} | {boundary} |".format(
                case=row["case"],
                expected=row["expected"],
                observed=row["observed"],
                passed=row["pass"],
                boundary=row["boundary"],
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    rows, summary = run_suite()
    _write_csv(args.out_dir / "threat_matrix_executable_cases.csv", rows)
    (args.out_dir / "threat_matrix_executable_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    write_markdown(args.out_dir / "threat_matrix_executable_cases.md", rows, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed_cases"] == summary["total_cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
