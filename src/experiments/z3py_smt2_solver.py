#!/usr/bin/env python3
"""Minimal external SMT-LIB runner for query-replay receipts.

The wrapper deliberately has no dependency on the TSDS evaluator.  It parses
one exported SMT-LIB file with z3py, checks it, and prints the result (and a
model for SAT queries) in the format consumed by replay_smt_query_bundles.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import z3


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: z3py_smt2_solver.py QUERY", file=sys.stderr)
        return 2
    query = Path(sys.argv[1])
    try:
        assertions = z3.parse_smt2_file(str(query))
        solver = z3.Solver()
        solver.add(*assertions)
        result = solver.check()
    except Exception as exc:  # pragma: no cover - exercised by external replay
        print(f"query_error:{type(exc).__name__}:{exc}", file=sys.stderr)
        return 1
    print(result)
    if result == z3.sat:
        print(solver.model())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
