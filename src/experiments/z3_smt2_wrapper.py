#!/usr/bin/env python3
"""Run one SMT-LIB file in a separate Z3 Python process.

This adapter exists for environments that provide the Z3 Python binding but
not the ``z3`` command-line executable.  It intentionally exposes only the
solver status and, when requested by the input, the external model text.  It
does not import the TSDS evaluator or reinterpret an unavailable solver as a
negative result.
"""

from __future__ import annotations

import sys
from pathlib import Path

import z3


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: z3_smt2_wrapper.py QUERY.smt2", file=sys.stderr)
        return 2
    query = Path(args[0])
    text = query.read_text(encoding="utf-8")
    solver = z3.Solver()
    assertions = z3.parse_smt2_file(str(query))
    if isinstance(assertions, z3.AstVector):
        solver.add(assertions)
    else:
        solver.add(*assertions)
    result = solver.check()
    print(result)
    if result == z3.sat and "(get-model)" in text:
        print("(model")
        print(solver.model().sexpr())
        print(")")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
