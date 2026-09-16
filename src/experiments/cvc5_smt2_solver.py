#!/usr/bin/env python3
"""Minimal external SMT-LIB runner backed by cvc5's Python API."""

from __future__ import annotations

import sys
from pathlib import Path

import cvc5


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: cvc5_smt2_solver.py QUERY", file=sys.stderr)
        return 2
    query = Path(sys.argv[1])
    try:
        solver = cvc5.Solver()
        parser = cvc5.InputParser(solver)
        parser.setFileInput(cvc5.InputLanguage.SMT_LIB_2_6, str(query))
        symbol_manager = parser.getSymbolManager()
        check_result = None
        model_text = None
        while True:
            command = parser.nextCommand()
            if command.isNull():
                break
            response = command.invoke(solver, symbol_manager)
            name = command.getCommandName()
            if name == "check-sat":
                check_result = str(response)
            elif name == "get-model" and response is not None:
                model_text = str(response)
    except Exception as exc:  # pragma: no cover - exercised by external replay
        print(f"query_error:{type(exc).__name__}:{exc}", file=sys.stderr)
        return 1
    if check_result is None:
        print("query_error:missing_check_sat", file=sys.stderr)
        return 1
    print(check_result)
    if model_text:
        print(model_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
