#!/usr/bin/env python3
"""External cvc5 runner for TSDS queries with Z3-only model annotations removed.

TSDS projected bundles may contain one-line ``model-add`` commands.  They
encode a producer-side model annotation rather than an assertion, and are not
accepted by cvc5's SMT-LIB parser.  This wrapper removes only those commands,
then replays the remaining declarations and assertions.  The normalization is
reported by the surrounding replay receipt and is not an exact-text replay.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import cvc5


MODEL_ADD = re.compile(r"^\s*\(model-add\b[^\n]*\)\s*$", re.MULTILINE)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: cvc5_smt2_solver_normalized.py QUERY", file=sys.stderr)
        return 2
    query = Path(sys.argv[1])
    try:
        text = query.read_text(encoding="utf-8")
        normalized = MODEL_ADD.sub("", text)
        solver = cvc5.Solver()
        solver.setOption("produce-models", "true")
        parser = cvc5.InputParser(solver)
        parser.setStringInput(
            cvc5.InputLanguage.SMT_LIB_2_6,
            normalized,
            str(query),
        )
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
