#!/usr/bin/env python3
"""Ensure broad evaluator exception handlers never swallow MemoryError."""

from __future__ import annotations

import argparse
import os
import re
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGET = PROJECT_ROOT / "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py"
EXCEPT_EXCEPTION = re.compile(
    r"^(?P<indent>[ \t]*)except Exception(?P<suffix>(?: as [A-Za-z_][A-Za-z0-9_]*)?):(?P<tail>.*)$"
)


def transform(text: str) -> tuple[str, int]:
    lines = text.splitlines(keepends=True)
    transformed: list[str] = []
    inserted = 0
    for line in lines:
        match = EXCEPT_EXCEPTION.match(line.rstrip("\r\n"))
        if match:
            previous = [value.strip() for value in transformed[-2:]]
            already_guarded = previous == ["except MemoryError:", "raise"]
            if not already_guarded:
                newline = "\r\n" if line.endswith("\r\n") else "\n"
                indent = match.group("indent")
                transformed.append(f"{indent}except MemoryError:{newline}")
                transformed.append(f"{indent}    raise{newline}")
                inserted += 1
        transformed.append(line)
    return "".join(transformed), inserted


def write_atomic(path: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    target = args.target.resolve()
    text = target.read_text(encoding="utf-8")
    transformed, inserted = transform(text)
    if args.apply and inserted:
        write_atomic(target, transformed)
    print(f"unguarded_exception_handlers={inserted}")
    return 1 if inserted and not args.apply else 0


if __name__ == "__main__":
    raise SystemExit(main())
