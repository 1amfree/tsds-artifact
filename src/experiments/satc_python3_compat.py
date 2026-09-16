#!/usr/bin/env python3
"""Run SaTC's Python-2-era front-end under a narrow Python 3 shim.

The compatibility layer deliberately provides only the historical names used
by SaTC's front-end startup path.  It does not rewrite SaTC source code,
alter candidate results, or emulate its taint engine.  Callers bind this file
in their experiment manifest so a Python 3 compatibility run remains
distinguishable from an unmodified Python 2 deployment.
"""

from __future__ import annotations

import argparse
import builtins
import importlib
import runpy
import sys
from pathlib import Path
from urllib import parse as urllib_parse


def install_compatibility() -> None:
    """Expose the two Python 2 names used by SaTC's front-end modules."""

    if not hasattr(builtins, "reload"):
        builtins.reload = importlib.reload  # type: ignore[attr-defined]
    if not hasattr(sys, "setdefaultencoding"):
        # Python 3 text is Unicode by default.  SaTC invokes this historical
        # interpreter hook during logger initialization but does not inspect
        # its return value.
        sys.setdefaultencoding = lambda _encoding: None  # type: ignore[attr-defined]
    sys.modules.setdefault("urlparse", urllib_parse)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("script_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    script = args.script.resolve()
    if not script.is_file():
        parser.error(f"missing script: {script}")
    script_args = list(args.script_args)
    if script_args[:1] == ["--"]:
        script_args = script_args[1:]
    install_compatibility()
    sys.argv = [str(script), *script_args]
    runpy.run_path(str(script), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
