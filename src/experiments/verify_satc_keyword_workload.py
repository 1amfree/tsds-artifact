#!/usr/bin/env python3
"""Bind a freshly reproduced SaTC keyword workload to a prior workload file."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "tsds-satc-keyword-workload-identity-v1"


def file_identity(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"missing or unsafe keyword workload: {resolved}")
    digest = hashlib.sha256()
    with resolved.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {
        "path": str(resolved),
        "size": resolved.stat().st_size,
        "sha256": digest.hexdigest(),
    }


def verify_workload(candidate: Path, reference: Path) -> dict[str, Any]:
    candidate_identity = file_identity(candidate)
    reference_identity = file_identity(reference)
    identical = (
        candidate_identity["size"] == reference_identity["size"]
        and candidate_identity["sha256"] == reference_identity["sha256"]
    )
    return {
        "schema": SCHEMA,
        "candidate": candidate_identity,
        "reference": reference_identity,
        "identical": identical,
        "claim_boundary": (
            "This check binds two keyword workload files by content. It does not "
            "establish candidate accuracy, frontend completeness, or TSDS outcomes."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-identical", action="store_true")
    args = parser.parse_args()
    try:
        document = verify_workload(args.candidate, args.reference)
        output = args.output.resolve()
        if output.exists():
            raise ValueError(f"refusing to reuse output: {output}")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, TypeError, ValueError) as exc:
        print(f"SATC_KEYWORD_WORKLOAD_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(document, indent=2, sort_keys=True))
    return 3 if args.require_identical and not document["identical"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
