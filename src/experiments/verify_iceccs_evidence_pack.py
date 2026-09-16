#!/usr/bin/env python3
"""Verify the integrity of the evidence-only ICECCS completion index."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    failures: list[dict[str, str]] = []
    checks: list[dict[str, Any]] = []
    for artifact in manifest.get("artifacts", []):
        relative = str(artifact["path"])
        path = (manifest_path.parent / relative).resolve()
        expected = str(artifact["sha256"])
        if not path.is_file():
            failures.append({"name": artifact["name"], "reason": "missing", "path": str(path)})
            continue
        actual = sha256(path)
        ok = actual == expected
        checks.append({
            "name": artifact["name"],
            "path": str(path),
            "expected_sha256": expected,
            "actual_sha256": actual,
            "pass": ok,
        })
        if not ok:
            failures.append({"name": artifact["name"], "reason": "sha256_mismatch", "path": str(path)})

    return {
        "schema": "tsds-iceccs-evidence-completion-verification-v1",
        "manifest": str(manifest_path.resolve()),
        "artifact_count": len(checks),
        "failed_count": len(failures),
        "pass": not failures and bool(checks),
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = verify(args.manifest)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
