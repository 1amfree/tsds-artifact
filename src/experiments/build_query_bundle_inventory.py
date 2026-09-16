#!/usr/bin/env python3
"""Create a content commitment for an exported SMT query bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_inventory(bundle_dir: Path, label: str) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for path in sorted(p for p in bundle_dir.rglob("*") if p.is_file()):
        relative = path.relative_to(bundle_dir).as_posix()
        files.append({
            "path": relative,
            "size": path.stat().st_size,
            "sha256": _sha256(path),
        })
    commitment_input = "".join(f"{row['sha256']}  {row['path']}\n" for row in files).encode("utf-8")
    return {
        "schema": "tsds-query-bundle-inventory-v1",
        "label": label,
        "bundle_dir": str(bundle_dir.resolve()),
        "file_count": len(files),
        "byte_count": sum(int(row["size"]) for row in files),
        "manifest_count": sum(str(row["path"]).endswith(".manifest.json") for row in files),
        "extension_counts": dict(sorted(Counter(Path(str(row["path"])).suffix for row in files).items())),
        "content_commitment_sha256": hashlib.sha256(commitment_input).hexdigest(),
        "files": files,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not args.bundle_dir.is_dir():
        parser.error(f"missing bundle directory: {args.bundle_dir}")
    result = build_inventory(args.bundle_dir, args.label)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("file_count", "byte_count", "manifest_count", "content_commitment_sha256")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
