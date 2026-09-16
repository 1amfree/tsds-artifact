#!/usr/bin/env python3
"""Atomically freeze and verify the reviewed TSDS deployment source set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.sync_tsds_sources_to_vm import SOURCE_FILES


SCHEMA = "tsds-reviewed-source-snapshot-v1"
MANIFEST_NAME = "reviewed_source_manifest.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_digest(rows: list[dict[str, Any]]) -> str:
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or path.is_absolute()
        or not path.parts
        or ".." in path.parts
        or any(part in {"", "."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise ValueError(f"unsafe reviewed source path: {value!r}")
    return path


def strict_json(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key {key!r}: {path}")
            value[key] = item
        return value

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"reviewed source manifest is not an object: {path}")
    return value


def source_entry(root: Path, relative: PurePosixPath) -> tuple[Path, dict[str, Any]]:
    source = root.joinpath(*relative.parts)
    resolved = source.resolve()
    if root != resolved and root not in resolved.parents:
        raise ValueError(f"reviewed source escapes source root: {relative}")
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"missing or unsafe reviewed source: {relative}")
    executable = bool(source.stat().st_mode & stat.S_IXUSR)
    return source, {
        "path": relative.as_posix(),
        "size": source.stat().st_size,
        "sha256": sha256_file(source),
        "executable": executable,
    }


def build_snapshot(
    source_root: Path,
    out_dir: Path,
    source_paths: Iterable[str] = SOURCE_FILES,
) -> dict[str, Any]:
    root = source_root.resolve()
    destination = out_dir.resolve()
    if destination.exists():
        raise ValueError(f"refusing to overwrite reviewed source snapshot: {destination}")
    relative_paths = [safe_relative(value) for value in source_paths]
    names = [path.as_posix() for path in relative_paths]
    if len(names) != len(set(names)):
        raise ValueError("duplicate reviewed source path")
    entries = [source_entry(root, relative) for relative in relative_paths]
    entries.sort(key=lambda item: item[1]["path"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
    installed = False
    try:
        for source, row in entries:
            relative = safe_relative(row["path"])
            target = staging.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o755 if row["executable"] else 0o644)
            if target.stat().st_size != row["size"] or sha256_file(target) != row["sha256"]:
                raise RuntimeError(f"reviewed source changed while copying: {row['path']}")
        rows = [row for _source, row in entries]
        manifest = {
            "schema": SCHEMA,
            "valid": True,
            "source_root": str(root),
            "source_files": len(rows),
            "aggregate_sha256": canonical_digest(rows),
            "files": rows,
            "claim_boundary": (
                "This snapshot binds the reviewed implementation used for post-run "
                "analysis and artifact construction; it does not establish analyzer accuracy."
            ),
        }
        (staging / MANIFEST_NAME).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(staging, destination)
        installed = True
        return validate_snapshot(destination)
    finally:
        if not installed and staging.exists():
            shutil.rmtree(staging)


def validate_snapshot(snapshot_root: Path) -> dict[str, Any]:
    root = snapshot_root.resolve()
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError(f"missing reviewed source manifest: {manifest_path}")
    manifest = strict_json(manifest_path)
    if manifest.get("schema") != SCHEMA or manifest.get("valid") is not True:
        raise ValueError("reviewed source snapshot schema or validity mismatch")
    rows = manifest.get("files")
    if not isinstance(rows, list) or not rows:
        raise ValueError("reviewed source snapshot has no file rows")
    observed: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"reviewed source row is not an object: {index}")
        relative = safe_relative(str(row.get("path") or ""))
        name = relative.as_posix()
        if name in names:
            raise ValueError(f"duplicate reviewed source snapshot path: {name}")
        names.add(name)
        path = root.joinpath(*relative.parts)
        resolved = path.resolve()
        if root not in resolved.parents or not path.is_file() or path.is_symlink():
            raise ValueError(f"missing or unsafe snapshotted source: {name}")
        expected = {
            "path": name,
            "size": row.get("size"),
            "sha256": row.get("sha256"),
            "executable": row.get("executable"),
        }
        actual = {
            "path": name,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
            "executable": bool(path.stat().st_mode & stat.S_IXUSR),
        }
        if expected != actual:
            raise ValueError(f"reviewed source snapshot drift: {name}")
        observed.append(actual)
    actual_names = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink() and path.name != MANIFEST_NAME
    }
    if actual_names != names:
        raise ValueError("reviewed source snapshot member set mismatch")
    if int(manifest.get("source_files") or -1) != len(observed):
        raise ValueError("reviewed source snapshot count mismatch")
    if manifest.get("aggregate_sha256") != canonical_digest(observed):
        raise ValueError("reviewed source snapshot aggregate hash mismatch")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = build_snapshot(args.source_root, args.out_dir)
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"REVIEWED_SOURCE_SNAPSHOT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
