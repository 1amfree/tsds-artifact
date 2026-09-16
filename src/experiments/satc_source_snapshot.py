"""Content-bound source snapshots for a native SaTC front-end run."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "tsds-satc-source-snapshot-v1"
TOP_LEVEL_FILES = ("Dockerfile", "README.md", "README_CN.md", "init.sh")
SOURCE_MANIFESTS = ("src/requirements.txt", "src/front_analysise/requirements.txt")
SOURCE_SUFFIXES = {".py", ".js", ".json"}
EXCLUDED_PARTS = {".git", "__pycache__", "node_modules"}


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
        raise ValueError(f"unsafe source snapshot path: {value!r}")
    return path


def source_paths(satc_root: Path) -> list[Path]:
    root = satc_root.resolve()
    source = root / "src"
    if not source.is_dir():
        raise ValueError(f"SaTC source directory missing: {source}")
    paths = [
        item
        for item in source.rglob("*")
        if item.is_file()
        and not item.is_symlink()
        and item.suffix.lower() in SOURCE_SUFFIXES
        and not set(item.relative_to(root).parts).intersection(EXCLUDED_PARTS)
    ]
    for name in TOP_LEVEL_FILES:
        path = root / name
        if path.is_file() and not path.is_symlink():
            paths.append(path)
    for name in SOURCE_MANIFESTS:
        path = root / name
        if path.is_file() and not path.is_symlink():
            paths.append(path)
    return sorted(set(paths), key=lambda item: item.relative_to(root).as_posix())


def build_snapshot(satc_root: Path) -> dict[str, Any]:
    root = satc_root.resolve()
    rows = [
        {
            "path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in source_paths(root)
    ]
    if not rows:
        raise ValueError(f"SaTC source snapshot is empty: {root}")
    return {
        "schema": SCHEMA,
        "valid": True,
        "source_root": str(root),
        "files": rows,
        "source_files": len(rows),
        "aggregate_sha256": canonical_digest(rows),
        "selection": {
            "root": "src",
            "suffixes": sorted(SOURCE_SUFFIXES),
            "excluded_path_parts": sorted(EXCLUDED_PARTS),
            "top_level_files": list(TOP_LEVEL_FILES),
            "source_manifests": list(SOURCE_MANIFESTS),
        },
        "claim_boundary": (
            "The snapshot binds the front-end source files exercised by a native "
            "SaTC ingestion run. It does not establish candidate accuracy."
        ),
    }


def load_snapshot(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key {key!r}: {path}")
            value[key] = item
        return value

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"source snapshot is not an object: {path}")
    return value


def validate_snapshot(path: Path, satc_root: Path) -> dict[str, Any]:
    snapshot = load_snapshot(path)
    if snapshot.get("schema") != SCHEMA or snapshot.get("valid") is not True:
        raise ValueError("SaTC source snapshot schema or validity check failed")
    rows = snapshot.get("files")
    if not isinstance(rows, list) or not rows:
        raise ValueError("SaTC source snapshot has no file rows")
    root = satc_root.resolve()
    expected_names = [path.relative_to(root).as_posix() for path in source_paths(root)]
    observed: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"SaTC source snapshot row is not an object: {index}")
        relative = safe_relative(str(row.get("path") or ""))
        name = relative.as_posix()
        if name in names:
            raise ValueError(f"duplicate SaTC source snapshot path: {name}")
        names.add(name)
        source = root.joinpath(*relative.parts)
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"snapshotted SaTC source is missing or unsafe: {name}")
        expected_size = row.get("size")
        expected_hash = row.get("sha256")
        if not isinstance(expected_size, int) or expected_size < 0:
            raise ValueError(f"invalid SaTC source snapshot size: {name}")
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            raise ValueError(f"invalid SaTC source snapshot hash: {name}")
        observed_row = {"path": name, "size": source.stat().st_size, "sha256": sha256_file(source)}
        if observed_row != {"path": name, "size": expected_size, "sha256": expected_hash}:
            raise ValueError(f"SaTC source snapshot drift: {name}")
        observed.append(observed_row)
    if [row["path"] for row in observed] != expected_names:
        raise ValueError("SaTC source snapshot does not cover the current source set")
    if snapshot.get("aggregate_sha256") != canonical_digest(observed):
        raise ValueError("SaTC source snapshot aggregate hash mismatch")
    return snapshot
