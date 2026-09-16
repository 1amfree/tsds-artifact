#!/usr/bin/env python3
"""Build a deterministic, content-addressed TSDS artifact archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "tsds-deterministic-artifact-archive-v1"
CONTENTS_NAME = "ARTIFACT_CONTENTS.json"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_inputs(specs: list[str]) -> list[tuple[str, Path]]:
    """解析并拒绝任何可被不同平台歧义解释的归档输入。"""

    rows = []
    prefixes: set[str] = set()
    roots: set[Path] = set()
    for spec in specs:
        if "=" not in spec:
            raise ValueError(f"input must use PREFIX=PATH syntax: {spec}")
        prefix, raw_path = spec.split("=", 1)
        prefix = prefix.strip()
        pure = PurePosixPath(prefix)
        if (
            not prefix
            or "\\" in prefix
            or "\x00" in prefix
            or not pure.parts
            or pure.is_absolute()
            or ".." in pure.parts
            or any(part in {"", "."} for part in pure.parts)
            or pure.as_posix() != prefix
        ):
            raise ValueError(f"unsafe archive prefix: {prefix!r}")
        unresolved = Path(raw_path).expanduser()
        if unresolved.is_symlink():
            raise ValueError(f"top-level symlink input is not allowed: {unresolved}")
        path = unresolved.resolve()
        if not path.exists():
            raise ValueError(f"input does not exist: {path}")
        if prefix in prefixes:
            raise ValueError(f"duplicate archive prefix: {prefix}")
        if path in roots:
            raise ValueError(f"duplicate input path: {path}")
        prefixes.add(prefix)
        roots.add(path)
        rows.append((prefix, path))
    if not rows:
        raise ValueError("at least one input is required")
    return rows


def collect_members(inputs: list[tuple[str, Path]]) -> list[dict[str, Any]]:
    """枚举普通文件并计算内容身份；符号链接始终失败关闭。"""

    members = []
    names: set[str] = set()
    for prefix, root in inputs:
        if root.is_symlink():
            raise ValueError(f"top-level symlink input is not allowed: {root}")
        paths = [root] if root.is_file() else sorted(root.rglob("*"))
        for path in paths:
            if path.is_symlink():
                raise ValueError(f"symlink members are not allowed: {path}")
            if not path.is_file():
                continue
            relative = path.name if root.is_file() else path.relative_to(root).as_posix()
            arcname = (PurePosixPath(prefix) / relative).as_posix()
            if arcname in names or arcname == CONTENTS_NAME:
                raise ValueError(f"duplicate or reserved archive member: {arcname}")
            names.add(arcname)
            members.append(
                {
                    "path": arcname,
                    "source": path,
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                    "executable": bool(path.stat().st_mode & 0o111),
                }
            )
    if not members:
        raise ValueError("inputs contain no regular files")
    return sorted(members, key=lambda row: row["path"])


def member_identity(members: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """剥离本地 source 路径，生成归档前后可比较的成员身份。"""

    return [
        {key: row[key] for key in ("path", "size", "sha256", "executable")}
        for row in members
    ]


def output_inside_inputs(output: Path, inputs: list[tuple[str, Path]]) -> bool:
    """判断输出是否位于任一输入树内，避免归档自包含和集合漂移。"""

    output = output.resolve()
    for _prefix, raw_root in inputs:
        root = raw_root.resolve()
        if output == root or (root.is_dir() and root in output.parents):
            return True
    return False


def add_bytes(archive: tarfile.TarFile, arcname: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(arcname)
    info.size = len(data)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def build_archive(inputs: list[tuple[str, Path]], archive_path: Path) -> dict[str, Any]:
    """事务式构建归档，并复核构建前后的完整成员集合。"""

    archive_path = archive_path.resolve()
    if archive_path.exists():
        raise ValueError(f"refusing to overwrite archive: {archive_path}")
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    if output_inside_inputs(archive_path, inputs):
        raise ValueError(f"archive output must be outside every input tree: {archive_path}")
    members = collect_members(inputs)
    contents = {
        "schema": SCHEMA,
        "files": [
            {key: row[key] for key in ("path", "size", "sha256", "executable")}
            for row in members
        ],
        "claim_boundary": (
            "This manifest establishes byte identity and deterministic packaging; "
            "it does not validate the scientific claims represented by the files."
        ),
    }
    contents_bytes = (
        json.dumps(contents, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        add_bytes(archive, CONTENTS_NAME, contents_bytes, 0o644)
        for row in members:
            data = row["source"].read_bytes()
            if len(data) != row["size"] or sha256_bytes(data) != row["sha256"]:
                raise RuntimeError(f"input changed while archiving: {row['source']}")
            add_bytes(archive, row["path"], data, 0o755 if row["executable"] else 0o644)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{archive_path.name}.",
            suffix=".tmp",
            dir=archive_path.parent,
            delete=False,
        ) as raw:
            temporary_path = Path(raw.name)
            with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
                compressed.write(tar_buffer.getvalue())
        # 第二次完整枚举可检测归档期间新增、删除、改名或权限变化的成员。
        observed_after = collect_members(inputs)
        if member_identity(observed_after) != member_identity(members):
            raise RuntimeError("input member set changed while archiving")
        os.replace(temporary_path, archive_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return {
        "schema": SCHEMA,
        "archive": archive_path.name,
        "archive_size": archive_path.stat().st_size,
        "archive_sha256": sha256_file(archive_path),
        "contents_member": CONTENTS_NAME,
        "contents_sha256": sha256_bytes(contents_bytes),
        "files": len(members),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", required=True, metavar="PREFIX=PATH")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.manifest.exists():
            raise ValueError(f"refusing to overwrite manifest: {args.manifest}")
        inputs = parse_inputs(args.input)
        if output_inside_inputs(args.manifest.resolve(), inputs):
            raise ValueError(
                f"manifest output must be outside every input tree: {args.manifest.resolve()}"
            )
        summary = build_archive(inputs, args.archive.resolve())
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
