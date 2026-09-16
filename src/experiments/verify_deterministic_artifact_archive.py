#!/usr/bin/env python3
"""Verify a deterministic TSDS artifact archive and its external manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.build_deterministic_artifact_archive import (
    CONTENTS_NAME,
    SCHEMA,
    sha256_file,
)


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def strict_json_object(payload: str | bytes, label: str) -> dict[str, Any]:
    """解析 JSON 对象并拒绝重复键，消除跨解析器语义歧义。"""

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key {key!r} in {label}")
            value[key] = item
        return value

    value = json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not an object")
    return value


def inspect_gzip_stream(path: Path) -> tuple[bytes, list[str]]:
    """验证单一、无尾随数据且 mtime 为零的规范 gzip 流。"""

    payload = path.read_bytes()
    issues: list[str] = []
    if len(payload) < 10 or payload[:3] != b"\x1f\x8b\x08":
        return b"", ["invalid_gzip_header"]
    flags = payload[3]
    if flags != 0 or payload[4:8] != b"\x00\x00\x00\x00":
        issues.append("noncanonical_gzip_header")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        raw_tar = decoder.decompress(payload) + decoder.flush()
    except zlib.error:
        return b"", sorted(set(issues + ["invalid_gzip_stream"]))
    if not decoder.eof:
        issues.append("truncated_gzip_stream")
    if decoder.unused_data:
        issues.append("gzip_trailing_or_concatenated_data")
    return raw_tar, sorted(set(issues))


def safe_member_name(name: str) -> bool:
    """Return whether a tar member is a canonical relative POSIX path."""

    path = PurePosixPath(name)
    return bool(
        name
        and "\\" not in name
        and "\x00" not in name
        and not path.is_absolute()
        and path.parts
        and ".." not in path.parts
        and all(part not in {"", "."} for part in path.parts)
    )


def member_metadata_valid(member: tarfile.TarInfo, executable: bool) -> bool:
    expected_mode = 0o755 if executable else 0o644
    return bool(
        member.isreg()
        and member.mode == expected_mode
        and member.mtime == 0
        and member.uid == 0
        and member.gid == 0
        and member.uname == ""
        and member.gname == ""
    )


def validate_embedded_rows(contents: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    raw_rows = contents.get("files")
    if not isinstance(raw_rows, list):
        return {}, ["embedded_files_not_list"]
    expected: dict[str, Any] = {}
    for index, row in enumerate(raw_rows):
        if not isinstance(row, dict):
            issues.append(f"embedded_file_not_object:{index}")
            continue
        name = row.get("path")
        if not isinstance(name, str) or not safe_member_name(name):
            issues.append(f"unsafe_embedded_member_path:{index}")
            continue
        if name == CONTENTS_NAME:
            issues.append("embedded_contents_self_reference")
            continue
        if name in expected:
            issues.append(f"duplicate_embedded_member:{name}")
            continue
        size = row.get("size")
        sha256 = row.get("sha256")
        executable = row.get("executable")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            issues.append(f"invalid_embedded_size:{name}")
        if not isinstance(sha256, str) or SHA256_RE.fullmatch(sha256) is None:
            issues.append(f"invalid_embedded_sha256:{name}")
        if not isinstance(executable, bool):
            issues.append(f"invalid_embedded_executable:{name}")
        expected[name] = row
    return expected, issues


def verify_archive(archive_path: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = strict_json_object(
        manifest_path.read_text(encoding="utf-8"), "external manifest"
    )
    issues: list[str] = []
    raw_tar, gzip_issues = inspect_gzip_stream(archive_path)
    issues.extend(gzip_issues)
    if manifest.get("schema") != SCHEMA:
        issues.append("external_manifest_schema_mismatch")
    if manifest.get("archive") != archive_path.name:
        issues.append("archive_name_mismatch")
    archive_size = manifest.get("archive_size")
    if isinstance(archive_size, bool) or not isinstance(archive_size, int) or archive_size < 0:
        issues.append("invalid_external_archive_size")
    elif archive_path.stat().st_size != archive_size:
        issues.append("archive_size_mismatch")
    archive_sha256 = manifest.get("archive_sha256")
    if not isinstance(archive_sha256, str) or SHA256_RE.fullmatch(archive_sha256) is None:
        issues.append("invalid_external_archive_sha256")
    elif sha256_file(archive_path) != archive_sha256:
        issues.append("archive_sha256_mismatch")
    if manifest.get("contents_member") != CONTENTS_NAME:
        issues.append("external_contents_member_mismatch")
    contents_sha256 = manifest.get("contents_sha256")
    if not isinstance(contents_sha256, str) or SHA256_RE.fullmatch(contents_sha256) is None:
        issues.append("invalid_external_contents_sha256")
    external_files = manifest.get("files")
    if isinstance(external_files, bool) or not isinstance(external_files, int) or external_files < 0:
        issues.append("invalid_external_file_count")
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if any(not safe_member_name(name) for name in names):
            issues.append("unsafe_archive_member_path")
        if len(names) != len(set(names)):
            issues.append("duplicate_archive_members")
        for member in members:
            if not member.isreg():
                issues.append(f"non_regular_member:{member.name}")
        if CONTENTS_NAME not in names:
            issues.append("missing_embedded_contents")
            contents: dict[str, Any] = {}
            contents_bytes = b""
        else:
            extracted = archive.extractfile(CONTENTS_NAME)
            contents_bytes = extracted.read() if extracted else b""
            contents = strict_json_object(contents_bytes, "embedded contents")
        if hashlib.sha256(contents_bytes).hexdigest() != contents_sha256:
            issues.append("embedded_contents_sha256_mismatch")
        if contents.get("schema") != SCHEMA:
            issues.append("embedded_contents_schema_mismatch")
        expected, embedded_issues = validate_embedded_rows(contents)
        issues.extend(embedded_issues)
        if external_files != len(expected):
            issues.append("external_file_count_mismatch")
        observed = set(names) - {CONTENTS_NAME}
        if observed != set(expected):
            issues.append("archive_member_set_mismatch")
        if names != [CONTENTS_NAME, *sorted(expected)]:
            issues.append("archive_member_order_mismatch")
        for name in sorted(observed & set(expected)):
            extracted = archive.extractfile(name)
            data = extracted.read() if extracted else b""
            row = expected[name]
            if len(data) != row.get("size"):
                issues.append(f"size_mismatch:{name}")
            if hashlib.sha256(data).hexdigest() != row.get("sha256"):
                issues.append(f"sha256_mismatch:{name}")
            member = archive.getmember(name)
            if not member_metadata_valid(member, row.get("executable") is True):
                issues.append(f"metadata_mismatch:{name}")
        if CONTENTS_NAME in names:
            contents_member = archive.getmember(CONTENTS_NAME)
            if not member_metadata_valid(contents_member, False):
                issues.append("embedded_contents_metadata_mismatch")
        if raw_tar and members:
            # tarfile 的逻辑 offset 用于验证规范双零块及其后的全零记录填充。
            last = max(
                member.offset_data + ((member.size + 511) // 512) * 512
                for member in members
            )
            if len(raw_tar) % tarfile.RECORDSIZE != 0:
                issues.append("noncanonical_tar_record_size")
            if raw_tar[last : last + 1024] != b"\0" * 1024 or any(raw_tar[last + 1024 :]):
                issues.append("noncanonical_tar_end_padding")
    return {
        "schema": "tsds-deterministic-artifact-verification-v1",
        "archive": str(archive_path.resolve()),
        "files": len((contents or {}).get("files") or []),
        "issues": sorted(set(issues)),
        "verified": not issues,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--require-valid", action="store_true")
    args = parser.parse_args()
    try:
        summary = verify_archive(args.archive, args.manifest)
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError) as exc:
        summary = {
            "schema": "tsds-deterministic-artifact-verification-v1",
            "issues": [str(exc)],
            "verified": False,
        }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.require_valid and not summary["verified"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
