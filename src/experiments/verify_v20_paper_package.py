#!/usr/bin/env python3
"""Independently verify a generated TSDS v20 paper-evidence package."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "tsds-v20-paper-package-verification-v1"
EXPECTED_CLAIMS = {f"C{index}" for index in range(1, 10)}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def strict_json(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}: {path}")
            result[key] = value
        return result

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def verify_package(root: Path) -> dict[str, Any]:
    root = root.resolve()
    issues: list[str] = []
    manifest_path = root / "paper_output_manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"missing paper output manifest: {manifest_path}")
    manifest = strict_json(manifest_path)
    if manifest.get("schema") != "tsds-v20-paper-output-manifest-v1":
        issues.append("manifest_schema")
    if manifest.get("ready") is not True:
        issues.append("manifest_not_ready")
    rows = manifest.get("files")
    if not isinstance(rows, list) or not rows:
        raise ValueError("paper output manifest has no files")
    declared: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            issues.append(f"manifest_row_not_object:{index}")
            continue
        name = row.get("path")
        pure = PurePosixPath(str(name or ""))
        if (
            not isinstance(name, str)
            or not name
            or "\\" in name
            or pure.is_absolute()
            or len(pure.parts) != 1
            or pure.as_posix() != name
        ):
            issues.append(f"unsafe_manifest_path:{index}")
            continue
        if name in declared:
            issues.append(f"duplicate_manifest_path:{name}")
            continue
        declared[name] = row
        path = root / name
        if not path.is_file() or path.is_symlink():
            issues.append(f"missing_or_linked_file:{name}")
            continue
        if path.stat().st_size != row.get("size"):
            issues.append(f"size_mismatch:{name}")
        if sha256_file(path) != row.get("sha256"):
            issues.append(f"sha256_mismatch:{name}")
    actual = {path.name for path in root.iterdir()}
    expected = set(declared) | {manifest_path.name}
    if actual != expected:
        issues.append(
            "package_file_set:" + json.dumps(
                {
                    "missing": sorted(expected - actual),
                    "extra": sorted(actual - expected),
                },
                sort_keys=True,
            )
        )

    index_path = root / "paper_evidence_index.json"
    snapshot_path = root / "paper_results_snapshot.json"
    macros_path = root / "paper_results_macros.tex"
    claims_path = root / "claim_to_evidence.csv"
    required = (index_path, snapshot_path, macros_path, claims_path)
    if any(not path.is_file() for path in required):
        issues.append("required_paper_inputs")
        return {
            "schema": SCHEMA,
            "valid": False,
            "issues": sorted(set(issues)),
        }
    index = strict_json(index_path)
    snapshot = strict_json(snapshot_path)
    tag = index.get("tag")
    if (
        index.get("schema") != "tsds-v20-paper-evidence-index-v1"
        or index.get("frozen") is not True
        or index.get("ready_for_full_paper_writing") is not True
    ):
        issues.append("paper_index_state")
    if (
        snapshot.get("schema") != "tsds-v20-paper-results-snapshot-v1"
        or snapshot.get("tag") != tag
    ):
        issues.append("paper_snapshot_state")
    headline = index.get("headline") or {}
    if (
        snapshot.get("records") != headline.get("records")
        or snapshot.get("verdicts") != headline.get("verdicts")
    ):
        issues.append("snapshot_headline_mismatch")
    paper_results = index.get("paper_results") or {}
    for name, key in (
        ("paper_results_snapshot.json", "snapshot"),
        ("paper_results_macros.tex", "macros"),
    ):
        identity = paper_results.get(key) or {}
        path = root / name
        if (
            identity.get("path") != name
            or identity.get("size") != path.stat().st_size
            or identity.get("sha256") != sha256_file(path)
        ):
            issues.append(f"paper_result_identity:{key}")
    macro_values = paper_results.get("values") or {}
    macro_text = macros_path.read_text(encoding="utf-8")
    for name, value in macro_values.items():
        if f"\\newcommand{{\\{name}}}{{{value}}}" not in macro_text:
            issues.append(f"missing_macro:{name}")

    with claims_path.open("r", newline="", encoding="utf-8") as stream:
        claim_rows = list(csv.DictReader(stream))
    claim_ids = {row.get("claim_id") for row in claim_rows}
    if claim_ids != EXPECTED_CLAIMS or any(row.get("status") != "supported" for row in claim_rows):
        issues.append("claim_evidence_rows")
    index_claims = {
        row.get("claim_id") for row in index.get("claims") or [] if isinstance(row, dict)
    }
    if index_claims != EXPECTED_CLAIMS:
        issues.append("index_claim_set")

    return {
        "schema": SCHEMA,
        "tag": tag,
        "valid": not issues,
        "issues": sorted(set(issues)),
        "files": len(declared),
        "records": snapshot.get("records"),
        "verdicts": snapshot.get("verdicts"),
        "claims": sorted(index_claims),
        "package_manifest": {
            "path": str(manifest_path),
            "size": manifest_path.stat().st_size,
            "sha256": sha256_file(manifest_path),
        },
        "claim_boundary": (
            "Verification establishes byte identity and internal consistency of the "
            "paper package. It does not extend the scientific claims recorded by the "
            "claim matrix."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-valid", action="store_true")
    args = parser.parse_args()
    try:
        document = verify_package(args.package_root)
        if args.output.exists():
            raise ValueError(f"refusing to overwrite verification output: {args.output}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"V20_PAPER_PACKAGE_VERIFICATION_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(document, indent=2, sort_keys=True))
    return 3 if args.require_valid and not document["valid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
