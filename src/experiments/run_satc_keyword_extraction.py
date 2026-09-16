#!/usr/bin/env python3
"""Produce a content-bound SaTC shared-keyword input for TSDS ingestion.

This runner covers only SaTC's front-end keyword extraction.  The subsequent
Ghidra candidate-generation and TSDS evidence stages are run by
``run_satc_ghidra_experiment.py``.  Keeping the stages separate makes the
front-end corpus, compatibility shim, generated keyword file, and firmware
tree independently auditable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.run_satc_ghidra_experiment import (
    artifact_identities,
    command_version,
    file_identity,
    python_environment_identity,
    run_stage,
    sha256_file,
)
from experiments.satc_source_snapshot import validate_snapshot
from experiments.capture_satc_js_parser_environment import validate_js_parser_manifest


SCHEMA = "tsds-satc-keyword-extraction-v1"


def directory_identity(root: Path) -> dict[str, Any]:
    """Create a deterministic, symlink-aware identity for a firmware tree."""

    root = root.resolve()
    digest = hashlib.sha256()
    regular_files = 0
    symlinks = 0
    total_bytes = 0
    for entry in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            row = {"kind": "symlink", "path": relative, "target": os.readlink(entry)}
            symlinks += 1
        elif entry.is_file():
            size = entry.stat().st_size
            row = {
                "kind": "file",
                "path": relative,
                "size": size,
                "sha256": sha256_file(entry),
            }
            regular_files += 1
            total_bytes += size
        else:
            continue
        digest.update(json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
    return {
        "path": str(root),
        "regular_files": regular_files,
        "symlinks": symlinks,
        "bytes": total_bytes,
        "sha256": digest.hexdigest(),
    }


def resolve_rootfs_binary(rootfs: Path, binary: Path) -> Path:
    """Resolve the exact analyzed binary within the supplied rootfs tree."""

    rootfs = rootfs.resolve()
    binary = binary.resolve()
    if not binary.is_file():
        raise ValueError(f"missing binary: {binary}")
    try:
        binary.relative_to(rootfs)
        return binary
    except ValueError:
        pass
    expected = sha256_file(binary)
    matches = [
        candidate
        for candidate in rootfs.rglob(binary.name)
        if candidate.is_file()
        and not candidate.is_symlink()
        and sha256_file(candidate) == expected
    ]
    if len(matches) != 1:
        raise ValueError(
            "expected exactly one content-identical rootfs binary for "
            f"{binary.name}; found {len(matches)}"
        )
    return matches[0]


def canonicalize_keywords(raw_keywords: Path, output: Path) -> dict[str, Any]:
    """Canonicalize SaTC's set-valued keyword file without changing its semantics.

    ``ref2sink_cmdi.py`` consumes its input with
    ``set(open(args[0]).read().strip().split())``.  Sorting the unique tokens
    therefore changes neither the target set nor the Ghidra query semantics,
    but removes Python set-iteration order from the artifact hash.
    """

    tokens = raw_keywords.read_text(encoding="utf-8", errors="replace").split()
    normalized = sorted(set(tokens))
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write("\n".join(normalized) + ("\n" if normalized else ""))
    return {
        "schema": "tsds-satc-keyword-canonicalization-v1",
        "raw_tokens": len(tokens),
        "unique_tokens": len(normalized),
        "semantic_basis": "ref2sink_cmdi_set_split",
    }


def validate_inputs(args: argparse.Namespace) -> dict[str, Path]:
    source_snapshot = getattr(args, "satc_source_snapshot", None)
    js_parser_manifest = getattr(args, "js_parser_environment_manifest", None)
    rootfs = args.rootfs.resolve()
    if not rootfs.is_dir():
        raise ValueError(f"missing rootfs directory: {rootfs}")
    paths = {
        "satc_main": args.satc_root / "src" / "satc.py",
        "compat_runner": args.compat_runner,
        "analyzed_binary": args.binary,
    }
    paths["rootfs_binary"] = resolve_rootfs_binary(rootfs, args.binary)
    if args.satc_archive is not None:
        paths["satc_archive"] = args.satc_archive
    if source_snapshot is not None:
        paths["satc_source_snapshot"] = source_snapshot
    if js_parser_manifest is not None:
        paths["js_parser_environment_manifest"] = js_parser_manifest
    missing = [f"{name}:{path}" for name, path in paths.items() if not path.is_file()]
    if missing:
        raise ValueError("missing keyword-extraction input(s): " + ", ".join(missing))
    if source_snapshot is not None:
        validate_snapshot(source_snapshot, args.satc_root)
    if js_parser_manifest is not None:
        validate_js_parser_manifest(
            js_parser_manifest, args.satc_root / "src" / "jsparse"
        )
    return paths


def run_keyword_extraction(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    logs = out_dir / "logs"
    logs.mkdir()
    inputs = validate_inputs(args)
    rootfs = args.rootfs.resolve()
    identities: dict[str, Any] = {
        name: file_identity(path) for name, path in inputs.items()
    }
    identities["rootfs_tree"] = directory_identity(rootfs)
    satc_output = out_dir / "satc_output"
    satc_src = (args.satc_root / "src").resolve()
    inherited_pythonpath = os.environ.get("PYTHONPATH")
    pythonpath = str(satc_src)
    if inherited_pythonpath:
        pythonpath = pythonpath + os.pathsep + inherited_pythonpath
    command = [
        str(args.frontend_python),
        str(args.compat_runner),
        "--script",
        str(inputs["satc_main"]),
        "--",
        "-d",
        str(rootfs),
        "-o",
        str(satc_output),
        "-b",
        inputs["rootfs_binary"].name,
    ]
    stage = run_stage(
        "01_satc_keyword_extraction",
        command,
        cwd=satc_src,
        timeout=args.timeout_sec,
        log_dir=logs,
        resource_path=out_dir / "satc_keyword_extraction.resource.txt",
        environment={"PYTHONPATH": pythonpath},
    )
    # SaTC's own ``ghidra_analysise`` consumes this per-binary, simple-data
    # file.  The human-readable clustering report contains headings and count
    # fields, so forwarding it to the Ghidra script would incorrectly treat
    # report metadata as candidate keywords.
    raw_keywords = (
        satc_output
        / "keyword_extract_result"
        / "simple"
        / ".data"
        / f"{inputs['rootfs_binary'].name}.result"
    )
    canonical_keywords = out_dir / "keywords.canonical.txt"
    canonicalization = None
    if stage["returncode"] == 0 and raw_keywords.is_file():
        canonicalization = canonicalize_keywords(raw_keywords, canonical_keywords)
    success = (
        stage["returncode"] == 0
        and raw_keywords.is_file()
        and canonical_keywords.is_file()
    )
    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "success": success,
        "claim_boundary": (
            "This experiment records SaTC front-end keyword production only. "
            "It does not establish candidate accuracy, TSDS evidence outcomes, "
            "or exploitability."
        ),
        "inputs": identities,
        "environment": {
            "frontend_python": python_environment_identity(args.frontend_python),
            "compatibility": {
                "mode": "narrow_python2_name_shim",
                "runner": file_identity(args.compat_runner),
            },
            "satc_source_snapshot_bound": getattr(args, "satc_source_snapshot", None) is not None,
            "js_parser_environment_bound": getattr(
                args, "js_parser_environment_manifest", None
            ) is not None,
        },
        "configuration": {
            "binary_name_passed_to_satc": inputs["rootfs_binary"].name,
            "raw_keyword_selection": "satc_native_per_binary_simple_data",
            "keyword_selection": "satc_set_semantics_canonicalized",
            "timeout_sec": args.timeout_sec,
        },
        "stage": stage,
        "raw_keyword_output": (
            file_identity(raw_keywords, out_dir) if raw_keywords.is_file() else None
        ),
        "canonicalization": canonicalization,
        "keyword_output": (
            file_identity(canonical_keywords, out_dir)
            if canonical_keywords.is_file()
            else None
        ),
    }
    manifest["artifacts"] = artifact_identities(out_dir)
    (out_dir / "experiment_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--satc-root", type=Path, required=True)
    parser.add_argument("--satc-archive", type=Path)
    parser.add_argument("--satc-source-snapshot", type=Path)
    parser.add_argument(
        "--js-parser-environment-manifest",
        type=Path,
        help="Successful tsds-satc-js-parser-environment-v1 manifest bound to the local parser service.",
    )
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--frontend-python", type=Path, default=Path(sys.executable))
    parser.add_argument(
        "--compat-runner",
        type=Path,
        default=PROJECT_ROOT / "experiments" / "satc_python3_compat.py",
    )
    parser.add_argument("--timeout-sec", type=int, default=3600)
    args = parser.parse_args()
    try:
        manifest = run_keyword_extraction(args)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "success": manifest["success"],
                "keyword_output": manifest["keyword_output"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if manifest["success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
