#!/usr/bin/env python3
"""Generate an offline CycloneDX SBOM and execution-environment lock for TSDS."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


EXCLUDED_PARTS = frozenset(
    {".git", ".pytest_cache", "__pycache__", "experiment_reports", ".venv"}
)
SOURCE_SUFFIXES = frozenset(
    {".py", ".json", ".jsonl", ".md", ".toml", ".ini", ".csv", ".txt", ".c", ".sh"}
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_inventory(root: Path, selected: Iterable[Path]) -> list[dict[str, Any]]:
    files: set[Path] = set()
    for entry in selected:
        path = (root / entry).resolve()
        if path.is_file():
            files.add(path)
        elif path.is_dir():
            files.update(
                child
                for child in path.rglob("*")
                if child.is_file()
                and child.suffix in SOURCE_SUFFIXES
                and not (EXCLUDED_PARTS & set(child.relative_to(root).parts))
            )
    rows = []
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        rows.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return rows


def installed_packages() -> list[dict[str, str]]:
    packages: dict[str, dict[str, str]] = {}
    for distribution in importlib.metadata.distributions():
        name = str(distribution.metadata.get("Name") or "").strip()
        if not name:
            continue
        key = name.lower().replace("_", "-")
        packages[key] = {"name": name, "version": str(distribution.version)}
    return [packages[key] for key in sorted(packages)]


def tool_inventory(names: Iterable[str]) -> list[dict[str, Any]]:
    rows = []
    for name in names:
        path_text = shutil.which(name)
        if path_text is None:
            rows.append({"name": name, "available": False})
            continue
        path = Path(path_text).resolve()
        try:
            result = subprocess.run(
                [str(path), "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=5,
                check=False,
            )
            version = (result.stdout or "").splitlines()[0][:240] if result.stdout else None
        except (OSError, subprocess.TimeoutExpired):
            version = None
        rows.append(
            {
                "name": name,
                "available": True,
                "path": str(path),
                "sha256": sha256_file(path),
                "version_output": version,
            }
        )
    return rows


def build_documents(
    source_rows: list[dict[str, Any]],
    package_rows: list[dict[str, str]],
    *,
    source_date_epoch: int = 0,
    environment: dict[str, Any] | None = None,
    tools: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    timestamp = datetime.fromtimestamp(source_date_epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    aggregate_payload = json.dumps(source_rows, separators=(",", ":"), sort_keys=True).encode()
    source_digest = hashlib.sha256(aggregate_payload).hexdigest()
    components = [
        {
            "type": "library",
            "name": row["name"],
            "version": row["version"],
            "bom-ref": f"pkg:pypi/{row['name'].lower().replace('_', '-')}@{row['version']}",
            "purl": f"pkg:pypi/{row['name'].lower().replace('_', '-')}@{row['version']}",
        }
        for row in package_rows
    ]
    components.extend(
        {
            "type": "file",
            "name": row["path"],
            "bom-ref": f"file:{row['sha256']}",
            "hashes": [{"alg": "SHA-256", "content": row["sha256"]}],
            "properties": [{"name": "tsds:file:size", "value": str(row["size"])}],
        }
        for row in source_rows
    )
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{source_digest[:8]}-{source_digest[8:12]}-{source_digest[12:16]}-{source_digest[16:20]}-{source_digest[20:32]}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": "application",
                "name": "TSDS",
                "version": "v18-development",
                "bom-ref": f"tsds-source:{source_digest}",
                "hashes": [{"alg": "SHA-256", "content": source_digest}],
            },
        },
        "components": components,
    }
    lock = {
        "schema": "tsds-reproduction-environment-lock-v1",
        "source_date_epoch": source_date_epoch,
        "source_files": len(source_rows),
        "source_aggregate_sha256": source_digest,
        "python_packages": package_rows,
        "environment": environment or {},
        "tools": tools or [],
        "claim_boundary": (
            "The lock records the artifact environment and content identities; firmware "
            "inputs remain separately bound by the campaign manifest."
        ),
    }
    return sbom, lock


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-path", type=Path, action="append", default=[])
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int, default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")))
    args = parser.parse_args()
    root = args.source_root.resolve()
    selected = args.source_path or [
        Path("experiments"),
        Path("tsds"),
        Path("schemas"),
        Path("containers"),
        Path("Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py"),
        Path("advanced_sanitizer_evaluator.py"),
        Path("pytest.ini"),
        Path("operation-mango-public/pyproject.toml"),
    ]
    sources = source_inventory(root, selected)
    packages = installed_packages()
    tools = tool_inventory(["bash", "dash", "busybox", "qemu-arm-static", "qemu-mips-static"])
    environment = {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
    }
    sbom, lock = build_documents(
        sources,
        packages,
        source_date_epoch=args.source_date_epoch,
        environment=environment,
        tools=tools,
    )
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"output directory is non-empty: {out_dir}", file=sys.stderr)
        return 3
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "tsds.cyclonedx.json").write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "environment_lock.json").write_text(
        json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "source_inventory.json").write_text(
        json.dumps({"files": sources}, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "schema": lock["schema"],
                "source_files": len(sources),
                "packages": len(packages),
                "tools": len(tools),
                "source_aggregate_sha256": lock["source_aggregate_sha256"],
                "valid": bool(sources and packages),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if sources and packages else 2


if __name__ == "__main__":
    raise SystemExit(main())
