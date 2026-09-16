#!/usr/bin/env python3
"""Build or verify a deterministic manifest for the local Python source closure.

The manifest is deliberately limited to statically resolvable, repository-local
Python imports.  It is a provenance aid for experiment artifacts, not a claim
that third-party packages, native libraries, or dynamic imports are captured.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "tsds-local-python-source-lock-v1"
DEFAULT_ENTRYPOINTS = (
    "experiments/run_saner2027_multistate_benchmark.py",
    "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py",
)
DEFAULT_OUTPUT = (
    "paper_work/TSDS_SANER2027_SOURCE_LOCK_20260914"
    "/source_dependency_manifest.json"
)


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def safe_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        "\\" in value
        or "\x00" in value
        or path.is_absolute()
        or not path.parts
        or ".." in path.parts
        or any(part in {"", "."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise ValueError(f"unsafe relative path: {value}")
    return path


def relative_path(root: Path, path: Path) -> str:
    resolved_root = root.resolve()
    resolved_path = path.resolve()
    try:
        rel = resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"path escapes project root: {path}") from exc
    return rel.as_posix()


def module_name_for_path(path: PurePosixPath) -> str:
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _candidate_paths(root: Path, module_name: str) -> list[Path]:
    if not module_name:
        return []
    parts = module_name.split(".")
    if any(not part or part in {".", ".."} for part in parts):
        return []
    base = root.joinpath(*parts)
    return [base.with_suffix(".py"), base / "__init__.py"]


def resolve_local_module(root: Path, module_name: str) -> Path | None:
    for candidate in _candidate_paths(root, module_name):
        if candidate.is_file():
            return candidate.resolve()
    return None


def package_for_path(path: PurePosixPath) -> list[str]:
    module_name = module_name_for_path(path)
    return module_name.split(".")[:-1] if module_name else []


def resolve_relative_module(
    current_path: PurePosixPath,
    level: int,
    module: str | None,
) -> str | None:
    """Resolve an AST relative import against the current source module."""

    if level == 0:
        return module
    package = package_for_path(current_path)
    remove = max(0, level - 1)
    if remove > len(package):
        return None
    base = package[: len(package) - remove]
    suffix = module.split(".") if module else []
    return ".".join(base + suffix)


def import_targets(
    node: ast.Import | ast.ImportFrom,
    current_path: PurePosixPath,
) -> tuple[list[str], list[str]]:
    """Return module names to resolve and names that remain external."""

    targets: list[str] = []
    displayed: list[str] = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            name = alias.name
            targets.append(name)
            displayed.append(name)
        return targets, displayed

    base = resolve_relative_module(current_path, node.level, node.module)
    if base is None:
        return [], ["." * node.level + (node.module or "")]
    targets.append(base)
    displayed.append("." * node.level + (node.module or ""))
    # ``from package import module`` executes the package and then resolves the
    # named child.  For ``from package.module import function`` the names are
    # attributes, not modules, so only the package form needs child probes.
    if node.module is None:
        for alias in node.names:
            if alias.name == "*":
                continue
            child = f"{base}.{alias.name}"
            targets.append(child)
            displayed.append(child)
    return targets, displayed


def parse_imports(path: Path, root: Path) -> tuple[list[str], list[str]]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    current = PurePosixPath(relative_path(root, path))
    targets: list[str] = []
    displayed: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        resolved, shown = import_targets(node, current)
        targets.extend(resolved)
        displayed.extend(shown)
    return sorted(set(targets)), sorted(set(displayed))


def parent_package_files(root: Path, path: Path) -> Iterable[Path]:
    """Include package initializers Python executes before a local module."""

    current = path.resolve().parent
    resolved_root = root.resolve()
    while current != resolved_root and resolved_root in current.parents:
        initializer = current / "__init__.py"
        if initializer.is_file() and initializer.resolve() != path.resolve():
            yield initializer.resolve()
        current = current.parent


def has_local_namespace(root: Path, module_name: str) -> bool:
    """Return whether an import starts in a repository-local namespace."""

    first = module_name.split(".", 1)[0] if module_name else ""
    return bool(first) and (root / first).exists()


def build_manifest(
    root: Path,
    entrypoints: Iterable[str],
    tool_path: str,
) -> dict[str, Any]:
    root = root.resolve()
    entries = tuple(sorted({safe_relative_path(item).as_posix() for item in entrypoints}))
    if not entries:
        raise ValueError("at least one entrypoint is required")
    entry_paths: list[Path] = []
    for item in entries:
        path = (root / Path(*safe_relative_path(item).parts)).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"entrypoint not found: {item}")
        entry_paths.append(path)

    tool_rel = safe_relative_path(tool_path).as_posix()
    tool = (root / Path(*safe_relative_path(tool_rel).parts)).resolve()
    if not tool.is_file():
        raise FileNotFoundError(f"lock tool not found: {tool_rel}")

    queue = list(entry_paths)
    seen: set[Path] = set()
    graph: dict[Path, set[Path]] = {}
    external: set[str] = set()
    missing_local: set[str] = set()
    while queue:
        path = queue.pop(0).resolve()
        if path in seen:
            continue
        seen.add(path)
        local_imports, displayed_imports = parse_imports(path, root)
        local_paths: set[Path] = set(parent_package_files(root, path))
        for module_name in local_imports:
            resolved = resolve_local_module(root, module_name)
            if resolved is not None:
                local_paths.add(resolved)
            else:
                (missing_local if has_local_namespace(root, module_name) else external).add(
                    module_name
                )
        # Keep only the names that could not be resolved anywhere in the
        # repository.  The displayed set preserves relative-import context.
        resolved_displayed: set[str] = set()
        for shown in displayed_imports:
            if shown.startswith("."):
                absolute = resolve_relative_module(
                    PurePosixPath(relative_path(root, path)),
                    len(shown) - len(shown.lstrip(".")),
                    shown.lstrip(".") or None,
                )
                if absolute and resolve_local_module(root, absolute) is not None:
                    resolved_displayed.add(shown)
            elif resolve_local_module(root, shown) is not None:
                resolved_displayed.add(shown)
        for shown in set(displayed_imports) - resolved_displayed:
            module_name = shown.lstrip(".")
            (missing_local if has_local_namespace(root, module_name) else external).add(
                shown
            )
        graph[path] = local_paths
        for dependency in sorted(local_paths):
            if dependency not in seen:
                queue.append(dependency)

    files: list[dict[str, Any]] = []
    for path in sorted(seen, key=lambda item: relative_path(root, item)):
        rel = relative_path(root, path)
        files.append(
            {
                "path": rel,
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
                "local_imports": sorted(
                    relative_path(root, dependency)
                    for dependency in graph.get(path, set())
                    if dependency in seen
                ),
            }
        )

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "root": ".",
        "entrypoints": list(entries),
        "lock_tool": {
            "path": tool_rel,
            "sha256": sha256_file(tool),
        },
        "files": files,
        "file_count": len(files),
        "external_imports": sorted(external),
        "unresolved_local_imports": sorted(missing_local),
    }
    payload["manifest_sha256"] = sha256_bytes(canonical_json(payload))
    return payload


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("manifest root must be an object")
    return value


def verify_manifest(root: Path, manifest_path: Path) -> tuple[bool, dict[str, Any]]:
    expected = load_json(manifest_path)
    if expected.get("schema") != SCHEMA:
        return False, {"error": "schema_mismatch", "expected": SCHEMA}
    entries = expected.get("entrypoints")
    tool = (expected.get("lock_tool") or {}).get("path")
    if not isinstance(entries, list) or not all(isinstance(item, str) for item in entries):
        return False, {"error": "invalid_entrypoints"}
    if not isinstance(tool, str):
        return False, {"error": "invalid_lock_tool"}
    actual = build_manifest(root, entries, tool)
    if expected == actual:
        return True, {
            "schema": SCHEMA,
            "status": "PASS",
            "manifest_sha256": actual["manifest_sha256"],
            "file_count": actual["file_count"],
        }
    expected_json = canonical_json(expected)
    actual_json = canonical_json(actual)
    return False, {
        "schema": SCHEMA,
        "status": "FAIL",
        "reason": "manifest_mismatch",
        "expected_manifest_sha256": expected.get("manifest_sha256"),
        "actual_manifest_sha256": actual.get("manifest_sha256"),
        "expected_file_count": expected.get("file_count"),
        "actual_file_count": actual.get("file_count"),
        "expected_payload_sha256": sha256_bytes(expected_json),
        "actual_payload_sha256": sha256_bytes(actual_json),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "verify"))
    parser.add_argument("--root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--output", type=Path, default=Path(DEFAULT_OUTPUT))
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--entrypoint", action="append", dest="entrypoints")
    parser.add_argument(
        "--tool-path",
        default="experiments/build_source_dependency_manifest.py",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.command == "build":
        entries = args.entrypoints or list(DEFAULT_ENTRYPOINTS)
        manifest = build_manifest(root, entries, args.tool_path)
        output = args.output if args.output.is_absolute() else root / args.output
        write_json(output, manifest)
        print(json.dumps({
            "status": "PASS",
            "manifest": str(output.resolve()),
            "manifest_sha256": manifest["manifest_sha256"],
            "file_count": manifest["file_count"],
        }, indent=2, sort_keys=True))
        return 0

    manifest_path = args.manifest or args.output
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    ok, result = verify_manifest(root, manifest_path.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
