from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.build_source_dependency_manifest import (
    SCHEMA,
    build_manifest,
    canonical_json,
    module_name_for_path,
    resolve_relative_module,
    verify_manifest,
    write_json,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINTS = (
    "experiments/run_saner2027_multistate_benchmark.py",
    "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py",
)
TOOL_PATH = "experiments/build_source_dependency_manifest.py"


def test_module_and_relative_import_resolution() -> None:
    assert module_name_for_path(Path("tsds/__init__.py")) == "tsds"
    assert module_name_for_path(Path("tsds/source_realizability.py")) == (
        "tsds.source_realizability"
    )
    assert resolve_relative_module(
        Path("tsds/source_realizability.py"), 1, "reconciliation_link"
    ) == "tsds.reconciliation_link"


def test_current_benchmark_manifest_contains_transitive_local_sources() -> None:
    manifest = build_manifest(PROJECT_ROOT, ENTRYPOINTS, TOOL_PATH)
    paths = {item["path"] for item in manifest["files"]}
    assert manifest["schema"] == SCHEMA
    assert manifest["file_count"] == len(paths)
    assert "experiments/run_saner2027_multistate_benchmark.py" in paths
    assert "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py" in paths
    assert "tsds/multi_state_aggregation.py" in paths
    assert "tsds/shell_matrix_spec.py" in paths
    assert "tsds/reconciliation_link.py" in paths
    assert manifest["unresolved_local_imports"] == []
    assert manifest["manifest_sha256"]


def test_verify_detects_manifest_changes_without_mutating_sources(tmp_path: Path) -> None:
    manifest = build_manifest(PROJECT_ROOT, ENTRYPOINTS, TOOL_PATH)
    path = tmp_path / "manifest.json"
    write_json(path, manifest)
    ok, result = verify_manifest(PROJECT_ROOT, path)
    assert ok is True
    assert result["status"] == "PASS"

    altered = json.loads(path.read_text(encoding="utf-8"))
    altered["files"][0]["sha256"] = "0" * 64
    write_json(path, altered)
    ok, result = verify_manifest(PROJECT_ROOT, path)
    assert ok is False
    assert result["reason"] == "manifest_mismatch"


def test_manifest_digest_uses_canonical_payload() -> None:
    left = {"b": 2, "a": [True, None]}
    right = {"a": [True, None], "b": 2}
    assert canonical_json(left) == canonical_json(right)
