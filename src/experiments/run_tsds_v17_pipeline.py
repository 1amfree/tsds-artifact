#!/usr/bin/env python3
"""Run the TSDS v17 run-locked evidence and artifact pipeline."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.run_tsds_v14_pipeline import main as run_pipeline  # noqa: E402
from experiments.run_tsds_v16_pipeline import (  # noqa: E402
    ADDITIONAL_REPRODUCIBILITY_SOURCES as V16_REPRODUCIBILITY_SOURCES,
    DEFAULT_SUBPROCESS_MEMORY_LIMIT_MIB,
    v16_mandatory_stages,
)


PIPELINE_TAG = "v17"
# v6 将重复性和负向确认从可为空检查升级为非空证据门禁。
PIPELINE_SCHEMA = "tsds-v17-pipeline-v6"
ARTIFACT_SOURCE_SUFFIXES = {
    ".c",
    ".csv",
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".result",
    ".result-alter2",
    ".sh",
    ".txt",
}


def artifact_source_candidate(path: Path) -> bool:
    """Return whether a repository path is a deliberate artifact source type."""

    return "__pycache__" not in path.parts and path.suffix in ARTIFACT_SOURCE_SUFFIXES


def artifact_source_set() -> tuple[str, ...]:
    """返回可在 artifact 内独立执行测试所需的确定排序源码闭包。"""

    files: list[Path] = []
    for directory in ("experiments", "tsds", "schemas"):
        base = PROJECT_ROOT / directory
        files.extend(
            path
            for path in base.rglob("*")
            if path.is_file()
            and artifact_source_candidate(path)
        )
    files.append(PROJECT_ROOT / "pytest.ini")
    files.append(PROJECT_ROOT / "operation-mango-public/pyproject.toml")
    # 先转成 POSIX 字符串再排序，避免 Windows/Linux Path 排序语义漂移。
    relatives = {
        path.relative_to(PROJECT_ROOT).as_posix() for path in files if path.is_file()
    }
    return tuple(sorted(relatives))


V17_ARTIFACT_SOURCE_SET = artifact_source_set()


def v17_mandatory_stages(**kwargs: Any) -> list[tuple[str, list[str], int]]:
    """在 v16 证据 stage 前加入可重放的源快照自测。"""

    python = Path(kwargs["python"])
    source_root = Path(kwargs.get("source_root") or kwargs["root"])
    out_dir = Path(kwargs["out_dir"])
    self_test = (
        "07_source_snapshot_self_test",
        [
            str(python),
            str(source_root / "experiments/run_source_snapshot_self_test.py"),
            "--source-root",
            str(source_root),
            "--out-dir",
            str(out_dir / "source_snapshot_self_test"),
            "--python",
            str(python),
            "--timeout",
            "1200",
        ],
        1500,
    )
    return [self_test, *v16_mandatory_stages(**kwargs)]


ADDITIONAL_REPRODUCIBILITY_SOURCES = tuple(
    dict.fromkeys(
        V16_REPRODUCIBILITY_SOURCES
        + V17_ARTIFACT_SOURCE_SET
        + (
            "experiments/run_tsds_v17_pipeline.py",
            "experiments/sync_tsds_sources_to_vm.py",
            "experiments/enforce_memoryerror_passthrough.py",
            "experiments/compare_external_baseline.py",
            "experiments/audit_repeatability.py",
            "experiments/audit_runtime_repeatability.py",
            "experiments/RUNTIME_REPEATABILITY_PROTOCOL.md",
            "experiments/build_blinded_ground_truth_sample.py",
            "experiments/validate_ground_truth_annotations.py",
            "experiments/unblind_ground_truth_audit.py",
            "experiments/package_blinded_audit.py",
            "experiments/GROUND_TRUTH_AUDIT_PROTOCOL.md",
            "experiments/build_deterministic_artifact_archive.py",
            "experiments/verify_deterministic_artifact_archive.py",
            "experiments/convert_satc_native_results.py",
            "experiments/convert_satc_to_tsds.py",
            "experiments/satc_python3_compat.py",
            "experiments/run_satc_keyword_extraction.py",
            "experiments/build_satc_keyword_slice.py",
            "experiments/run_satc_ghidra_experiment.py",
            "experiments/audit_release_readiness.py",
            "experiments/EXTERNAL_BASELINE_PROTOCOL.md",
            "experiments/satc_adapter_README.md",
            "experiments/fixtures/external_baseline_schema_example.json",
            "schemas/tsds-ledger-v17.schema.json",
        )
    )
)


def main() -> int:
    return run_pipeline(
        default_pipeline_tag=PIPELINE_TAG,
        default_pipeline_schema=PIPELINE_SCHEMA,
        additional_reproducibility_sources=ADDITIONAL_REPRODUCIBILITY_SOURCES,
        additional_mandatory_stages_builder=v17_mandatory_stages,
        busybox_stage_name="14_busybox_calibration",
        negative_stage_name="15_negative_confirmation",
        repeatability_stage_name="15b_repeatability_consensus",
        paper_stage_name="16_paper_tables",
        default_subprocess_memory_limit_mib=DEFAULT_SUBPROCESS_MEMORY_LIMIT_MIB,
        require_resource_calibration=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
