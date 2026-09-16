#!/usr/bin/env python3
"""Run the TSDS v18/v7 evidence-contract and reproducibility pipeline."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.run_tsds_v14_pipeline import (  # noqa: E402
    V14_REPRODUCIBILITY_SOURCES,
    main as run_pipeline,
)
from experiments.run_tsds_v16_pipeline import DEFAULT_SUBPROCESS_MEMORY_LIMIT_MIB  # noqa: E402
from experiments.run_tsds_v17_pipeline import (  # noqa: E402
    ADDITIONAL_REPRODUCIBILITY_SOURCES as V17_REPRODUCIBILITY_SOURCES,
    V17_ARTIFACT_SOURCE_SET,
    v17_mandatory_stages,
)


PIPELINE_TAG = "v18"
PIPELINE_SCHEMA = "tsds-v18-pipeline-v7"


def v18_artifact_source_set() -> tuple[str, ...]:
    values = set(V17_ARTIFACT_SOURCE_SET)
    container_root = PROJECT_ROOT / "containers"
    if container_root.is_dir():
        values.update(
            path.relative_to(PROJECT_ROOT).as_posix()
            for path in container_root.rglob("*")
            if path.is_file()
        )
    return tuple(sorted(values))


V18_ARTIFACT_SOURCE_SET = v18_artifact_source_set()
ADDITIONAL_REPRODUCIBILITY_SOURCES = tuple(
    dict.fromkeys(
        V14_REPRODUCIBILITY_SOURCES
        + V17_REPRODUCIBILITY_SOURCES
        + V18_ARTIFACT_SOURCE_SET
        + (
            "experiments/run_tsds_v18_pipeline.py",
            "experiments/run_tsds_v18_evidence_extension.py",
            "experiments/verify_v18_evidence_extension.py",
            "experiments/run_v20_post_release.sh",
            "experiments/run_tsds_pipeline.py",
            "experiments/export_paper_tables.py",
            "experiments/audit_residual_root_causes.py",
            "experiments/build_exploitability_calibration_pack.py",
            "experiments/validate_exploitability_calibration.py",
            "experiments/verify_evidence_certificates.py",
            "experiments/audit_performance_diagnostics.py",
            "experiments/audit_candidate_contract.py",
            "experiments/generate_reproduction_sbom.py",
            "tsds/statistical_evidence.py",
            "tsds/residual_root_causes.py",
            "tsds/exploitability_calibration.py",
            "tsds/shell_matrix_spec.py",
            "tsds/independent_certificate_verifier.py",
            "tsds/performance_diagnostics.py",
            "tsds/candidate_contract.py",
            "containers/tsds-reproduction.Dockerfile",
            "containers/README.md",
            "TSDS_V18_SYSTEM_README.md",
        )
    )
)


def v18_mandatory_stages(**kwargs: Any) -> list[tuple[str, list[str], int]]:
    stages = list(v17_mandatory_stages(**kwargs))
    python = Path(kwargs["python"])
    campaign = Path(kwargs["campaign"])
    out_dir = Path(kwargs["out_dir"])
    source_root = Path(kwargs.get("source_root") or kwargs["root"])
    stages.extend(
        [
            (
                "13a_independent_certificate_verifier",
                [
                    str(python),
                    str(source_root / "experiments/verify_evidence_certificates.py"),
                    "--certificates",
                    str(out_dir / "evidence_certificates/evidence_certificates.jsonl"),
                    "--source-dir",
                    str(campaign),
                    "--shell",
                    "/bin/bash",
                    "--shell",
                    "/bin/dash",
                    "--out-dir",
                    str(out_dir / "independent_certificate_verifier"),
                    "--fail-on-issues",
                ],
                900,
            ),
            (
                "13b_residual_root_causes",
                [
                    str(python),
                    str(source_root / "experiments/audit_residual_root_causes.py"),
                    "--campaign",
                    str(campaign),
                    "--out-dir",
                    str(out_dir / "residual_root_causes"),
                    "--require-complete",
                ],
                900,
            ),
            (
                "13c_performance_diagnostics",
                [
                    str(python),
                    str(source_root / "experiments/audit_performance_diagnostics.py"),
                    "--campaign",
                    str(campaign),
                    "--out-dir",
                    str(out_dir / "performance_diagnostics"),
                    "--require-complete",
                ],
                900,
            ),
            (
                "13d_reproduction_sbom",
                [
                    str(python),
                    str(source_root / "experiments/generate_reproduction_sbom.py"),
                    "--source-root",
                    str(source_root),
                    "--out-dir",
                    str(out_dir / "reproduction_sbom"),
                ],
                900,
            ),
            (
                "13e_satc_adapter_fixture",
                [
                    str(python),
                    str(source_root / "experiments/convert_satc_to_tsds.py"),
                    str(source_root / "experiments/fixtures/satc_sample.csv"),
                    "--input-format",
                    "csv",
                    "--output",
                    str(out_dir / "candidate_adapter/satc_closures.json"),
                ],
                300,
            ),
            (
                "13f_candidate_contract",
                [
                    str(python),
                    str(source_root / "experiments/audit_candidate_contract.py"),
                    "--input",
                    str(out_dir / "candidate_adapter/satc_closures.json"),
                    "--out-dir",
                    str(out_dir / "candidate_contract"),
                    "--require-valid",
                ],
                300,
            ),
        ]
    )
    return stages


def main() -> int:
    return run_pipeline(
        default_pipeline_tag=PIPELINE_TAG,
        default_pipeline_schema=PIPELINE_SCHEMA,
        additional_reproducibility_sources=ADDITIONAL_REPRODUCIBILITY_SOURCES,
        additional_mandatory_stages_builder=v18_mandatory_stages,
        busybox_stage_name="14_busybox_calibration",
        negative_stage_name="15_negative_confirmation",
        repeatability_stage_name="15b_repeatability_consensus",
        paper_stage_name="16_paper_tables",
        default_subprocess_memory_limit_mib=DEFAULT_SUBPROCESS_MEMORY_LIMIT_MIB,
        require_resource_calibration=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
