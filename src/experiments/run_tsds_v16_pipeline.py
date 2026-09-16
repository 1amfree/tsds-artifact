#!/usr/bin/env python3
"""Run the TSDS v16 evidence, refinement, and artifact-quality pipeline."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.run_tsds_v14_pipeline import main as run_pipeline  # noqa: E402


PIPELINE_TAG = "v16"
PIPELINE_SCHEMA = "tsds-v16-pipeline-v2"
DEFAULT_SUBPROCESS_MEMORY_LIMIT_MIB = 8192
ADDITIONAL_REPRODUCIBILITY_SOURCES = (
    "experiments/run_tsds_v16_pipeline.py",
    "experiments/build_evidence_certificates.py",
    "experiments/build_residual_refinement_v2.py",
    "experiments/run_residual_refinement_v2.py",
    "experiments/audit_resource_envelopes.py",
    "experiments/audit_shell_dialect_profiles.py",
    "experiments/build_counterfactual_repair_pack.py",
    "experiments/audit_ledger_schema.py",
    "experiments/run_resource_limit_calibration.py",
    "tsds/__init__.py",
    "tsds/evidence_certificates.py",
    "tsds/residual_refinement.py",
    "tsds/resource_envelopes.py",
    "tsds/shell_dialects.py",
    "tsds/sanitizer_repair.py",
    "tsds/ledger_schema.py",
    "schemas/tsds-ledger-v16.schema.json",
)


def v16_mandatory_stages(**kwargs: Any) -> list[tuple[str, list[str], int]]:
    python = kwargs["python"]
    campaign = kwargs["campaign"]
    out_dir = kwargs["out_dir"]
    args = kwargs["args"]
    source_root = kwargs.get("source_root") or kwargs["root"]
    resource_command = [
        str(python), str(source_root / "experiments/audit_resource_envelopes.py"),
        "--input-dir", str(campaign),
        "--out-dir", str(out_dir / "resource_envelope"),
        "--require-per-record-rss",
        "--fail-on-issues",
    ]
    if int(args.subprocess_memory_limit_mib or 0) > 0:
        resource_command.extend([
            "--require-memory-limit-enforced",
            "--fail-on-resource-limit-hits",
        ])
    resource_command.append("--fail-on-unavailable-worker-metrics")
    return [
        (
            "08_evidence_certificates",
            [
                str(python), str(source_root / "experiments/build_evidence_certificates.py"),
                "--input-dir", str(campaign),
                "--out-dir", str(out_dir / "evidence_certificates"),
                "--fail-on-issues",
            ],
            900,
        ),
        (
            "09_resource_envelope",
            resource_command,
            900,
        ),
        (
            "10_ledger_schema",
            [
                str(python), str(source_root / "experiments/audit_ledger_schema.py"),
                "--input-dir", str(campaign),
                "--out-dir", str(out_dir / "ledger_schema"),
                "--fail-on-issues",
            ],
            900,
        ),
        (
            "11_shell_dialect_profiles",
            [
                str(python), str(source_root / "experiments/audit_shell_dialect_profiles.py"),
                "--input-dir", str(campaign),
                "--out-dir", str(out_dir / "shell_dialect_profiles"),
                "--fail-on-sat-issues",
            ],
            900,
        ),
        (
            "12_counterfactual_repair_pack",
            [
                str(python), str(source_root / "experiments/build_counterfactual_repair_pack.py"),
                "--input-dir", str(campaign),
                "--out-dir", str(out_dir / "counterfactual_repair"),
            ],
            900,
        ),
        (
            "13_residual_refinement_plan",
            [
                str(python), str(source_root / "experiments/build_residual_refinement_v2.py"),
                "--input-dir", str(campaign),
                "--out-dir", str(out_dir / "residual_refinement_plan"),
            ],
            900,
        ),
    ]


def main() -> int:
    return run_pipeline(
        default_pipeline_tag=PIPELINE_TAG,
        default_pipeline_schema=PIPELINE_SCHEMA,
        additional_reproducibility_sources=ADDITIONAL_REPRODUCIBILITY_SOURCES,
        additional_mandatory_stages_builder=v16_mandatory_stages,
        busybox_stage_name="14_busybox_calibration",
        negative_stage_name="15_negative_confirmation",
        paper_stage_name="16_paper_tables",
        default_subprocess_memory_limit_mib=DEFAULT_SUBPROCESS_MEMORY_LIMIT_MIB,
    )


if __name__ == "__main__":
    raise SystemExit(main())
