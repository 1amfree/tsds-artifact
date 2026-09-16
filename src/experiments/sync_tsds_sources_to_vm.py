#!/usr/bin/env python3
"""Atomically synchronize the reviewed TSDS source set to the Ubuntu VM."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.run_tsds_v14_pipeline import (  # noqa: E402
    V14_REPRODUCIBILITY_SOURCES,
)
from experiments.run_tsds_v18_pipeline import (  # noqa: E402
    ADDITIONAL_REPRODUCIBILITY_SOURCES as V18_REPRODUCIBILITY_SOURCES,
)


# Keep deployment parity with every source that the v18 run lock declares.
# The support set adds regression tests and synchronization-only fixtures that
# are intentionally not part of the analyzer's paper-facing source identity.
SYNC_SUPPORT_FILES = (
    "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py",
    "TSDS_P012_INNOVATION.md",
    "experiments/V19_EXPERIMENT_PROTOCOL.md",
    "tsds/ledger_schema.py",
    "tsds/evidence_scheduler.py",
    "tsds/sink_corridor.py",
    "tsds/model_refinement.py",
    "tsds/summary_synthesis.py",
    "tsds/constraint_projection.py",
    "tsds/evidence_scope.py",
    "tsds/reconciliation_link.py",
    "tsds/source_realizability.py",
    "tsds/forkserver.py",
    "tsds/provenance_graph.py",
    "tsds/sink_semantics.py",
    "tsds/online_refinement.py",
    "tsds/multi_state_aggregation.py",
    "schemas/tsds-ledger-v16.schema.json",
    "schemas/tsds-ledger-v17.schema.json",
    "experiments/run_full_firmware_campaign.py",
    "experiments/run_tsds_v19_experiment_matrix.py",
    "experiments/analyze_tsds_v19_experiment_matrix.py",
    "experiments/audit_v19_mechanism_invariants.py",
    "experiments/audit_v19_refinement_bundles.py",
    "experiments/build_v20_refinement_bundles.py",
    "experiments/run_tsds_v14_pipeline.py",
    "experiments/run_tsds_v16_pipeline.py",
    "experiments/run_tsds_v17_pipeline.py",
    "experiments/run_tsds_v18_pipeline.py",
    "experiments/run_tsds_pipeline.py",
    "experiments/run_resource_limit_calibration.py",
    "experiments/run_residual_refinement_v2.py",
    "experiments/run_negative_confirmation.py",
    "experiments/audit_evidence_contract.py",
    "experiments/test_campaign_conservation_audit.py",
    "experiments/audit_ledger_schema.py",
    "experiments/verify_v10_artifact_manifest.py",
    "experiments/compare_external_baseline.py",
    "experiments/sync_tsds_sources_to_vm.py",
    "experiments/enforce_memoryerror_passthrough.py",
    "experiments/fixtures/golden_ledger_v16.jsonl",
    "experiments/test_sink_evidence_boundaries.py",
    "experiments/test_ledger_schema.py",
    "experiments/test_evidence_contract_audit.py",
    "experiments/test_v14_pipeline_reproducibility.py",
    "experiments/test_v16_pipeline_entrypoint.py",
    "experiments/test_v17_pipeline_entrypoint.py",
    "experiments/test_resource_limit_calibration.py",
    "experiments/test_residual_refinement_runner_v2.py",
    "experiments/test_negative_confirmation.py",
    "experiments/test_verify_v10_artifact_manifest.py",
    "experiments/test_external_baseline_comparison.py",
    "experiments/test_sync_tsds_sources_to_vm.py",
    "experiments/test_memoryerror_passthrough.py",
    "experiments/test_memory_limit_fail_closed.py",
    "experiments/test_residual_root_causes.py",
    "experiments/test_evidence_scheduler.py",
    "experiments/test_sink_corridor.py",
    "experiments/test_model_refinement.py",
    "experiments/test_summary_synthesis.py",
    "experiments/test_constraint_projection.py",
    "experiments/audit_evidence_scope.py",
    "experiments/test_evidence_scope.py",
    "experiments/run_saner2027_semantic_benchmark.py",
    "experiments/test_saner2027_semantic_benchmark.py",
    "experiments/test_reconciliation_link.py",
    "experiments/run_source_realizability_preflight.py",
    "experiments/test_source_realizability.py",
    "experiments/audit_conditioned_links.py",
    "experiments/replay_smt_query_bundles.py",
    "experiments/build_saner2027_t03_preflight.py",
    "experiments/audit_matrix_profile_conservation.py",
    "experiments/test_audit_matrix_profile_conservation.py",
    "experiments/fixtures/saner2027_ground_truth_quota_20260913.json",
    "experiments/test_build_blinded_ground_truth_sample.py",
    "experiments/build_saner2027_baseline_lock.py",
    "experiments/build_saner2027_scope_receipts.py",
    "experiments/test_replay_smt_query_bundles.py",
    "experiments/test_forkserver.py",
    "experiments/test_provenance_graph.py",
    "experiments/test_sink_semantics.py",
    "experiments/test_online_refinement.py",
    "experiments/test_multi_state_aggregation.py",
    "experiments/test_tsds_innovation_integration.py",
    "experiments/test_tsds_v19_experiment_matrix.py",
    "experiments/test_analyze_tsds_v19_experiment_matrix.py",
    "experiments/test_v19_mechanism_invariants.py",
    "experiments/test_v19_refinement_bundles.py",
    "experiments/test_build_v20_refinement_bundles.py",
    "experiments/audit_repeatability.py",
    "experiments/test_repeatability_audit.py",
    "experiments/audit_runtime_repeatability.py",
    "experiments/test_runtime_repeatability.py",
    "experiments/RUNTIME_REPEATABILITY_PROTOCOL.md",
    "experiments/build_blinded_ground_truth_sample.py",
    "experiments/validate_ground_truth_annotations.py",
    "experiments/unblind_ground_truth_audit.py",
    "experiments/package_blinded_audit.py",
    "experiments/test_ground_truth_audit.py",
    "experiments/GROUND_TRUTH_AUDIT_PROTOCOL.md",
    "experiments/build_deterministic_artifact_archive.py",
    "experiments/verify_deterministic_artifact_archive.py",
    "experiments/test_deterministic_artifact_archive.py",
    "experiments/audit_release_readiness.py",
    "experiments/test_release_readiness.py",
    "experiments/test_satc_adapter.py",
    "experiments/test_convert_satc_native_results.py",
    "experiments/satc_python3_compat.py",
    "experiments/test_satc_python3_compat.py",
    "experiments/run_satc_keyword_extraction.py",
    "experiments/test_satc_keyword_extraction.py",
    "experiments/build_satc_keyword_slice.py",
    "experiments/test_satc_keyword_slice.py",
    "experiments/run_satc_ghidra_experiment.py",
    "experiments/test_satc_ghidra_experiment.py",
    "experiments/satc_source_snapshot.py",
    "experiments/build_satc_source_snapshot.py",
    "experiments/test_satc_source_snapshot.py",
    "experiments/capture_satc_js_parser_environment.py",
    "experiments/test_capture_satc_js_parser_environment.py",
    "experiments/build_reviewed_source_snapshot.py",
    "experiments/test_build_reviewed_source_snapshot.py",
    "experiments/export_v20_ablation_transitions.py",
    "experiments/test_export_v20_ablation_transitions.py",
    "experiments/build_runtime_validation_expansion_pack.py",
    "experiments/test_runtime_validation_expansion_pack.py",
    "experiments/test_runtime_validation_v20.py",
    "experiments/build_v20_claim_evidence_matrix.py",
    "experiments/test_build_v20_claim_evidence_matrix.py",
    "experiments/run_v20_r3_experiment_queue.sh",
    "experiments/resume_v20_queue_after_runtime_audit.sh",
    "experiments/run_v20_post_release.sh",
    "experiments/run_saner2027_controlled_benchmark.py",
    "experiments/build_saner2027_controlled_baseline.py",
    "experiments/run_saner2027_witness_replay.py",
    "experiments/test_saner2027_witness_replay.py",
    "experiments/run_saner2027_multistate_benchmark.py",
    "experiments/build_source_dependency_manifest.py",
    "experiments/test_saner2027_multistate_benchmark.py",
    "experiments/test_source_dependency_manifest.py",
    "experiments/test_v20_post_release_orchestrator.py",
    "experiments/test_v20_queue_resume.py",
    "experiments/fixtures/satc_sample.result-alter2",
    "experiments/fixtures/satc_sample_result.txt",
    "experiments/fixtures/satc_sample_ref2sink_cmdi.result",
)
SOURCE_FILES = tuple(
    dict.fromkeys(
        V14_REPRODUCIBILITY_SOURCES
        + V18_REPRODUCIBILITY_SOURCES
        + SYNC_SUPPORT_FILES
    )
)
ACTIVE_PROCESS_MARKERS = (
    "advanced_sanitizer_evaluator.py",
    "run_full_firmware_campaign.py",
    "run_tsds_v19_experiment_matrix.py",
    "analyze_tsds_v19_experiment_matrix.py",
    "audit_v19_mechanism_invariants.py",
    "audit_v19_refinement_bundles.py",
    "build_v20_refinement_bundles.py",
    "run_tsds_v16_pipeline.py",
    "run_tsds_v17_pipeline.py",
    "run_tsds_v18_pipeline.py",
    "run_tsds_pipeline.py",
    "run_resource_limit_calibration.py",
    "run_residual_refinement_v2.py",
    "run_negative_confirmation.py",
    "audit_repeatability.py",
    "audit_runtime_repeatability.py",
    "build_blinded_ground_truth_sample.py",
    "validate_ground_truth_annotations.py",
    "unblind_ground_truth_audit.py",
    "package_blinded_audit.py",
    "compare_external_baseline.py",
    "build_deterministic_artifact_archive.py",
    "verify_deterministic_artifact_archive.py",
    "audit_release_readiness.py",
    "verify_v18_evidence_extension.py",
    "run_source_snapshot_self_test.py",
    "build_repeatability_slice.py",
    "export_v10_paper_tables.py",
    "audit_campaign_conservation.py",
    "audit_evidence_contract.py",
    "audit_vector_decision_integrity.py",
    "audit_shell_witness_syntax.py",
    "run_threat_matrix_boundary_suite.py",
    "run_busybox_shell_vector_calibration.py",
    "audit_ledger_schema.py",
    "audit_resource_envelopes.py",
    "audit_shell_dialect_profiles.py",
    "convert_satc_native_results.py",
    "convert_satc_to_tsds.py",
    "run_satc_ghidra_experiment.py",
    "build_satc_source_snapshot.py",
    "capture_satc_js_parser_environment.py",
    "build_reviewed_source_snapshot.py",
    "export_v20_ablation_transitions.py",
    "build_runtime_validation_expansion_pack.py",
    "build_v20_claim_evidence_matrix.py",
    "run_saner2027_witness_replay.py",
    "run_saner2027_multistate_benchmark.py",
    "resume_v20_queue_after_runtime_audit.sh",
)


def safe_relative_path(value: str) -> PurePosixPath:
    """将同步路径限制为规范相对 POSIX 路径，避免跨平台路径穿越。"""

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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_remote(sftp: paramiko.SFTPClient, path: str) -> str:
    digest = hashlib.sha256()
    with sftp.open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ensure_remote_dir(sftp: paramiko.SFTPClient, path: str) -> None:
    current = "/" if path.startswith("/") else ""
    for part in PurePosixPath(path).parts:
        if part == "/":
            continue
        current = posixpath.join(current, part)
        try:
            sftp.stat(current)
        except OSError:
            sftp.mkdir(current)


def copy_remote(sftp: paramiko.SFTPClient, source: str, destination: str) -> None:
    ensure_remote_dir(sftp, posixpath.dirname(destination))
    with sftp.open(source, "rb") as reader, sftp.open(destination, "wb") as writer:
        for block in iter(lambda: reader.read(1024 * 1024), b""):
            writer.write(block)


def active_analysis_processes(ssh: paramiko.SSHClient) -> list[str]:
    _stdin, stdout, _stderr = ssh.exec_command("ps -eo pid=,args=")
    lines = stdout.read().decode("utf-8", "replace").splitlines()
    return [
        line.strip()
        for line in lines
        if any(marker in line for marker in ACTIVE_PROCESS_MARKERS)
        and "sync_tsds_sources_to_vm.py" not in line
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="192.168.206.137")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", default="ubuntu")
    parser.add_argument("--password-env", default="TSDS_VM_PASSWORD")
    parser.add_argument("--local-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--remote-root", default="/home/ubuntu/work/sanitizer")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    local_root = args.local_root.resolve()
    entries: list[dict[str, Any]] = []
    for value in SOURCE_FILES:
        relative = safe_relative_path(value)
        local = local_root / Path(*relative.parts)
        if not local.is_file():
            parser.error(f"missing local source: {local}")
        entries.append(
            {
                "path": str(relative),
                "local": local,
                "sha256": sha256_file(local),
                "size": local.stat().st_size,
            }
        )
    if args.dry_run:
        print(json.dumps({"files": len(entries), "paths": [row["path"] for row in entries]}, indent=2))
        return 0

    password = os.environ.get(args.password_env)
    if not password:
        parser.error(f"missing password environment variable: {args.password_env}")

    # Paramiko is a deployment-only dependency.  Keep it out of module import
    # so the analysis virtual environment can import and test the manifest/path
    # helpers without carrying host-side SSH tooling.
    try:
        import paramiko
    except ImportError as exc:
        parser.error(f"paramiko is required for a non-dry-run synchronization: {exc}")

    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(args.host, args.port, args.user, password)
    try:
        active = active_analysis_processes(ssh)
        if active:
            print("refusing source sync while analysis processes are active:", file=sys.stderr)
            for line in active:
                print(f"  {line}", file=sys.stderr)
            return 4
        sftp = ssh.open_sftp()
        try:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup_root = posixpath.join(
                args.remote_root, "experiment_reports", "source_backups", f"pre_v18_{stamp}"
            )
            token = uuid.uuid4().hex
            for row in entries:
                remote = posixpath.join(args.remote_root, row["path"])
                ensure_remote_dir(sftp, posixpath.dirname(remote))
                temporary = f"{remote}.upload-{token}"
                sftp.put(str(row["local"]), temporary)
                if sha256_remote(sftp, temporary) != row["sha256"]:
                    raise RuntimeError(f"staged upload hash mismatch: {row['path']}")
                row["remote"] = remote
                row["temporary"] = temporary
            for row in entries:
                try:
                    sftp.stat(row["remote"])
                except OSError:
                    row["backup"] = None
                else:
                    backup = posixpath.join(backup_root, row["path"])
                    copy_remote(sftp, row["remote"], backup)
                    row["backup"] = backup
            for row in entries:
                sftp.posix_rename(row["temporary"], row["remote"])
                if sha256_remote(sftp, row["remote"]) != row["sha256"]:
                    raise RuntimeError(f"installed source hash mismatch: {row['path']}")
            manifest = {
                "schema": "tsds-source-sync-v1",
                "generated_at_utc": stamp,
                "remote_root": args.remote_root,
                "backup_root": backup_root,
                "files": [
                    {
                        "path": row["path"],
                        "size": row["size"],
                        "sha256": row["sha256"],
                        "backup": row["backup"],
                    }
                    for row in entries
                ],
            }
            manifest_path = posixpath.join(
                args.remote_root, "experiment_reports", f"source_sync_v18_{stamp}.json"
            )
            with sftp.open(manifest_path, "w") as stream:
                stream.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        finally:
            sftp.close()
    finally:
        ssh.close()
    print(json.dumps({"synced": len(entries), "manifest": manifest_path}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
