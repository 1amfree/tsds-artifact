#!/usr/bin/env python3
"""Run a reproducible TSDS v14 campaign with fail-closed acceptance gates.

The runner keeps campaign output immutable, records implementation identities,
and makes ledger, parser, and vector-decision audits mandatory before paper
tables are exported. It is an experiment orchestrator, not an exploit runner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.run_tsds_v10_pipeline import (  # noqa: E402
    artifact_identities,
    file_identity,
    load_campaign_targets,
    prepare_fresh_output_dir,
    query_host_environment,
    query_python_environment,
    run_stage,
)


V14_REPRODUCIBILITY_SOURCES = (
    "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py",
    "advanced_sanitizer_evaluator.py",
    "experiments/run_full_firmware_campaign.py",
    "experiments/run_tsds_v10_pipeline.py",
    "experiments/run_tsds_v14_pipeline.py",
    "experiments/audit_campaign_conservation.py",
    "experiments/audit_evidence_contract.py",
    "experiments/audit_vector_decision_integrity.py",
    "experiments/audit_shell_witness_syntax.py",
    "experiments/run_threat_matrix_boundary_suite.py",
    "experiments/export_v10_paper_tables.py",
    "experiments/verify_v10_artifact_manifest.py",
    "experiments/run_busybox_shell_vector_calibration.py",
    "experiments/run_negative_confirmation.py",
)

DETERMINISTIC_CHILD_ENVIRONMENT = {
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "LC_ALL": "C",
    "LANG": "C",
    "TZ": "UTC",
}


def select_targets(root: Path, requested: list[str]) -> list[dict[str, str]]:
    """Return requested targets in the canonical campaign-manifest order."""
    targets = load_campaign_targets(root)
    if not requested:
        return targets
    requested_set = set(requested)
    known = {str(target["name"]) for target in targets}
    unknown = sorted(requested_set - known)
    if unknown:
        raise ValueError(f"unknown target(s): {', '.join(unknown)}")
    selected = [target for target in targets if target["name"] in requested_set]
    if not selected:
        raise ValueError("target selection is empty")
    return selected


def build_campaign_command(
    python: Path,
    root: Path,
    campaign: Path,
    target_timeout: int,
    max_closures: int | None,
    subprocess_memory_limit_mib: int,
    targets: list[dict[str, str]],
    campaign_script: Path | None = None,
    evaluator: Path | None = None,
) -> list[str]:
    command = [
        str(python),
        str(campaign_script or "experiments/run_full_firmware_campaign.py"),
        "--root",
        str(root),
        "--out-dir",
        str(campaign),
        "--target-timeout",
        str(target_timeout),
        "--subprocess-memory-limit-mib",
        str(subprocess_memory_limit_mib),
    ]
    if evaluator is not None:
        command.extend(["--evaluator", str(evaluator)])
    if max_closures is not None:
        command.extend(["--max-closures", str(max_closures)])
    for target in targets:
        command.extend(["--target", str(target["name"])])
    return command


def build_reproducibility_manifest(
    root: Path,
    python: Path,
    targets: list[dict[str, str]],
    pipeline_schema: str = "tsds-v14-pipeline-v2",
    additional_sources: tuple[str, ...] = (),
    resource_calibration: Path | None = None,
) -> dict[str, Any]:
    source_paths = tuple(
        dict.fromkeys(V14_REPRODUCIBILITY_SOURCES + tuple(additional_sources))
    )
    source_files = [root / rel for rel in source_paths]
    missing_sources = [str(path) for path in source_files if not path.is_file()]
    inputs: list[dict[str, Any]] = []
    missing_inputs: list[str] = []
    for target in targets:
        row: dict[str, Any] = {
            "target": target["name"],
            "label": target["label"],
        }
        for kind in ("binary", "mango"):
            path = root / target[kind]
            if path.is_file():
                row[kind] = file_identity(path, root)
            else:
                missing_inputs.append(str(path))
        inputs.append(row)
    manifest = {
        "schema": "tsds-reproducibility-v2",
        "pipeline": pipeline_schema,
        "host_environment": query_host_environment(),
        "python_environment": query_python_environment(python, root),
        "python_executable": file_identity(python, root) if python.is_file() else None,
        "source_files": [
            file_identity(path, root) for path in source_files if path.is_file()
        ],
        "campaign_inputs": inputs,
        "selected_targets": [target["name"] for target in targets],
        "missing_sources": missing_sources,
        "missing_inputs": missing_inputs,
        "deterministic_child_environment": dict(DETERMINISTIC_CHILD_ENVIRONMENT),
    }
    if resource_calibration is not None and resource_calibration.is_file():
        manifest["resource_calibration"] = file_identity(resource_calibration, root)
    return manifest


def reproducibility_identity_map(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Flatten content identities into stable comparison keys."""

    identities: dict[str, dict[str, Any]] = {}
    for entry in manifest.get("source_files") or []:
        identities[f"source:{entry.get('path')}"] = entry
    for target in manifest.get("campaign_inputs") or []:
        target_name = str(target.get("target") or "")
        for kind in ("binary", "mango"):
            entry = target.get(kind)
            if entry:
                identities[f"input:{target_name}:{kind}"] = entry
    if manifest.get("resource_calibration"):
        identities["resource_calibration"] = manifest["resource_calibration"]
    if manifest.get("python_executable"):
        identities["python_executable"] = manifest["python_executable"]
    for entry in (manifest.get("repeatability_baseline") or {}).get("files") or []:
        identities[f"repeatability_baseline:{entry.get('path')}"] = entry
    return identities


def validate_resource_calibration(
    path: Path,
    limit_mib: int,
    *,
    project_root: Path | None = None,
    python: Path | None = None,
) -> list[str]:
    """Validate that a selected memory limit passed its declared stress set."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"resource_calibration_unreadable:{type(exc).__name__}"]
    issues: list[str] = []
    if document.get("schema") != "tsds-resource-limit-calibration-v2":
        issues.append("resource_calibration_schema_mismatch")
    required = {int(value) for value in document.get("required_limits_mib") or []}
    if int(limit_mib) not in required:
        issues.append("configured_limit_not_calibration_required")
    accepted = int((document.get("accepted_by_limit") or {}).get(str(limit_mib)) or 0)
    cases = int((document.get("cases_by_limit") or {}).get(str(limit_mib)) or 0)
    if cases <= 0:
        issues.append("configured_limit_has_no_calibration_cases")
    elif accepted != cases:
        issues.append("configured_limit_has_unaccepted_calibration_cases")
    if document.get("required_cases_accepted") is not True:
        issues.append("resource_calibration_required_cases_not_accepted")
    if document.get("input_identity_stable") is not True:
        issues.append("resource_calibration_input_identity_drift")
    identities = (
        (document.get("reproducibility") or {}).get("preflight_identities") or []
    )
    if len(identities) < 5 or any(
        len(str(row.get("sha256") or "")) != 64 for row in identities
    ):
        issues.append("resource_calibration_missing_input_identities")
    python_environment = (
        (document.get("reproducibility") or {}).get("python_environment") or {}
    )
    packages = python_environment.get("packages") or {}
    if not python_environment.get("python") or any(
        not packages.get(name) for name in ("angr", "claripy", "z3-solver")
    ):
        issues.append("resource_calibration_missing_python_environment")
    if project_root is not None:
        by_path = {
            str(row.get("path") or "").replace("\\", "/"): row
            for row in identities
        }
        for relative, observed in sorted(by_path.items()):
            declared = Path(relative)
            if declared.is_absolute() or ".." in declared.parts:
                continue
            expected_path = project_root / declared
            if not expected_path.is_file():
                issues.append(f"resource_calibration_input_missing:{relative}")
                continue
            expected = file_identity(expected_path, project_root)
            if (
                observed.get("sha256") != expected.get("sha256")
                or observed.get("size") != expected.get("size")
            ):
                issues.append(f"resource_calibration_input_mismatch:{relative}")
        for relative in (
            "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py",
            "experiments/run_resource_limit_calibration.py",
        ):
            expected_path = project_root / relative
            observed = by_path.get(relative)
            if not expected_path.is_file() or observed is None:
                issues.append(f"resource_calibration_missing_current_identity:{relative}")
                continue
            expected = file_identity(expected_path, project_root)
            if (
                observed.get("sha256") != expected.get("sha256")
                or observed.get("size") != expected.get("size")
            ):
                issues.append(f"resource_calibration_current_identity_mismatch:{relative}")
    if python is not None:
        current_python_environment = query_python_environment(python, project_root or Path.cwd())
        comparable_fields = ("python", "implementation", "packages")
        if any(
            python_environment.get(field) != current_python_environment.get(field)
            for field in comparable_fields
        ):
            issues.append("resource_calibration_python_environment_mismatch")
    return sorted(set(issues))


def compare_reproducibility_manifests(
    before: dict[str, Any], after: dict[str, Any]
) -> list[dict[str, Any]]:
    """Report source, input, or environment drift across a pipeline run."""

    baseline = reproducibility_identity_map(before)
    observed = reproducibility_identity_map(after)
    drift: list[dict[str, Any]] = []
    for key in sorted(set(baseline) | set(observed)):
        expected = baseline.get(key)
        actual = observed.get(key)
        if expected is None:
            drift.append({"identity": key, "outcome": "added_during_run", "after": actual})
        elif actual is None:
            drift.append({"identity": key, "outcome": "missing_after_run", "before": expected})
        elif (
            expected.get("sha256") != actual.get("sha256")
            or expected.get("size") != actual.get("size")
        ):
            drift.append(
                {
                    "identity": key,
                    "outcome": "content_drift",
                    "before": expected,
                    "after": actual,
                }
            )
    for field in (
        "host_environment",
        "python_environment",
        "missing_sources",
        "missing_inputs",
    ):
        if before.get(field) != after.get(field):
            drift.append(
                {
                    "identity": field,
                    "outcome": "environment_drift",
                    "before": before.get(field),
                    "after": after.get(field),
                }
            )
    return drift


def snapshot_reproducibility_sources(
    root: Path, manifest: dict[str, Any], destination: Path
) -> list[dict[str, Any]]:
    """Copy the exact preflight source set into the immutable artifact tree."""

    destination.mkdir(parents=True, exist_ok=True)
    snapshots: list[dict[str, Any]] = []
    for entry in manifest.get("source_files") or []:
        relative = Path(str(entry["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError(f"source snapshot path escapes project root: {relative}")
        source = (root / relative).resolve()
        target = (destination / relative).resolve()
        if destination.resolve() not in target.parents:
            raise RuntimeError(f"source snapshot destination escapes artifact root: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied = file_identity(target, destination)
        if (
            copied.get("sha256") != entry.get("sha256")
            or copied.get("size") != entry.get("size")
        ):
            raise RuntimeError(f"source changed while creating preflight snapshot: {relative}")
        snapshots.append(copied)
    if os.name == "posix":
        for path in sorted(destination.rglob("*"), reverse=True):
            if path.is_file():
                path.chmod(0o444)
        for path in sorted(
            (item for item in destination.rglob("*") if item.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            path.chmod(0o555)
        destination.chmod(0o555)
    return snapshots


def repeatability_baseline_manifest(directory: Path) -> dict[str, Any]:
    """Return a content identity for every baseline result ledger."""

    directory = directory.resolve()
    files = []
    for path in sorted(directory.rglob("*.results.jsonl")):
        resolved = path.resolve()
        if directory not in resolved.parents:
            raise RuntimeError(f"repeatability baseline path escapes root: {path}")
        if resolved.is_file():
            files.append(file_identity(resolved, directory))
    if not files:
        raise RuntimeError(f"no repeatability result ledgers in {directory}")
    payload = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema": "tsds-repeatability-baseline-lock-v1",
        "source_path": str(directory),
        "files": files,
        "files_count": len(files),
        "aggregate_sha256": hashlib.sha256(payload).hexdigest(),
    }


def snapshot_repeatability_baseline(
    source: Path, destination: Path
) -> dict[str, Any]:
    """Copy a repeatability baseline before campaign execution and verify it."""

    source_manifest = repeatability_baseline_manifest(source)
    destination.mkdir(parents=True, exist_ok=False)
    for entry in source_manifest["files"]:
        relative = Path(str(entry["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError(f"unsafe repeatability baseline path: {relative}")
        source_path = source / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target)
        copied = file_identity(target, destination)
        if copied.get("sha256") != entry.get("sha256") or copied.get(
            "size"
        ) != entry.get("size"):
            raise RuntimeError(
                f"repeatability baseline changed while snapshotting: {relative}"
            )
    snapshot_manifest = repeatability_baseline_manifest(destination)
    if snapshot_manifest["aggregate_sha256"] != source_manifest["aggregate_sha256"]:
        raise RuntimeError("repeatability baseline snapshot aggregate mismatch")
    if os.name == "posix":
        for path in destination.rglob("*"):
            if path.is_file():
                path.chmod(0o444)
        for path in sorted(
            (item for item in destination.rglob("*") if item.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            path.chmod(0o555)
        destination.chmod(0o555)
    return source_manifest


def acquire_pipeline_lock(root: Path, out_dir: Path) -> tuple[Any, dict[str, Any]]:
    """Hold one host-level campaign lock for uncontaminated resource metrics."""

    lock_path = root / "experiment_reports" / ".tsds_pipeline.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    if lock_path.stat().st_size == 0:
        handle.write(b"\0")
        handle.flush()
    mode = ""
    try:
        if os.name == "posix":
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            mode = "posix_flock_exclusive_nonblocking"
        elif os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            mode = "windows_byte_lock_exclusive_nonblocking"
        else:
            raise RuntimeError(f"unsupported platform for exclusive run lock: {os.name}")
    except (OSError, RuntimeError) as exc:
        owner = ""
        try:
            handle.seek(0)
            owner = handle.read().decode("utf-8", "replace").strip("\0\r\n ")
        except OSError:
            pass
        finally:
            handle.close()
        detail = f"; current owner: {owner}" if owner else ""
        raise RuntimeError(f"another TSDS pipeline holds {lock_path}{detail}") from exc

    lock_info = {
        "schema": "tsds-exclusive-run-lock-v1",
        "path": str(lock_path.resolve()),
        "mode": mode,
        "pid": os.getpid(),
        "out_dir": str(out_dir.resolve()),
        "acquired_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "claim_boundary": (
            "The lock excludes concurrent TSDS campaigns on this workspace; it "
            "does not exclude unrelated host workloads."
        ),
    }
    payload = (json.dumps(lock_info, sort_keys=True) + "\n").encode("utf-8")
    handle.seek(0)
    handle.truncate()
    handle.write(payload)
    handle.flush()
    os.fsync(handle.fileno())
    return handle, lock_info


def main(
    *,
    default_pipeline_tag: str = "v14",
    default_pipeline_schema: str = "tsds-v14-pipeline-v2",
    additional_reproducibility_sources: tuple[str, ...] = (),
    additional_mandatory_stages_builder: Any | None = None,
    busybox_stage_name: str = "08_busybox_calibration",
    negative_stage_name: str = "09_negative_confirmation",
    repeatability_stage_name: str = "09b_repeatability_consensus",
    paper_stage_name: str = "10_paper_tables",
    default_subprocess_memory_limit_mib: int = 0,
    require_resource_calibration: bool = False,
) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--python", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--max-closures", type=int, default=None)
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--target-timeout", type=int, default=7200)
    parser.add_argument(
        "--subprocess-memory-limit-mib",
        type=int,
        default=default_subprocess_memory_limit_mib,
        help="Per-closure POSIX address-space ceiling; 0 disables it.",
    )
    parser.add_argument("--pipeline-tag", default=default_pipeline_tag)
    parser.add_argument(
        "--pipeline-schema", default=default_pipeline_schema
    )
    parser.add_argument("--skip-busybox-calibration", action="store_true")
    parser.add_argument("--run-negative-confirmation", action="store_true")
    parser.add_argument("--negative-max-records", type=int, default=0)
    parser.add_argument("--repeatability-baseline", type=Path)
    parser.add_argument(
        "--require-sink-semantic-repeatability", action="store_true"
    )
    parser.add_argument("--resource-calibration-summary", type=Path)
    args = parser.parse_args()

    if args.subprocess_memory_limit_mib < 0:
        parser.error("--subprocess-memory-limit-mib must be non-negative")
    if (
        args.require_sink_semantic_repeatability
        and args.repeatability_baseline is None
    ):
        parser.error(
            "--require-sink-semantic-repeatability requires "
            "--repeatability-baseline"
        )

    root = args.root.resolve()
    python = (
        args.python.absolute()
        if args.python
        else root / "operation-mango-public" / ".venv" / "bin" / "python"
    )
    repeatability_baseline_live = None
    if args.repeatability_baseline is not None:
        repeatability_baseline_live = args.repeatability_baseline
        if not repeatability_baseline_live.is_absolute():
            repeatability_baseline_live = root / repeatability_baseline_live
        repeatability_baseline_live = repeatability_baseline_live.resolve()
        if not repeatability_baseline_live.is_dir():
            parser.error(
                f"repeatability baseline is not a directory: "
                f"{repeatability_baseline_live}"
            )
    calibration_path = None
    if args.resource_calibration_summary is not None:
        calibration_path = args.resource_calibration_summary
        if not calibration_path.is_absolute():
            calibration_path = root / calibration_path
        calibration_path = calibration_path.resolve()
    if args.subprocess_memory_limit_mib > 0:
        if require_resource_calibration and calibration_path is None:
            parser.error(
                "--resource-calibration-summary is required for this pipeline "
                "when a worker memory limit is enabled"
            )
        if calibration_path is not None:
            calibration_issues = validate_resource_calibration(
                calibration_path,
                args.subprocess_memory_limit_mib,
                project_root=root,
                python=python,
            )
            if calibration_issues:
                parser.error("invalid resource calibration: " + ", ".join(calibration_issues))
    try:
        targets = select_targets(root, args.target)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 3

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = (
        args.out_dir.resolve()
        if args.out_dir
        else root / "experiment_reports" / f"tsds_{args.pipeline_tag}_pipeline_{stamp}"
    )
    try:
        pipeline_lock, lock_info = acquire_pipeline_lock(root, out_dir)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    try:
        prepare_fresh_output_dir(out_dir)
    except RuntimeError as exc:
        pipeline_lock.close()
        print(str(exc), file=sys.stderr)
        return 3

    for key, value in DETERMINISTIC_CHILD_ENVIRONMENT.items():
        os.environ[key] = value

    repeatability_baseline_snapshot = None
    repeatability_baseline_preflight = None
    if repeatability_baseline_live is not None:
        repeatability_baseline_snapshot = out_dir / "repeatability_baseline_snapshot"
        try:
            repeatability_baseline_preflight = snapshot_repeatability_baseline(
                repeatability_baseline_live,
                repeatability_baseline_snapshot,
            )
            repeatability_baseline_preflight[
                "execution_path"
            ] = repeatability_baseline_snapshot.relative_to(out_dir).as_posix()
        except RuntimeError as exc:
            pipeline_lock.close()
            print(str(exc), file=sys.stderr)
            return 3

    preflight_reproducibility = build_reproducibility_manifest(
        root,
        python,
        targets,
        pipeline_schema=str(args.pipeline_schema),
        additional_sources=additional_reproducibility_sources,
        resource_calibration=calibration_path,
    )
    if repeatability_baseline_preflight is not None:
        preflight_reproducibility[
            "repeatability_baseline"
        ] = repeatability_baseline_preflight
    preflight_reproducibility["source_execution_root"] = "source_snapshot"
    preflight_reproducibility["source_snapshot_mode"] = (
        "read_only" if os.name == "posix" else "content_addressed"
    )
    if calibration_path is not None:
        calibration_snapshot = out_dir / "resource_limit_calibration.json"
        shutil.copyfile(calibration_path, calibration_snapshot)
        preflight_reproducibility["resource_calibration_execution_path"] = (
            calibration_snapshot.name
        )
    preflight_path = out_dir / "reproducibility_preflight.json"
    preflight_path.write_text(
        json.dumps(preflight_reproducibility, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    try:
        source_root = out_dir / "source_snapshot"
        source_snapshots = snapshot_reproducibility_sources(
            root, preflight_reproducibility, source_root
        )
    except RuntimeError as exc:
        pipeline_lock.close()
        print(str(exc), file=sys.stderr)
        return 3

    logs = out_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    campaign = out_dir / "campaign"
    stages: list[dict[str, Any]] = []
    campaign_command = build_campaign_command(
        python,
        root,
        campaign,
        args.target_timeout,
        args.max_closures,
        args.subprocess_memory_limit_mib,
        targets,
        campaign_script=source_root / "experiments/run_full_firmware_campaign.py",
        evaluator=source_root / "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py",
    )
    stages.append(
        run_stage(
            "01_full_campaign",
            campaign_command,
            root,
            max(args.target_timeout * len(targets) + 600, 1800),
            logs,
        )
    )

    mandatory = [
        (
            "02_campaign_conservation",
            [
                str(python),
                str(source_root / "experiments/audit_campaign_conservation.py"),
                "--campaign-dir",
                str(campaign),
                "--out-dir",
                str(out_dir / "campaign_conservation"),
                "--expected-targets",
                str(len(targets)),
                "--require-resource-metrics",
                "--fail-on-issues",
            ],
            900,
        ),
        (
            "03_evidence_contract",
            [
                str(python),
                str(source_root / "experiments/audit_evidence_contract.py"),
                "--input-dir",
                str(campaign),
                "--out-dir",
                str(out_dir / "evidence_contract"),
                "--fail-on-contract-issues",
            ],
            900,
        ),
        (
            "04_vector_decision_integrity",
            [
                str(python),
                str(source_root / "experiments/audit_vector_decision_integrity.py"),
                "--input-dir",
                str(campaign),
                "--out-dir",
                str(out_dir / "vector_decision_integrity"),
                "--fail-on-issues",
            ],
            900,
        ),
        (
            "05_shell_witness_syntax",
            [
                str(python),
                str(source_root / "experiments/audit_shell_witness_syntax.py"),
                "--input-dir",
                str(campaign),
                "--out-dir",
                str(out_dir / "shell_witness_syntax"),
                "--fail-on-invalid-minimal",
            ],
            900,
        ),
        (
            "06_threat_matrix_boundary",
            [
                str(python),
                str(source_root / "experiments/run_threat_matrix_boundary_suite.py"),
                "--out-dir",
                str(out_dir / "threat_matrix_boundary"),
            ],
            900,
        ),
    ]
    if stages[0]["returncode"] == 0:
        for name, command, timeout in mandatory:
            stages.append(run_stage(name, command, root, timeout, logs))
        if additional_mandatory_stages_builder is not None:
            for name, command, timeout in additional_mandatory_stages_builder(
                root=root,
                python=python,
                campaign=campaign,
                out_dir=out_dir,
                args=args,
                targets=targets,
                source_root=source_root,
            ):
                stages.append(run_stage(name, command, root, timeout, logs))

    if not args.skip_busybox_calibration and stages[0]["returncode"] == 0:
        stages.append(
            run_stage(
                busybox_stage_name,
                [
                    str(python),
                    str(source_root / "experiments/run_busybox_shell_vector_calibration.py"),
                    "--workspace",
                    str(root),
                    "--out-dir",
                    str(out_dir / "busybox_calibration"),
                ],
                root,
                1800,
                logs,
            )
        )

    if args.run_negative_confirmation and stages[0]["returncode"] == 0:
        command = [
            str(python),
            str(source_root / "experiments/run_negative_confirmation.py"),
            "--root",
            str(root),
            "--evaluator",
            str(source_root / "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py"),
            "--memory-limit-mib",
            str(args.subprocess_memory_limit_mib),
            "--fail-on-replay-errors",
            "--fail-on-positive-change",
            # 运行负向确认时必须至少真正重放一条记录，禁止空实验通过。
            "--minimum-records",
            "1",
            "--campaign-dir",
            str(campaign),
            "--out-dir",
            str(out_dir / "negative_confirmation"),
        ]
        if args.negative_max_records:
            command.extend(["--max-records", str(args.negative_max_records)])
        stages.append(
            run_stage(
                negative_stage_name,
                command,
                root,
                max(args.target_timeout * len(targets), 1800),
                logs,
            )
        )

    if repeatability_baseline_snapshot is not None and stages[0]["returncode"] == 0:
        command = [
            str(python),
            str(source_root / "experiments/audit_repeatability.py"),
            "--baseline-dir",
            str(repeatability_baseline_snapshot),
            "--replay-dir",
            str(campaign),
            "--out-dir",
            str(out_dir / "repeatability_consensus"),
        ]
        if args.require_sink_semantic_repeatability:
            command.extend(
                [
                    "--fail-on-sink-semantic-drift",
                    # 拒绝 0/0 agreement，保证重复性门禁具有实际证据支撑。
                    "--require-sink-semantic-records",
                    "--require-same-record-set",
                ]
            )
        stages.append(
            run_stage(
                repeatability_stage_name,
                command,
                root,
                900,
                logs,
            )
        )

    # Re-hash the live sources and campaign inputs before exporting any
    # paper-facing table.  The campaign itself executes from the immutable
    # source snapshot, but a changed live input still invalidates the declared
    # run identity and must fail closed before derived claims are emitted.
    postflight_reproducibility = build_reproducibility_manifest(
        root,
        python,
        targets,
        pipeline_schema=str(args.pipeline_schema),
        additional_sources=additional_reproducibility_sources,
        resource_calibration=calibration_path,
    )
    if repeatability_baseline_live is not None:
        try:
            postflight_reproducibility[
                "repeatability_baseline"
            ] = repeatability_baseline_manifest(repeatability_baseline_live)
        except RuntimeError as exc:
            postflight_reproducibility["repeatability_baseline"] = {
                "schema": "tsds-repeatability-baseline-lock-v1",
                "source_path": str(repeatability_baseline_live),
                "files": [],
                "error": str(exc),
            }
    identity_drift = compare_reproducibility_manifests(
        preflight_reproducibility, postflight_reproducibility
    )
    drift_report = {
        "schema": "tsds-run-identity-drift-v1",
        "stable": not identity_drift,
        "drift_count": len(identity_drift),
        "drift": identity_drift,
        "claim_boundary": (
            "This gate binds a pipeline run to its preflight source and input identities; "
            "it does not validate analyzer semantics or exploitability."
        ),
    }
    drift_path = out_dir / "reproducibility_drift.json"
    drift_path.write_text(
        json.dumps(drift_report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    stages.append(
        {
            "name": "99_run_identity_drift_gate",
            "command": ["internal:compare-preflight-postflight-identities"],
            "returncode": 0 if not identity_drift else 2,
            "elapsed_sec": 0.0,
            "log": str(drift_path),
        }
    )

    paper_command = [
        str(python),
        str(source_root / "experiments/export_v10_paper_tables.py"),
        "--campaign-dir",
        str(campaign),
        "--out-dir",
        str(out_dir / "paper_tables"),
        "--contract-audit",
        str(out_dir / "evidence_contract" / "evidence_contract_audit.json"),
        "--syntax-audit",
        str(
            out_dir
            / "shell_witness_syntax"
            / "shell_witness_syntax_summary.json"
        ),
    ]
    if repeatability_baseline_snapshot is not None:
        paper_command.extend(
            [
                "--repeatability-audit",
                str(out_dir / "repeatability_consensus" / "repeatability_summary.json"),
            ]
        )
    blocking_stages = [
        stage["name"] for stage in stages if int(stage.get("returncode") or 0) != 0
    ]
    if not blocking_stages:
        stages.append(run_stage(paper_stage_name, paper_command, root, 900, logs))
    else:
        blocked_path = logs / f"{paper_stage_name}.log"
        blocked_path.write_text(
            "PAPER_TABLE_EXPORT_BLOCKED\n" + "\n".join(blocking_stages) + "\n",
            encoding="utf-8",
        )
        stages.append(
            {
                "name": paper_stage_name,
                "command": paper_command,
                "returncode": 125,
                "elapsed_sec": 0.0,
                "log": str(blocked_path),
                "blocked_by": blocking_stages,
            }
        )

    success = all(stage["returncode"] == 0 for stage in stages)
    manifest = {
        "schema": str(args.pipeline_schema),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "out_dir": str(out_dir),
        "invocation": sys.argv,
        "exclusive_run_lock": lock_info,
        "success": success,
        "stages": stages,
        "reproducibility": preflight_reproducibility,
        "postflight_reproducibility": postflight_reproducibility,
        "source_snapshots": source_snapshots,
        "identity_drift": drift_report,
        "artifacts": artifact_identities(out_dir),
    }
    (out_dir / "pipeline_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    pipeline_lock.close()
    print(
        json.dumps(
            {
                "success": success,
                "manifest": str(out_dir / "pipeline_manifest.json"),
                "stages": [
                    {"name": stage["name"], "returncode": stage["returncode"]}
                    for stage in stages
                ],
                "artifact_files": len(manifest["artifacts"]),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if success else 2


if __name__ == "__main__":
    raise SystemExit(main())
