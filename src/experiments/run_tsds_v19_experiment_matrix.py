#!/usr/bin/env python3
"""Run an immutable, auditable P0/P1/P2 TSDS v19 experiment matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "tsds-v19-experiment-matrix-v1"
DEFAULT_TARGET_NAMES = (
    "asus_rt_be57",
    "dir878",
    "r6400v2",
    "r7000",
    "tenda_ac15",
    "tenda_ac18",
    "tenda_w20e",
    "xr300",
)
CONFIGURATIONS: dict[str, dict[str, Any]] = {
    "full": {
        "description": "All v19 P0/P1/P2 mechanisms enabled.",
        "arguments": [],
    },
    "p0_scheduler_off": {
        "description": "Disable evidence-aware adaptive scheduling only.",
        "arguments": ["--no-evidence-aware-scheduler"],
    },
    "p0_corridor_off": {
        "description": "Disable the sink-directed corridor only.",
        "arguments": ["--no-sink-corridor"],
    },
    "p0_all_off": {
        "description": "Disable both P0 scheduling and sink-corridor control.",
        "arguments": ["--no-evidence-aware-scheduler", "--no-sink-corridor"],
    },
    "p1_projection_off": {
        "description": "Disable source-projected matrix constraints.",
        "arguments": ["--no-source-projected-constraints"],
    },
    "p1_spawn_backend": {
        "description": "Use isolated spawn workers instead of copy-on-write fork workers.",
        "execution_backend": "spawn",
        "arguments": [],
    },
    "p2_provenance_off": {
        "description": "Disable byte-level provenance graph construction.",
        "arguments": ["--no-byte-provenance"],
    },
    "p2_semantics_off": {
        "description": "Disable sink-semantics plugins and direct-exec shell-c recognition.",
        "arguments": ["--no-sink-semantic-plugins"],
    },
    "p2_refinement_off": {
        "description": "Disable bounded online residual refinement.",
        "arguments": ["--online-refinement-rounds", "0"],
    },
    "p2_refinement_replay": {
        "description": "Replay target-specific admitted residual-CEGAR summaries.",
        "requires_refinement_bundle_dir": True,
        "arguments": [],
    },
}
DEFAULT_CONFIGURATION_NAMES = tuple(
    name
    for name, specification in CONFIGURATIONS.items()
    if not specification.get("requires_refinement_bundle_dir")
)

DETERMINISTIC_ENVIRONMENT = {
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "LC_ALL": "C",
    "LANG": "C",
    "TZ": "UTC",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def preserve_executable_path(path: Path) -> Path:
    """Make an executable path absolute without dereferencing a venv symlink."""

    return Path(os.path.abspath(os.fspath(path)))


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def parse_configurations(value: str) -> list[str]:
    names = [item.strip() for item in value.split(",") if item.strip()]
    names = names or list(DEFAULT_CONFIGURATION_NAMES)
    unknown = sorted(set(names) - set(CONFIGURATIONS))
    if unknown:
        raise ValueError("unknown configuration(s): " + ", ".join(unknown))
    return list(dict.fromkeys(names))


def effective_configuration_arguments(name: str) -> list[str]:
    """Return arguments with scalar overrides replacing the full defaults."""
    return list(CONFIGURATIONS[name]["arguments"])


def build_campaign_command(
    args: argparse.Namespace,
    configuration: str,
    campaign_dir: Path,
) -> list[str]:
    command = [
        str(args.python),
        str(args.campaign_driver),
        "--root",
        str(args.root),
        "--python",
        str(args.python),
        "--evaluator",
        str(args.evaluator),
        "--out-dir",
        str(campaign_dir),
        "--engine-timeout",
        str(args.engine_timeout),
        "--max-steps",
        str(args.max_steps),
        "--closure-timeout",
        str(args.closure_timeout),
        "--subprocess-timeout",
        str(args.subprocess_timeout),
        "--subprocess-memory-limit-mib",
        str(args.subprocess_memory_limit_mib),
        "--target-timeout",
        str(args.target_timeout),
        "--execution-backend",
        str(CONFIGURATIONS[configuration].get("execution_backend", "forkserver")),
    ]
    if args.max_closures > 0:
        command.extend(["--max-closures", str(args.max_closures)])
    for target in args.target:
        command.extend(["--target", target])
    if args.generate_refinement_bundles:
        command.append("--generate-refinement-bundles")
    if CONFIGURATIONS[configuration].get("requires_refinement_bundle_dir"):
        command.extend(
            ["--refinement-bundle-dir", str(args.refinement_bundle_dir)]
        )
    if args.dry_run:
        command.append("--dry-run")
    command.extend(effective_configuration_arguments(configuration))
    return command


def plan_identity(args: argparse.Namespace, configurations: Iterable[str]) -> dict[str, Any]:
    selected_targets = list(args.target) or list(DEFAULT_TARGET_NAMES)
    refinement_bundles = []
    if args.refinement_bundle_dir:
        for target in selected_targets:
            path = args.refinement_bundle_dir / f"{target}.refinement.json"
            if not path.is_file() and not args.dry_run:
                raise ValueError(f"missing target refinement bundle: {path}")
            refinement_bundles.append(
                {
                    "target": target,
                    "path": str(path),
                    "exists": path.is_file(),
                    "sha256": sha256_file(path) if path.is_file() else None,
                }
            )
    return {
        "schema": SCHEMA,
        "root": str(args.root.resolve()),
        "python": str(preserve_executable_path(args.python)),
        "evaluator": str(args.evaluator.resolve()),
        "evaluator_sha256": sha256_file(args.evaluator),
        "campaign_driver": str(args.campaign_driver.resolve()),
        "campaign_driver_sha256": sha256_file(args.campaign_driver),
        "configurations": [
            {
                "name": name,
                "description": CONFIGURATIONS[name]["description"],
                "execution_backend": CONFIGURATIONS[name].get(
                    "execution_backend", "forkserver"
                ),
                "requires_refinement_bundle_dir": bool(
                    CONFIGURATIONS[name].get("requires_refinement_bundle_dir")
                ),
                "arguments": effective_configuration_arguments(name),
            }
            for name in configurations
        ],
        "targets": list(args.target),
        "max_closures_per_target": args.max_closures or None,
        "selection_policy": (
            "all sorted unique closures"
            if args.max_closures == 0
            else "deterministic prefix of sorted unique closures"
        ),
        "resource_envelope": {
            "engine_timeout": args.engine_timeout,
            "max_steps": args.max_steps,
            "closure_timeout": args.closure_timeout,
            "subprocess_timeout": args.subprocess_timeout,
            "subprocess_memory_limit_mib": args.subprocess_memory_limit_mib,
            "target_timeout": args.target_timeout,
        },
        "generate_refinement_bundles": args.generate_refinement_bundles,
        "refinement_bundles": refinement_bundles,
        "evidence_cache": "disabled by campaign driver",
    }


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def prepare_plan(
    out_dir: Path,
    identity: dict[str, Any],
    *,
    resume: bool,
) -> dict[str, Any]:
    plan_path = out_dir / "experiment_plan.json"
    digest = canonical_digest(identity)
    if out_dir.exists() and any(out_dir.iterdir()):
        if not resume:
            raise ValueError(f"refusing to reuse non-empty matrix directory: {out_dir}")
        if not plan_path.is_file():
            raise ValueError("resume directory has no experiment_plan.json")
        existing = json.loads(plan_path.read_text(encoding="utf-8"))
        if existing.get("identity_sha256") != digest:
            raise ValueError("resume plan identity does not match current inputs")
        return existing
    out_dir.mkdir(parents=True, exist_ok=True)
    plan = {
        "schema": SCHEMA,
        "registered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "identity_sha256": digest,
        "identity": identity,
        "claim_boundary": (
            "This matrix attributes behavior and overhead within TSDS under a fixed "
            "candidate cohort; it is not an accuracy comparison against another tool."
        ),
    }
    write_json_atomic(plan_path, plan)
    return plan


def completed_campaign(path: Path) -> bool:
    aggregate = path / "full_campaign_aggregate.json"
    if not aggregate.is_file():
        return False
    value = json.loads(aggregate.read_text(encoding="utf-8"))
    rows = value.get("targets") or []
    return bool(rows) and all(int(row.get("returncode") or 0) == 0 for row in rows)


def audit_commands(args: argparse.Namespace, campaign_dir: Path, audit_root: Path) -> list[list[str]]:
    expected_targets = len(args.target) if args.target else 8
    return [
        [
            str(args.python),
            str(args.root / "experiments/audit_campaign_conservation.py"),
            "--campaign-dir",
            str(campaign_dir),
            "--out-dir",
            str(audit_root / "conservation"),
            "--expected-targets",
            str(expected_targets),
            "--require-resource-metrics",
            "--fail-on-issues",
        ],
        [
            str(args.python),
            str(args.root / "experiments/audit_evidence_contract.py"),
            "--input-dir",
            str(campaign_dir),
            "--out-dir",
            str(audit_root / "contract"),
            "--fail-on-contract-issues",
        ],
        [
            str(args.python),
            str(args.root / "experiments/audit_ledger_schema.py"),
            "--input-dir",
            str(campaign_dir),
            "--out-dir",
            str(audit_root / "schema"),
            "--fail-on-issues",
        ],
        [
            str(args.python),
            str(args.root / "experiments/audit_vector_decision_integrity.py"),
            "--input-dir",
            str(campaign_dir),
            "--out-dir",
            str(audit_root / "vectors"),
            "--fail-on-issues",
        ],
        [
            str(args.python),
            str(args.root / "experiments/audit_v19_mechanism_invariants.py"),
            "--campaign",
            str(campaign_dir),
            "--out-dir",
            str(audit_root / "v19_mechanisms"),
            "--fail-on-issues",
        ],
    ]


def run_logged(command: list[str], log_path: Path, cwd: Path) -> tuple[int, float]:
    start = time.perf_counter()
    with log_path.open("w", encoding="utf-8", errors="replace") as stream:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            stdout=stream,
            stderr=subprocess.STDOUT,
            env={**os.environ, **DETERMINISTIC_ENVIRONMENT},
            check=False,
        )
    return int(completed.returncode), time.perf_counter() - start


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/home/ubuntu/work/sanitizer"))
    parser.add_argument("--python", type=Path, default=None)
    parser.add_argument("--evaluator", type=Path, default=None)
    parser.add_argument("--campaign-driver", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--configs", default=",".join(DEFAULT_CONFIGURATION_NAMES))
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--max-closures", type=int, default=12, help="0 selects the full corpus")
    parser.add_argument("--engine-timeout", type=int, default=45)
    parser.add_argument("--max-steps", type=int, default=500)
    parser.add_argument("--closure-timeout", type=int, default=90)
    parser.add_argument("--subprocess-timeout", type=int, default=150)
    parser.add_argument("--subprocess-memory-limit-mib", type=int, default=8192)
    parser.add_argument("--target-timeout", type=int, default=7200)
    parser.add_argument("--generate-refinement-bundles", action="store_true")
    parser.add_argument("--refinement-bundle-dir", type=Path, default=None)
    parser.add_argument("--skip-audits", action="store_true")
    parser.add_argument("--continue-on-failure", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.max_closures < 0:
        parser.error("--max-closures must be non-negative")
    args.root = args.root.resolve()
    args.python = preserve_executable_path(
        args.python or args.root / "operation-mango-public/.venv/bin/python"
    )
    args.evaluator = (
        args.evaluator
        or args.root / "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py"
    ).resolve()
    args.campaign_driver = (
        args.campaign_driver or args.root / "experiments/run_full_firmware_campaign.py"
    ).resolve()
    if args.refinement_bundle_dir:
        args.refinement_bundle_dir = (
            args.refinement_bundle_dir
            if args.refinement_bundle_dir.is_absolute()
            else args.root / args.refinement_bundle_dir
        ).resolve()
    args.out_dir = args.out_dir if args.out_dir.is_absolute() else args.root / args.out_dir
    try:
        configurations = parse_configurations(args.configs)
        if any(
            CONFIGURATIONS[name].get("requires_refinement_bundle_dir")
            for name in configurations
        ) and not args.refinement_bundle_dir:
            raise ValueError(
                "p2_refinement_replay requires --refinement-bundle-dir"
            )
        plan = prepare_plan(
            args.out_dir,
            plan_identity(args, configurations),
            resume=args.resume,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"EXPERIMENT_MATRIX_ERROR: {exc}", file=sys.stderr)
        return 2

    status_path = args.out_dir / "experiment_status.json"
    status = {
        "schema": SCHEMA,
        "identity_sha256": plan["identity_sha256"],
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "configurations": {},
    }
    if args.resume and status_path.is_file():
        status = json.loads(status_path.read_text(encoding="utf-8"))

    failed = False
    for name in configurations:
        campaign_dir = args.out_dir / "campaigns" / name
        previous = status.get("configurations", {}).get(name) or {}
        campaign_ready = args.resume and completed_campaign(campaign_dir)
        prior_audits_valid = bool(previous.get("audit_attempts")) and all(
            int(item.get("returncode") or 0) == 0
            for attempt in previous.get("audit_attempts", [])
            for item in attempt.get("audits", [])
        )
        if (
            campaign_ready
            and previous.get("state") == "completed"
            and (args.skip_audits or args.dry_run or prior_audits_valid)
        ):
            status["configurations"][name] = {
                **previous,
                "state": "completed",
                "resumed": True,
            }
            write_json_atomic(status_path, status)
            continue
        command = build_campaign_command(args, name, campaign_dir)
        log_path = args.out_dir / f"{name}.launch.log"
        if campaign_ready:
            returncode = 0
            elapsed = float(previous.get("elapsed_sec") or 0.0)
            status["configurations"][name] = {
                **previous,
                "state": "auditing",
                "command": command,
                "resumed": True,
            }
            write_json_atomic(status_path, status)
        else:
            status["configurations"][name] = {
                **previous,
                "state": "running",
                "command": command,
                "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
            write_json_atomic(status_path, status)
            returncode, elapsed = run_logged(command, log_path, args.root)
        audit_results = []
        if returncode == 0 and not args.skip_audits and not args.dry_run:
            audit_attempts = list(previous.get("audit_attempts") or [])
            attempt_number = len(audit_attempts) + 1
            attempt_root = (
                args.out_dir / "audits" / name / f"attempt_{attempt_number}"
            )
            for audit_index, audit in enumerate(
                audit_commands(args, campaign_dir, attempt_root),
                start=1,
            ):
                audit_log = args.out_dir / (
                    f"{name}.audit_attempt{attempt_number}_{audit_index}.log"
                )
                audit_code, audit_elapsed = run_logged(audit, audit_log, args.root)
                audit_results.append(
                    {
                        "command": audit,
                        "returncode": audit_code,
                        "elapsed_sec": round(audit_elapsed, 4),
                    }
                )
                if audit_code != 0:
                    returncode = audit_code
            audit_attempts.append(
                {
                    "attempt": attempt_number,
                    "audits": audit_results,
                    "returncode": 0
                    if all(item["returncode"] == 0 for item in audit_results)
                    else 1,
                }
            )
        else:
            audit_attempts = list(previous.get("audit_attempts") or [])
        status["configurations"][name] = {
            **status["configurations"][name],
            "state": "completed" if returncode == 0 else "failed",
            "returncode": returncode,
            "elapsed_sec": round(elapsed, 4),
            "audit_attempts": audit_attempts,
            "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        status["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        write_json_atomic(status_path, status)
        if returncode != 0:
            failed = True
            if not args.continue_on_failure:
                break

    print(json.dumps(status, indent=2, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
