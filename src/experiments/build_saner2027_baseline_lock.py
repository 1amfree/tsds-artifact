#!/usr/bin/env python3
"""Materialize the T00 source/corpus lock and a conservative identity map.

The lock records which local source line is used for new remediation work and
keeps it separate from the historical V20 pipeline and the v92 archive.  The
identity map is a traceability aid; it does not reclassify historical results
as independently confirmed truth.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
HISTORICAL_ROOT = (
    PROJECT_ROOT
    / "experiment_reports"
    / "tsds_v20_release_20260718_r7_v8"
    / "tsds_v20_accepted_repeat_20260718_r7"
)
HISTORICAL_CAMPAIGN = HISTORICAL_ROOT / "campaign"
DEFAULT_V92_MANIFEST = PROJECT_ROOT / "TSDS_current_v92_snapshot_20260912" / "SNAPSHOT_MANIFEST.json"
DEFAULT_PRIMARY_SNAPSHOT = PROJECT_ROOT / "saner_work" / "source_baseline_t01_final"
DEFAULT_PRE_SNAPSHOT = PROJECT_ROOT / "saner_work" / "source_baseline_pre_t01"

ENTRYPOINTS = (
    "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py",
    "tsds/multi_state_aggregation.py",
    "tsds/constraint_projection.py",
    "tsds/evidence_scope.py",
    "tsds/reconciliation_link.py",
    "tsds/source_realizability.py",
    "experiments/run_saner2027_controlled_benchmark.py",
    "experiments/run_saner2027_multistate_benchmark.py",
    "experiments/run_saner2027_witness_replay.py",
    "experiments/replay_smt_query_bundles.py",
    "experiments/build_saner2027_t03_preflight.py",
    "experiments/audit_evidence_scope.py",
    "experiments/run_saner2027_semantic_benchmark.py",
    "experiments/test_reconciliation_link.py",
    "experiments/run_source_realizability_preflight.py",
    "experiments/test_source_realizability.py",
    "experiments/audit_conditioned_links.py",
    "experiments/build_saner2027_baseline_lock.py",
)

STATUS_MAP = {
    "VECTOR_SAT": ("direct", "sv_sat", "direct_evidence"),
    "CT_SAT": ("conditioned", "ct_sat", "conditioned_feasibility"),
    "MATRIX_UNSAT": ("local", "m_filt", "selected_instance_profile"),
    "NO_MODELED_SOURCE": ("local", "nms", "selected_instance_profile"),
    "STATIC_SOURCE_INFERENCE": ("static", "local_unknown", "static_observation"),
    "STATIC_WARNING_REDUCTION": ("static", "local_unknown", "static_observation"),
    "RESIDUAL": ("residual", "local_unknown", "residual_obligation"),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def file_info(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": rel(path), "exists": False}
    return {
        "path": rel(path),
        "exists": True,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: expected JSON object")
        rows.append(value)
    return rows


def elf_description(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"status": "UNAVAILABLE"}
    header = path.read_bytes()[:20]
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return {"status": "NOT_ELF"}
    machine_bytes = header[18:20]
    endian = {1: "little", 2: "big"}.get(header[5])
    machine = int.from_bytes(machine_bytes, endian) if endian else None
    machine_names = {3: "x86", 8: "MIPS", 40: "ARM", 62: "x86_64", 183: "AArch64"}
    return {
        "status": "OK",
        "class": {1: "ELF32", 2: "ELF64"}.get(header[4], "UNKNOWN"),
        "endianness": {1: "little", 2: "big"}.get(header[5], "UNKNOWN"),
        "machine": machine_names.get(machine, f"EM_{machine}" if machine is not None else "UNKNOWN"),
    }


def result_rows(campaign: Path) -> Iterable[tuple[str, dict[str, Any]]]:
    for path in sorted(campaign.glob("*.results.jsonl")):
        target = path.name[: -len(".results.jsonl")]
        for row in load_jsonl(path):
            yield target, row


def result_identity(target: str, row: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        target,
        str(row.get("closure_idx") if row.get("closure_idx") is not None else ""),
        str(row.get("source_addr") or "").lower(),
        str(row.get("sink_addr") or "").lower(),
    )


def identity_digest(prefix: str, identity: tuple[str, ...]) -> str:
    return hashlib.sha256((prefix + "|" + "|".join(identity)).encode("utf-8")).hexdigest()[:24]


def map_mode(verdict: str, provenance: str) -> tuple[str, str, str]:
    if verdict in {"VECTOR_SAT", "CT_SAT"} and provenance == "SINK_RECONCILED":
        return "conditioned", "ct_sat", "conditioned_feasibility"
    return STATUS_MAP.get(verdict, ("residual", "local_unknown", "residual_obligation"))


def make_scope_row(target: str, row: dict[str, Any], ordinal: int, raw_count: int) -> dict[str, Any]:
    verdict = str(row.get("verdict") or "")
    provenance = str(row.get("evidence_provenance") or "")
    identity = result_identity(target, row)
    mode, profile, candidate_status = map_mode(verdict, provenance)
    candidate_id = identity_digest("candidate", identity)
    instance_seed = identity + (
        str(row.get("sink_snapshot_source") or ""),
        str(row.get("sink_snapshot_terminator_offset") or ""),
        str(row.get("engine_exit_fingerprint") or ""),
    )
    instance_id = identity_digest("instance", instance_seed)
    matrix: dict[str, Any] | None = None
    if profile == "m_filt":
        decisions = []
        for decision in row.get("vector_decisions") or []:
            if not isinstance(decision, dict):
                continue
            decisions.append(
                {
                    "vector_id": str(decision.get("vector_id") or ""),
                    "decision": str(decision.get("decision") or ""),
                }
            )
        vector_ids = [item["vector_id"] for item in decisions]
        matrix = {
            "expected_vector_ids": vector_ids,
            "decisions": decisions,
            "complete": len(decisions) == 11 and len(set(vector_ids)) == 11,
            "source": "historical_selected_instance_record",
        }

    matrix_state = "UNKNOWN"
    if verdict == "VECTOR_SAT":
        matrix_state = "CONFIRMED"
    elif verdict == "MATRIX_UNSAT":
        matrix_state = "CONTRADICTED"
    elif verdict in {"NO_MODELED_SOURCE", "STATIC_SOURCE_INFERENCE", "STATIC_WARNING_REDUCTION"}:
        matrix_state = "NOT_APPLICABLE"

    return {
        "schema": "tsds-evidence-scope-v1",
        "candidate_id": candidate_id,
        "instance_id": instance_id,
        "evidence_mode": mode,
        "local_profile": profile,
        "candidate_status": candidate_status,
        "direct_provenance": mode == "direct" and provenance == "DIRECT_SINK_BYTE",
        "source_link_status": (
            "observed" if mode == "direct" else "unknown" if mode == "conditioned" else "not_applicable"
        ),
        "primary_aggregate_eligible": mode == "direct",
        "input_effect": "UNKNOWN",
        "instance_source_realizable": "UNKNOWN",
        "matrix_feasible": matrix_state,
        "bounded_program_effect_exists": "UNKNOWN",
        "candidate_vulnerability": "UNKNOWN",
        "matrix": matrix,
        "traceability": {
            "corpus_target": target,
            "raw_closure_count_for_target": raw_count,
            "selected_record_ordinal": ordinal,
            "historical_verdict": verdict,
            "historical_provenance": provenance,
            "historical_identity": {
                "closure_idx": row.get("closure_idx"),
                "source_addr": row.get("source_addr"),
                "sink_addr": row.get("sink_addr"),
                "sink_function": row.get("sink_function"),
            },
            "identity_scope": "historical_record_identity_not_complete_instance_semantics",
            "independent_semantic_confirmation": "NOT_PERFORMED",
        },
    }


def build_identity_map(campaign: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    summary_by_target: dict[str, dict[str, Any]] = {}
    for path in sorted(campaign.glob("*.summary.json")):
        target = path.name[: -len(".summary.json")]
        summary_by_target[target] = load_json(path)
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    duplicates = 0
    for target, row in result_rows(campaign):
        identity = result_identity(target, row)
        if identity in seen:
            duplicates += 1
        seen.add(identity)
        ordinal = sum(1 for existing in rows if existing["traceability"]["corpus_target"] == target)
        raw_count = int(summary_by_target.get(target, {}).get("total_closures") or 0)
        rows.append(make_scope_row(target, row, ordinal, raw_count))
    verdicts = Counter(str(row["traceability"]["historical_verdict"]) for row in rows)
    modes = Counter(str(row["evidence_mode"]) for row in rows)
    raw_count = sum(int(value.get("total_closures") or 0) for value in summary_by_target.values())
    return rows, {
        "schema": "tsds-saner2027-candidate-identity-map-v1",
        "raw_closures": raw_count,
        "normalized_records": len(rows),
        "unique_historical_identities": len(seen),
        "duplicate_historical_identities": duplicates,
        "targets": sorted(summary_by_target),
        "verdict_counts": dict(sorted(verdicts.items())),
        "evidence_mode_counts": dict(sorted(modes.items())),
        "claim_boundary": (
            "This map provides candidate and selected-record traceability. It does not "
            "independently confirm solver results, source realizability, or vulnerability."
        ),
    }


def build_lock(primary_snapshot: Path, pre_snapshot: Path, v92_manifest: Path, campaign: Path) -> dict[str, Any]:
    config = load_json(campaign / "campaign_configuration.json")
    historical_pipeline = HISTORICAL_ROOT / "pipeline_manifest.json"
    primary_manifest_path = primary_snapshot / "reviewed_source_manifest.json"
    pre_manifest_path = pre_snapshot / "reviewed_source_manifest.json"
    v92 = load_json(v92_manifest)
    entrypoint_info = [file_info(PROJECT_ROOT / path) for path in ENTRYPOINTS]
    return {
        "schema": "tsds-saner2027-source-lock-v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "lock_status": "source_and_input_identity_frozen",
        "source_selection": {
            "primary_label": "local_root_shell_evidence_line",
            "primary_snapshot": rel(primary_snapshot),
            "reason": (
                "The root evaluator and tsds modules are the source line used by the "
                "2026-09-13 controlled, multi-state, and witness calibration runners."
            ),
            "v92_role": "reference_archive_not_mixed_into_primary_results",
            "historical_v20_role": "frozen_comparison_and_traceability_only",
        },
        "primary_snapshot": file_info(primary_manifest_path)
        | {
            "aggregate_sha256": load_json(primary_manifest_path).get("aggregate_sha256"),
            "source_files": load_json(primary_manifest_path).get("source_files"),
        },
        "pre_t01_snapshot": file_info(pre_manifest_path)
        | {
            "aggregate_sha256": load_json(pre_manifest_path).get("aggregate_sha256"),
            "source_files": load_json(pre_manifest_path).get("source_files"),
        },
        "v92_reference": {
            "manifest": file_info(v92_manifest),
            "archive_hashes": {
                key: value.get("archive_sha256")
                for key, value in (
                    (v92.get("trees") or {}).items()
                    if isinstance(v92.get("trees"), dict)
                    else []
                )
            },
            "manifest_claim_boundary": v92.get("claim_boundary", []),
        },
        "historical_v20": {
            "root": rel(HISTORICAL_ROOT),
            "campaign": rel(campaign),
            "campaign_configuration": file_info(campaign / "campaign_configuration.json"),
            "pipeline_manifest": file_info(historical_pipeline),
            "evaluator_sha256_recorded_by_historical_config": config.get("evaluator_sha256"),
            "python_version_recorded_by_historical_config": config.get("python_version"),
            "raw_closures": sum(
                int(load_json(path).get("total_closures") or 0)
                for path in campaign.glob("*.summary.json")
            ),
            "normalized_records": sum(
                len(load_jsonl(path)) for path in campaign.glob("*.results.jsonl")
            ),
        },
        "current_entrypoints": entrypoint_info,
        "environment": {
            "python_executable": sys.executable,
            "python_version": sys.version,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "implementation": platform.python_implementation(),
            "pytest_command_environment": "system Python was used for the initial 14-test regression; .venv_tsds_saner lacks pytest",
        },
        "reference_artifacts": [
            file_info(PROJECT_ROOT / "experiment_reports/saner2027_controlled_benchmark_20260913/summary.json"),
            file_info(PROJECT_ROOT / "experiment_reports/saner2027_controlled_benchmark_20260913/baseline_comparison.json"),
            file_info(PROJECT_ROOT / "experiment_reports/saner2027_multistate_benchmark_20260913_r2/summary.json"),
            file_info(PROJECT_ROOT / "experiment_reports/saner2027_witness_replay_20260913_r2/witness_replay_summary.json"),
        ],
        "protected_hashes": [
            file_info(PROJECT_ROOT / "overleaf_TSDS_final/main.tex"),
            file_info(PROJECT_ROOT / "overleaf_TSDS_upload/main.tex"),
            file_info(PROJECT_ROOT / "overleaf_TSDS_saner2027/paper_work/TSDS_saner2027_final_20260913_final.pdf"),
        ],
        "claim_boundary": (
            "This lock identifies code, inputs, and historical reports for the remediation "
            "campaign. It is not evidence that the analyzer is sound or that a finding is exploitable."
        ),
    }


def build_review_traceability() -> str:
    """Record the provenance of review inputs without inventing a conference source."""

    plan = PROJECT_ROOT / "paper_work/SANER2027_LUNA_REMEDIATION_PLAN_20260913.md"
    tasks = PROJECT_ROOT / "paper_work/SANER2027_LUNA_TASKS_20260913.json"
    plan_info = file_info(plan)
    task_info = file_info(tasks)
    return f"""# Review traceability

This file records the provenance used to construct the remediation worklist.
It does not authenticate the pasted review text as an official conference decision.

## Inputs

- Review material: user-supplied review bundle in the working conversation; no local
  conference-mail export or signed review artifact was available at lock time.
- Issue identifiers: R01--R14 are stable worklist identifiers defined by the
  remediation plan; they are not claims that a specific reviewer used those IDs.
- Plan: `{plan_info.get('path')}`, SHA-256 `{plan_info.get('sha256', 'UNAVAILABLE')}`.
- Task ledger: `{task_info.get('path')}`, SHA-256 `{task_info.get('sha256', 'UNAVAILABLE')}`.

## Evidence policy

- Quoted reviewer language must be linked to an original source before it is used
  in an anonymous artifact or rebuttal.
- The current campaign uses the review bundle only to define engineering questions.
- Missing source provenance remains `UNVERIFIED`; it is not converted to a claim
  about ICECCS reviewer consensus.
- The historical V20 reports are comparison inputs and are not new ground truth.

## Scope

The lock covers the local implementation line, historical V20 identifiers, and
the explicitly recorded corpus metadata. It does not establish solver soundness,
source realizability, device-level exploitability, or acceptance likelihood.
"""


def build_environment_smoke(primary_snapshot: Path, pre_snapshot: Path) -> dict[str, Any]:
    """Check lightweight imports and snapshot availability in the chosen interpreter."""

    modules = (
        "tsds.evidence_scope",
        "tsds.reconciliation_link",
        "tsds.multi_state_aggregation",
        "tsds.constraint_projection",
        "tsds.source_realizability",
        "experiments.audit_evidence_scope",
        "experiments.build_reviewed_source_snapshot",
        "experiments.run_source_realizability_preflight",
    )
    imports: dict[str, Any] = {}
    for module_name in modules:
        try:
            importlib.import_module(module_name)
        except Exception as exc:  # report dependency failures instead of hiding them
            imports[module_name] = {"status": "FAIL", "error": f"{type(exc).__name__}: {exc}"}
        else:
            imports[module_name] = {"status": "PASS"}

    optional = {}
    for module_name in ("angr", "claripy", "z3", "cvc5"):
        optional[module_name] = {
            "available": importlib.util.find_spec(module_name) is not None,
            "scope": "optional_runtime_dependency",
        }
    snapshots = {
        "primary": file_info(primary_snapshot / "reviewed_source_manifest.json"),
        "pre_t01": file_info(pre_snapshot / "reviewed_source_manifest.json"),
    }
    failures = [name for name, value in imports.items() if value.get("status") != "PASS"]
    return {
        "schema": "tsds-saner2027-environment-smoke-v1",
        "status": "PASS" if not failures and all(item.get("exists") for item in snapshots.values()) else "FAIL",
        "python": {
            "executable": sys.executable,
            "version": sys.version,
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "imports": imports,
        "optional_dependencies": optional,
        "snapshots": snapshots,
        "failures": failures,
        "claim_boundary": (
            "A passing smoke receipt proves only that lightweight modules and source "
            "manifests load in this interpreter. It is not an analyzer-correctness or "
            "firmware-execution result."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--primary-snapshot", type=Path, default=DEFAULT_PRIMARY_SNAPSHOT)
    parser.add_argument("--pre-snapshot", type=Path, default=DEFAULT_PRE_SNAPSHOT)
    parser.add_argument("--v92-manifest", type=Path, default=DEFAULT_V92_MANIFEST)
    parser.add_argument("--campaign", type=Path, default=HISTORICAL_CAMPAIGN)
    args = parser.parse_args()
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(f"refusing to overwrite non-empty output: {out_dir}")
    lock = build_lock(args.primary_snapshot.resolve(), args.pre_snapshot.resolve(), args.v92_manifest.resolve(), args.campaign.resolve())
    rows, map_summary = build_identity_map(args.campaign.resolve())
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "source_lock.json").write_text(json.dumps(lock, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "corpus_manifest.json").write_text(
        json.dumps(build_corpus_manifest(args.campaign.resolve()), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with (out_dir / "candidate_identity_map.jsonl").open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    (out_dir / "candidate_identity_summary.json").write_text(json.dumps(map_summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "review_traceability.md").write_text(build_review_traceability(), encoding="utf-8")
    (out_dir / "environment_smoke.json").write_text(
        json.dumps(
            build_environment_smoke(args.primary_snapshot.resolve(), args.pre_snapshot.resolve()),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"source_lock": lock, "identity_summary": map_summary}, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def build_corpus_manifest(campaign: Path) -> dict[str, Any]:
    config = load_json(campaign / "campaign_configuration.json")
    targets = []
    for item in config.get("targets") or []:
        if not isinstance(item, dict):
            continue
        target = str(item.get("name") or "")
        binary_relative = str(item.get("binary") or "")
        binary = PROJECT_ROOT / Path(binary_relative)
        summary_path = campaign / f"{target}.summary.json"
        summary = load_json(summary_path) if summary_path.is_file() else {}
        result_path = campaign / f"{target}.results.jsonl"
        result_count = len(load_jsonl(result_path)) if result_path.is_file() else 0
        rows = load_jsonl(result_path) if result_path.is_file() else []
        targets.append(
            {
                "corpus_id": target,
                "label": item.get("label"),
                "binary": {
                    "declared_path": binary_relative,
                    "declared_sha256": item.get("binary_sha256"),
                    "local": file_info(binary),
                    "elf": elf_description(binary),
                },
                "mango": {
                    "declared_path": item.get("mango"),
                    "declared_sha256": item.get("mango_sha256"),
                    "local_path_status": "remote_historical_path_not_assumed_local",
                },
                "raw_closures": int(summary.get("total_closures") or 0),
                "normalized_records": result_count,
                "unique_sink_addresses": len({str(row.get("sink_addr") or "") for row in rows}),
                "unique_sink_functions": sorted({str(row.get("sink_function") or "") for row in rows if row.get("sink_function")}),
                "wrapper_count": "NOT_RECORDED_IN_V20_CAMPAIGN_MANIFEST",
                "shell_version": "NOT_RECORDED_IN_V20_CAMPAIGN_MANIFEST",
                "architecture_source": "local ELF header when available; otherwise UNKNOWN",
            }
        )
    return {
        "schema": "tsds-saner2027-corpus-manifest-v1",
        "source": "historical_v20_campaign_configuration_and_results",
        "targets": targets,
        "raw_closures": sum(int(item["raw_closures"]) for item in targets),
        "normalized_records": sum(int(item["normalized_records"]) for item in targets),
        "claim_boundary": (
            "The manifest binds declared firmware/binary identities and recorded counts. "
            "Unavailable wrapper, shell, release, and runtime metadata remain explicit unknowns."
        ),
    }


if __name__ == "__main__":
    raise SystemExit(main())
