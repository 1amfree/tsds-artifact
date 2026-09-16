#!/usr/bin/env python3
"""Build the final, content-bound TSDS v20 paper-writing evidence index."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.audit_v20_downloaded_release import (
    SCHEMA as AUDIT_SCHEMA,
    audit_release,
    strict_json,
)
from experiments.fetch_v20_release import release_names
from experiments.audit_v20_paired_experiments import SCHEMA as PAIRED_AUDIT_SCHEMA


SCHEMA = "tsds-v20-paper-evidence-index-v1"
CLAIM_IDS = tuple(f"C{index}" for index in range(1, 10))
VERDICT_LABELS = {
    "VECTOR_SAT": "SV-SAT",
    "MATRIX_UNSAT": "M-Filt",
    "NO_MODELED_SOURCE": "NMS",
    "STATIC_SOURCE_INFERENCE": "Static source obligation",
    "STATIC_WARNING_REDUCTION": "Static warning reduction",
    "RESIDUAL": "Residual",
}
VERIFICATION_TOOL_PATHS = (
    "experiments/fetch_v20_release.py",
    "experiments/build_v20_manuscript_binding.py",
    "experiments/audit_v20_downloaded_release.py",
    "experiments/wait_and_audit_v20_release.py",
    "experiments/build_v20_paper_evidence_index.py",
    "experiments/audit_v20_paired_experiments.py",
    "experiments/verify_v20_paper_package.py",
    "experiments/test_fetch_v20_release.py",
    "experiments/test_build_v20_manuscript_binding.py",
    "experiments/test_audit_v20_downloaded_release.py",
    "experiments/test_wait_and_audit_v20_release.py",
    "experiments/test_build_v20_paper_evidence_index.py",
    "experiments/test_audit_v20_paired_experiments.py",
    "experiments/test_verify_v20_paper_package.py",
    "experiments/V20_RELEASE_WORKFLOW.md",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def file_identity(path: Path, base: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"missing regular file: {path}")
    return {
        "path": path.relative_to(base).as_posix(),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def flatten_downloads(fetch: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    downloads = fetch.get("downloads") or {}
    for directory in sorted(downloads):
        for entry in downloads[directory]:
            rows.append(
                {
                    "category": "download",
                    "path": f"{directory}/{entry['path']}",
                    "size": int(entry["size"]),
                    "sha256": str(entry["sha256"]),
                }
            )
    return rows


def select_prefixes(rows: list[dict[str, Any]], prefixes: tuple[str, ...]) -> list[dict[str, Any]]:
    return [row for row in rows if any(row["path"].startswith(prefix) for prefix in prefixes)]


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    require(path.is_file(), f"missing CSV artifact: {path}")
    with path.open("r", newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    require(rows, f"empty CSV artifact: {path}")
    return rows


def nonnegative_int(value: Any, label: str) -> int:
    require(not isinstance(value, bool), f"{label} is not an integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not an integer") from exc
    require(result >= 0, f"{label} is negative")
    return result


def locate_one(root: Path, filename: str) -> Path:
    values = sorted(root.rglob(filename))
    require(len(values) == 1, f"expected one {filename} under {root}, found {len(values)}")
    return values[0]


def build_results_snapshot(
    release_root: Path,
    paired_audit_root: Path,
    tag: str,
    binding: dict[str, Any],
    verified_claim_evidence: dict[str, Any],
) -> dict[str, Any]:
    records = nonnegative_int(binding.get("records"), "binding records")
    verdicts = {
        name: nonnegative_int(value, f"binding verdict {name}")
        for name, value in (binding.get("verdicts") or {}).items()
    }
    paper_root = (
        release_root / f"tsds_v20_accepted_repeat_{tag}" / "paper_tables"
    )
    paper_summary_path = paper_root / "paper_data_summary.json"
    paper_summary = strict_json(paper_summary_path)
    require(
        paper_summary.get("schema") == "tsds-paper-table-export-v2"
        and paper_summary.get("all_contract_valid") is True,
        "paper table summary is not contract-valid v2",
    )
    require(
        nonnegative_int(paper_summary.get("records"), "paper records") == records
        and paper_summary.get("verdicts") == verdicts,
        "paper summary and manuscript binding disagree",
    )

    overall_rows = read_csv_rows(paper_root / "paper_overall.csv")
    overall = {
        row["evidence_class"]: nonnegative_int(row["count"], "overall count")
        for row in overall_rows
    }
    require(overall == verdicts, "paper overall CSV and manuscript binding disagree")
    per_target = read_csv_rows(paper_root / "paper_per_target.csv")
    require(len(per_target) == 8, "paper per-target table does not contain eight targets")
    require(
        sum(nonnegative_int(row.get("records"), "per-target records") for row in per_target)
        == records,
        "per-target record counts do not conserve the accepted corpus",
    )
    for verdict, expected in verdicts.items():
        require(
            sum(nonnegative_int(row.get(verdict, 0), f"per-target {verdict}") for row in per_target)
            == expected,
            f"per-target {verdict} counts do not conserve the accepted corpus",
        )

    residual_rows = read_csv_rows(paper_root / "paper_residuals.csv")
    require(
        sum(nonnegative_int(row.get("count"), "paper residual count") for row in residual_rows)
        == verdicts.get("RESIDUAL", 0),
        "paper residual table does not conserve residual records",
    )
    runtime_rows = read_csv_rows(paper_root / "paper_runtime.csv")
    workload_rows = read_csv_rows(paper_root / "paper_workload.csv")
    runtime_total = next((row for row in runtime_rows if row.get("target") == "TOTAL"), None)
    workload_total = next((row for row in workload_rows if row.get("target") == "TOTAL"), None)
    require(runtime_total is not None and workload_total is not None, "paper runtime/workload totals are missing")
    require(
        nonnegative_int(runtime_total.get("records"), "runtime total records") == records
        and nonnegative_int(workload_total.get("records"), "workload total records")
        == records,
        "paper runtime/workload totals do not conserve records",
    )
    vector_profile = read_csv_rows(paper_root / "paper_vector_profile.csv")
    require(len(vector_profile) == 11, "paper vector profile does not contain 11 vectors")

    repeatability_path = (
        release_root
        / f"tsds_v20_accepted_repeat_{tag}"
        / "repeatability_consensus"
        / "repeatability_summary.json"
    )
    repeatability = strict_json(repeatability_path)
    require(
        repeatability.get("schema") == "tsds-repeatability-audit-v4"
        and nonnegative_int(repeatability.get("baseline_records"), "repeatability records")
        == records,
        "repeatability summary is not bound to the accepted corpus",
    )
    sink_core = repeatability.get("sink_semantic_core") or {}
    require(
        sink_core.get("baseline_reproduced") is True
        and nonnegative_int(sink_core.get("semantic_drift"), "sink semantic drift") == 0,
        "sink-semantic repeatability gate failed",
    )

    extension_root = release_root / f"tsds_v20_evidence_extension_{tag}"
    residual_path = locate_one(extension_root, "residual_root_cause_summary.json")
    residual = strict_json(residual_path)
    require(
        residual.get("schema") == "tsds-residual-root-cause-audit-v1"
        and residual.get("valid") is True
        and residual.get("classification_complete") is True,
        "residual root-cause audit is invalid or incomplete",
    )

    runtime_path = (
        release_root
        / f"tsds_v20_runtime_validation_expansion_{tag}"
        / "runtime_validation_expansion_summary.json"
    )
    runtime = strict_json(runtime_path)
    require(
        runtime.get("schema") == "tsds-runtime-validation-expansion-v2"
        and runtime.get("valid") is True
        and nonnegative_int(runtime.get("runtime_attempts"), "runtime attempts") > 0,
        "runtime validation expansion is invalid or empty",
    )

    satc_identity = verified_claim_evidence.get("satc") or {}
    satc_relative = PurePosixPath(str(satc_identity.get("path") or ""))
    satc_path = release_root.joinpath(*satc_relative.parts)
    satc = strict_json(satc_path)
    require(
        satc.get("schema") == "tsds-satc-ghidra-ingestion-v1"
        and satc.get("success") is True
        and nonnegative_int(satc.get("satc_candidates"), "SaTC candidates") > 0,
        "SaTC/Ghidra ingestion is invalid or empty",
    )

    resource_path = (
        release_root
        / f"tsds_v20_resource_calibration_{tag}"
        / "resource_limit_calibration_summary.json"
    )
    resource = strict_json(resource_path)
    require(
        resource.get("schema") == "tsds-resource-limit-calibration-v2"
        and resource.get("required_cases_accepted") is True
        and resource.get("input_identity_stable") is True,
        "resource calibration gate failed",
    )

    paired = strict_json(paired_audit_root / "paired_experiment_audit.json")
    bounded = next(
        row for row in paired["datasets"] if row.get("dataset") == "bounded_matrix"
    )
    confirmation = next(
        row
        for row in paired["datasets"]
        if row.get("dataset") == "full_corpus_confirmation"
    )
    bounded_common = {
        nonnegative_int(row.get("common_records"), "bounded common records")
        for row in bounded.get("configurations") or []
    }
    require(len(bounded_common) == 1, "bounded paired cohort size is not unique")
    confirmation_common = {
        nonnegative_int(row.get("common_records"), "confirmation common records")
        for row in confirmation.get("configurations") or []
    }
    require(confirmation_common == {records}, "full-corpus confirmation is incomplete")

    input_paths = {
        "paper_summary": paper_summary_path,
        "paper_overall": paper_root / "paper_overall.csv",
        "paper_per_target": paper_root / "paper_per_target.csv",
        "paper_residuals": paper_root / "paper_residuals.csv",
        "paper_runtime": paper_root / "paper_runtime.csv",
        "paper_workload": paper_root / "paper_workload.csv",
        "paper_vector_profile": paper_root / "paper_vector_profile.csv",
        "repeatability": repeatability_path,
        "residual_root_causes": residual_path,
        "runtime_validation": runtime_path,
        "satc_ingestion": satc_path,
        "resource_calibration": resource_path,
        "paired_experiment_audit": paired_audit_root / "paired_experiment_audit.json",
    }
    macros = {
        "TSDSFirmwareTargets": 8,
        "TSDSBoundedCohortRecords": next(iter(bounded_common)),
        "TSDSRepeatabilityStableRecords": nonnegative_int(
            repeatability.get("stable_records"), "repeatability stable records"
        ),
        "TSDSSinkSemanticStableRecords": nonnegative_int(
            sink_core.get("stable_records"), "sink semantic stable records"
        ),
        "TSDSRuntimeAttempts": nonnegative_int(
            runtime.get("runtime_attempts"), "runtime attempts"
        ),
        "TSDSPositiveTokenSinkAttempts": nonnegative_int(
            runtime.get("positive_token_to_sink_attempts"),
            "positive token-to-sink attempts",
        ),
        "TSDSSatCCandidates": nonnegative_int(
            satc.get("satc_candidates"), "SaTC candidates"
        ),
        "TSDSResidualClassifiedRecords": nonnegative_int(
            residual.get("classified_records"), "classified residual records"
        ),
    }
    return {
        "schema": "tsds-v20-paper-results-snapshot-v1",
        "tag": tag,
        "records": records,
        "verdicts": verdicts,
        "per_target": per_target,
        "residual_stop_reasons": residual_rows,
        "runtime_table": runtime_rows,
        "workload_table": workload_rows,
        "vector_profile": vector_profile,
        "repeatability": repeatability,
        "residual_root_causes": residual,
        "runtime_validation": runtime,
        "satc_ingestion": satc,
        "resource_calibration": resource,
        "paired_experiments": paired,
        "macros": macros,
        "inputs": {
            name: file_identity(path, release_root if release_root in path.parents else paired_audit_root)
            for name, path in input_paths.items()
        },
        "claim_boundary": (
            "Snapshot values are content-bound analyzer and validation results. Runtime "
            "token-to-sink observations are not shell execution; SaTC ingestion is not a "
            "cross-tool accuracy comparison; SV-SAT is not device-level exploitability."
        ),
    }


def results_macros(snapshot: dict[str, Any]) -> str:
    lines = [
        "% Generated by experiments/build_v20_paper_evidence_index.py; do not edit.",
        "% Values are bound to the frozen paper-results snapshot.",
    ]
    lines.extend(
        f"\\newcommand{{\\{name}}}{{{value}}}"
        for name, value in sorted((snapshot.get("macros") or {}).items())
    )
    return "\n".join(lines) + "\n"


def build_index(
    release_root: Path,
    audit_root: Path,
    paired_audit_root: Path,
    tag: str,
    suffix: str,
) -> dict[str, Any]:
    release_root = release_root.resolve()
    audit_root = audit_root.resolve()
    paired_audit_root = paired_audit_root.resolve()
    audit_path = audit_root / "downloaded_release_audit.json"
    require(audit_path.is_file(), f"missing final downloaded-release audit: {audit_path}")
    recorded_audit = strict_json(audit_path)
    require(recorded_audit.get("schema") == AUDIT_SCHEMA, "downloaded-release audit schema mismatch")
    require(recorded_audit.get("tag") == tag, "downloaded-release audit tag mismatch")
    require(recorded_audit.get("post_release_suffix") == suffix, "downloaded-release audit suffix mismatch")
    require(recorded_audit.get("valid") is True and not recorded_audit.get("issues"), "downloaded release is not valid")

    current_audit = audit_release(release_root, tag, suffix)
    require(current_audit.get("valid") is True and not current_audit.get("issues"), "release no longer passes the current audit")
    for field in (
        "records",
        "verdicts",
        "claims",
        "claim_evidence",
        "downloaded_files",
        "archive",
    ):
        require(recorded_audit.get(field) == current_audit.get(field), f"recorded audit drift in {field}")

    fetch_path = release_root / "fetch_manifest.json"
    binding_path = release_root / "manuscript_binding" / "manuscript_binding.json"
    counts_path = release_root / "manuscript_binding" / "manuscript_counts.tex"
    post_root = release_root / f"tsds_v20_post_release_{tag}_{suffix}"
    claim_path = post_root / "claim_evidence" / "claim_evidence_matrix.json"
    post_summary_path = post_root / "post_release_summary.json"
    release_readiness_path = post_root / "release_readiness" / "release_readiness.json"
    fetch = strict_json(fetch_path)
    binding = strict_json(binding_path)
    claim_matrix = strict_json(claim_path)
    post_summary = strict_json(post_summary_path)
    release_readiness = strict_json(release_readiness_path)
    paired_audit_path = paired_audit_root / "paired_experiment_audit.json"
    require(paired_audit_path.is_file(), f"missing paired experiment audit: {paired_audit_path}")
    paired_audit = strict_json(paired_audit_path)

    require(binding.get("ready") is True, "manuscript binding is not ready")
    require(claim_matrix.get("ready_for_full_paper_writing") is True, "claim matrix is not ready")
    require(post_summary.get("ready_for_full_paper_writing") is True, "post-release summary is not ready")
    require(release_readiness.get("valid") is True and not release_readiness.get("issues"), "release-readiness gate is not valid")
    require(set(binding.get("claims") or []) == set(CLAIM_IDS), "manuscript binding does not cover C1-C9")
    require(paired_audit.get("schema") == PAIRED_AUDIT_SCHEMA, "paired experiment audit schema mismatch")
    require(paired_audit.get("tag") == tag, "paired experiment audit tag mismatch")
    require(paired_audit.get("valid") is True and not paired_audit.get("issues"), "paired experiment audit is not valid")
    require(
        int(paired_audit.get("accepted_records") or -1) == int(binding.get("records") or -2),
        "paired experiment audit record count mismatch",
    )
    paired_datasets = paired_audit.get("datasets") or []
    require(
        {row.get("dataset") for row in paired_datasets if isinstance(row, dict)}
        == {"bounded_matrix", "full_corpus_confirmation"}
        and all(row.get("valid") is True and not row.get("issues") for row in paired_datasets),
        "paired experiment datasets are incomplete or invalid",
    )
    paired_inputs = paired_audit.get("inputs") or {}
    require(
        isinstance(paired_inputs, dict)
        and set(paired_inputs) == {"bounded_matrix", "full_corpus_confirmation"},
        "paired experiment input set is invalid",
    )
    for dataset, identities in paired_inputs.items():
        require(
            dataset in {"bounded_matrix", "full_corpus_confirmation"}
            and isinstance(identities, dict),
            "paired experiment input map is invalid",
        )
        for name in ("analysis", "transition_summary", "transition_csv"):
            identity = identities.get(name)
            require(isinstance(identity, dict), f"missing paired input identity: {dataset}/{name}")
            raw_relative = identity.get("path")
            relative = PurePosixPath(str(raw_relative or ""))
            require(
                isinstance(raw_relative, str)
                and raw_relative
                and "\\" not in raw_relative
                and not relative.is_absolute()
                and relative.as_posix() == raw_relative
                and ".." not in relative.parts,
                f"unsafe paired input path: {dataset}/{name}",
            )
            path = release_root.joinpath(*relative.parts)
            require(
                path.is_file()
                and path.stat().st_size == identity.get("size")
                and sha256_file(path) == identity.get("sha256"),
                f"paired input identity mismatch: {dataset}/{name}",
            )

    downloaded_rows = flatten_downloads(fetch)
    require(len(downloaded_rows) == int(fetch.get("files") or -1), "flattened fetch count mismatch")
    registered_names = set(release_names(tag, suffix))
    require(
        {row["path"].split("/", 1)[0] for row in downloaded_rows} == registered_names,
        "paper index does not cover every registered release directory",
    )

    claims_by_id = {
        str(row["claim_id"]): row
        for row in claim_matrix.get("claims") or []
        if isinstance(row, dict) and row.get("claim_id")
    }
    require(set(claims_by_id) == set(CLAIM_IDS), "claim matrix does not contain exactly C1-C9")
    verified_evidence = current_audit.get("claim_evidence") or {}
    claim_rows: list[dict[str, Any]] = []
    for claim_id in CLAIM_IDS:
        row = claims_by_id[claim_id]
        require(row.get("status") == "supported", f"unsupported claim: {claim_id}")
        evidence_keys = row.get("evidence_paths") or []
        require(isinstance(evidence_keys, list) and evidence_keys, f"claim has no evidence: {claim_id}")
        identities = []
        for key in evidence_keys:
            require(key in verified_evidence, f"claim evidence was not independently verified: {claim_id}/{key}")
            identities.append({"evidence_key": key, **verified_evidence[key]})
        claim_rows.append(
            {
                "claim_id": claim_id,
                "statement": row.get("statement"),
                "status": row.get("status"),
                "verification_predicate": row.get("verification_predicate"),
                "non_claim": row.get("non_claim"),
                "evidence": identities,
            }
        )

    accepted_prefix = f"tsds_v20_accepted_repeat_{tag}/"
    evidence_groups = {
        "RQ1_main_outcomes": select_prefixes(
            downloaded_rows,
            (
                accepted_prefix + "paper_tables/",
                f"tsds_v20_full_audits_{tag}/",
            ),
        ),
        "RQ2_RQ3_bounded_mechanisms": select_prefixes(
            downloaded_rows,
            (
                f"tsds_v20_matrix_analysis_{tag}/",
                f"tsds_v20_matrix_transitions_{tag}/",
            ),
        ),
        "RQ2_RQ3_full_corpus_confirmation": select_prefixes(
            downloaded_rows,
            (
                f"tsds_v20_confirmatory_analysis_{tag}/",
                f"tsds_v20_confirmatory_transitions_{tag}/",
            ),
        ),
        "RQ4_residuals_and_traceability": select_prefixes(
            downloaded_rows,
            (
                f"tsds_v20_evidence_extension_{tag}/",
                f"tsds_v20_evidence_extension_verification_{tag}/",
            ),
        ),
        "RQ5_repeatability_runtime_and_frontend": select_prefixes(
            downloaded_rows,
            (
                accepted_prefix + "repeatability_consensus/",
                f"tsds_v20_runtime_repeatability_{tag}/",
                f"tsds_v20_runtime_validation_expansion_{tag}/",
                f"tsds_v20_shell_syntax_{tag}/",
                f"tsds_v20_boundary_suite_{tag}/",
                f"tsds_v20_post_release_{tag}_{suffix}/satc",
            ),
        ),
        "implementation_source_snapshot": select_prefixes(
            downloaded_rows,
            (accepted_prefix + "source_snapshot",),
        ),
    }
    for name, rows in evidence_groups.items():
        require(rows, f"empty paper evidence group: {name}")

    local_rows = [
        {"category": "local-gate", **file_identity(fetch_path, release_root)},
        {"category": "local-gate", **file_identity(binding_path, release_root)},
        {"category": "local-gate", **file_identity(counts_path, release_root)},
        {"category": "local-gate", **file_identity(audit_path, audit_root)},
    ]
    paired_output_names = (
        "paired_experiment_audit.json",
        "paired_cohort_audit.csv",
        "firmware_clustered_effects.csv",
        "README.md",
    )
    paired_members = {path.name for path in paired_audit_root.iterdir()}
    require(
        paired_members == set(paired_output_names),
        "paired experiment audit output file set mismatch",
    )
    paired_rows = [
        {
            "category": "local-statistical-gate",
            **file_identity(paired_audit_root / name, paired_audit_root),
        }
        for name in paired_output_names
    ]
    tooling_rows = [
        {
            "category": "local-verification-tool",
            **file_identity(PROJECT_ROOT / relative, PROJECT_ROOT),
        }
        for relative in VERIFICATION_TOOL_PATHS
    ]
    results_snapshot = build_results_snapshot(
        release_root,
        paired_audit_root,
        tag,
        binding,
        current_audit.get("claim_evidence") or {},
    )
    snapshot_text = json.dumps(results_snapshot, indent=2, sort_keys=True) + "\n"
    macros_text = results_macros(results_snapshot)
    generated_rows = [
        {
            "category": "generated-paper-input",
            "path": "paper_results_snapshot.json",
            "size": len(snapshot_text.encode("utf-8")),
            "sha256": hashlib.sha256(snapshot_text.encode("utf-8")).hexdigest(),
        },
        {
            "category": "generated-paper-input",
            "path": "paper_results_macros.tex",
            "size": len(macros_text.encode("utf-8")),
            "sha256": hashlib.sha256(macros_text.encode("utf-8")).hexdigest(),
        },
    ]
    verdicts = {name: int(value) for name, value in (binding.get("verdicts") or {}).items()}
    records = int(binding.get("records") or 0)
    require(records > 0 and sum(verdicts.values()) == records, "headline evidence counts do not conserve records")

    return {
        "schema": SCHEMA,
        "tag": tag,
        "post_release_suffix": suffix,
        "frozen": True,
        "ready_for_full_paper_writing": True,
        "headline": {
            "records": records,
            "verdicts": verdicts,
            "verdict_labels": VERDICT_LABELS,
        },
        "release_identities": {
            "fetch_manifest": local_rows[0],
            "manuscript_binding": local_rows[1],
            "manuscript_counts": local_rows[2],
            "downloaded_release_audit": local_rows[3],
            "claim_matrix": file_identity(claim_path, release_root),
            "post_release_summary": file_identity(post_summary_path, release_root),
            "release_readiness": file_identity(release_readiness_path, release_root),
            "paired_experiment_audit": paired_rows[0],
            "paper_results_snapshot": generated_rows[0],
        },
        "claims": claim_rows,
        "evidence_groups": evidence_groups,
        "registered_artifacts": downloaded_rows,
        "registered_artifact_count": len(downloaded_rows),
        "verification_tooling": tooling_rows,
        "paired_statistical_validation": paired_rows,
        "paper_results": {
            "snapshot": generated_rows[0],
            "macros": generated_rows[1],
            "values": results_snapshot["macros"],
        },
        "checksum_rows": (
            downloaded_rows + local_rows + paired_rows + tooling_rows + generated_rows
        ),
        "_generated_documents": {
            "paper_results_snapshot.json": snapshot_text,
            "paper_results_macros.tex": macros_text,
        },
        "claim_boundary": (
            "The frozen package supports analyzer-level, contract-gated sink-byte evidence, "
            "paired mechanism sensitivity, semantic repeatability, content-bound front-end "
            "ingestion, and bounded token-to-sink observations. It does not establish device "
            "reachability, authentication state, shell execution, exploitability, comparative "
            "accuracy, or SOTA superiority."
        ),
    }


def markdown(index: dict[str, Any]) -> str:
    headline = index["headline"]
    lines = [
        "# TSDS v20 Paper Evidence Index",
        "",
        f"Frozen release: `{index['tag']}`. Ready for full paper writing: **yes**.",
        "",
        "## Headline Evidence Classes",
        "",
        "| Class | Records |",
        "|---|---:|",
    ]
    for name, count in headline["verdicts"].items():
        lines.append(f"| {headline['verdict_labels'].get(name, name)} (`{name}`) | {count} |")
    lines.extend(
        [
            f"| **Total** | **{headline['records']}** |",
            "",
            "## Claim Gates",
            "",
            "| Claim | Status | Evidence keys |",
            "|---|---|---|",
        ]
    )
    for row in index["claims"]:
        keys = ", ".join(f"`{entry['evidence_key']}`" for entry in row["evidence"])
        lines.append(f"| {row['claim_id']} | {row['status']} | {keys} |")
    lines.extend(
        [
            "",
            "## RQ Evidence Groups",
            "",
            "| Group | Registered files |",
            "|---|---:|",
        ]
    )
    for name, rows in index["evidence_groups"].items():
        lines.append(f"| `{name}` | {len(rows)} |")
    lines.extend(
        [
            "",
            "## Use Rule",
            "",
            "Import `manuscript_binding/manuscript_counts.tex` and derive tables only from "
            "the files listed in this index. Do not transcribe historical or intermediate counts.",
            "",
            index["claim_boundary"],
        ]
    )
    return "\n".join(lines) + "\n"


def write_outputs(out_dir: Path, index: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    generated = index.get("_generated_documents") or {}
    public_index = {
        key: value for key, value in index.items() if not key.startswith("_")
    }
    (out_dir / "paper_evidence_index.json").write_text(
        json.dumps(public_index, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "PAPER_EVIDENCE_INDEX.md").write_text(
        markdown(public_index), encoding="utf-8"
    )
    for name in ("paper_results_snapshot.json", "paper_results_macros.tex"):
        content = generated.get(name)
        if not isinstance(content, str):
            raise ValueError(f"missing generated paper input: {name}")
        path = out_dir / name
        path.write_bytes(content.encode("utf-8"))
        identity = next(
            row for row in public_index["checksum_rows"] if row.get("path") == name
        )
        if path.stat().st_size != identity["size"] or sha256_file(path) != identity["sha256"]:
            raise RuntimeError(f"generated paper input identity mismatch: {name}")
    with (out_dir / "paper_evidence_checksums.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=["category", "path", "size", "sha256"],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(public_index["checksum_rows"])
    with (out_dir / "claim_to_evidence.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=["claim_id", "status", "evidence_key", "path", "size", "sha256"],
            lineterminator="\n",
        )
        writer.writeheader()
        for claim in public_index["claims"]:
            for evidence in claim["evidence"]:
                writer.writerow(
                    {
                        "claim_id": claim["claim_id"],
                        "status": claim["status"],
                        **evidence,
                    }
                )
    (out_dir / "FREEZE_STATEMENT.md").write_text(
        "# TSDS v20 Freeze Statement\n\n"
        f"Release `{public_index['tag']}` passed the registered queue, post-release gates, "
        "download integrity audit, claim-evidence identity audit, and manuscript binding. "
        "System code and experimental inputs are frozen for manuscript result reporting.\n\n"
        + public_index["claim_boundary"]
        + "\n",
        encoding="utf-8",
    )
    output_rows = []
    for path in sorted(out_dir.iterdir()):
        if path.name == "paper_output_manifest.json" or not path.is_file():
            continue
        output_rows.append(
            {
                "path": path.name,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    (out_dir / "paper_output_manifest.json").write_text(
        json.dumps(
            {
                "schema": "tsds-v20-paper-output-manifest-v1",
                "tag": public_index["tag"],
                "ready": True,
                "files": output_rows,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-root", type=Path, required=True)
    parser.add_argument("--audit-root", type=Path, required=True)
    parser.add_argument("--paired-audit-root", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--post-release-suffix", default="v2")
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        index = build_index(
            args.release_root,
            args.audit_root,
            args.paired_audit_root,
            args.tag,
            args.post_release_suffix,
        )
        write_outputs(args.out_dir.resolve(), index)
    except (
        OSError,
        TypeError,
        ValueError,
        RuntimeError,
        json.JSONDecodeError,
        tarfile.TarError,
    ) as exc:
        print(f"V20_PAPER_EVIDENCE_INDEX_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(index, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
