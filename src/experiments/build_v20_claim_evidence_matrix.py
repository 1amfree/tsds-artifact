#!/usr/bin/env python3
"""Build a content-bound claim-to-evidence map for the frozen TSDS release."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "tsds-v20-claim-evidence-matrix-v1"
SHA256_LENGTH = 64


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def strict_json(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}: {path}")
            result[key] = value
        return result

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def resolve_json(path: Path, filename: str) -> Path:
    candidate = path / filename if path.is_dir() else path
    if not candidate.is_file():
        raise ValueError(f"missing required JSON artifact: {candidate}")
    return candidate.resolve()


def identity(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def as_configuration_map(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = document.get("configurations") or []
    return {
        str(row.get("configuration")): row
        for row in rows
        if isinstance(row, dict) and row.get("configuration")
    }


def valid_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != SHA256_LENGTH:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def audit_has_zero_issues(
    audits: dict[str, Any], name: str, issue_field: str
) -> bool:
    value = audits.get(name) or {}
    return bool(
        isinstance(value, dict)
        and int(value.get("records") or 0) > 0
        and int(value.get(issue_field) or 0) == 0
    )


def claim(
    identifier: str,
    statement: str,
    status: str,
    evidence: list[str],
    predicate: str,
    non_claim: str,
) -> dict[str, Any]:
    return {
        "claim_id": identifier,
        "statement": statement,
        "status": status,
        "evidence_paths": evidence,
        "verification_predicate": predicate,
        "non_claim": non_claim,
    }


def build_matrix(args: argparse.Namespace) -> dict[str, Any]:
    accepted = args.accepted_run.resolve()
    accepted_manifest_path = resolve_json(accepted, "pipeline_manifest.json")
    paper_path = resolve_json(accepted / "paper_tables", "paper_data_summary.json")
    repeatability_path = resolve_json(
        accepted / "repeatability_consensus", "repeatability_summary.json"
    )
    matrix_path = resolve_json(args.matrix_analysis, "v19_ablation_analysis.json")
    confirm_path = resolve_json(args.confirmatory_analysis, "v19_ablation_analysis.json")
    transitions_path = resolve_json(
        args.record_transitions, "record_level_ablation_summary.json"
    )
    # 确认性全语料消融也必须保留逐记录证据，避免 C9 仅依赖聚合统计。
    confirm_transitions_path = resolve_json(
        args.confirmatory_transitions, "record_level_ablation_summary.json"
    )
    extension_path = resolve_json(args.extension_verification, "extension_verification.json")
    runtime_path = resolve_json(args.runtime_pack, "runtime_validation_expansion_summary.json")
    satc_path = resolve_json(args.satc_manifest, "experiment_manifest.json")

    accepted_manifest = strict_json(accepted_manifest_path)
    paper = strict_json(paper_path)
    repeatability = strict_json(repeatability_path)
    matrix = strict_json(matrix_path)
    confirm = strict_json(confirm_path)
    transitions = strict_json(transitions_path)
    confirm_transitions = strict_json(confirm_transitions_path)
    extension = strict_json(extension_path)
    runtime = strict_json(runtime_path)
    satc = strict_json(satc_path)
    matrix_configs = as_configuration_map(matrix)
    confirm_configs = as_configuration_map(confirm)
    transition_configs = as_configuration_map(transitions)
    confirm_transition_configs = as_configuration_map(confirm_transitions)

    evidence_paths = {
        "accepted_manifest": identity(accepted_manifest_path),
        "paper_tables": identity(paper_path),
        "repeatability": identity(repeatability_path),
        "matrix": identity(matrix_path),
        "confirmatory": identity(confirm_path),
        "record_transitions": identity(transitions_path),
        "confirmatory_transitions": identity(confirm_transitions_path),
        "extension_verification": identity(extension_path),
        "runtime": identity(runtime_path),
        "satc": identity(satc_path),
    }
    accepted_ok = bool(
        accepted_manifest.get("schema") == "tsds-v18-pipeline-v7"
        and accepted_manifest.get("success") is True
    )
    paper_ok = paper.get("all_contract_valid") is True and int(paper.get("records") or 0) > 0
    matrix_ok = matrix.get("valid") is True
    transitions_ok = bool(
        transitions.get("valid") is True
        and int(transitions.get("transition_rows") or 0) > 0
    )
    confirm_transitions_ok = bool(
        confirm_transitions.get("valid") is True
        and int(confirm_transitions.get("transition_rows") or 0) > 0
    )
    p0_names = {"p0_scheduler_off", "p0_corridor_off", "p0_all_off"}
    p1_names = {"p1_projection_off", "p1_spawn_backend"}
    p2_names = {"p2_provenance_off", "p2_semantics_off", "p2_refinement_off", "p2_refinement_replay"}
    repeat_core = repeatability.get("sink_semantic_core") or {}
    repeat_ok = bool(
        repeatability.get("schema") == "tsds-repeatability-audit-v4"
        and repeat_core.get("baseline_reproduced") is True
        and int(repeat_core.get("baseline_records") or 0) > 0
        and int(repeat_core.get("stable_records") or 0)
        == int(repeat_core.get("baseline_records") or 0)
        and int(repeat_core.get("semantic_drift") or 0) == 0
        and int(repeat_core.get("baseline_only") or 0) == 0
        and int(repeatability.get("baseline_only") or 0) == 0
        and int(repeatability.get("replay_only") or 0) == 0
    )
    confirm_ok = bool(
        confirm.get("valid") is True
        and {"p0_all_off", "p1_projection_off"}.issubset(confirm_configs)
        and confirm_transitions_ok
        and {"p0_all_off", "p1_projection_off"}.issubset(
            confirm_transition_configs
        )
    )
    extension_ok = bool(
        extension.get("schema") == "tsds-v18-evidence-extension-verification-v1"
        and extension.get("valid") is True
    )
    runtime_campaign = runtime.get("campaign_identity") or {}
    runtime_ok = bool(
        runtime.get("schema") == "tsds-runtime-validation-expansion-v2"
        and runtime.get("valid") is True
        and int(runtime.get("runtime_attempts") or 0) > 0
        and int(runtime_campaign.get("result_files") or 0) > 0
        and valid_sha256(runtime_campaign.get("results_identity_sha256"))
        and valid_sha256(runtime.get("runtime_attempts_identity_sha256"))
        and valid_sha256(runtime.get("candidate_rows_identity_sha256"))
        and valid_sha256(runtime.get("path_control_rows_identity_sha256"))
    )
    satc_audits = satc.get("tsds_audits") or {}
    satc_contract = satc_audits.get("candidate_contract") or {}
    satc_configuration = satc.get("configuration") or {}
    satc_inputs = satc.get("inputs") or {}
    satc_tsds = satc.get("tsds") or {}
    # 布尔标记不足以证明来源绑定；同时校验快照和关键词清单的文件身份。
    satc_source_identity = satc_inputs.get("satc_source_snapshot") or {}
    satc_keyword_identity = satc_inputs.get("keyword_provenance_manifest") or {}
    satc_ok = bool(
        satc.get("schema") == "tsds-satc-ghidra-ingestion-v1"
        and satc.get("success") is True
        and int(satc.get("satc_candidates") or 0) > 0
        and satc_contract.get("valid") is True
        and int(satc_tsds.get("unique_pairs_analyzed") or 0) > 0
        and satc_configuration.get("satc_source_snapshot_bound") is True
        and satc_configuration.get("keyword_provenance_manifest_bound") is True
        and int(satc_source_identity.get("size") or 0) > 0
        and valid_sha256(satc_source_identity.get("sha256"))
        and int(satc_keyword_identity.get("size") or 0) > 0
        and valid_sha256(satc_keyword_identity.get("sha256"))
        and audit_has_zero_issues(
            satc_audits, "evidence_contract", "records_with_contract_issues"
        )
        and audit_has_zero_issues(
            satc_audits, "vector_integrity", "records_with_integrity_issues"
        )
        and audit_has_zero_issues(
            satc_audits, "ledger_schema", "records_with_issues"
        )
    )

    claims = [
        claim(
            "C1",
            "TSDS emits contract-gated final-command-byte evidence classes over the accepted corpus.",
            "supported" if accepted_ok and paper_ok else "pending",
            ["accepted_manifest", "paper_tables"],
            "pipeline success, nonempty paper population, and all_contract_valid=true",
            "No end-to-end exploitability, reachability, authentication, or device-execution claim.",
        ),
        claim(
            "C2",
            "P0 scheduling and corridor controls have paired, closure-level sensitivity evidence.",
            "supported" if matrix_ok and transitions_ok and p0_names.issubset(matrix_configs) and p0_names.issubset(transition_configs) else "pending",
            ["matrix", "record_transitions"],
            "valid paired matrix and transition exports for all P0 configurations",
            "No soundness/completeness or universal performance claim.",
        ),
        claim(
            "C3",
            "P1 projected constraints and worker backend have paired mechanism-attribution evidence.",
            "supported" if matrix_ok and transitions_ok and p1_names.issubset(matrix_configs) and p1_names.issubset(transition_configs) else "pending",
            ["matrix", "record_transitions"],
            "valid paired matrix containing both P1 configurations",
            "No cross-tool accuracy or SOTA claim.",
        ),
        claim(
            "C4",
            "P2 provenance, sink semantics, and refinement are evaluated by isolated mechanism variants.",
            "supported" if matrix_ok and transitions_ok and p2_names.issubset(matrix_configs) and p2_names.issubset(transition_configs) else "pending",
            ["matrix", "record_transitions"],
            "valid paired matrix containing all P2 configurations",
            "No claim that a disabled mechanism is globally unsound.",
        ),
        claim(
            "C5",
            "Residual obligations are classified and bound to a successful accepted pipeline.",
            "supported" if extension_ok else "pending",
            ["extension_verification"],
            "independent evidence-extension verification is valid",
            "A residual is not a negative result or a benignness proof.",
        ),
        claim(
            "C6",
            "The accepted full-corpus repeat has no sink-semantic drift on aligned records.",
            "supported" if repeat_ok else "pending",
            ["repeatability"],
            "repeatability v4 reports reproduced baseline, zero semantic drift, and zero baseline-only records",
            "No claim of timing-invariant performance across arbitrary hosts.",
        ),
        claim(
            "C7",
            "QEMU/GDB canaries establish only token-to-sink consistency for recorded attempts.",
            "supported" if runtime_ok else "pending",
            ["runtime"],
            "v2 runtime pack has a nonempty, content-bound attempt population",
            "No shell execution, device-confirmed exploit, or exploit-rate claim.",
        ),
        claim(
            "C8",
            "A real SaTC front end can be normalized and passed through the TSDS evidence contract.",
            "supported" if satc_ok else "pending",
            ["satc"],
            "native ingestion succeeds with nonzero candidates and a valid candidate-contract audit",
            "No SaTC-versus-TSDS accuracy or superiority claim.",
        ),
        claim(
            "C9",
            "The confirmation matrix checks key P0/P1 effects on the full corpus.",
            "supported" if confirm_ok else "pending",
            ["confirmatory", "confirmatory_transitions"],
            "valid confirmation analysis and record-level export include full-corpus p0_all_off and p1_projection_off",
            "No extrapolation beyond the evaluated corpus and resource envelope.",
        ),
    ]
    ready = all(row["status"] == "supported" for row in claims)
    return {
        "schema": SCHEMA,
        "ready_for_full_paper_writing": ready,
        "claims": claims,
        "evidence": evidence_paths,
        "input_summary": {
            "accepted_pipeline_schema": accepted_manifest.get("schema"),
            "accepted_records": paper.get("records"),
            "matrix_configurations": sorted(matrix_configs),
            "confirmation_configurations": sorted(confirm_configs),
            "transition_rows": transitions.get("transition_rows"),
            "confirmatory_transition_rows": confirm_transitions.get(
                "transition_rows"
            ),
            "runtime_attempts": runtime.get("runtime_attempts"),
            "satc_candidates": satc.get("satc_candidates"),
        },
        "claim_boundary": (
            "The matrix binds only the listed analyzer-level claims to immutable artifacts. "
            "It does not transform any evidence class into a device-level exploit claim."
        ),
    }


def write_outputs(out_dir: Path, document: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "claim_evidence_matrix.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    rows = document["claims"]
    with (out_dir / "claim_evidence_matrix.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        for row in rows:
            value = dict(row)
            value["evidence_paths"] = ";".join(row["evidence_paths"])
            writer.writerow(value)
    lines = [
        "# TSDS v20 Claim-to-Evidence Matrix",
        "",
        document["claim_boundary"],
        "",
        "| ID | Claim | Status | Evidence |",
        "|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['claim_id']} | {row['statement']} | {row['status']} | "
            + ", ".join(f"`{name}`" for name in row["evidence_paths"])
            + " |"
        )
    lines.extend(
        [
            "",
            f"Ready for full paper writing: **{document['ready_for_full_paper_writing']}**.",
        ]
    )
    (out_dir / "claim_evidence_matrix.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--accepted-run", type=Path, required=True)
    parser.add_argument("--matrix-analysis", type=Path, required=True)
    parser.add_argument("--confirmatory-analysis", type=Path, required=True)
    parser.add_argument("--record-transitions", type=Path, required=True)
    parser.add_argument("--confirmatory-transitions", type=Path, required=True)
    parser.add_argument("--extension-verification", type=Path, required=True)
    parser.add_argument("--runtime-pack", type=Path, required=True)
    parser.add_argument("--satc-manifest", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    try:
        document = build_matrix(args)
        write_outputs(args.out_dir.resolve(), document)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"CLAIM_EVIDENCE_MATRIX_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(document, indent=2, sort_keys=True))
    return 3 if args.require_ready and not document["ready_for_full_paper_writing"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
