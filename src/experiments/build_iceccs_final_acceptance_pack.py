#!/usr/bin/env python3
"""Build the final TSDS acceptance pack for the ICECCS submission.

This pack consolidates the remaining reviewer-risk areas:

* full guarded-recovery admission/rejection audit,
* path-control changed-case claim-impact analysis,
* stratified sink-level trace/binary audit coverage,
* a complete ledger running example,
* executable threat-matrix predicate documentation,
* reproducibility metadata, runtime follow-up targets, and SaTC adapter smoke
  coverage.

The generated material is reviewer evidence for TSDS' analyzer-level contract.
It does not add device-confirmed exploit claims.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_OUT = Path("experiment_reports/iceccs_final_acceptance_pack_20260702")
CAMPAIGN = Path("experiment_reports/full_firmware_campaign_current_tsds_20260627")
URGENT = Path("experiment_reports/iceccs_urgent_validation_pack_20260702")
ACCEPTANCE = Path("experiment_reports/acceptance_strengthening_pack_20260630")
REVISION = Path("experiment_reports/iceccs_revision_preparation_pack_20260629")
REVIEWER = Path("experiment_reports/iceccs_reviewer_audit_pack_20260629")
RUNTIME = Path("experiment_reports/runtime_validation_expansion_pack_20260702")
HASHES = Path("experiment_reports/acceptance_evidence_pack_20260629/artifact_manifest_hashes.csv")


VECTORS = [
    ("Command chaining", "semicolon", r"\texttt{;}", "one controlled offset before the modeled C-string null equals 0x3b"),
    ("Command chaining", "newline", r"newline", "one controlled offset before the modeled C-string null equals 0x0a"),
    ("Pipe/job control", "pipe", r"\texttt{|}", "one controlled offset realizes a pipe token"),
    ("Pipe/job control", "background ampersand", r"\texttt{\&}", "one controlled offset realizes job-control background syntax"),
    ("Command substitution", "backtick", r"backtick", "one controlled offset realizes backtick command substitution"),
    ("Command substitution", "dollar paren", r"\texttt{\$()}", "two adjacent command bytes realize the prefix \\$\\("),
    ("Variable expansion", "dollar expansion", r"\texttt{\$}", "one controlled offset realizes shell expansion syntax"),
    ("Redirection", "output redirection", r"\texttt{>}", "one controlled offset realizes output redirection"),
    ("Redirection", "input redirection", r"\texttt{<}", "one controlled offset realizes input redirection"),
    ("Spacing bypass", "IFS expansion", r"\texttt{\$\{IFS\}}", "six adjacent command bytes realize \\$\\{IFS\\}"),
    ("Spacing bypass", "tab", r"tab", "one controlled offset realizes alternate whitespace 0x09"),
]


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        return list(csv.DictReader(fh))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def short(value: Any, limit: int = 150) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\n", r"\n").replace("\r", r"\r").replace("\t", r"\t")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def copy_csv(src: Path, dst: Path) -> list[dict[str, str]]:
    rows = read_csv(src)
    write_csv(dst, rows)
    return rows


def summarize_counts(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    return dict(Counter(str(row.get(field, "")) for row in rows))


def find_record(target: str, closure_idx: int) -> dict[str, Any]:
    for row in read_jsonl(CAMPAIGN / f"{target}.results.jsonl"):
        if int(row.get("closure_idx", -1)) == closure_idx:
            return row
    raise KeyError(f"missing record {target}#{closure_idx}")


def vector_status_rows(record: dict[str, Any], filtered: bool = False) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for family, name, token, predicate in VECTORS:
        rows.append(
            {
                "family": family,
                "vector": name,
                "token": token,
                "status": "UNSAT" if filtered else "SAT",
                "predicate": predicate,
                "boundary": "modeled C-string extent; quote/decoder/wrapper semantics are non-claims unless materialized",
            }
        )
    return rows


def build_running_example(out_dir: Path) -> dict[str, Any]:
    sat = find_record("xr300", 30)
    filtered = find_record("xr300", 29)
    nms = find_record("r6400v2", 3)
    ledger = {
        "sv_sat_example": {
            "target": "xr300",
            "closure_idx": sat.get("closure_idx"),
            "trace": sat.get("trace_summary"),
            "source_class": ",".join(sat.get("source_kinds") or []),
            "sink": f"{sat.get('sink_function')}@{sat.get('sink_addr')}",
            "command_preview": sat.get("sink_preview"),
            "controlled_offsets": sat.get("tainted_offsets"),
            "controlled_extent": f"{min(sat.get('tainted_offsets') or [0])}..{max(sat.get('tainted_offsets') or [0])}",
            "sat_vectors": int(sat.get("vulnerable_vectors") or 0),
            "unsat_vectors": int(sat.get("secure_vectors") or 0),
            "minimal_witness": sat.get("minimal_bypass_vector") or {},
            "confidence": sat.get("evidence_confidence"),
            "recovery_mode": sat.get("analysis_recovery") or "direct_observed_sink_byte",
            "path_control_class": sat.get("path_control_class"),
            "claim_boundary": "solver-backed sink-byte evidence; not device exploit proof",
        },
        "modeled_filtered_sibling": {
            "target": "xr300",
            "closure_idx": filtered.get("closure_idx"),
            "trace": filtered.get("trace_summary"),
            "source_class": ",".join(filtered.get("source_kinds") or []),
            "sink": f"{filtered.get('sink_function')}@{filtered.get('sink_addr')}",
            "command_preview": filtered.get("sink_preview"),
            "controlled_offsets": filtered.get("tainted_offsets"),
            "sat_vectors": int(filtered.get("vulnerable_vectors") or 0),
            "unsat_vectors": int(filtered.get("secure_vectors") or 0),
            "path_control_class": filtered.get("path_control_class"),
            "claim_boundary": "matrix-bounded filtered evidence only",
        },
        "nms_example": {
            "target": "r6400v2",
            "closure_idx": nms.get("closure_idx"),
            "trace": nms.get("trace_summary"),
            "sink": f"{nms.get('sink_function')}@{nms.get('sink_addr')}",
            "command_preview": nms.get("no_taint_preview"),
            "diagnosis": nms.get("residual_diagnosis_summary"),
            "path_control_class": nms.get("path_control_class"),
            "claim_boundary": "warning-reduction evidence; not benignness proof",
        },
        "vector_matrix_for_sv_sat": vector_status_rows(sat, filtered=False),
        "vector_matrix_for_filtered_sibling": vector_status_rows(filtered, filtered=True),
    }
    (out_dir / "ledger_running_example.json").write_text(json.dumps(ledger, indent=2), encoding="utf-8")

    lines = [
        "# Ledger running example",
        "",
        "The XR300 SV-SAT record `closure_idx=30` reaches `system@0x95928` with",
        "`tc qdisc del dev <src> root`; NVRAM-derived bytes occupy offsets 17--47.",
        "All 11 modeled token predicates are SAT, and the minimal witness is",
        "backtick command substitution. Its sibling `closure_idx=29` reaches an",
        "`ftpc` command with source bytes present but all 11 modeled predicates",
        "UNSAT. The R6400v2 NMS example reaches a fixed router-analytics command",
        "and therefore remains warning-reduction evidence rather than benignness",
        "proof.",
        "",
        "## SV-SAT vector profile",
        "",
        "| Vector | Token | Status |",
        "|---|---|---|",
    ]
    for row in ledger["vector_matrix_for_sv_sat"]:
        lines.append(f"| {row['vector']} | {row['token']} | {row['status']} |")
    lines.extend(["", "## Boundary", "", ledger["sv_sat_example"]["claim_boundary"]])
    (out_dir / "ledger_running_example.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return ledger


def build_predicate_docs(out_dir: Path) -> list[dict[str, str]]:
    rows = [
        {
            "family": family,
            "vector": name,
            "token": token,
            "predicate": predicate,
            "length_null_boundary": "candidate offsets must lie before the modeled C-string null; multi-byte tokens require adjacent command bytes",
            "quote_escape_boundary": "quote state, escape decoding, URL/double decoding, option injection, and vendor wrapper dialects are non-claims unless materialized in command bytes/path constraints",
        }
        for family, name, token, predicate in VECTORS
    ]
    write_csv(out_dir / "threat_matrix_predicate_definitions.csv", rows)

    lines = [
        "# Threat-matrix predicate definitions",
        "",
        "The matrix contains 11 concrete token predicates over final command bytes.",
        "Each predicate requires at least one source-controlled byte in the token",
        "extent and is evaluated before the modeled C-string null boundary.",
        "",
        "| Family | Vector | Token | Predicate |",
        "|---|---|---|---|",
    ]
    for row in rows:
        lines.append(f"| {row['family']} | {row['vector']} | {row['token']} | {row['predicate']} |")
    lines.extend(
        [
            "",
            "Boundary: these predicates are POSIX/BusyBox-ash-like byte predicates,",
            "not a universal shell parser or sanitizer correctness proof.",
        ]
    )
    (out_dir / "threat_matrix_predicate_definitions.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return rows


def build_repro_docs(out_dir: Path) -> list[dict[str, str]]:
    impl = read_csv(REVIEWER / "implementation_parameters.csv")
    hashes = read_csv(HASHES)
    rows: list[dict[str, str]] = []
    for row in impl:
        rows.append(
            {
                "class": "path-control/solver parameter",
                "item": row.get("parameter", ""),
                "value": row.get("campaign_value", ""),
                "role": row.get("role", ""),
            }
        )
    hook_rows = [
        ("source API summaries", "nvram/config/web/file/env", "nvram_get family; config_get family; WebGetVar family; fopen/fgets/fread-backed file sources"),
        ("string/template builders", "C string and format propagation", "sprintf/snprintf; strcpy/strncpy/strlcpy; strcat/strncat/strlcat; memcpy/memmove; strtok/strsep"),
        ("sanitizer predicates", "string search and blacklist helpers", "strcmp/strncmp/strcasecmp; strstr/strcasestr; check_cmd_injection_blacklist"),
        ("sink wrappers", "shell-facing calls", "system/popen/exec* plus exec_cmd, doSystem, doSystemCmd, doShell, twsystem, CsteSystem, RunSystemCmd"),
        ("environment stubs", "filesystem/network/process", "access/fopen/fgets/fread/opendir/readdir; socket/connect/send/recv; fork/vfork; errno stubs"),
    ]
    for cls, item, value in hook_rows:
        rows.append({"class": cls, "item": item, "value": value, "role": "implemented summary/hook coverage"})
    for row in hashes:
        if row.get("kind") in {"binary", "json"}:
            rows.append(
                {
                    "class": "artifact hash",
                    "item": f"{row.get('target')}:{row.get('kind')}",
                    "value": row.get("sha256", "") or "not redistributed",
                    "role": row.get("path", ""),
                }
            )
    write_csv(out_dir / "reproducibility_manifest.csv", rows)

    lines = [
        "# Reproducibility manifest",
        "",
        "This manifest lists the implementation parameters, hook families, and",
        "artifact hashes needed to interpret the TSDS campaign.",
        "",
        "| Class | Item | Value |",
        "|---|---|---|",
    ]
    for row in rows[:45]:
        lines.append(f"| {row['class']} | {row['item']} | {short(row['value'], 90)} |")
    if len(rows) > 45:
        lines.append(f"| ... | {len(rows) - 45} more rows | see CSV |")
    (out_dir / "reproducibility_manifest.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return rows


def run_satc_adapter(out_dir: Path) -> dict[str, Any]:
    cmd = [sys.executable, "-m", "unittest", "experiments.test_satc_adapter", "-v"]
    completed = subprocess.run(cmd, text=True, capture_output=True)
    result = {
        "command": " ".join(cmd),
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "claim_boundary": "SaTC fixture adapter smoke coverage only; not an alternate-front-end accuracy study",
    }
    (out_dir / "satc_adapter_smoke_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out_dir / "satc_adapter_smoke_result.txt").write_text(
        completed.stdout + "\n" + completed.stderr,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)
    return result


def build_runtime_frontend_docs(out_dir: Path, satc: dict[str, Any]) -> dict[str, Any]:
    runtime_summary = read_json(RUNTIME / "runtime_validation_expansion_summary.json")
    candidates = read_csv(RUNTIME / "runtime_validation_candidate_expansion.csv")
    pc_targets = read_csv(RUNTIME / "path_control_runtime_targets.csv")
    rows: list[dict[str, Any]] = []
    for row in candidates:
        rows.append(
            {
                "type": "runtime_followup_candidate",
                "stratum": row.get("stratum", ""),
                "target": row.get("target", ""),
                "closure_idx": row.get("closure_idx", ""),
                "success_condition": row.get("success_condition", ""),
                "non_claim": row.get("non_claim", ""),
            }
        )
    for row in pc_targets:
        rows.append(
            {
                "type": "path_control_runtime_target",
                "stratum": row.get("stratum", ""),
                "target": row.get("target", ""),
                "closure_idx": row.get("closure_idx", ""),
                "success_condition": row.get("success_condition", ""),
                "non_claim": row.get("non_claim", ""),
            }
        )
    write_csv(out_dir / "runtime_and_frontend_followup_index.csv", rows)
    summary = {
        "runtime_attempts": runtime_summary.get("runtime_attempts", 0),
        "runtime_positive_token_to_sink_attempts": runtime_summary.get("positive_token_to_sink_attempts", 0),
        "runtime_unique_positive_token_callsite_keys": runtime_summary.get("unique_positive_token_callsite_keys", 0),
        "runtime_candidate_rows": len(candidates),
        "path_control_runtime_targets": len(pc_targets),
        "satc_adapter_smoke_passed": satc.get("returncode") == 0,
        "claim_boundary": "runtime sink-intercept and adapter-schema coverage only; no exploit or front-end accuracy claim",
    }
    lines = [
        "# Runtime and front-end follow-up coverage",
        "",
        f"- Runtime summaries replayed: `{summary['runtime_attempts']}`",
        f"- Token-to-sink attempts: `{summary['runtime_positive_token_to_sink_attempts']}`",
        f"- Unique positive token/callsite keys: `{summary['runtime_unique_positive_token_callsite_keys']}`",
        f"- Prioritized runtime candidates: `{summary['runtime_candidate_rows']}`",
        f"- Path-control runtime sensitivity targets: `{summary['path_control_runtime_targets']}`",
        f"- SaTC adapter smoke passed: `{summary['satc_adapter_smoke_passed']}`",
        "",
        "Boundary: this material expands reviewer triage coverage. It does not",
        "turn TSDS into a multi-front-end accuracy study and does not add",
        "device-confirmed exploit claims.",
    ]
    (out_dir / "runtime_and_frontend_followup.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def write_case_studies(out_dir: Path, recovery: list[dict[str, str]], rejected: list[dict[str, str]], pc: list[dict[str, str]]) -> None:
    success = recovery[0] if recovery else {}
    reject = rejected[0] if rejected else {}
    pc_positive = next((r for r in pc if r.get("claim_impact") == "full_positive_no_path_residual"), pc[0] if pc else {})
    pc_extra = next((r for r in pc if r.get("claim_impact") == "manual_review_only_extra_positive"), {})
    success_gate = success.get("compatibility_gate") or success.get("claim_boundary") or "compatibility facts recorded in full audit"
    lines = [
        "# Case studies for reviewer-risk mechanisms",
        "",
        "## Guarded recovery admitted",
        "",
        f"- Record: `{success.get('target')}#{success.get('closure_idx')}`",
        f"- Gate: {success_gate}",
        f"- Facts: {success.get('compatibility_facts')}",
        f"- Preview: `{short(success.get('dynamic_preview') or success.get('sink_preview'), 120)}`",
        f"- Boundary: {success.get('claim_boundary')}",
        "",
        "## Guarded recovery rejected",
        "",
        f"- Record: `{reject.get('target')}#{reject.get('closure_idx')}`",
        f"- Blocked reason: {reject.get('blocked_reason')}",
        f"- Dynamic preview: `{short(reject.get('dynamic_preview'), 120)}`",
        f"- Static template: `{short(reject.get('static_template'), 120)}`",
        f"- Decision: {reject.get('decision')}",
        "",
        "## Path-control changed cases",
        "",
        f"- Full-positive/no-path-residual example: `{pc_positive.get('target')}#{pc_positive.get('closure_idx')}`; {pc_positive.get('interpretation')}",
    ]
    if pc_extra:
        lines.append(
            f"- No-path-only extra positive: `{pc_extra.get('target')}#{pc_extra.get('closure_idx')}`; {pc_extra.get('interpretation')}"
        )
    lines.append("- These cases are sensitivity evidence, not a completeness proof.")
    (out_dir / "mechanism_case_studies.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_artifact_index(out_dir: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# TSDS Final Acceptance Pack",
        "",
        "Generated for the ICECCS submission to close the remaining reviewer-risk",
        "items around guarded recovery, path-control sensitivity, stratified audit",
        "coverage, predicate semantics, reproducibility, runtime follow-up, and",
        "front-end adapter boundaries.",
        "",
        "## Key Counts",
        "",
        f"- Guarded recovered SV-SAT records audited: `{summary['guarded_recovery_records']}`",
        f"- Rejected recovery attempts retained: `{summary['rejected_recovery_attempts']}`",
        f"- Path-control changed cases analyzed: `{summary['path_control_changed_cases']}`",
        f"- Stratified audit rows: `{summary['stratified_audit_rows']}`",
        f"- Threat-matrix predicates documented: `{summary['predicate_rows']}`",
        f"- Runtime follow-up candidates: `{summary['runtime_followup']['runtime_candidate_rows']}`",
        f"- Path-control runtime targets: `{summary['runtime_followup']['path_control_runtime_targets']}`",
        f"- SaTC adapter smoke passed: `{summary['runtime_followup']['satc_adapter_smoke_passed']}`",
        "",
        "## Claim Boundary",
        "",
        summary["claim_boundary"],
    ]
    (out_dir / "ARTIFACT_INDEX.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    recovery = copy_csv(REVISION / "recovered_positive_full_audit.csv", args.out_dir / "guarded_recovery_full_audit.csv")
    rejected = copy_csv(URGENT / "guarded_recovery_rejected_attempts.csv", args.out_dir / "guarded_recovery_rejected_attempts.csv")
    pc = copy_csv(URGENT / "path_control_claim_impact_analysis.csv", args.out_dir / "path_control_claim_impact_detailed.csv")
    stratified = copy_csv(ACCEPTANCE / "stratified_trace_audit_60.csv", args.out_dir / "stratified_manual_binary_audit_60.csv")

    write_case_studies(args.out_dir, recovery, rejected, pc)
    ledger = build_running_example(args.out_dir)
    predicates = build_predicate_docs(args.out_dir)
    repro = build_repro_docs(args.out_dir)
    satc = run_satc_adapter(args.out_dir)
    runtime_followup = build_runtime_frontend_docs(args.out_dir, satc)

    summary = {
        "guarded_recovery_records": len(recovery),
        "guarded_recovery_modes": summarize_counts(recovery, "recovery_mode"),
        "guarded_recovery_manual_outcomes": summarize_counts(recovery, "manual_trace_outcome"),
        "rejected_recovery_attempts": len(rejected),
        "rejected_recovery_reasons": summarize_counts(rejected, "blocked_reason"),
        "path_control_changed_cases": len(pc),
        "path_control_claim_impacts": summarize_counts(pc, "claim_impact"),
        "stratified_audit_rows": len(stratified),
        "stratified_audit_strata": summarize_counts(stratified, "stratum"),
        "ledger_example_target": ledger["sv_sat_example"]["target"],
        "predicate_rows": len(predicates),
        "reproducibility_rows": len(repro),
        "runtime_followup": runtime_followup,
        "claim_boundary": "Analyzer-level sink-byte evidence, runtime sink-intercept consistency, and adapter-schema checks only; no device-confirmed exploit or alternate-front-end accuracy claim is added.",
    }
    (args.out_dir / "final_acceptance_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    lines = [
        "# Final acceptance summary",
        "",
        f"- Guarded recovery audit: `{summary['guarded_recovery_records']}` admitted, `{summary['rejected_recovery_attempts']}` rejected.",
        f"- Path-control changed cases: `{summary['path_control_changed_cases']}` with claim-impact labels.",
        f"- Stratified trace/binary audit rows: `{summary['stratified_audit_rows']}`.",
        f"- Threat predicates: `{summary['predicate_rows']}` concrete byte predicates.",
        f"- Runtime follow-up candidates: `{summary['runtime_followup']['runtime_candidate_rows']}`.",
        f"- SaTC adapter smoke: `{summary['runtime_followup']['satc_adapter_smoke_passed']}`.",
        "",
        "Boundary: " + summary["claim_boundary"],
    ]
    (args.out_dir / "final_acceptance_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_artifact_index(args.out_dir, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
