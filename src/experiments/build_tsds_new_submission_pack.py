#!/usr/bin/env python3
"""Build reviewer-facing tables for the TSDS_new submission draft.

The pack derives two paper-facing artifacts from the current full-campaign
ledgers:

* per-vector SAT/UNSAT counts over records with a sanitizer-gap profile, and
* five concise ledger case studies spanning SV-SAT, partial filtering,
  modeled-vector filtering, NMS, and residual outcomes.

The script only summarizes existing analyzer-level evidence. It does not add
device exploit claims.
"""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path("experiment_reports/full_firmware_campaign_current_tsds_20260627")
OUT = Path("experiment_reports/tsds_new_submission_pack_20260706")
AGG = ROOT / "full_campaign_aggregate.json"

VECTOR_ORDER = [
    ("Command chaining", ";", r"\texttt{;}"),
    ("Command chaining", "\\n", "newline"),
    ("Pipe/job control", "|", r"\texttt{|}"),
    ("Pipe/job control", "&", r"\texttt{\&}"),
    ("Command substitution", "`", "backtick"),
    ("Command substitution", "$(", r"\texttt{\$()}"),
    ("Variable expansion", "$", r"\texttt{\$}"),
    ("Redirection", ">", r"\texttt{>}"),
    ("Redirection", "<", r"\texttt{<}"),
    ("Spacing bypass", "${IFS}", r"\texttt{\$\{IFS\}}"),
    ("Spacing bypass", "\\t", "tab"),
]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


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


def short(text: Any, limit: int = 76) -> str:
    s = str(text or "").replace("\n", r"\n")
    return s if len(s) <= limit else s[: limit - 3] + "..."


def latex_escape(text: Any) -> str:
    s = str(text or "")
    repl = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(repl.get(ch, ch) for ch in s)


def load_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(ROOT.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        for row in read_jsonl(path):
            row["_target"] = target
            records.append(row)
    return records


def vector_summary(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    profiled_records = 0
    for row in records:
        profile = row.get("sanitizer_gap_profile") or {}
        if not profile:
            continue
        profiled_records += 1
        for item in profile.get("bypass_vectors") or []:
            counts[item.get("vector", "")]["SAT"] += 1
        for item in profile.get("blocked_vectors") or []:
            counts[item.get("vector", "")]["UNSAT"] += 1
        for item in profile.get("inconclusive_vectors") or []:
            counts[item.get("vector", "")]["INC"] += 1

    rows: list[dict[str, Any]] = []
    for family, vector, token in VECTOR_ORDER:
        c = counts[vector]
        rows.append(
            {
                "family": family,
                "vector": vector,
                "token": token,
                "sat_records": c["SAT"],
                "unsat_records": c["UNSAT"],
                "inconclusive_records": c["INC"],
                "profiled_records": profiled_records,
            }
        )
    return rows


def find_record(records: list[dict[str, Any]], target: str, idx: int) -> dict[str, Any]:
    for row in records:
        if row.get("_target") == target and row.get("closure_idx") == idx:
            return row
    raise KeyError((target, idx))


def case_row(kind: str, row: dict[str, Any], audit_meaning: str) -> dict[str, Any]:
    profile = row.get("sanitizer_gap_profile") or {}
    offsets = row.get("tainted_offsets") or []
    if offsets:
        extent = f"{min(offsets)}..{max(offsets)} ({len(offsets)} bytes)"
    else:
        extent = "--"
    return {
        "case": kind,
        "target": row.get("_target", ""),
        "closure_idx": row.get("closure_idx", ""),
        "status": row.get("status", ""),
        "trace": row.get("trace_summary", ""),
        "command_preview": short(row.get("sink_preview") or row.get("residual_diagnosis_summary") or "", 90),
        "controlled_extent": extent,
        "vector_profile": f"{profile.get('vulnerable_count', 0)} SAT / {profile.get('secure_count', 0)} UNSAT",
        "recovery_or_path": row.get("recovery_mode") or row.get("path_control_class") or row.get("engine_stop_reason") or "",
        "audit_meaning": audit_meaning,
    }


def case_studies(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cases = [
        case_row(
            "SV-SAT",
            find_record(records, "xr300", 30),
            "source-controlled sink bytes satisfy every modeled vector; minimal witness is command substitution",
        ),
        case_row(
            "Partial filter",
            find_record(records, "dir878", 3),
            "nine modeled vectors remain SAT while newline/tab-like spacing vectors are blocked",
        ),
        case_row(
            "Modeled-vector filtered",
            find_record(records, "xr300", 29),
            "source bytes reach the sink, but all 11 implemented predicates are UNSAT",
        ),
        case_row(
            "NMS",
            find_record(records, "r6400v2", 3),
            "reached fixed command template with no modeled source slot under TSDS abstraction",
        ),
        case_row(
            "Residual",
            find_record(records, "asus_rt_be57", 27),
            "time-budget exhaustion is retained as an explicit follow-up obligation",
        ),
    ]
    return cases


def write_vector_tex(rows: list[dict[str, Any]], path: Path) -> None:
    lines = [
        r"\begin{tabularx}{\textwidth}{@{}P{0.22\textwidth}P{0.18\textwidth}rrrY@{}}",
        r"\toprule",
        r"Family & Token & SAT & UNSAT & Inc. & Interpretation\\",
        r"\midrule",
    ]
    for row in rows:
        sat = int(row["sat_records"])
        unsat = int(row["unsat_records"])
        if sat == 224 and unsat == 22:
            interp = "same aggregate count as a coarse metacharacter check"
        else:
            interp = "separates partial filtering and blocked-vector evidence"
        lines.append(
            f"{latex_escape(row['family'])} & {row['token']} & {sat} & {unsat} & {row['inconclusive_records']} & {latex_escape(interp)}\\\\"
        )
    lines += [r"\bottomrule", r"\end{tabularx}"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_cases_tex(rows: list[dict[str, Any]], path: Path) -> None:
    lines = [
        r"\begin{tabularx}{\textwidth}{@{}P{0.15\textwidth}P{0.17\textwidth}P{0.23\textwidth}P{0.16\textwidth}Y@{}}",
        r"\toprule",
        r"Case & Record & Sanitized command evidence & Vector profile & Audit meaning\\",
        r"\midrule",
    ]
    for row in rows:
        record = f"{row['target']}:{row['closure_idx']} ({row['status']})"
        evidence = f"{row['trace']}; {row['controlled_extent']}; {row['command_preview']}"
        lines.append(
            f"{latex_escape(row['case'])} & {latex_escape(record)} & {latex_escape(short(evidence, 105))} & {latex_escape(row['vector_profile'])} & {latex_escape(row['audit_meaning'])}\\\\"
        )
    lines += [r"\bottomrule", r"\end{tabularx}"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def artifact_manifest(path: Path) -> None:
    def posix(p: Path | str) -> str:
        return str(p).replace("\\", "/")

    rows = [
        ("Table 2 / controlled variants", "experiment_reports/full_ablation_8firmware_current_tsds_20260628/", "ablation_table.tex; ablation_aggregate.json"),
        ("Table 3 / evidence tiers", "experiment_reports/full_firmware_campaign_current_tsds_20260627/*.results.jsonl", "manual audit index and recovery labels"),
        ("Table 4 / per-target campaign", "experiment_reports/full_firmware_campaign_current_tsds_20260627/full_campaign_aggregate.json", "full_campaign_per_target.csv"),
        ("Table 5 / vector profile", posix(OUT / "per_vector_matrix_summary.csv"), "generated by this script"),
        ("Table 6 / ledger cases", posix(OUT / "ledger_case_studies.csv"), "generated by this script"),
        ("Path-control sensitivity", "experiment_reports/iceccs_final_acceptance_pack_20260702/", "path_control_claim_impact_details.csv"),
        ("SaTC adapter check", "experiment_reports/iceccs_final_acceptance_pack_20260702/satc_adapter_smoke_result.json", "python experiments/test_satc_adapter.py"),
        ("Runtime canaries", "experiment_reports/runtime_validation_expansion_pack_20260702/", "qemu/gdb token-to-sink summaries"),
    ]
    lines = [
        "# Artifact-to-paper mapping",
        "",
        "This manifest maps paper claims to reviewer-facing files. The listed",
        "artifacts support analyzer-level sink-byte evidence only; they do not",
        "add device-level exploit claims.",
        "",
        "| Paper result | Artifact path | Reproduction note |",
        "| --- | --- | --- |",
    ]
    for result, artifact, command in rows:
        lines.append(f"| {result} | `{artifact}` | {command} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def diagnostic_summaries(path_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    agg = json.loads(AGG.read_text(encoding="utf-8"))
    total = agg["total"]
    residual_rows = [
        {
            "residual_type": "Unreachable/model-gap",
            "count": total["unreachable"],
            "root_cause": "target sink not reached under current model",
            "follow_up": "extend source/wrapper/env summaries or replay with targeted seed",
        },
        {
            "residual_type": "Timeout/budget",
            "count": total["timeout"],
            "root_cause": "solver or execution budget exhausted",
            "follow_up": "replay with extended timeout or refined path slicing",
        },
    ]
    path_rows = [
        {
            "sensitivity_outcome": "Same verdict/vector signature",
            "count": 494,
            "interpretation": "stable evidence under full and no-path-control runs",
            "tsds_treatment": "included in aggregate",
        },
        {
            "sensitivity_outcome": "Changed cases",
            "count": 24,
            "interpretation": "frontier-management sensitivity boundary",
            "tsds_treatment": "retained for audit",
        },
        {
            "sensitivity_outcome": "Full-positive/no-path-residual",
            "count": 2,
            "interpretation": "unguided frontier failed to preserve reached evidence",
            "tsds_treatment": "not refuted by no-path run",
        },
        {
            "sensitivity_outcome": "No-path-only NMS-to-SV-SAT",
            "count": 1,
            "interpretation": "possible missed positive in full run",
            "tsds_treatment": "manual review; not counted as TSDS positive",
        },
        {
            "sensitivity_outcome": "Path-explosion residuals",
            "count": "73 full / 102 no-path",
            "interpretation": "path control reduces residual burden",
            "tsds_treatment": "reported, not hidden",
        },
    ]
    write_csv(path_dir / "residual_obligation_summary.csv", residual_rows)
    write_csv(path_dir / "path_control_sensitivity_summary.csv", path_rows)
    return residual_rows, path_rows


def main() -> None:
    records = load_records()
    OUT.mkdir(parents=True, exist_ok=True)
    vrows = vector_summary(records)
    crows = case_studies(records)
    write_csv(OUT / "per_vector_matrix_summary.csv", vrows)
    write_csv(OUT / "ledger_case_studies.csv", crows)
    write_vector_tex(vrows, OUT / "per_vector_matrix_table.tex")
    write_cases_tex(crows, OUT / "ledger_case_studies_table.tex")
    residual_rows, path_rows = diagnostic_summaries(OUT)
    artifact_manifest(OUT / "artifact_manifest.md")

    summary = {
        "claim_boundary": "Analyzer-level sink-byte matrix evidence only; no device exploit claim.",
        "records": len(records),
        "profiled_records": vrows[0]["profiled_records"] if vrows else 0,
        "vector_rows": len(vrows),
        "case_study_rows": len(crows),
        "partial_filter_records": sum(1 for r in records if r.get("partially_filtered")),
        "residual_rows": len(residual_rows),
        "path_sensitivity_rows": len(path_rows),
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (OUT / "README.md").write_text(
        "\n".join(
            [
                "# TSDS_new submission pack",
                "",
                "Derived from full-campaign JSONL ledgers. The pack supports the",
                "per-vector matrix table and five ledger case studies used in the",
                "TSDS_new paper draft.",
                "",
                f"- Records: {summary['records']}",
                f"- Profiled records: {summary['profiled_records']}",
                f"- Vector predicates: {summary['vector_rows']}",
                f"- Ledger case studies: {summary['case_study_rows']}",
                f"- Partial-filter records: {summary['partial_filter_records']}",
                f"- Residual diagnostic rows: {summary['residual_rows']}",
                f"- Path sensitivity rows: {summary['path_sensitivity_rows']}",
                "- Artifact mapping: artifact_manifest.md",
                "",
                summary["claim_boundary"],
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
