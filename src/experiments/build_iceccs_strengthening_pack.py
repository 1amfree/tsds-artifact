#!/usr/bin/env python3
"""Build reviewer-facing TSDS evidence tables for the ICECCS paper.

The script is intentionally conservative. It only re-summarizes existing
campaign, ablation, path-control, and canary artifacts; it does not create new
device-confirmation claims.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


DEFAULT_ABLATION = Path("experiment_reports/full_ablation_8firmware_current_tsds_20260628/ablation_aggregate.json")
DEFAULT_REVIEWER = Path("experiment_reports/acceptance_evidence_pack_20260629/reviewer_response_evidence.json")
DEFAULT_CANARIES = Path("experiment_reports/runtime_canary_validation_cross_vendor_20260629/cross_vendor_runtime_canary_summary.json")
DEFAULT_AUDIT = Path("experiment_reports/manual_evidence_audit_20260628/manual_evidence_audit_summary.json")
DEFAULT_OUT = Path("experiment_reports/iceccs_strengthening_pack_20260629")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def esc(value: Any) -> str:
    text = "" if value is None else str(value)
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
    return "".join(repl.get(ch, ch) for ch in text)


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def by_config(ablation: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row.get("config")): row for row in ablation}


def validator_rows(ablation: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = by_config(ablation)
    full = rows["full"]
    no_matrix = rows["no_threat_matrix"]
    no_summary = rows["no_firmware_summaries"]
    direct = rows["no_reconciliation"]
    no_path = rows["no_path_control"]
    static = rows["static_only"]

    return [
        {
            "baseline": "Raw Mango closures",
            "records": 546,
            "resolved": "",
            "sv_sat": "",
            "m_filt": "",
            "nms": "",
            "residual": "",
            "triage": 546,
            "boundary": "candidate discovery only",
        },
        {
            "baseline": "Deduplicated source/sink",
            "records": 518,
            "resolved": "",
            "sv_sat": "",
            "m_filt": "",
            "nms": "",
            "residual": "",
            "triage": 518,
            "boundary": "candidate-only duplicate removal",
        },
        {
            "baseline": "Static-only TSDS",
            "records": static["analyzed"],
            "resolved": static["resolved"],
            "sv_sat": static["injectable"],
            "m_filt": static["filtered"],
            "nms": static["no_taint"],
            "residual": static["residual"],
            "triage": static["analyzed"],
            "boundary": "normalizes closures; no sink execution",
        },
        {
            "baseline": "No-summary guided sink hook",
            "records": no_summary["analyzed"],
            "resolved": no_summary["resolved"],
            "sv_sat": no_summary["injectable"],
            "m_filt": no_summary["filtered"],
            "nms": no_summary["no_taint"],
            "residual": no_summary["residual"],
            "triage": no_summary["residual"],
            "boundary": "sink hook without firmware source/string summaries",
        },
        {
            "baseline": "Coarse metacharacter validator",
            "records": no_matrix["analyzed"],
            "resolved": no_matrix["resolved"],
            "sv_sat": no_matrix["injectable"],
            "m_filt": no_matrix["filtered"],
            "nms": no_matrix["no_taint"],
            "residual": no_matrix["residual"],
            "triage": no_matrix["residual"],
            "boundary": "drops vector-specific matrix evidence",
        },
        {
            "baseline": "Direct-only validator",
            "records": direct["analyzed"],
            "resolved": direct["resolved"],
            "sv_sat": direct["injectable"],
            "m_filt": direct["filtered"],
            "nms": direct["no_taint"],
            "residual": direct["residual"],
            "triage": direct["residual"],
            "boundary": "disables guarded static/dynamic recovery",
        },
        {
            "baseline": "No path-control validator",
            "records": no_path["analyzed"],
            "resolved": no_path["resolved"],
            "sv_sat": no_path["injectable"],
            "m_filt": no_path["filtered"],
            "nms": no_path["no_taint"],
            "residual": no_path["residual"],
            "triage": no_path["residual"],
            "boundary": "disables semantic frontier and source-liveness cuts",
        },
        {
            "baseline": "Full TSDS",
            "records": full["analyzed"],
            "resolved": full["resolved"],
            "sv_sat": full["injectable"],
            "m_filt": full["filtered"],
            "nms": full["no_taint"],
            "residual": full["residual"],
            "triage": full["residual"],
            "boundary": "full sink-byte evidence contract",
        },
    ]


def validator_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        r"\begin{tabularx}{\textwidth}{@{}P{0.23\textwidth}rrrrrrY@{}}",
        r"\toprule",
        r"Comparison layer & Rec. & Res. & SV-SAT & M-Filt. & NMS & Open & Evidence boundary\\",
        r"\midrule",
    ]
    for row in rows:
        lines.append(
            f"{esc(row['baseline'])} & {row['records']} & {row['resolved']} & {row['sv_sat']} & "
            f"{row['m_filt']} & {row['nms']} & {row['triage']} & {esc(row['boundary'])}\\\\"
        )
    lines.extend([r"\bottomrule", r"\end{tabularx}", ""])
    return "\n".join(lines)


def canary_rows(canaries: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in canaries.get("positive_canaries") or []:
        rows.append(
            {
                "id": item.get("id", ""),
                "firmware": item.get("firmware", ""),
                "level": item.get("level", "").replace(" runtime consistency", ""),
                "entry": item.get("entry", ""),
                "sink": item.get("sink", ""),
                "callsite": item.get("callsite", ""),
                "token_or_effect": item.get("token", ""),
                "boundary": "sink argument observed; shell skipped",
            }
        )
    rows.append(
        {
            "id": "Boundary probes",
            "firmware": "5 probes",
            "level": "negative/environment-bound",
            "entry": "mixed",
            "sink": "mixed",
            "callsite": "--",
            "token_or_effect": "token absent or sink not hit",
            "boundary": "not counted as runtime-positive",
        }
    )
    return rows


def canary_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        r"\begin{tabularx}{\textwidth}{@{}P{0.16\textwidth}P{0.12\textwidth}P{0.16\textwidth}P{0.20\textwidth}P{0.13\textwidth}Y@{}}",
        r"\toprule",
        r"Canary & Firmware & Level & Entry & Sink & Observation boundary\\",
        r"\midrule",
    ]
    for row in rows:
        lines.append(
            f"{esc(row['id'])} & {esc(row['firmware'])} & {esc(row['level'])} & "
            f"{esc(row['entry'])} & {esc(row['sink'])} & {esc(row['boundary'])}\\\\"
        )
    lines.extend([r"\bottomrule", r"\end{tabularx}", ""])
    return "\n".join(lines)


def path_rows(reviewer: dict[str, Any], ablation: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = by_config(ablation)
    full = rows["full"]
    no_path = rows["no_path_control"]
    audit = reviewer.get("path_control_record_audit", {}).get("global", {})
    return [
        {
            "metric": "same verdict and vector signature",
            "full": f"{audit.get('same_vector_signature')}/518",
            "no_path": f"{audit.get('same_vector_signature')}/518",
            "interpretation": "record-level equivalence for most closures",
        },
        {
            "metric": "SV-SAT records",
            "full": full["injectable"],
            "no_path": no_path["injectable"],
            "interpretation": "two full positives become unreachable without path control",
        },
        {
            "metric": "path-explosion residuals",
            "full": full["residual_classes"].get("path_explosion_residual", ""),
            "no_path": no_path["residual_classes"].get("path_explosion_residual", ""),
            "interpretation": "semantic controls reduce undifferentiated path explosion",
        },
        {
            "metric": "semantic-frontier prunes",
            "full": full["semantic_pruned"],
            "no_path": no_path["semantic_pruned"],
            "interpretation": "full run emits auditable semantic pruning events",
        },
        {
            "metric": "source-liveness cuts",
            "full": full["source_liveness_cuts"],
            "no_path": no_path["source_liveness_cuts"],
            "interpretation": "full run records source-dead frontier decisions",
        },
    ]


def path_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        r"\begin{tabularx}{\textwidth}{@{}P{0.30\textwidth}rrY@{}}",
        r"\toprule",
        r"Path-control audit metric & Full & w/o PC & Interpretation\\",
        r"\midrule",
    ]
    for row in rows:
        lines.append(
            f"{esc(row['metric'])} & {esc(row['full'])} & {esc(row['no_path'])} & {esc(row['interpretation'])}\\\\"
        )
    lines.extend([r"\bottomrule", r"\end{tabularx}", ""])
    return "\n".join(lines)


def guarded_rows(reviewer: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in reviewer.get("evidence_split", {}).get("guarded_examples", []):
        rows.append(
            {
                "target": item.get("target", ""),
                "closure": item.get("closure_idx", ""),
                "sink": item.get("sink", ""),
                "source": item.get("source", ""),
                "preview": item.get("preview", ""),
                "confidence": item.get("confidence", ""),
            }
        )
    return rows


def guarded_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        r"\begin{tabular}{@{}lrrrrl@{}}",
        r"\toprule",
        r"Target & Closure & Sink & Source & Preview & Conf.\\",
        r"\midrule",
    ]
    for row in rows:
        lines.append(
            f"{esc(row['target'])} & {row['closure']} & {esc(row['sink'])} & "
            f"{esc(row['source'])} & {esc(row['preview'])} & {esc(row['confidence'])}\\\\"
        )
    lines.extend([r"\bottomrule", r"\end{tabular}", ""])
    return "\n".join(lines)


def markdown(
    validator: list[dict[str, Any]],
    canary: list[dict[str, Any]],
    path: list[dict[str, Any]],
    guarded: list[dict[str, Any]],
    audit: dict[str, Any],
    canaries: dict[str, Any],
) -> str:
    lines = [
        "# ICECCS strengthening evidence pack",
        "",
        "This package re-summarizes existing TSDS artifacts. It does not add device-confirmed exploit claims.",
        "",
        f"- Manual/evidence audit: {audit.get('sampled_records')} sampled records; verdict boundary: {audit.get('boundary')}.",
        f"- Runtime positives: {canaries.get('positive_count')} across {canaries.get('positive_firmware_count')} firmware images and {canaries.get('positive_vendor_count')} vendors.",
        f"- Boundary probes: {canaries.get('boundary_probe_count')}.",
        "",
        "## Validator baselines",
        "",
        "| Baseline | Rec. | Res. | SV-SAT | M-Filt. | NMS | Open | Boundary |",
        "|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for row in validator:
        lines.append(
            f"| {row['baseline']} | {row['records']} | {row['resolved']} | {row['sv_sat']} | "
            f"{row['m_filt']} | {row['nms']} | {row['triage']} | {row['boundary']} |"
        )
    lines.extend(["", "## Runtime canaries", "", "| Canary | Firmware | Level | Entry | Sink | Boundary |", "|---|---|---|---|---|---|"])
    for row in canary:
        lines.append(
            f"| {row['id']} | {row['firmware']} | {row['level']} | {row['entry']} | {row['sink']} | {row['boundary']} |"
        )
    lines.extend(["", "## Path-control audit", "", "| Metric | Full | w/o PC | Interpretation |", "|---|---:|---:|---|"])
    for row in path:
        lines.append(f"| {row['metric']} | {row['full']} | {row['no_path']} | {row['interpretation']} |")
    lines.extend(["", "## Guarded/static SV-SAT examples", "", "| Target | Closure | Sink | Source | Preview | Confidence |", "|---|---:|---|---|---|---|"])
    for row in guarded:
        lines.append(
            f"| {row['target']} | {row['closure']} | {row['sink']} | {row['source']} | {row['preview']} | {row['confidence']} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ablation", type=Path, default=DEFAULT_ABLATION)
    parser.add_argument("--reviewer", type=Path, default=DEFAULT_REVIEWER)
    parser.add_argument("--canaries", type=Path, default=DEFAULT_CANARIES)
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    ablation = read_json(args.ablation)
    reviewer = read_json(args.reviewer)
    canaries = read_json(args.canaries)
    audit = read_json(args.audit)

    validator = validator_rows(ablation)
    canary = canary_rows(canaries)
    path = path_rows(reviewer, ablation)
    guarded = guarded_rows(reviewer)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.out_dir / "validator_baselines.csv", validator)
    write_csv(args.out_dir / "runtime_canary_details.csv", canary)
    write_csv(args.out_dir / "path_control_audit.csv", path)
    write_csv(args.out_dir / "guarded_static_examples.csv", guarded)
    (args.out_dir / "validator_baselines_table.tex").write_text(validator_table(validator), encoding="utf-8")
    (args.out_dir / "runtime_canary_details_table.tex").write_text(canary_table(canary), encoding="utf-8")
    (args.out_dir / "path_control_audit_table.tex").write_text(path_table(path), encoding="utf-8")
    (args.out_dir / "guarded_static_examples_table.tex").write_text(guarded_table(guarded), encoding="utf-8")
    (args.out_dir / "strengthening_pack.json").write_text(
        json.dumps(
            {
                "validator_baselines": validator,
                "runtime_canary_details": canary,
                "path_control_audit": path,
                "guarded_static_examples": guarded,
                "manual_audit_boundary": audit.get("boundary"),
                "manual_audit_sampled_records": audit.get("sampled_records"),
                "canary_claim_boundary": canaries.get("claim_boundary"),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (args.out_dir / "strengthening_pack.md").write_text(
        markdown(validator, canary, path, guarded, audit, canaries),
        encoding="utf-8",
    )
    print(args.out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
