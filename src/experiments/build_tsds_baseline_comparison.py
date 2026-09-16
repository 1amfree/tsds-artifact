#!/usr/bin/env python3
"""Build baseline-comparison artifacts for the TSDS paper.

The comparison is deliberately scoped to post-discovery validation.  Existing
SOTA firmware analyzers are primarily candidate generators; TSDS is evaluated
as a validation layer over a fixed candidate set.  This script therefore
separates three evidence levels:

1. raw static closures, i.e., the review burden produced by the front end;
2. deduplicated source/sink hypotheses, i.e., a simple candidate-only baseline;
3. TSDS semantic validation, i.e., sink-byte verdicts and residual diagnoses.

The generated tables are intended to be included directly in the paper, while
the JSON/CSV files make the numbers reproducible from campaign artifacts.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


DEFAULT_CAMPAIGN = Path("experiment_reports/full_firmware_campaign_v9_20260625")
DEFAULT_OUT = Path("experiment_reports/baseline_comparison_v9_20260626")
DEFAULT_ABLATION = Path("experiment_reports/r6400_full_ablation_20260622_v3/ablation_records.json")
DEFAULT_REPRO = Path("experiment_reports/poc_candidate_repro_v9_20260626/candidate_repro_summary.json")
DEFAULT_PREFLIGHT = Path("experiment_reports/dynamic_validation_preflight_v9_20260626/dynamic_validation_preflight_summary.json")


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def as_int(value: Any) -> int:
    if value in (None, ""):
        return 0
    return int(float(value))


def as_float(value: Any) -> float:
    if value in (None, ""):
        return 0.0
    return float(value)


def pct(num: int, den: int) -> float:
    return round((100.0 * num / den), 1) if den else 0.0


def fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.1f}"
    return str(value)


def latex_escape(value: Any) -> str:
    text = str(value)
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


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields: List[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def campaign_totals(aggregate: Dict[str, Any], per_target: List[Dict[str, str]]) -> Dict[str, int]:
    total_row = next((row for row in per_target if row.get("target") == "TOTAL"), None)
    if total_row is None:
        total_row = {}
    status_counts = aggregate.get("status_counts_from_jsonl") or {}
    return {
        "raw_closures": as_int(total_row.get("mango_closures") or 0),
        "unique_pairs": as_int(total_row.get("unique_pairs") or total_row.get("records") or 0),
        "records": as_int(total_row.get("records") or 0),
        "vulnerable": as_int(status_counts.get("vulnerable") or total_row.get("vulnerable") or 0),
        "filtered": as_int(status_counts.get("filtered") or total_row.get("filtered") or 0),
        "no_taint": as_int(status_counts.get("no_taint_sink") or total_row.get("no_taint_sink") or 0),
        "unreachable": as_int(status_counts.get("unreachable") or total_row.get("unreachable") or 0),
        "timeout": as_int(status_counts.get("timeout") or total_row.get("timeout") or 0),
        "sat_vectors": as_int(total_row.get("vulnerable_vectors") or 0),
        "unsat_vectors": as_int(total_row.get("secure_vectors") or 0),
    }


def make_layer_rows(totals: Dict[str, int], validation_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = totals["raw_closures"]
    pairs = totals["unique_pairs"]
    records = totals["records"]
    vuln = totals["vulnerable"]
    filtered = totals["filtered"]
    no_taint = totals["no_taint"]
    residual = totals["unreachable"] + totals["timeout"]
    semantic = vuln + filtered + no_taint
    negative = filtered + no_taint
    duplicates = max(0, raw - pairs)
    audit_sample = as_int(
        validation_summary.get("selected_for_audit")
        or validation_summary.get("total_audit_sample")
        or validation_summary.get("audit_sample")
        or 0
    )
    return [
        {
            "Layer": "Raw Mango closures",
            "Input": raw,
            "Review_focus": raw,
            "Resolved_semantic": "N/A",
            "Vulnerable": "N/A",
            "Negative_evidence": "N/A",
            "Residual": "N/A",
            "Vector_evidence": "No",
            "Boundary": "Candidate discovery only",
        },
        {
            "Layer": "Deduplicated source/sink baseline",
            "Input": pairs,
            "Review_focus": pairs,
            "Resolved_semantic": "N/A",
            "Vulnerable": "N/A",
            "Negative_evidence": "N/A",
            "Residual": "N/A",
            "Vector_evidence": "No",
            "Boundary": f"Removes {duplicates} duplicate closures but keeps warning semantics",
        },
        {
            "Layer": "TSDS semantic validation",
            "Input": records,
            "Review_focus": residual,
            "Resolved_semantic": semantic,
            "Vulnerable": vuln,
            "Negative_evidence": negative,
            "Residual": residual,
            "Vector_evidence": f"{totals['sat_vectors']} SAT / {totals['unsat_vectors']} UNSAT",
            "Boundary": "Sink-level evidence; not device exploit proof",
        },
        {
            "Layer": "TSDS audit package",
            "Input": records,
            "Review_focus": audit_sample,
            "Resolved_semantic": semantic,
            "Vulnerable": vuln,
            "Negative_evidence": negative,
            "Residual": residual,
            "Vector_evidence": "Trace JSONL + Markdown",
            "Boundary": "Deterministic audit sample plus full per-record ledger",
        },
    ]


def make_evidence_contract_rows() -> List[Dict[str, Any]]:
    """Compare what each line of work is expected to produce.

    This is intentionally a capability/evidence-boundary matrix, not a
    vulnerability-count leaderboard across incomparable tools.
    """
    return [
        {
            "System": "Mango / closure front end",
            "Input role": "Candidate discovery",
            "Primary artifact": "Static source/sink closures",
            "Sink-byte vectors": "No",
            "Negative evidence": "No",
            "Residual ledger": "No",
            "Missing for TSDS claim": "vector SAT/UNSAT; negative sink evidence; typed residuals",
            "TSDS comparison use": "Fixed candidate set",
        },
        {
            "System": "SaTC / Karonte / LARA / HermeScan",
            "Input role": "Firmware static analysis",
            "Primary artifact": "Warnings, taint, summaries, or inter-binary links",
            "Sink-byte vectors": "Not the primary artifact",
            "Negative evidence": "Limited",
            "Residual ledger": "Limited",
            "Missing for TSDS claim": "vector SAT/UNSAT; negative sink evidence; typed residuals",
            "TSDS comparison use": "Representative SOTA discovery layer",
        },
        {
            "System": "Static-only TSDS mode",
            "Input role": "Ablation baseline",
            "Primary artifact": "Closure normalization and static hints",
            "Sink-byte vectors": "No",
            "Negative evidence": "No",
            "Residual ledger": "Not executed",
            "Missing for TSDS claim": "sink-byte execution; vector SAT/UNSAT; negative sink evidence",
            "TSDS comparison use": "Shows why execution is needed",
        },
        {
            "System": "TSDS full",
            "Input role": "Post-discovery validation",
            "Primary artifact": "Sink-level evidence record",
            "Sink-byte vectors": "SAT/UNSAT matrix",
            "Negative evidence": "Filtered and no-taint sinks",
            "Residual ledger": "Typed path/model/budget diagnoses",
            "Missing for TSDS claim": "none at the sink-level evidence boundary",
            "TSDS comparison use": "Main system",
        },
        {
            "System": "TSDS + canary scaffold",
            "Input role": "Follow-up validation preparation",
            "Primary artifact": "Sink-intercept manifest and fixture",
            "Sink-byte vectors": "Reused from TSDS",
            "Negative evidence": "No shell execution by design",
            "Residual ledger": "Preflight blockers and resource requests",
            "Missing for TSDS claim": "isolated service run requires QEMU and target rootfs",
            "TSDS comparison use": "Analyzer-to-emulation bridge",
        },
    ]


def make_ablation_rows(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    records = load_json(path)
    order = {
        "full": "Full TSDS",
        "no_source_liveness": "No source-liveness",
        "no_memo_cache": "No memo/cache",
        "static_only": "Static-only",
    }
    rows: List[Dict[str, Any]] = []
    for rec in sorted(records, key=lambda item: list(order).index(item.get("config", "static_only")) if item.get("config") in order else 99):
        ledger = rec.get("path_control_ledger") or {}
        totals = ledger.get("totals") or {}
        pressure = ledger.get("budget_pressure") or {}
        residual = as_int(pressure.get("residual_risk"))
        if residual == 0 and rec.get("config") != "static_only":
            residual = as_int(rec.get("unreachable")) + as_int(rec.get("timeout"))
        rows.append(
            {
                "Configuration": order.get(rec.get("config"), rec.get("config")),
                "Analyzed": as_int(rec.get("unique_pairs_analyzed")),
                "NoT": as_int(rec.get("no_taint_sink")),
                "Unr": as_int(rec.get("unreachable")),
                "TO": as_int(rec.get("timeout")),
                "Residual": residual,
                "Pruned": as_int(totals.get("path_control_pruned_states")),
                "SourceCuts": as_int(totals.get("path_control_source_liveness_cuts")),
                "Memoized": as_int(rec.get("memoized_closures")),
                "WallSec": round(as_float(rec.get("elapsed_wall_sec")), 1),
                "AvgSec": round(as_float(rec.get("avg_closure_time_sec")), 2),
            }
        )
    return rows


def make_validation_chain_rows(repro_path: Path, preflight_path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if repro_path.exists():
        repro = load_json(repro_path)
        candidate_count = as_int(repro.get("candidate_count") or repro.get("candidates"))
        passed = as_int(repro.get("pass") or repro.get("passed"))
        failed = as_int(repro.get("drift") or repro.get("semantic_drift")) + as_int(repro.get("run_failed"))
        rows.append(
            {
                "Stage": "Analyzer reproducibility",
                "Artifact": "10-candidate rerun",
                "Completed": f"{passed}/{candidate_count}",
                "Failures": failed,
                "Boundary": "Sink-level signatures only",
            }
        )
    if preflight_path.exists():
        preflight = load_json(preflight_path)
        rows.append(
            {
                "Stage": "Dynamic preflight",
                "Artifact": "First-wave sink-intercept scaffolds",
                "Completed": f"{as_int(preflight.get('ready'))}/{as_int(preflight.get('tasks'))} ready",
                "Failures": as_int(preflight.get("blocked")),
                "Boundary": "No firmware service execution",
            }
        )
    return rows


def make_per_target_rows(per_target: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for row in per_target:
        target = row.get("target") or ""
        if not target or target == "TOTAL":
            continue
        records = as_int(row.get("records"))
        vuln = as_int(row.get("vulnerable"))
        filtered = as_int(row.get("filtered"))
        no_taint = as_int(row.get("no_taint_sink"))
        residual = as_int(row.get("unreachable")) + as_int(row.get("timeout"))
        rows.append(
            {
                "Target": target,
                "Raw": as_int(row.get("mango_closures")),
                "Pair": as_int(row.get("unique_pairs")),
                "Eval": records,
                "Vuln": vuln,
                "Neg": filtered + no_taint,
                "Resid": residual,
                "Resolved_pct": pct(vuln + filtered + no_taint, records),
                "Avg_sec": round(as_float(row.get("avg_closure_time_sec")), 2),
            }
        )
    return rows


def markdown_table(rows: List[Dict[str, Any]]) -> str:
    headers = list(rows[0].keys()) if rows else []
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(fmt(row.get(h, "")) for h in headers) + " |")
    return "\n".join(lines)


def latex_layer_table(rows: List[Dict[str, Any]]) -> str:
    lines = [
        "% Auto-generated by experiments/build_tsds_baseline_comparison.py",
        "\\begin{tabularx}{\\textwidth}{@{}P{0.24\\textwidth}rrrrrY@{}}",
        "\\toprule",
        "Comparison layer & Input & Focus & Res. & Vuln. & Neg. & Evidence boundary\\\\",
        "\\midrule",
    ]
    for row in rows:
        lines.append(
            "{} & {} & {} & {} & {} & {} & {}\\\\".format(
                row["Layer"],
                row["Input"],
                row["Review_focus"],
                row["Resolved_semantic"],
                row["Vulnerable"],
                row["Negative_evidence"],
                row["Boundary"],
            )
        )
    lines.extend(["\\bottomrule", "\\end{tabularx}", ""])
    return "\n".join(lines)


def latex_per_target_table(rows: List[Dict[str, Any]]) -> str:
    lines = [
        "% Auto-generated by experiments/build_tsds_baseline_comparison.py",
        "\\begin{tabular}{@{}lrrrrrrrr@{}}",
        "\\toprule",
        "Target & Raw & Pair & Eval. & Vuln. & Neg. & Resid. & Res.\\% & Avg(s)\\\\",
        "\\midrule",
    ]
    for row in rows:
        lines.append(
            "{} & {} & {} & {} & {} & {} & {} & {:.1f} & {:.2f}\\\\".format(
                row["Target"],
                row["Raw"],
                row["Pair"],
                row["Eval"],
                row["Vuln"],
                row["Neg"],
                row["Resid"],
                float(row["Resolved_pct"]),
                float(row["Avg_sec"]),
            )
        )
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    return "\n".join(lines)


def latex_contract_table(rows: List[Dict[str, Any]]) -> str:
    lines = [
        "% Auto-generated by experiments/build_tsds_baseline_comparison.py",
        "\\begin{tabularx}{\\textwidth}{@{}P{0.22\\textwidth}P{0.23\\textwidth}P{0.20\\textwidth}Y@{}}",
        "\\toprule",
        "Comparison point & Primary artifact & Missing for sink-byte validation & Role in our evaluation\\\\",
        "\\midrule",
    ]
    for row in rows:
        missing = row.get("Missing for TSDS claim") or "none at its evidence boundary"
        lines.append(
            "{} & {} & {} & {}\\\\".format(
                latex_escape(row["System"]),
                latex_escape(row["Primary artifact"]),
                latex_escape(missing),
                latex_escape(row["TSDS comparison use"]),
            )
        )
    lines.extend(["\\bottomrule", "\\end{tabularx}", ""])
    return "\n".join(lines)


def latex_ablation_table(rows: List[Dict[str, Any]]) -> str:
    lines = [
        "% Auto-generated by experiments/build_tsds_baseline_comparison.py",
        "\\begin{tabular}{@{}lrrrrrrrrr@{}}",
        "\\toprule",
        "Configuration & Eval. & NoT & Unr. & TO & Resid. & Pruned & Cuts & Memo & Wall(s)\\\\",
        "\\midrule",
    ]
    for row in rows:
        lines.append(
            "{} & {} & {} & {} & {} & {} & {} & {} & {} & {:.1f}\\\\".format(
                latex_escape(row["Configuration"]),
                row["Analyzed"],
                row["NoT"],
                row["Unr"],
                row["TO"],
                row["Residual"],
                row["Pruned"],
                row["SourceCuts"],
                row["Memoized"],
                float(row["WallSec"]),
            )
        )
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    return "\n".join(lines)


def write_markdown(
    path: Path,
    layer_rows: List[Dict[str, Any]],
    target_rows: List[Dict[str, Any]],
    contract_rows: List[Dict[str, Any]],
    ablation_rows: List[Dict[str, Any]],
    validation_rows: List[Dict[str, Any]],
    totals: Dict[str, int],
) -> None:
    semantic = totals["vulnerable"] + totals["filtered"] + totals["no_taint"]
    negative = totals["filtered"] + totals["no_taint"]
    residual = totals["unreachable"] + totals["timeout"]
    lines = [
        "# TSDS Baseline Comparison Framework",
        "",
        "Generated deterministically from the v9 campaign artifacts.",
        "",
        "## Comparison Layers",
        "",
        markdown_table(layer_rows),
        "",
        "## Evidence Contract Matrix",
        "",
        markdown_table(contract_rows),
        "",
        "## Per-Target Conversion",
        "",
        markdown_table(target_rows),
        "",
        "## Controlled Ablation",
        "",
        markdown_table(ablation_rows),
        "",
        "## Validation Chain",
        "",
        markdown_table(validation_rows),
        "",
        "## Paper Interpretation",
        "",
        f"- Raw Mango candidate burden: `{totals['raw_closures']}` closures.",
        f"- Deduplicated source/sink hypotheses: `{totals['unique_pairs']}` records.",
        f"- TSDS semantic verdicts: `{semantic}` / `{totals['records']}` (`{pct(semantic, totals['records']):.1f}%`).",
        f"- Vulnerability evidence: `{totals['vulnerable']}` records.",
        f"- Negative evidence: `{negative}` records (`{totals['filtered']}` filtered and `{totals['no_taint']}` no-taint).",
        f"- Typed residuals: `{residual}` records.",
        f"- Vector-level evidence: `{totals['sat_vectors']}` SAT shell-vector instances and `{totals['unsat_vectors']}` UNSAT blocked-vector proofs.",
        "",
        "This framework is the fair SOTA-facing comparison unit for TSDS: discovery-oriented tools produce candidate closures, while TSDS measures how many of those candidates can be converted into auditable sink-byte evidence.",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", help="Repository/workspace root")
    parser.add_argument("--campaign-dir", default=str(DEFAULT_CAMPAIGN), help="Directory containing v9 aggregate artifacts")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT), help="Output directory for comparison artifacts")
    parser.add_argument("--ablation-json", default=str(DEFAULT_ABLATION), help="Controlled ablation JSON")
    parser.add_argument("--repro-json", default=str(DEFAULT_REPRO), help="Candidate reproducibility summary JSON")
    parser.add_argument("--preflight-json", default=str(DEFAULT_PREFLIGHT), help="Dynamic validation preflight summary JSON")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    campaign = (root / args.campaign_dir).resolve()
    out_dir = (root / args.out_dir).resolve()
    aggregate = load_json(campaign / "v9_full_campaign_aggregate.json")
    per_target = load_csv(campaign / "v9_full_campaign_per_target.csv")
    validation_path = campaign / "validation_summary.json"
    validation_summary = load_json(validation_path) if validation_path.exists() else {}

    totals = campaign_totals(aggregate, per_target)
    layer_rows = make_layer_rows(totals, validation_summary)
    target_rows = make_per_target_rows(per_target)
    contract_rows = make_evidence_contract_rows()
    ablation_rows = make_ablation_rows(root / args.ablation_json)
    validation_rows = make_validation_chain_rows(root / args.repro_json, root / args.preflight_json)

    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / "baseline_layers.csv", layer_rows)
    write_csv(out_dir / "baseline_per_target.csv", target_rows)
    write_csv(out_dir / "baseline_evidence_contract.csv", contract_rows)
    write_csv(out_dir / "baseline_ablation.csv", ablation_rows)
    write_csv(out_dir / "baseline_validation_chain.csv", validation_rows)
    (out_dir / "baseline_comparison_summary.json").write_text(
        json.dumps(
            {
                "analysis_version": aggregate.get("analysis_version"),
                "campaign_dir": str(campaign),
                "totals": totals,
                "layers": layer_rows,
                "targets": target_rows,
                "evidence_contract": contract_rows,
                "ablation": ablation_rows,
                "validation_chain": validation_rows,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (out_dir / "baseline_layer_table.tex").write_text(latex_layer_table(layer_rows), encoding="utf-8")
    (out_dir / "baseline_per_target_table.tex").write_text(latex_per_target_table(target_rows), encoding="utf-8")
    (out_dir / "baseline_evidence_contract_table.tex").write_text(latex_contract_table(contract_rows), encoding="utf-8")
    (out_dir / "baseline_ablation_table.tex").write_text(latex_ablation_table(ablation_rows), encoding="utf-8")
    write_markdown(out_dir / "baseline_comparison.md", layer_rows, target_rows, contract_rows, ablation_rows, validation_rows, totals)
    print(json.dumps({"out_dir": str(out_dir), "records": totals["records"], "semantic_verdicts": totals["vulnerable"] + totals["filtered"] + totals["no_taint"]}, indent=2))


if __name__ == "__main__":
    main()
