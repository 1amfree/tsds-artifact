#!/usr/bin/env python3
"""Build reproducible Mango-vs-TSDS evidence tables for the paper.

The script intentionally compares TSDS against Mango's raw closure set on the
same candidate universe. It does not claim a full discovery-system benchmark;
instead it quantifies how many raw static command-injection candidates become
sink-byte semantic evidence, non-vulnerable evidence, or auditable residuals.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


TARGETS = [
    {
        "target": "ASUS RT-BE57",
        "arch": "ARM",
        "mango": "ASUS_RT-BE57/result/cmdi_results.json",
        "summary": "experiment_reports/full_campaign_20260622_v1/asus_rt_be57_full.summary.json",
        "jsonl": "experiment_reports/full_campaign_20260622_v1/asus_rt_be57_full.results.jsonl",
    },
    {
        "target": "D-Link DIR-878",
        "arch": "MIPS",
        "mango": "DIR-878/DIR_878_results/cmdi_results.json",
        "summary": "experiment_reports/full_campaign_20260622_v1/dir878_full.summary.json",
        "jsonl": "experiment_reports/full_campaign_20260622_v1/dir878_full.results.jsonl",
    },
    {
        "target": "Tenda AC15",
        "arch": "ARM",
        "mango": "Tenda_AC15/Tenda_AC15_results/cmdi_results.json",
        "summary": "experiment_reports/full_campaign_20260622_v1/tenda_ac15_full.summary.json",
        "jsonl": "experiment_reports/full_campaign_20260622_v1/tenda_ac15_full.results.jsonl",
    },
    {
        "target": "Tenda AC18",
        "arch": "ARM",
        "mango": "Tenda_AC18/results/cmdi_results.json",
        "summary": "Tenda_AC18/reports/ac18_summary_v2.json",
        "jsonl": "Tenda_AC18/reports/ac18_results_v2.jsonl",
    },
    {
        "target": "Tenda W20E",
        "arch": "ARM",
        "mango": "Tenda_W20E/results/cmdi_results.json",
        "summary": "Tenda_W20E/reports/w20e_summary.json",
        "jsonl": "Tenda_W20E/reports/w20e_results.jsonl",
    },
    {
        "target": "Netgear R6400v2",
        "arch": "ARM",
        "mango": "R6400v2/R6400v2_result/cmdi_results.json",
        "summary": "experiment_reports/r6400_reclassified_20260624_v1/r6400v2_full.summary.json",
        "jsonl": "experiment_reports/r6400_reclassified_20260624_v1/r6400v2_full.results.jsonl",
    },
    {
        "target": "Netgear R7000",
        "arch": "ARM",
        "mango": "R7000/R7000_result/cmdi_results.json",
        "summary": "experiment_reports/full_campaign_20260622_v1/r7000_full.summary.json",
        "jsonl": "experiment_reports/full_campaign_20260622_v1/r7000_full.results.jsonl",
    },
    {
        "target": "Netgear XR300",
        "arch": "ARM",
        "mango": "XR300/results/cmdi_results.json",
        "summary": "XR300/reports/xr300_summary.json",
        "jsonl": "XR300/reports/xr300_results.jsonl",
    },
]


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def norm_addr(value: Any) -> str:
    return str(value or "").strip().lower()


def closure_pair(closure: Dict[str, Any]) -> Tuple[str, str]:
    trace = closure.get("trace") or []
    src = ""
    if trace and isinstance(trace[0], dict):
        src = trace[0].get("ins_addr") or trace[0].get("addr") or ""
    sink = (closure.get("sink") or {}).get("ins_addr") or ""
    return norm_addr(src), norm_addr(sink)


def sink_func(closure: Dict[str, Any]) -> str:
    return str((closure.get("sink") or {}).get("function") or "unknown")


def source_func(closure: Dict[str, Any]) -> str:
    trace = closure.get("trace") or []
    if trace and isinstance(trace[0], dict):
        return str(trace[0].get("function") or "unknown")
    return "unknown"


def mango_metrics(path: Path) -> Dict[str, Any]:
    data = load_json(path)
    closures = data.get("closures") or []
    pairs = {closure_pair(c) for c in closures}
    sink_counts = Counter(sink_func(c) for c in closures)
    source_counts = Counter(source_func(c) for c in closures)
    likely_inputs = 0
    possible_inputs = 0
    sanitized = 0
    for closure in closures:
        inputs = closure.get("inputs") or {}
        if inputs.get("likely"):
            likely_inputs += 1
        if inputs.get("possibly"):
            possible_inputs += 1
        if closure.get("sanitized"):
            sanitized += 1
    return {
        "mango_closures": len(closures),
        "mango_unique_pairs": len(pairs),
        "mango_duplicate_closures": max(0, len(closures) - len(pairs)),
        "mango_likely_input_closures": likely_inputs,
        "mango_possible_input_closures": possible_inputs,
        "mango_sanitized_flag_closures": sanitized,
        "top_sink": sink_counts.most_common(1)[0][0] if sink_counts else "",
        "top_sink_count": sink_counts.most_common(1)[0][1] if sink_counts else 0,
        "top_source": source_counts.most_common(1)[0][0] if source_counts else "",
        "top_source_count": source_counts.most_common(1)[0][1] if source_counts else 0,
    }


def result_metrics(summary: Dict[str, Any]) -> Dict[str, Any]:
    results = summary.get("results") or summary
    vulnerable = int(results.get("vulnerable") or 0)
    partial = int(results.get("partial_vulnerable") or results.get("partially_filtered") or 0)
    filtered = int(results.get("filtered") or 0)
    no_taint = int(results.get("no_taint_sink") or 0)
    unreachable = int(results.get("unreachable") or 0)
    timeout = int(results.get("timeout") or 0)
    crashed = int(results.get("crashed") or 0)
    eval_error = int(results.get("eval_error") or 0)
    state_error = int(results.get("state_error") or 0)
    residual = unreachable + timeout + crashed + eval_error + state_error
    semantic = vulnerable + partial + filtered + no_taint
    evaluated_from_outcomes = semantic + residual
    evaluated = max(
        evaluated_from_outcomes,
        int(summary.get("unique_pairs_analyzed") or summary.get("unique_pairs_expected") or 0),
    )
    non_vuln_evidence = filtered + no_taint
    return {
        "tsds_evaluated": evaluated,
        "tsds_vulnerable": vulnerable,
        "tsds_partial": partial,
        "tsds_filtered": filtered,
        "tsds_no_taint": no_taint,
        "tsds_residual": residual,
        "tsds_unreachable": unreachable,
        "tsds_timeout": timeout,
        "tsds_crashed": crashed,
        "tsds_semantic_verdicts": semantic,
        "tsds_non_vulnerable_evidence": non_vuln_evidence,
        "tsds_vulnerable_vectors": int(results.get("vulnerable_vectors") or 0),
        "tsds_secure_vectors": int(results.get("secure_vectors") or 0),
        "tsds_avg_closure_sec": float(summary.get("avg_closure_time_sec") or 0.0),
        "tsds_wall_sec": float(summary.get("wall_time_sec") or 0.0),
        "path_control_classes": json.dumps(
            (summary.get("path_control_ledger") or {}).get("classes") or {},
            sort_keys=True,
        ),
        "residual_plan_strategies": json.dumps(
            (summary.get("residual_recovery_plan_ledger") or {}).get("strategies") or {},
            sort_keys=True,
        ),
    }


def jsonl_metrics(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    confidence = Counter()
    recovery = Counter()
    residual = Counter()
    for record in records:
        if record.get("recovery_confidence"):
            confidence[str(record.get("recovery_confidence"))] += 1
        if record.get("analysis_recovery"):
            recovery[str(record.get("analysis_recovery"))] += 1
        if record.get("residual_diagnosis_class"):
            residual[str(record.get("residual_diagnosis_class"))] += 1
    return {
        "recovery_confidence_counts": json.dumps(dict(sorted(confidence.items())), sort_keys=True),
        "analysis_recovery_counts": json.dumps(dict(sorted(recovery.items())), sort_keys=True),
        "residual_diagnosis_counts": json.dumps(dict(sorted(residual.items())), sort_keys=True),
    }


def pct(num: int, den: int) -> float:
    return round((100.0 * num / den), 1) if den else 0.0


def build_rows(root: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for target in TARGETS:
        mango_path = root / target["mango"]
        summary_path = root / target["summary"]
        if not mango_path.exists():
            raise FileNotFoundError(f"Missing Mango result for {target['target']}: {mango_path}")
        if not summary_path.exists():
            raise FileNotFoundError(f"Missing TSDS summary for {target['target']}: {summary_path}")
        row: Dict[str, Any] = {
            "target": target["target"],
            "arch": target["arch"],
            "mango_path": str(mango_path.relative_to(root)),
            "summary_path": str(summary_path.relative_to(root)),
        }
        row.update(mango_metrics(mango_path))
        summary = load_json(summary_path)
        row.update(result_metrics(summary))
        jsonl_rel = target.get("jsonl")
        if jsonl_rel:
            row.update(jsonl_metrics(load_jsonl(root / jsonl_rel)))
        else:
            row.update(jsonl_metrics([]))
        evaluated = int(row["tsds_evaluated"])
        row["semantic_verdict_rate_pct"] = pct(int(row["tsds_semantic_verdicts"]), evaluated)
        row["non_vuln_evidence_rate_pct"] = pct(int(row["tsds_non_vulnerable_evidence"]), evaluated)
        row["residual_rate_pct"] = pct(int(row["tsds_residual"]), evaluated)
        row["mango_duplicate_rate_pct"] = pct(int(row["mango_duplicate_closures"]), int(row["mango_closures"]))
        rows.append(row)
    return rows


def totals_row(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    fields = [
        "mango_closures",
        "mango_unique_pairs",
        "mango_duplicate_closures",
        "mango_likely_input_closures",
        "mango_possible_input_closures",
        "mango_sanitized_flag_closures",
        "tsds_evaluated",
        "tsds_vulnerable",
        "tsds_partial",
        "tsds_filtered",
        "tsds_no_taint",
        "tsds_residual",
        "tsds_unreachable",
        "tsds_timeout",
        "tsds_crashed",
        "tsds_semantic_verdicts",
        "tsds_non_vulnerable_evidence",
        "tsds_vulnerable_vectors",
        "tsds_secure_vectors",
    ]
    out: Dict[str, Any] = {"target": "Total", "arch": "--"}
    for field in fields:
        out[field] = sum(int(row.get(field) or 0) for row in rows)
    out["semantic_verdict_rate_pct"] = pct(out["tsds_semantic_verdicts"], out["tsds_evaluated"])
    out["non_vuln_evidence_rate_pct"] = pct(out["tsds_non_vulnerable_evidence"], out["tsds_evaluated"])
    out["residual_rate_pct"] = pct(out["tsds_residual"], out["tsds_evaluated"])
    out["mango_duplicate_rate_pct"] = pct(out["mango_duplicate_closures"], out["mango_closures"])
    weighted_time = sum(
        float(row.get("tsds_avg_closure_sec") or 0.0) * int(row.get("tsds_evaluated") or 0)
        for row in rows
    )
    out["tsds_avg_closure_sec"] = round(
        weighted_time / float(out["tsds_evaluated"]),
        2,
    ) if out["tsds_evaluated"] else 0.0
    return out


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row.keys()})
    priority = [
        "target", "arch", "mango_closures", "mango_unique_pairs",
        "mango_duplicate_closures", "mango_duplicate_rate_pct",
        "tsds_evaluated", "tsds_vulnerable", "tsds_partial",
        "tsds_filtered", "tsds_no_taint", "tsds_residual",
        "semantic_verdict_rate_pct", "non_vuln_evidence_rate_pct",
        "residual_rate_pct", "tsds_vulnerable_vectors",
        "tsds_secure_vectors", "tsds_avg_closure_sec",
    ]
    ordered = priority + [name for name in fieldnames if name not in priority]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ordered)
        writer.writeheader()
        writer.writerows(rows)


def markdown_table(rows: List[Dict[str, Any]]) -> str:
    headers = [
        "Target", "Mango closures", "Pairs", "Eval.", "Vuln.", "Non-vuln ev.",
        "Residual", "Verdict %", "SAT vec.", "Avg(s)",
    ]
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append(
            "| {target} | {mango_closures} | {mango_unique_pairs} | {tsds_evaluated} | "
            "{vuln} | {non_vuln} | {residual} | {rate:.1f} | {vec} | {avg:.2f} |".format(
                target=row["target"],
                mango_closures=row.get("mango_closures", ""),
                mango_unique_pairs=row.get("mango_unique_pairs", ""),
                tsds_evaluated=row.get("tsds_evaluated", ""),
                vuln=int(row.get("tsds_vulnerable", 0)) + int(row.get("tsds_partial", 0)),
                non_vuln=row.get("tsds_non_vulnerable_evidence", ""),
                residual=row.get("tsds_residual", ""),
                rate=float(row.get("semantic_verdict_rate_pct") or 0.0),
                vec=row.get("tsds_vulnerable_vectors", ""),
                avg=float(row.get("tsds_avg_closure_sec") or 0.0),
            )
        )
    return "\n".join(lines) + "\n"


def latex_table(rows: List[Dict[str, Any]]) -> str:
    body = []
    for row in rows:
        body.append(
            "{} & {} & {} & {} & {} & {} & {} & {:.1f} & {} & {:.2f}\\\\".format(
                row["target"],
                row.get("mango_closures", ""),
                row.get("mango_unique_pairs", ""),
                row.get("tsds_evaluated", ""),
                int(row.get("tsds_vulnerable", 0)) + int(row.get("tsds_partial", 0)),
                row.get("tsds_non_vulnerable_evidence", ""),
                row.get("tsds_residual", ""),
                float(row.get("semantic_verdict_rate_pct") or 0.0),
                row.get("tsds_vulnerable_vectors", ""),
                float(row.get("tsds_avg_closure_sec") or 0.0),
            )
        )
    return "\n".join([
        "% Auto-generated by experiments/build_mango_tsds_evidence_tables.py",
        "\\begin{tabular}{@{}lrrrrrrrrr@{}}",
        "\\toprule",
        "Target & Mango & Pair & Eval. & Vuln. & Non-vuln & Resid. & Verdict\\% & SAT vec. & Avg(s)\\\\",
        "\\midrule",
        *body,
        "\\bottomrule",
        "\\end{tabular}",
        "",
    ])


def write_markdown_report(path: Path, rows: List[Dict[str, Any]]) -> None:
    total = totals_row(rows)
    rows_with_total = rows + [total]
    lines = [
        "# Mango-to-TSDS Evidence Conversion",
        "",
        "This report is generated from existing Mango `cmdi_results.json` files and TSDS summary/jsonl reports.",
        "It treats Mango closures as the raw static candidate set and measures how TSDS resolves those candidates.",
        "",
        markdown_table(rows_with_total),
        "## Aggregate Interpretation",
        "",
        f"- Mango raw closures: {total['mango_closures']}",
        f"- Unique source/sink pairs: {total['mango_unique_pairs']}",
        f"- TSDS evaluated hypotheses: {total['tsds_evaluated']}",
        f"- Semantic verdicts: {total['tsds_semantic_verdicts']} ({total['semantic_verdict_rate_pct']:.1f}%)",
        f"- Vulnerable or partial: {total['tsds_vulnerable'] + total['tsds_partial']}",
        f"- Non-vulnerable semantic evidence: {total['tsds_non_vulnerable_evidence']} ({total['non_vuln_evidence_rate_pct']:.1f}%)",
        f"- Auditable residuals: {total['tsds_residual']} ({total['residual_rate_pct']:.1f}%)",
        f"- SAT shell-vector instances: {total['tsds_vulnerable_vectors']}",
        f"- Secure vector proofs: {total['tsds_secure_vectors']}",
        "",
        "## Paper-ready Claim",
        "",
        "On a fixed Mango candidate set, TSDS does not compete by finding more raw warnings. "
        "It converts raw closures into sink-byte evidence: vulnerability evidence, "
        "non-vulnerable evidence, or explicit residual diagnoses. This is the fair comparison "
        "unit for a validation system layered after discovery-oriented SOTA tools.",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="/home/ubuntu/work/sanitizer", help="Repository/data root")
    parser.add_argument("--out-dir", default="experiment_reports/mango_tsds_evidence_20260624")
    args = parser.parse_args()

    root = Path(args.root)
    out_dir = root / args.out_dir
    rows = build_rows(root)
    rows_with_total = rows + [totals_row(rows)]
    write_csv(out_dir / "mango_tsds_evidence.csv", rows_with_total)
    write_markdown_report(out_dir / "mango_tsds_evidence.md", rows)
    (out_dir / "mango_tsds_evidence_table.tex").write_text(
        latex_table(rows_with_total),
        encoding="utf-8",
    )
    print(f"Wrote {out_dir / 'mango_tsds_evidence.csv'}")
    print(f"Wrote {out_dir / 'mango_tsds_evidence.md'}")
    print(f"Wrote {out_dir / 'mango_tsds_evidence_table.tex'}")


if __name__ == "__main__":
    main()
