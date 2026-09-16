#!/usr/bin/env python3
"""Build a cross-target TSDS final campaign report.

This script is intentionally evidence-oriented. It does not collapse every
``no_taint_sink`` record into a false-positive claim. Records with strong static
evidence, or weak resource evidence, but no dynamic taint are reported as
actionable taint/model gaps.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

try:
    from advanced_sanitizer_evaluator import (
        evidence_profile_for_record,
        model_gap_requests_for_record,
        residual_diagnosis_for_record,
        residual_recovery_plan_for_record,
    )
except Exception:  # pragma: no cover - allows CSV/report postprocessing without angr.
    evidence_profile_for_record = None
    model_gap_requests_for_record = None
    residual_diagnosis_for_record = None
    residual_recovery_plan_for_record = None


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


UNCLEAR_STATUSES = {"unreachable", "timeout", "crashed", "eval_error", "state_error"}
POSITIVE_STATUSES = {"vulnerable"}


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def enrich_record(record: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(record)
    if evidence_profile_for_record is not None:
        enriched.update(evidence_profile_for_record(enriched))
    if residual_diagnosis_for_record is not None:
        diagnosis = residual_diagnosis_for_record(enriched)
        if diagnosis:
            enriched.update(diagnosis)
    if (
        residual_recovery_plan_for_record is not None
        and enriched.get("residual_diagnosis_class")
    ):
        enriched.update(residual_recovery_plan_for_record(enriched))
    if model_gap_requests_for_record is not None:
        enriched["model_gap_requests"] = model_gap_requests_for_record(enriched)
    return enriched


def norm_addr(value: Any) -> str:
    return str(value or "").strip().lower()


def closure_pair(closure: Dict[str, Any]) -> Tuple[str, str]:
    trace = closure.get("trace") or []
    source = ""
    if trace and isinstance(trace[0], dict):
        source = trace[0].get("ins_addr") or trace[0].get("addr") or ""
    sink = (closure.get("sink") or {}).get("ins_addr") or ""
    return norm_addr(source), norm_addr(sink)


def mango_metrics(path: Path) -> Dict[str, Any]:
    data = load_json(path)
    closures = data.get("closures") or []
    pairs = {closure_pair(closure) for closure in closures}
    likely = sum(1 for closure in closures if (closure.get("inputs") or {}).get("likely"))
    possible = sum(1 for closure in closures if (closure.get("inputs") or {}).get("possibly"))
    sanitized = sum(1 for closure in closures if closure.get("sanitized"))
    return {
        "mango_closures": len(closures),
        "mango_unique_pairs": len(pairs),
        "mango_duplicates": max(0, len(closures) - len(pairs)),
        "mango_likely_input_closures": likely,
        "mango_possible_input_closures": possible,
        "mango_sanitized_flag_closures": sanitized,
    }


def result_count(summary: Dict[str, Any], key: str) -> int:
    return int(((summary.get("results") or summary).get(key)) or 0)


def pct(num: int, den: int) -> float:
    return round((100.0 * num / den), 1) if den else 0.0


def short(value: Any, limit: int = 180) -> str:
    text = str(value or "").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def normalize_strength(record: Dict[str, Any]) -> str:
    strength = str(record.get("static_evidence_strength") or record.get("static_source_strength") or "").lower()
    if strength in {"strong", "weak", "absent"}:
        return strength
    return "unknown"


def no_taint_bucket(record: Dict[str, Any]) -> str:
    if record.get("status") != "no_taint_sink":
        return ""
    diagnosis = str(record.get("residual_diagnosis_class") or "")
    obligation = str(record.get("source_obligation_class") or "")
    strength = normalize_strength(record)
    has_resource_gap = bool(record.get("static_possible_resource_inputs"))
    if diagnosis == "static_overapprox_no_taint" or obligation == "static_overapprox_no_taint":
        return "explained_no_taint"
    if diagnosis == "static_dynamic_taint_disagreement":
        return "model_gap_no_taint"
    if strength == "strong" or (strength == "weak" and has_resource_gap):
        return "model_gap_no_taint"
    if diagnosis == "resolved_source_dead":
        return "explained_no_taint"
    if record.get("evidence_confidence") == "high":
        return "high_confidence_no_taint"
    if record.get("evidence_confidence") == "low":
        return "low_confidence_no_taint"
    return "medium_confidence_no_taint"


def claim_bucket(record: Dict[str, Any]) -> str:
    status = str(record.get("status") or "")
    if status == "no_taint_sink" and no_taint_bucket(record) == "model_gap_no_taint":
        return "model_gap_or_taint_disagreement_residual"
    return str(record.get("paper_claim_bucket") or "")


def collect_record_metrics(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    status_counts = Counter()
    confidence_counts = Counter()
    claim_counts = Counter()
    residual_counts = Counter()
    residual_severity_counts = Counter()
    no_taint_counts = Counter()
    model_gap_kinds = Counter()
    model_gap_keys = Counter()
    static_strength_counts = Counter()
    actionable_records = 0
    for record in records:
        status = str(record.get("status") or "unknown")
        status_counts[status] += 1
        if record.get("evidence_confidence"):
            confidence_counts[str(record.get("evidence_confidence"))] += 1
        bucket = claim_bucket(record)
        if bucket:
            claim_counts[bucket] += 1
        if record.get("residual_diagnosis_class"):
            residual_counts[str(record.get("residual_diagnosis_class"))] += 1
        if record.get("residual_diagnosis_severity"):
            residual_severity_counts[str(record.get("residual_diagnosis_severity"))] += 1
        if status == "no_taint_sink":
            no_taint_counts[no_taint_bucket(record)] += 1
        static_strength_counts[normalize_strength(record)] += 1
        for request in record.get("model_gap_requests") or []:
            model_gap_kinds[str(request.get("kind") or "unknown")] += 1
            model_gap_keys[str(request.get("key") or "")] += 1
        if status in UNCLEAR_STATUSES or no_taint_bucket(record) == "model_gap_no_taint":
            actionable_records += 1

    return {
        "record_status_counts": dict(sorted(status_counts.items())),
        "evidence_confidence_counts": dict(sorted(confidence_counts.items())),
        "claim_bucket_counts": dict(sorted(claim_counts.items())),
        "residual_diagnosis_counts": dict(sorted(residual_counts.items())),
        "residual_severity_counts": dict(sorted(residual_severity_counts.items())),
        "no_taint_breakdown": dict(sorted(no_taint_counts.items())),
        "static_strength_counts": dict(sorted(static_strength_counts.items())),
        "model_gap_kinds": dict(sorted(model_gap_kinds.items(), key=lambda item: (-item[1], item[0]))),
        "top_model_gap_keys": dict(model_gap_keys.most_common(20)),
        "actionable_records": actionable_records,
    }


def target_row(root: Path, target: Dict[str, str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    mango_path = root / target["mango"]
    summary_path = root / target["summary"]
    jsonl_path = root / target["jsonl"]
    if not mango_path.exists():
        raise FileNotFoundError(f"Missing Mango result: {mango_path}")
    if not summary_path.exists():
        raise FileNotFoundError(f"Missing TSDS summary: {summary_path}")
    summary = load_json(summary_path)
    records = [enrich_record(record) for record in load_jsonl(jsonl_path)]
    row: Dict[str, Any] = {
        "target": target["target"],
        "arch": target["arch"],
        "mango_path": target["mango"],
        "summary_path": target["summary"],
        "jsonl_path": target["jsonl"],
    }
    row.update(mango_metrics(mango_path))
    row.update({
        "evaluated": int(summary.get("unique_pairs_analyzed") or summary.get("unique_pairs_expected") or 0),
        "total_closures": int(summary.get("total_closures") or 0),
        "vulnerable": result_count(summary, "vulnerable"),
        "partial_vulnerable": result_count(summary, "partial_vulnerable"),
        "filtered": result_count(summary, "filtered"),
        "no_taint_sink": result_count(summary, "no_taint_sink"),
        "unreachable": result_count(summary, "unreachable"),
        "timeout": result_count(summary, "timeout"),
        "crashed": result_count(summary, "crashed"),
        "eval_error": result_count(summary, "eval_error"),
        "state_error": result_count(summary, "state_error"),
        "vulnerable_vectors": result_count(summary, "vulnerable_vectors"),
        "secure_vectors": result_count(summary, "secure_vectors"),
        "avg_closure_time_sec": round(float(summary.get("avg_closure_time_sec") or 0.0), 4),
        "wall_time_sec": round(float(summary.get("wall_time_sec") or 0.0), 4),
        "records": len(records),
    })
    row["semantic_verdicts"] = (
        row["vulnerable"] + row["partial_vulnerable"] + row["filtered"] + row["no_taint_sink"]
    )
    row["unclear_statuses"] = (
        row["unreachable"] + row["timeout"] + row["crashed"] + row["eval_error"] + row["state_error"]
    )
    record_metrics = collect_record_metrics(records)
    row.update(record_metrics)
    no_taint_breakdown = record_metrics["no_taint_breakdown"]
    row["model_gap_no_taint"] = int(no_taint_breakdown.get("model_gap_no_taint") or 0)
    row["explained_no_taint"] = int(no_taint_breakdown.get("explained_no_taint") or 0)
    row["high_confidence_no_taint"] = int(no_taint_breakdown.get("high_confidence_no_taint") or 0)
    row["actionable_residuals"] = row["unclear_statuses"] + row["model_gap_no_taint"]
    row["resolved_evidence"] = max(0, row["semantic_verdicts"] - row["model_gap_no_taint"])
    row["semantic_verdict_rate_pct"] = pct(row["semantic_verdicts"], row["evaluated"])
    row["resolved_evidence_rate_pct"] = pct(row["resolved_evidence"], row["evaluated"])
    row["actionable_residual_rate_pct"] = pct(row["actionable_residuals"], row["evaluated"])
    return row, records


def totals_row(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    count_fields = [
        "mango_closures", "mango_unique_pairs", "mango_duplicates",
        "mango_likely_input_closures", "mango_possible_input_closures",
        "mango_sanitized_flag_closures", "evaluated", "total_closures",
        "vulnerable", "partial_vulnerable", "filtered", "no_taint_sink",
        "unreachable", "timeout", "crashed", "eval_error", "state_error",
        "vulnerable_vectors", "secure_vectors", "records", "semantic_verdicts",
        "unclear_statuses", "model_gap_no_taint", "explained_no_taint",
        "high_confidence_no_taint", "actionable_residuals", "resolved_evidence",
    ]
    total: Dict[str, Any] = {"target": "Total", "arch": "--"}
    for field in count_fields:
        total[field] = sum(int(row.get(field) or 0) for row in rows)
    total["semantic_verdict_rate_pct"] = pct(total["semantic_verdicts"], total["evaluated"])
    total["resolved_evidence_rate_pct"] = pct(total["resolved_evidence"], total["evaluated"])
    total["actionable_residual_rate_pct"] = pct(total["actionable_residuals"], total["evaluated"])
    weighted = sum(float(row.get("avg_closure_time_sec") or 0.0) * int(row.get("evaluated") or 0) for row in rows)
    total["avg_closure_time_sec"] = round(weighted / total["evaluated"], 4) if total["evaluated"] else 0.0
    for dict_field in [
        "record_status_counts", "evidence_confidence_counts", "claim_bucket_counts",
        "residual_diagnosis_counts", "residual_severity_counts", "no_taint_breakdown",
        "static_strength_counts", "model_gap_kinds",
    ]:
        merged = Counter()
        for row in rows:
            merged.update(row.get(dict_field) or {})
        total[dict_field] = dict(sorted(merged.items(), key=lambda item: (-item[1], item[0])))
    keys = Counter()
    for row in rows:
        keys.update(row.get("top_model_gap_keys") or {})
    total["top_model_gap_keys"] = dict(keys.most_common(30))
    return total


def actionable_trace_rows(target: str, records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for record in records:
        status = str(record.get("status") or "")
        bucket = no_taint_bucket(record)
        if status not in UNCLEAR_STATUSES and bucket != "model_gap_no_taint":
            continue
        requests = record.get("model_gap_requests") or []
        rows.append({
            "target": target,
            "closure": record.get("closure_ordinal") or (
                int(record.get("closure_idx")) + 1 if record.get("closure_idx") is not None else ""
            ),
            "closure_idx": record.get("closure_idx"),
            "status": status,
            "no_taint_bucket": bucket,
            "diagnosis": record.get("residual_diagnosis_class") or "",
            "severity": record.get("residual_diagnosis_severity") or "",
            "confidence": record.get("evidence_confidence") or "",
            "review_priority": record.get("review_priority") or "",
            "static_strength": normalize_strength(record),
            "source": short(record.get("source_function") or record.get("source_addr"), 120),
            "sink": short(record.get("sink_function") or record.get("sink_addr"), 120),
            "trace": short(record.get("trace_summary"), 220),
            "stop_reason": short(
                record.get("engine_stop_reason") or record.get("timeout_kind") or record.get("error"),
                160,
            ),
            "preview": short(
                record.get("sink_preview")
                or record.get("no_taint_preview")
                or record.get("dynamic_no_taint_preview")
                or record.get("error"),
                220,
            ),
            "model_gap_requests": short(
                "; ".join(f"{req.get('kind')}:{req.get('key')}" for req in requests),
                260,
            ),
        })
    rows.sort(key=lambda row: (
        row["target"],
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(str(row["severity"]), 4),
        int(row["closure_idx"] or 0),
    ))
    return rows


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row.keys()})
    priority = [
        "target", "arch", "mango_closures", "mango_unique_pairs", "evaluated",
        "vulnerable", "partial_vulnerable", "filtered", "no_taint_sink",
        "model_gap_no_taint", "unclear_statuses", "actionable_residuals",
        "resolved_evidence", "resolved_evidence_rate_pct",
        "actionable_residual_rate_pct", "vulnerable_vectors", "secure_vectors",
        "avg_closure_time_sec", "summary_path", "jsonl_path",
    ]
    ordered = priority + [name for name in fieldnames if name not in priority]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ordered,
            quoting=csv.QUOTE_ALL,
            escapechar="\\",
            doublequote=True,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def markdown_table(rows: List[Dict[str, Any]]) -> str:
    headers = [
        "Target", "Mango", "Pair", "Eval", "Vuln", "Filt", "NoT",
        "NoT-gap", "Unclear", "Resolved%", "Action%", "Avg(s)",
    ]
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        vuln = int(row.get("vulnerable") or 0) + int(row.get("partial_vulnerable") or 0)
        lines.append(
            "| {target} | {mango} | {pairs} | {evals} | {vuln} | {filt} | {notaint} | "
            "{notgap} | {unclear} | {resolved:.1f} | {action:.1f} | {avg:.2f} |".format(
                target=row["target"],
                mango=row.get("mango_closures", ""),
                pairs=row.get("mango_unique_pairs", ""),
                evals=row.get("evaluated", ""),
                vuln=vuln,
                filt=row.get("filtered", ""),
                notaint=row.get("no_taint_sink", ""),
                notgap=row.get("model_gap_no_taint", ""),
                unclear=row.get("unclear_statuses", ""),
                resolved=float(row.get("resolved_evidence_rate_pct") or 0.0),
                action=float(row.get("actionable_residual_rate_pct") or 0.0),
                avg=float(row.get("avg_closure_time_sec") or 0.0),
            )
        )
    return "\n".join(lines)


def latex_table(rows: List[Dict[str, Any]]) -> str:
    body = []
    for row in rows:
        vuln = int(row.get("vulnerable") or 0) + int(row.get("partial_vulnerable") or 0)
        body.append(
            "{} & {} & {} & {} & {} & {} & {} & {} & {} & {:.1f} & {:.1f} & {:.2f}\\\\".format(
                row["target"],
                row.get("mango_closures", ""),
                row.get("mango_unique_pairs", ""),
                row.get("evaluated", ""),
                vuln,
                row.get("filtered", ""),
                row.get("no_taint_sink", ""),
                row.get("model_gap_no_taint", ""),
                row.get("unclear_statuses", ""),
                float(row.get("resolved_evidence_rate_pct") or 0.0),
                float(row.get("actionable_residual_rate_pct") or 0.0),
                float(row.get("avg_closure_time_sec") or 0.0),
            )
        )
    return "\n".join([
        "% Auto-generated by experiments/build_tsds_final_campaign_report.py",
        "\\begin{tabular}{@{}lrrrrrrrrrrr@{}}",
        "\\toprule",
        "Target & Mango & Pair & Eval. & Vuln. & Filt. & NoT & NoT-gap & Unclear & Resolved\\% & Action\\% & Avg(s)\\\\",
        "\\midrule",
        *body,
        "\\bottomrule",
        "\\end{tabular}",
        "",
    ])


def write_markdown(path: Path, rows: List[Dict[str, Any]], total: Dict[str, Any], trace_rows: List[Dict[str, Any]]) -> None:
    rows_with_total = rows + [total]
    lines = [
        "# TSDS Final Campaign Report",
        "",
        "This report summarizes the current TSDS evidence after the latest weak-resource NoT reclassification.",
        "A `NoT-gap` is a sink-reached/no-dynamic-taint result that still has strong static evidence or weak resource evidence; it is counted as actionable rather than as high-confidence false-positive evidence.",
        "",
        "## Campaign Summary",
        "",
        markdown_table(rows_with_total),
        "",
        "## Aggregate Findings",
        "",
        f"- Mango raw closures: `{total['mango_closures']}` over `{len(rows)}` firmware targets.",
        f"- Unique source/sink pairs: `{total['mango_unique_pairs']}`.",
        f"- TSDS evaluated hypotheses: `{total['evaluated']}`.",
        f"- Vulnerable or partial findings: `{total['vulnerable'] + total['partial_vulnerable']}`.",
        f"- Filtered/sanitized evidence: `{total['filtered']}`.",
        f"- Sink-reached no-taint outcomes: `{total['no_taint_sink']}`, including `{total['model_gap_no_taint']}` actionable NoT model gaps.",
        f"- Unclear operational/reachability statuses: `{total['unclear_statuses']}`.",
        f"- Resolved evidence after NoT-gap separation: `{total['resolved_evidence']}` (`{total['resolved_evidence_rate_pct']:.1f}%`).",
        f"- Actionable residuals after NoT-gap separation: `{total['actionable_residuals']}` (`{total['actionable_residual_rate_pct']:.1f}%`).",
        f"- Vulnerable shell-vector instances: `{total['vulnerable_vectors']}`; secure vector proofs: `{total['secure_vectors']}`.",
        f"- Weighted average closure time: `{total['avg_closure_time_sec']:.2f}s`.",
        "",
        "## Residual Diagnosis Ledger",
        "",
        f"- Residual classes: `{json.dumps(total.get('residual_diagnosis_counts') or {}, sort_keys=True)}`",
        f"- Residual severities: `{json.dumps(total.get('residual_severity_counts') or {}, sort_keys=True)}`",
        f"- No-taint breakdown: `{json.dumps(total.get('no_taint_breakdown') or {}, sort_keys=True)}`",
        f"- Evidence confidence: `{json.dumps(total.get('evidence_confidence_counts') or {}, sort_keys=True)}`",
        f"- Claim buckets: `{json.dumps(total.get('claim_bucket_counts') or {}, sort_keys=True)}`",
        "",
        "## Model-Gap Requests",
        "",
        f"- Request kinds: `{json.dumps(total.get('model_gap_kinds') or {}, sort_keys=True)}`",
        f"- Top request keys: `{json.dumps(total.get('top_model_gap_keys') or {}, sort_keys=True)}`",
        "",
        "## Actionable Trace Sample",
        "",
        "| Target | Closure | Status | Diagnosis | Severity | Static | Request | Trace |",
        "|---|---:|---|---|---|---|---|---|",
    ]
    for row in trace_rows[:80]:
        lines.append(
            "| {target} | {closure} | {status} | {diagnosis} | {severity} | {static} | {request} | {trace} |".format(
                target=row["target"],
                closure=row["closure"],
                status=row["status"],
                diagnosis=short(row["diagnosis"], 60),
                severity=row["severity"],
                static=row["static_strength"],
                request=short(row["model_gap_requests"], 90),
                trace=short(row["trace"], 110),
            )
        )
    if len(trace_rows) > 80:
        lines.append(f"| ... | ... | ... | ... | ... | ... | ... | Showing 80 of {len(trace_rows)} actionable traces |")
    lines.extend([
        "",
        "## Interpretation",
        "",
        "The current TSDS result should be presented as an evidence-validation system: it turns raw Mango closures into vulnerable evidence, filtered evidence, high-confidence no-taint evidence, or auditable residuals. The latest change makes this claim more conservative by separating NoT model gaps from resolved false-positive reductions.",
        "",
    ])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="/home/ubuntu/work/sanitizer")
    parser.add_argument("--out-dir", default="experiment_reports/final_campaign_20260624_v1")
    args = parser.parse_args()

    root = Path(args.root)
    out_dir = root / args.out_dir
    rows: List[Dict[str, Any]] = []
    traces: List[Dict[str, Any]] = []
    for target in TARGETS:
        row, records = target_row(root, target)
        rows.append(row)
        traces.extend(actionable_trace_rows(row["target"], records))
    total = totals_row(rows)
    rows_with_total = rows + [total]
    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / "tsds_final_campaign_per_target.csv", rows_with_total)
    write_csv(out_dir / "tsds_final_campaign_actionable_traces.csv", traces)
    (out_dir / "tsds_final_campaign_summary.json").write_text(
        json.dumps({"targets": rows, "total": total, "actionable_trace_count": len(traces)}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (out_dir / "tsds_final_campaign_table.tex").write_text(latex_table(rows_with_total), encoding="utf-8")
    write_markdown(out_dir / "tsds_final_campaign_report.md", rows, total, traces)
    print(json.dumps({
        "out_dir": str(out_dir),
        "targets": len(rows),
        "evaluated": total["evaluated"],
        "resolved_evidence": total["resolved_evidence"],
        "actionable_residuals": total["actionable_residuals"],
        "model_gap_no_taint": total["model_gap_no_taint"],
        "unclear_statuses": total["unclear_statuses"],
        "avg_closure_time_sec": total["avg_closure_time_sec"],
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
