#!/usr/bin/env python3
"""Build a trace-level validation evidence package from TSDS JSONL records.

The paper needs more than aggregate counts. This script creates deterministic
audit artifacts that map each claim stratum to concrete traces, evidence fields,
and residual obligations. It does not assign external ground truth; it packages
the evidence that TSDS already emits so reviewers can inspect how each campaign
number was obtained.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence


TARGET_NAMES = {
    "asus_rt_be57": ("ASUS RT-BE57", "ARM"),
    "dir878": ("D-Link DIR-878", "MIPS"),
    "r6400v2": ("Netgear R6400v2", "ARM"),
    "r7000": ("Netgear R7000", "ARM"),
    "tenda_ac15": ("Tenda AC15", "ARM"),
    "tenda_ac18": ("Tenda AC18", "ARM"),
    "tenda_w20e": ("Tenda W20E", "ARM"),
    "xr300": ("Netgear XR300", "ARM"),
}

RECOVERY_VULN = {
    "static_direct_source_fallback",
    "static_dynamic_taint_reconciliation",
    "static_sink_template_fallback",
}

ALL_SELECTED_STRATA = {
    "partial_filter_profile",
    "fully_filtered_negative",
    "recovery_backed_vulnerability",
}

PER_TARGET_LIMITS = {
    "direct_vulnerability": 3,
    "fixed_template_no_taint": 3,
    "other_no_taint_explanation": 2,
    "residual_path_explosion": 2,
    "residual_model_gap": 2,
    "residual_time_budget": 2,
    "residual_weak_or_other": 2,
}


@dataclass
class LoadedRecord:
    target_key: str
    target_name: str
    arch: str
    jsonl_file: str
    record: Dict[str, Any]


def load_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def load_records(input_dir: Path) -> List[LoadedRecord]:
    records: List[LoadedRecord] = []
    for path in sorted(input_dir.glob("*.results.jsonl")):
        target_key = path.name.replace(".results.jsonl", "")
        target_name, arch = TARGET_NAMES.get(target_key, (target_key, "unknown"))
        for record in load_jsonl(path):
            records.append(
                LoadedRecord(
                    target_key=target_key,
                    target_name=target_name,
                    arch=arch,
                    jsonl_file=path.name,
                    record=record,
                )
            )
    return records


def short(value: Any, limit: int = 180) -> str:
    if value is None:
        return ""
    text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def join_values(values: Any, limit: int = 8) -> str:
    if not values:
        return ""
    if isinstance(values, dict):
        values = list(values.keys())
    if not isinstance(values, list):
        return str(values)
    rendered = [str(v) for v in values[:limit]]
    if len(values) > limit:
        rendered.append(f"...(+{len(values) - limit})")
    return "; ".join(rendered)


def model_gap_keys(record: Dict[str, Any], limit: int = 6) -> str:
    keys = []
    for request in record.get("model_gap_requests") or []:
        key = request.get("key") or request.get("evidence") or request.get("kind")
        if key and key not in keys:
            keys.append(str(key))
    return join_values(keys, limit)


def stratum(record: Dict[str, Any]) -> str:
    status = str(record.get("status") or "unknown")
    recovery = record.get("analysis_recovery")
    residual_class = str(record.get("residual_diagnosis_class") or "")
    if status == "vulnerable" and record.get("partially_filtered"):
        return "partial_filter_profile"
    if status == "vulnerable" and recovery in RECOVERY_VULN:
        return "recovery_backed_vulnerability"
    if status == "vulnerable":
        return "direct_vulnerability"
    if status == "filtered":
        return "fully_filtered_negative"
    if status == "no_taint_sink" and recovery == "binary_static_fixed_command_template":
        return "fixed_template_no_taint"
    if status == "no_taint_sink":
        return "other_no_taint_explanation"
    if status in {"unreachable", "timeout"}:
        if residual_class == "path_explosion_residual":
            return "residual_path_explosion"
        if residual_class == "model_gap_reachability":
            return "residual_model_gap"
        if residual_class == "time_budget_exhaustion":
            return "residual_time_budget"
        return "residual_weak_or_other"
    return "other"


def score(item: LoadedRecord) -> tuple:
    record = item.record
    priority_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    confidence_rank = {"high": 3, "medium": 2, "low": 1}
    return (
        priority_rank.get(str(record.get("review_priority")), 0),
        confidence_rank.get(str(record.get("evidence_confidence")), 0),
        int(bool(record.get("analysis_recovery"))),
        int(record.get("vulnerable_vectors") or 0),
        int(record.get("secure_vectors") or 0),
        int(bool(record.get("model_gap_requests"))),
        int(record.get("path_control_pruned_states") or record.get("engine_pruned_states") or 0),
        -int(record.get("closure_idx") or 0),
    )


def select_records(records: Sequence[LoadedRecord]) -> List[LoadedRecord]:
    buckets: Dict[str, List[LoadedRecord]] = defaultdict(list)
    for item in records:
        buckets[stratum(item.record)].append(item)

    selected: List[LoadedRecord] = []
    for name, items in sorted(buckets.items()):
        ranked = sorted(items, key=score, reverse=True)
        if name in ALL_SELECTED_STRATA:
            selected.extend(ranked)
            continue
        limit = PER_TARGET_LIMITS.get(name)
        if limit is None:
            selected.extend(ranked[: min(8, len(ranked))])
            continue
        per_target: Dict[str, int] = defaultdict(int)
        for item in ranked:
            if per_target[item.target_key] >= limit:
                continue
            selected.append(item)
            per_target[item.target_key] += 1

    selected.sort(
        key=lambda item: (
            stratum(item.record),
            item.target_name,
            int(item.record.get("closure_idx") or 0),
        )
    )
    return selected


def why_selected(item: LoadedRecord) -> str:
    record = item.record
    name = stratum(record)
    if name == "direct_vulnerability":
        return "high-priority direct sink-byte SAT evidence with concrete bypass vectors"
    if name == "partial_filter_profile":
        return "mixed SAT/UNSAT sanitizer profile; tests vector-level sanitizer semantics"
    if name == "fully_filtered_negative":
        return "all modeled shell vectors are UNSAT while source bytes reach the sink"
    if name == "recovery_backed_vulnerability":
        return "vulnerability depends on guarded static/dynamic source recovery"
    if name == "fixed_template_no_taint":
        return "static closure reaches a concrete command template with no source slot"
    if name == "other_no_taint_explanation":
        return "no-taint explanation not covered by fixed-template recovery"
    if name.startswith("residual_"):
        return "typed residual with path-control and model-gap obligations"
    return "representative trace-level evidence"


def audit_questions(item: LoadedRecord) -> str:
    name = stratum(item.record)
    if name in {"direct_vulnerability", "partial_filter_profile"}:
        return "confirm sink address; inspect tainted offsets; replay SAT/UNSAT vector classes"
    if name == "fully_filtered_negative":
        return "confirm source bytes at sink; inspect all-vector UNSAT evidence"
    if name == "recovery_backed_vulnerability":
        return "confirm static source marker/template; verify guarded recovery label"
    if "no_taint" in name:
        return "confirm reached command preview; inspect absence of source slot"
    if name.startswith("residual_"):
        return "confirm stop reason; inspect residual diagnosis and requested environment/model facts"
    return "inspect trace report and JSONL fields"


def static_inputs(record: Dict[str, Any]) -> str:
    evidence = record.get("static_evidence") or {}
    values: List[str] = []
    for key in (
        "static_likely_inputs",
        "static_possible_inputs",
        "static_source_markers",
        "static_possible_source_markers",
    ):
        for value in evidence.get(key) or record.get(key) or []:
            if value not in values:
                values.append(value)
    return join_values(values)


def csv_row(item: LoadedRecord, selected: bool) -> Dict[str, Any]:
    record = item.record
    minimal = record.get("minimal_bypass_vector") or {}
    preview = record.get("sink_preview") or record.get("no_taint_preview")
    return {
        "stratum": stratum(record),
        "selected_for_audit": int(selected),
        "target": item.target_name,
        "arch": item.arch,
        "jsonl_file": item.jsonl_file,
        "closure_idx": record.get("closure_idx"),
        "closure_ordinal": record.get("closure_ordinal"),
        "status": record.get("status"),
        "paper_claim_bucket": record.get("paper_claim_bucket"),
        "review_priority": record.get("review_priority"),
        "evidence_confidence": record.get("evidence_confidence"),
        "analysis_recovery": record.get("analysis_recovery") or "",
        "sink_function": record.get("sink_function") or "",
        "sink_addr": record.get("sink_addr") or "",
        "source_expr": short(record.get("source_expr"), 140),
        "trace_summary": short(record.get("trace_summary"), 140),
        "sink_or_no_taint_preview": short(preview, 220),
        "tainted_byte_count": record.get("tainted_byte_count") or "",
        "tainted_offsets": join_values(record.get("tainted_offsets"), 12),
        "vulnerable_vectors": record.get("vulnerable_vectors") or "",
        "secure_vectors": record.get("secure_vectors") or "",
        "minimal_bypass_category": minimal.get("category") or "",
        "minimal_bypass_vector": minimal.get("vector") or "",
        "blocked_vector_categories": join_values(record.get("blocked_vector_categories")),
        "bypass_vector_categories": join_values(record.get("bypass_vector_categories")),
        "sanitizer_gap_summary": record.get("sanitizer_gap_summary") or "",
        "static_evidence_strength": record.get("static_evidence_strength") or "",
        "static_inputs_or_markers": static_inputs(record),
        "source_obligation_class": record.get("source_obligation_class") or "",
        "source_obligation_summary": record.get("source_obligation_summary") or "",
        "residual_diagnosis_class": record.get("residual_diagnosis_class") or "",
        "residual_diagnosis_summary": record.get("residual_diagnosis_summary") or "",
        "residual_plan_strategy": record.get("residual_plan_strategy") or "",
        "residual_next_actions": join_values(record.get("residual_next_actions")),
        "model_gap_keys": model_gap_keys(record),
        "engine_stop_reason": record.get("engine_stop_reason") or "",
        "path_control_class": record.get("path_control_class") or "",
        "path_control_audit": short(record.get("path_control_audit"), 220),
        "why_selected": why_selected(item) if selected else "",
        "audit_questions": audit_questions(item) if selected else "",
    }


def write_csv(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def consistency_audit(records: Sequence[LoadedRecord]) -> Dict[str, Any]:
    issues: Counter[str] = Counter()
    examples: Dict[str, List[str]] = defaultdict(list)

    def add(issue: str, item: LoadedRecord) -> None:
        issues[issue] += 1
        if len(examples[issue]) < 5:
            examples[issue].append(f"{item.target_key}#{item.record.get('closure_idx')}")

    for item in records:
        record = item.record
        status = record.get("status")
        recovery = record.get("analysis_recovery")
        if status == "vulnerable":
            if not (record.get("vulnerable_vectors") or 0):
                add("vulnerable_without_sat_vector", item)
            if not record.get("minimal_bypass_vector"):
                add("vulnerable_without_minimal_bypass", item)
            if not (record.get("tainted_byte_count") or 0) and recovery not in RECOVERY_VULN:
                add("direct_vulnerable_without_tainted_bytes", item)
        elif status == "filtered":
            if record.get("vulnerable_vectors") not in {0, None}:
                add("filtered_with_sat_vector", item)
            if not (record.get("secure_vectors") or 0):
                add("filtered_without_secure_vector", item)
            if record.get("sanitizer_gap_strength") != "fully_filtered":
                add("filtered_without_fully_filtered_label", item)
        elif status == "no_taint_sink":
            if record.get("tainted_byte_count"):
                add("no_taint_with_tainted_bytes", item)
            if record.get("vulnerable_vectors"):
                add("no_taint_with_sat_vector", item)
            if not (record.get("source_obligation_class") or record.get("residual_diagnosis_class")):
                add("no_taint_without_explanation", item)
        elif status in {"unreachable", "timeout"}:
            if not record.get("residual_diagnosis_class"):
                add("residual_without_diagnosis", item)
            if not record.get("residual_plan_strategy"):
                add("residual_without_plan", item)
            if not record.get("engine_stop_reason"):
                add("residual_without_stop_reason", item)

    return {
        "issue_counts": dict(sorted(issues.items())),
        "examples": dict(sorted(examples.items())),
        "passed": not issues,
    }


def stratum_description(name: str) -> str:
    return {
        "direct_vulnerability": "Dynamic sink-byte taint reaches a command sink and at least one shell-vector query is SAT.",
        "partial_filter_profile": "A reached sink has both blocked and bypassable shell-vector classes.",
        "fully_filtered_negative": "Source bytes reach the sink, but every modeled shell-vector query is UNSAT.",
        "recovery_backed_vulnerability": "A vulnerability is recovered through guarded static/dynamic template or source reconciliation.",
        "fixed_template_no_taint": "The sink is reached with a fixed command template that has no source slot.",
        "other_no_taint_explanation": "The sink is reached without taint, but the explanation is not the fixed-template fast path.",
        "residual_path_explosion": "The closure remains unresolved under path explosion; path-control evidence and model-gap requests are retained.",
        "residual_model_gap": "The closure likely needs additional firmware environment or API semantics.",
        "residual_time_budget": "The configured execution budget is exhausted before a semantic verdict.",
        "residual_weak_or_other": "Other residuals, usually weak static candidates or source-dead paths.",
        "other": "Records outside the main paper strata.",
    }.get(name, "Trace-level evidence stratum.")


def build_summary(records: Sequence[LoadedRecord], selected: Sequence[LoadedRecord]) -> Dict[str, Any]:
    population = Counter(stratum(item.record) for item in records)
    selected_counts = Counter(stratum(item.record) for item in selected)
    status_counts = Counter(str(item.record.get("status")) for item in records)
    claim_counts = Counter(str(item.record.get("paper_claim_bucket")) for item in records)
    recovery_counts = Counter(str(item.record.get("analysis_recovery")) for item in records)
    residual_counts = Counter(str(item.record.get("residual_diagnosis_class")) for item in records)
    strata = []
    for name in sorted(population):
        strata.append(
            {
                "stratum": name,
                "population": population[name],
                "selected": selected_counts.get(name, 0),
                "description": stratum_description(name),
            }
        )
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "records": len(records),
        "selected_for_audit": len(selected),
        "strata": strata,
        "status_counts": dict(sorted(status_counts.items())),
        "paper_claim_bucket_counts": dict(sorted(claim_counts.items())),
        "analysis_recovery_counts": dict(sorted(recovery_counts.items())),
        "residual_diagnosis_class_counts": dict(sorted(residual_counts.items())),
        "consistency_audit": consistency_audit(records),
    }


def pick_case_studies(selected: Sequence[LoadedRecord]) -> List[LoadedRecord]:
    preferences = [
        ("partial_filter_profile", "dir878"),
        ("partial_filter_profile", "xr300"),
        ("recovery_backed_vulnerability", "tenda_ac15"),
        ("recovery_backed_vulnerability", "tenda_ac18"),
        ("fixed_template_no_taint", "r6400v2"),
        ("fixed_template_no_taint", "r7000"),
        ("residual_path_explosion", "xr300"),
        ("residual_model_gap", "dir878"),
    ]
    picked: List[LoadedRecord] = []
    seen = set()
    for stratum_name, target in preferences:
        candidates = [
            item
            for item in selected
            if stratum(item.record) == stratum_name and item.target_key == target
        ]
        if not candidates:
            continue
        item = sorted(candidates, key=score, reverse=True)[0]
        key = (item.target_key, item.record.get("closure_idx"))
        if key not in seen:
            picked.append(item)
            seen.add(key)
    return picked


def write_markdown(path: Path, summary: Dict[str, Any], selected: Sequence[LoadedRecord]) -> None:
    lines = [
        "# TSDS v9 Validation Evidence Package",
        "",
        f"Generated at: `{summary['generated_at']}`",
        "",
        f"Records parsed: **{summary['records']}**. Records selected for trace-level audit: **{summary['selected_for_audit']}**.",
        "",
        "## Validation Strata",
        "",
        "| Stratum | Population | Selected | Validation purpose |",
        "|---|---:|---:|---|",
    ]
    for row in summary["strata"]:
        lines.append(
            f"| `{row['stratum']}` | {row['population']} | {row['selected']} | {row['description']} |"
        )

    audit = summary["consistency_audit"]
    lines.extend(["", "## Automated Consistency Audit", ""])
    if audit["passed"]:
        lines.append("All records passed the internal consistency checks used by this package.")
    else:
        lines.extend(["| Issue | Count | Examples |", "|---|---:|---|"])
        for issue, count in audit["issue_counts"].items():
            examples = "; ".join(audit["examples"].get(issue, []))
            lines.append(f"| `{issue}` | {count} | {examples} |")

    lines.extend(["", "## Case-Study Candidates", ""])
    for item in pick_case_studies(selected):
        record = item.record
        minimal = record.get("minimal_bypass_vector") or {}
        preview = record.get("sink_preview") or record.get("no_taint_preview")
        lines.extend(
            [
                f"### {item.target_name} closure {record.get('closure_idx')} ({stratum(record)})",
                "",
                f"- Status: `{record.get('status')}`; claim bucket: `{record.get('paper_claim_bucket')}`; confidence: `{record.get('evidence_confidence')}`.",
                f"- Trace: `{short(record.get('trace_summary'), 220)}`; sink: `{record.get('sink_function')}` at `{record.get('sink_addr')}`.",
                f"- Preview: `{short(preview, 260)}`.",
                f"- Vectors: SAT `{record.get('vulnerable_vectors') or 0}`, UNSAT `{record.get('secure_vectors') or 0}`; minimal bypass: `{minimal.get('vector') or ''}` ({minimal.get('category') or ''}).",
                f"- Recovery/residual: `{record.get('analysis_recovery') or record.get('residual_diagnosis_class') or ''}`.",
                f"- Audit question: {audit_questions(item)}.",
                "",
            ]
        )

    lines.extend(
        [
            "## How to Use This Package",
            "",
            "The CSV contains one row per analyzed record and marks the deterministic audit sample with `selected_for_audit=1`. A reviewer can start from the case-study candidates, then inspect every selected filtered, partially filtered, and recovery-backed record. The JSONL files remain the canonical source for full vector details and path-control ledgers.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_case_studies(path: Path, selected: Sequence[LoadedRecord]) -> None:
    lines = ["# TSDS v9 Case-Study Candidate Details", ""]
    for item in pick_case_studies(selected):
        record = item.record
        lines.extend(
            [
                f"## {item.target_name} closure {record.get('closure_idx')}",
                "",
                f"- Stratum: `{stratum(record)}`",
                f"- JSONL file: `{item.jsonl_file}`",
                f"- Status: `{record.get('status')}`",
                f"- Paper claim bucket: `{record.get('paper_claim_bucket')}`",
                f"- Sink: `{record.get('sink_function')}` at `{record.get('sink_addr')}`",
                f"- Source: `{short(record.get('source_expr'), 300)}`",
                f"- Trace: `{short(record.get('trace_summary'), 300)}`",
                f"- Sink/no-taint preview: `{short(record.get('sink_preview') or record.get('no_taint_preview'), 360)}`",
                f"- Tainted bytes: `{record.get('tainted_byte_count') or 0}`; offsets: `{join_values(record.get('tainted_offsets'), 20)}`",
                f"- Vulnerable vectors: `{record.get('vulnerable_vectors') or 0}`; secure vectors: `{record.get('secure_vectors') or 0}`",
                f"- Minimal bypass: `{short(record.get('minimal_bypass_vector'), 360)}`",
                f"- Blocked categories: `{join_values(record.get('blocked_vector_categories'))}`",
                f"- Bypass categories: `{join_values(record.get('bypass_vector_categories'))}`",
                f"- Sanitizer summary: `{record.get('sanitizer_gap_summary') or ''}`",
                f"- Static evidence strength: `{record.get('static_evidence_strength') or ''}`; inputs/markers: `{static_inputs(record)}`",
                f"- Source obligation: `{record.get('source_obligation_summary') or ''}`",
                f"- Residual diagnosis: `{record.get('residual_diagnosis_summary') or ''}`",
                f"- Residual plan: `{record.get('residual_plan_strategy') or ''}`; next actions: `{join_values(record.get('residual_next_actions'))}`",
                f"- Model-gap keys: `{model_gap_keys(record)}`",
                f"- Path-control audit: `{short(record.get('path_control_audit'), 360)}`",
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input-dir",
        default="experiment_reports/full_firmware_campaign_v9_20260625",
        help="Directory containing *.results.jsonl files.",
    )
    parser.add_argument(
        "--out-dir",
        default="experiment_reports/full_firmware_campaign_v9_20260625",
        help="Directory for validation evidence artifacts.",
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    out_dir = Path(args.out_dir)
    records = load_records(input_dir)
    selected = select_records(records)
    selected_keys = {
        (item.target_key, item.record.get("closure_idx"), item.record.get("sink_addr"))
        for item in selected
    }

    rows = [
        csv_row(
            item,
            (item.target_key, item.record.get("closure_idx"), item.record.get("sink_addr"))
            in selected_keys,
        )
        for item in records
    ]
    rows.sort(
        key=lambda row: (
            row["stratum"],
            0 if row["selected_for_audit"] else 1,
            row["target"],
            int(row["closure_idx"] or 0),
        )
    )

    summary = build_summary(records, selected)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / "validation_sampling_plan.csv", rows)
    write_markdown(out_dir / "validation_sampling_plan.md", summary, selected)
    write_case_studies(out_dir / "validation_case_study_candidates.md", selected)
    (out_dir / "validation_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
