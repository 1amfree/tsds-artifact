#!/usr/bin/env python3
"""Build a deterministic manual-audit sample from TSDS JSONL records."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


TARGETS = [
    ("ASUS RT-BE57", "experiment_reports/full_campaign_20260622_v1/asus_rt_be57_full.results.jsonl"),
    ("D-Link DIR-878", "experiment_reports/full_campaign_20260622_v1/dir878_full.results.jsonl"),
    ("Tenda AC15", "experiment_reports/full_campaign_20260622_v1/tenda_ac15_full.results.jsonl"),
    ("Tenda AC18", "Tenda_AC18/reports/ac18_results_v2.jsonl"),
    ("Tenda W20E", "Tenda_W20E/reports/w20e_results.jsonl"),
    ("Netgear R6400v2", "experiment_reports/r6400_full_ablation_20260622_v3/r6400v2_full.results.jsonl"),
    ("Netgear R7000", "experiment_reports/full_campaign_20260622_v1/r7000_full.results.jsonl"),
    ("Netgear XR300", "XR300/reports/xr300_results.jsonl"),
]


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def category(record: Dict[str, Any]) -> str:
    status = str(record.get("status") or "unknown")
    if status == "vulnerable" and record.get("partially_filtered"):
        return "partial"
    if status in {"unreachable", "timeout", "crashed", "eval_error", "state_error"}:
        return "residual"
    return status


def evidence_score(record: Dict[str, Any]) -> tuple:
    """Rank records for auditing by evidence richness and novelty."""
    return (
        int(bool(record.get("analysis_recovery"))),
        int(record.get("vulnerable_vectors") or 0),
        int(record.get("secure_vectors") or 0),
        int(bool(record.get("residual_plan_strategy"))),
        int(record.get("path_control_pruned_states") or 0),
        -int(record.get("closure_idx") or 0),
    )


def short(value: Any, limit: int = 180) -> str:
    text = str(value or "").replace("\n", "\\n").replace("\r", "")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def collect(root: Path, per_category: int) -> List[Dict[str, Any]]:
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for target, rel in TARGETS:
        path = root / rel
        if not path.exists():
            continue
        for record in load_jsonl(path):
            record = dict(record)
            record["target"] = target
            record["jsonl_path"] = rel
            buckets.setdefault(category(record), []).append(record)

    selected: List[Dict[str, Any]] = []
    for cat in ["vulnerable", "partial", "filtered", "no_taint_sink", "residual"]:
        records = sorted(buckets.get(cat, []), key=evidence_score, reverse=True)
        selected.extend(records[:per_category])
    selected.sort(key=lambda r: (category(r), r.get("target", ""), int(r.get("closure_idx") or 0)))
    return selected


def to_audit_row(record: Dict[str, Any]) -> Dict[str, Any]:
    minimal = record.get("minimal_bypass_vector") or {}
    return {
        "target": record.get("target"),
        "closure_idx": record.get("closure_idx"),
        "category": category(record),
        "status": record.get("status"),
        "source_kinds": ",".join(record.get("source_kinds") or []),
        "sink_preview": short(record.get("sink_preview") or record.get("no_taint_preview") or record.get("memo_evidence_preview"), 220),
        "minimal_vector": minimal.get("vector") or "",
        "minimal_vector_category": minimal.get("category") or "",
        "vulnerable_vectors": record.get("vulnerable_vectors") or 0,
        "secure_vectors": record.get("secure_vectors") or 0,
        "sanitizer_gap_strength": record.get("sanitizer_gap_strength") or "",
        "path_control_class": record.get("path_control_class") or "",
        "engine_stop_reason": record.get("engine_stop_reason") or "",
        "residual_diagnosis": record.get("residual_diagnosis_class") or "",
        "residual_strategy": record.get("residual_plan_strategy") or "",
        "recovery": record.get("analysis_recovery") or "",
        "recovery_confidence": record.get("recovery_confidence") or "",
        "static_evidence_strength": record.get("static_evidence_strength") or record.get("static_source_strength") or "",
        "jsonl_path": record.get("jsonl_path"),
        "audit_check_sink_template": "",
        "audit_check_source_binding": "",
        "audit_check_vector_semantics": "",
        "audit_verdict": "",
        "audit_notes": "",
    }


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, rows: List[Dict[str, Any]]) -> None:
    lines = [
        "# Manual Audit Set",
        "",
        "This deterministic sample is intended for a paper validation appendix. Fill the blank audit columns after inspecting the JSONL record, Markdown trace report, and binary context when needed.",
        "",
        "| Target | Closure | Category | Status | Evidence focus | Audit checks |",
        "|---|---:|---|---|---|---|",
    ]
    for row in rows:
        focus = row["sink_preview"] or row["residual_diagnosis"] or row["path_control_class"]
        checks = "sink template; source binding; vector semantics; final verdict"
        lines.append(
            f"| {row['target']} | {row['closure_idx']} | {row['category']} | {row['status']} | {short(focus, 120)} | {checks} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="/home/ubuntu/work/sanitizer")
    parser.add_argument("--out-dir", default="experiment_reports/manual_audit_set_20260624")
    parser.add_argument("--per-category", type=int, default=6)
    args = parser.parse_args()

    root = Path(args.root)
    selected = collect(root, args.per_category)
    rows = [to_audit_row(record) for record in selected]
    out_dir = root / args.out_dir
    write_csv(out_dir / "manual_audit_set.csv", rows)
    write_markdown(out_dir / "manual_audit_set.md", rows)
    print(json.dumps({
        "records": len(rows),
        "out_dir": str(out_dir),
        "categories": {cat: sum(1 for row in rows if row["category"] == cat) for cat in sorted({row["category"] for row in rows})},
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
