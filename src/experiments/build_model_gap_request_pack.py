#!/usr/bin/env python3
"""Build a cross-target model-gap request pack from TSDS JSONL artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from advanced_sanitizer_evaluator import (
    evidence_profile_for_record,
    model_gap_requests_for_record,
    residual_diagnosis_for_record,
    residual_recovery_plan_for_record,
)


TARGETS = [
    ("ASUS RT-BE57", "experiment_reports/full_campaign_20260622_v1/asus_rt_be57_full.results.jsonl"),
    ("D-Link DIR-878", "experiment_reports/full_campaign_20260622_v1/dir878_full.results.jsonl"),
    ("Tenda AC15", "experiment_reports/full_campaign_20260622_v1/tenda_ac15_full.results.jsonl"),
    ("Tenda AC18", "Tenda_AC18/reports/ac18_results_v2.jsonl"),
    ("Tenda W20E", "Tenda_W20E/reports/w20e_results.jsonl"),
    ("Netgear R6400v2", "experiment_reports/r6400_reclassified_20260624_v1/r6400v2_full.results.jsonl"),
    ("Netgear R7000", "experiment_reports/full_campaign_20260622_v1/r7000_full.results.jsonl"),
    ("Netgear XR300", "XR300/reports/xr300_results.jsonl"),
]


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


def short(value: Any, limit: int = 180) -> str:
    text = str(value or "").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def enrich_record(record: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(record)
    enriched.update(evidence_profile_for_record(enriched))
    diagnosis = residual_diagnosis_for_record(enriched)
    if diagnosis:
        enriched.update(diagnosis)
    if enriched.get("residual_diagnosis_class"):
        enriched.update(residual_recovery_plan_for_record(enriched))
    return enriched


def collect(root: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for target, rel in TARGETS:
        path = root / rel
        for record in load_jsonl(path):
            record = enrich_record(record)
            # Always recompute from the current TSDS logic. Older JSONL files
            # may contain stale requests before noise/internal-resource filters
            # were tightened.
            requests = model_gap_requests_for_record(record)
            for request in requests:
                rows.append({
                    "target": target,
                    "jsonl_path": rel,
                    "closure_idx": record.get("closure_idx"),
                    "closure_ordinal": record.get("closure_ordinal") or (
                        int(record.get("closure_idx")) + 1 if record.get("closure_idx") is not None else ""
                    ),
                    "status": record.get("status"),
                    "diagnosis": record.get("residual_diagnosis_class") or "",
                    "strategy": record.get("residual_plan_strategy") or "",
                    "priority": record.get("residual_plan_priority") or "",
                    "source": short(record.get("source_function") or record.get("source_addr"), 80),
                    "sink": short(record.get("sink_function") or record.get("sink_addr"), 80),
                    "trace": short(record.get("trace_summary"), 140),
                    "kind": request.get("kind"),
                    "key": request.get("key"),
                    "reason": request.get("reason"),
                    "confidence": request.get("confidence"),
                    "evidence": short(request.get("evidence"), 220),
                })
    rows.sort(key=lambda row: (
        row["target"],
        {"high": 0, "medium": 1, "low": 2}.get(str(row.get("confidence")), 3),
        str(row.get("kind") or ""),
        int(row.get("closure_idx") or 0),
        str(row.get("key") or ""),
    ))
    return rows


def summarize(rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = list(rows)
    by_target = Counter(row["target"] for row in rows)
    by_kind = Counter(row["kind"] for row in rows)
    by_reason = Counter(row["reason"] for row in rows)
    by_confidence = Counter(row["confidence"] for row in rows)
    return {
        "requests": len(rows),
        "targets": dict(sorted(by_target.items())),
        "kinds": dict(sorted(by_kind.items(), key=lambda item: (-item[1], item[0]))),
        "reasons": dict(sorted(by_reason.items(), key=lambda item: (-item[1], item[0]))),
        "confidence": dict(sorted(by_confidence.items(), key=lambda item: (-item[1], item[0]))),
    }


CONFIDENCE_SCORE = {"high": 30, "medium": 15, "low": 5}
STATUS_SCORE = {
    "timeout": 18,
    "unreachable": 16,
    "no_taint_sink": 10,
    "crashed": 8,
    "eval_error": 8,
    "state_error": 8,
}
KIND_SCORE = {
    "web": 16,
    "file": 15,
    "config_key": 12,
    "path_model": 8,
    "string_model": 8,
}
REASON_SCORE = {
    "mango_likely_input": 18,
    "trace_uses_web_parser": 12,
    "trace_uses_config_api": 12,
    "trace_expression_token": 10,
    "mango_possible_input": 6,
    "sink_distance_model": 5,
    "taint_carrier_summary": 5,
}


def priority_score(row: Dict[str, Any]) -> int:
    return (
        CONFIDENCE_SCORE.get(str(row.get("confidence") or ""), 0)
        + STATUS_SCORE.get(str(row.get("status") or ""), 0)
        + KIND_SCORE.get(str(row.get("kind") or ""), 0)
        + REASON_SCORE.get(str(row.get("reason") or ""), 0)
    )


def prioritise(rows: List[Dict[str, Any]], top_limit: int, top_per_target: int) -> List[Dict[str, Any]]:
    grouped: Dict[tuple, Dict[str, Any]] = {}
    closures: Dict[tuple, set] = defaultdict(set)
    statuses: Dict[tuple, Counter] = defaultdict(Counter)
    for row in rows:
        key = (row.get("target"), row.get("kind"), row.get("key"))
        score = priority_score(row)
        closures[key].add(str(row.get("closure_ordinal") or row.get("closure_idx") or ""))
        statuses[key][str(row.get("status") or "unknown")] += 1
        current = grouped.get(key)
        if current is None or score > int(current.get("priority_score") or 0):
            grouped[key] = {**row, "priority_score": score}

    ranked = []
    per_target = Counter()
    for key, row in sorted(
        grouped.items(),
        key=lambda item: (
            -int(item[1].get("priority_score") or 0),
            item[1].get("target") or "",
            item[1].get("kind") or "",
            item[1].get("key") or "",
        ),
    ):
        target = row.get("target") or ""
        if top_per_target and per_target[target] >= top_per_target:
            continue
        enriched = dict(row)
        enriched["affected_closures"] = ",".join(sorted(x for x in closures[key] if x))
        enriched["affected_count"] = len(closures[key])
        enriched["status_mix"] = ";".join(f"{status}:{count}" for status, count in sorted(statuses[key].items()))
        ranked.append(enriched)
        per_target[target] += 1
        if top_limit and len(ranked) >= top_limit:
            break
    return ranked


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys()) if rows else [
        "target", "jsonl_path", "closure_idx", "closure_ordinal", "status",
        "diagnosis", "strategy", "priority", "source", "sink", "trace",
        "kind", "key", "reason", "confidence", "evidence",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
            quoting=csv.QUOTE_ALL,
            escapechar="\\",
            doublequote=True,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows([
            {key: short(row.get(key), 10000) for key in fieldnames}
            for row in rows
        ])


def write_top_markdown(path: Path, rows: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# TSDS Prioritized Model-Gap Requests",
        "",
        "This file deduplicates the request pack by `(target, kind, key)` and ranks resources that are most likely to reduce residual uncertainty in the next experiment round.",
        "",
        "## Summary",
        "",
        f"- Raw requests: `{summary['requests']}`",
        f"- Prioritized unique requests: `{len(rows)}`",
        f"- Raw by target: `{json.dumps(summary['targets'], sort_keys=True)}`",
        "",
        "## Top Requests",
        "",
        "| Rank | Target | Kind | Key | Score | Affected | Status mix | Reason | Confidence | Evidence |",
        "|---:|---|---|---|---:|---:|---|---|---|---|",
    ]
    for idx, row in enumerate(rows, 1):
        lines.append(
            "| {rank} | {target} | {kind} | {key} | {score} | {affected} | {status_mix} | {reason} | {confidence} | {evidence} |".format(
                rank=idx,
                target=row.get("target", ""),
                kind=row.get("kind", ""),
                key=short(row.get("key"), 80),
                score=row.get("priority_score", 0),
                affected=row.get("affected_count", 0),
                status_mix=short(row.get("status_mix"), 90),
                reason=row.get("reason", ""),
                confidence=row.get("confidence", ""),
                evidence=short(row.get("evidence"), 100),
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_fixture_skeleton(path: Path, rows: List[Dict[str, Any]]) -> None:
    skeleton: Dict[str, Any] = {
        "_comment": "Fill values for prioritized TSDS model-gap resources, then rerun advanced_sanitizer_evaluator.py with --env-fixture-json.",
        "config": {},
        "web": {},
        "files": {},
    }
    for row in rows:
        kind = row.get("kind")
        key = str(row.get("key") or "")
        if not key:
            continue
        placeholder = {
            "value": "",
            "target": row.get("target"),
            "reason": row.get("reason"),
            "confidence": row.get("confidence"),
            "affected_closures": row.get("affected_closures"),
        }
        if kind == "config_key":
            skeleton["config"].setdefault(key, placeholder)
        elif kind == "web":
            skeleton["web"].setdefault(key, placeholder)
        elif kind == "file":
            skeleton["files"].setdefault(key, {"content": "", **placeholder})
    path.write_text(json.dumps(skeleton, indent=2, sort_keys=True), encoding="utf-8")


def write_markdown(path: Path, rows: List[Dict[str, Any]], summary: Dict[str, Any], max_rows: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = rows if max_rows == 0 else rows[:max_rows]
    lines = [
        "# TSDS Model-Gap Request Pack",
        "",
        "This pack converts unresolved TSDS evidence into concrete resources needed for the next modeling round.",
        "",
        "## Summary",
        "",
        f"- Requests: `{summary['requests']}`",
        f"- By kind: `{json.dumps(summary['kinds'], sort_keys=True)}`",
        f"- By reason: `{json.dumps(summary['reasons'], sort_keys=True)}`",
        f"- By confidence: `{json.dumps(summary['confidence'], sort_keys=True)}`",
        "",
        "## Requests",
        "",
        "| Target | Closure | Status | Kind | Key | Reason | Confidence | Trace |",
        "|---|---:|---|---|---|---|---|---|",
    ]
    for row in rendered:
        lines.append(
            "| {target} | {closure} | {status} | {kind} | {key} | {reason} | {confidence} | {trace} |".format(
                target=row["target"],
                closure=row["closure_ordinal"],
                status=row["status"],
                kind=row["kind"],
                key=short(row["key"], 80),
                reason=row["reason"],
                confidence=row["confidence"],
                trace=short(row["trace"], 100),
            )
        )
    if max_rows and len(rows) > max_rows:
        lines.append(f"| ... | ... | ... | ... | ... | ... | ... | Showing first {max_rows} of {len(rows)} requests |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="/home/ubuntu/work/sanitizer")
    parser.add_argument("--out-dir", default="experiment_reports/model_gap_requests_20260624")
    parser.add_argument("--max-md-rows", type=int, default=120)
    parser.add_argument("--top-limit", type=int, default=80)
    parser.add_argument("--top-per-target", type=int, default=15)
    args = parser.parse_args()

    root = Path(args.root)
    out_dir = root / args.out_dir
    rows = collect(root)
    summary = summarize(rows)
    top_rows = prioritise(rows, args.top_limit, args.top_per_target)
    write_csv(out_dir / "model_gap_requests.csv", rows)
    write_markdown(out_dir / "model_gap_requests.md", rows, summary, args.max_md_rows)
    write_csv(out_dir / "top_model_gap_requests.csv", top_rows)
    write_top_markdown(out_dir / "top_model_gap_requests.md", top_rows, summary)
    write_fixture_skeleton(out_dir / "env_fixture_skeleton.json", top_rows)
    (out_dir / "model_gap_requests_summary.json").write_text(
        json.dumps({**summary, "prioritized_unique_requests": len(top_rows)}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(json.dumps({"out_dir": str(out_dir), **summary, "prioritized_unique_requests": len(top_rows)}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
