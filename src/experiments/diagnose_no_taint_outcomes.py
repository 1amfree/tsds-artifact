#!/usr/bin/env python3
"""Classify TSDS no-taint outcomes against Mango closures.

The report is deliberately diagnostic: it does not relabel records. It separates
fixed maintenance commands from cases where static source obligations did not
materialize dynamically, which are the useful targets for model repair.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import advanced_sanitizer_evaluator as tsds


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def load_closures(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return sorted(data.get("closures", []), key=lambda c: len(c.get("trace", [])))


def text_preview(value: Any, limit: int = 160) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\n", "\\n").replace("\t", "\\t")
    return text[:limit]


def classify_no_taint(
    project: Any,
    closure: Dict[str, Any],
    record: Dict[str, Any],
) -> Dict[str, Any]:
    trace = closure.get("trace", []) or []
    source_addr = tsds.resolve_source_address(project, trace) if trace else 0
    sink_addr = int(closure.get("sink", {}).get("ins_addr", "0"), 16)
    static_evidence = tsds.closure_static_source_evidence(closure)
    recovered_template = tsds.recover_local_static_command_template(project, source_addr, sink_addr)
    has_obligation = tsds.static_evidence_has_source_obligation(static_evidence)
    fixed_template = bool(
        recovered_template
        and tsds.preview_is_fixed_command_template(recovered_template)
    )
    top_preview = (
        record.get("sink_preview")
        or record.get("no_taint_preview")
        or recovered_template
        or ""
    )

    if fixed_template and not has_obligation:
        diagnosis = "fixed_command_no_source_obligation"
    elif fixed_template and has_obligation:
        diagnosis = "fixed_command_with_static_obligation"
    elif has_obligation and record.get("residual_diagnosis_class") == "static_dynamic_taint_disagreement":
        diagnosis = "static_obligation_not_dynamically_bound"
    elif has_obligation:
        diagnosis = "static_obligation_no_taint"
    elif top_preview:
        diagnosis = "dynamic_no_taint_preview"
    else:
        diagnosis = "weak_no_source_no_preview"

    static_inputs = []
    if static_evidence:
        for key in (
            "static_likely_inputs",
            "static_possible_inputs",
            "static_possible_resource_inputs",
        ):
            static_inputs.extend(static_evidence.get(key) or [])

    return {
        "closure_ordinal": record.get("closure_ordinal") or (int(record.get("closure_idx", -1)) + 1),
        "closure_idx": record.get("closure_idx"),
        "status": record.get("status"),
        "diagnosis": diagnosis,
        "source_addr": hex(source_addr) if source_addr else "",
        "sink_addr": hex(sink_addr) if sink_addr else "",
        "sink_function": closure.get("sink", {}).get("function", ""),
        "residual_diagnosis_class": record.get("residual_diagnosis_class", ""),
        "engine_stop_reason": record.get("engine_stop_reason", ""),
        "analysis_recovery": record.get("analysis_recovery", ""),
        "fixed_template": fixed_template,
        "has_static_source_obligation": has_obligation,
        "recovered_template": text_preview(recovered_template),
        "preview": text_preview(top_preview),
        "static_inputs": text_preview(", ".join(str(item) for item in static_inputs[:12])),
    }


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    rows = list(rows)
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("mango_json", type=Path)
    parser.add_argument("results_jsonl", type=Path)
    parser.add_argument("--out-csv", type=Path, default=None)
    parser.add_argument("--top", type=int, default=25)
    args = parser.parse_args()

    project = tsds.angr.Project(str(args.binary), auto_load_libs=False)
    closures = load_closures(args.mango_json)
    records = load_jsonl(args.results_jsonl)
    rows: List[Dict[str, Any]] = []
    for record in records:
        if record.get("status") != "no_taint_sink":
            continue
        idx = record.get("closure_idx")
        if idx is None or int(idx) < 0 or int(idx) >= len(closures):
            continue
        rows.append(classify_no_taint(project, closures[int(idx)], record))

    counts = Counter(row["diagnosis"] for row in rows)
    print(json.dumps({
        "records": len(records),
        "no_taint_records": len(rows),
        "diagnosis_counts": dict(counts),
    }, indent=2, sort_keys=True))
    for row in rows[: max(0, args.top)]:
        print(
            f"#{row['closure_ordinal']} {row['diagnosis']} "
            f"{row['source_addr']}->{row['sink_addr']} "
            f"preview={row['preview']!r} inputs={row['static_inputs']!r}"
        )

    if args.out_csv:
        write_csv(args.out_csv, rows)
        print(f"wrote_csv={args.out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
