#!/usr/bin/env python3
"""Build record-to-evidence-unit deduplication summaries for TSDS campaigns."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


STATUS_ORDER = [
    "vulnerable",
    "filtered",
    "no_taint_sink",
    "unreachable",
    "timeout",
    "crashed",
    "eval_error",
]


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def short_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", "replace")).hexdigest()[:12]


def norm(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "|".join(norm(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, ensure_ascii=True)
    text = str(value)
    return " ".join(text.split())


def status_of(record: dict[str, Any]) -> str:
    status = str(record.get("status") or "")
    if status:
        return status
    if record.get("timeout"):
        return "timeout"
    if record.get("unreachable"):
        return "unreachable"
    return "unknown"


def target_from_path(path: Path) -> str:
    return path.name.replace(".results.jsonl", "")


def sink_callsite_key(target: str, r: dict[str, Any]) -> str:
    return "::".join([target, norm(r.get("sink_function")), norm(r.get("sink_addr"))])


def source_sink_key(target: str, r: dict[str, Any]) -> str:
    source_group = r.get("source_group")
    if source_group:
        return target + "::" + norm(source_group)
    return "::".join(
        [
            target,
            norm(r.get("source_function")),
            norm(r.get("source_addr")),
            norm(r.get("sink_function")),
            norm(r.get("sink_addr")),
        ]
    )


def trace_shape_key(target: str, r: dict[str, Any]) -> str:
    trace = norm(r.get("trace_summary"))
    if not trace:
        trace = "->".join(norm(n.get("function")) for n in r.get("trace_nodes") or [] if isinstance(n, dict))
    return target + "::" + trace


def sink_function_key(target: str, r: dict[str, Any]) -> str:
    return target + "::" + norm(r.get("sink_function"))


def command_template_key(target: str, r: dict[str, Any]) -> str:
    template = (
        r.get("static_sink_template")
        or r.get("no_taint_preview")
        or r.get("sink_preview")
        or r.get("sink_expr")
        or ""
    )
    return "::".join([target, norm(r.get("sink_function")), short_hash(norm(template))])


def summarize(records_by_target: dict[str, list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    all_records: list[tuple[str, dict[str, Any]]] = [
        (target, r) for target, records in records_by_target.items() for r in records
    ]

    def make_row(label: str, pairs: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
        statuses = Counter(status_of(r) for _, r in pairs)
        sink_calls = {sink_callsite_key(t, r) for t, r in pairs}
        source_sinks = {source_sink_key(t, r) for t, r in pairs}
        trace_shapes = {trace_shape_key(t, r) for t, r in pairs}
        sink_functions = {sink_function_key(t, r) for t, r in pairs}
        templates = {command_template_key(t, r) for t, r in pairs}
        return {
            "label": label,
            "records": len(pairs),
            "sink_callsites": len(sink_calls),
            "source_sink_pairs": len(source_sinks),
            "trace_shapes": len(trace_shapes),
            "sink_functions": len(sink_functions),
            "command_templates": len(templates),
            "status_counts": dict(statuses),
        }

    rows.append(make_row("All records", all_records))
    for status in ["vulnerable", "filtered", "no_taint_sink"]:
        rows.append(make_row(status, [(t, r) for t, r in all_records if status_of(r) == status]))
    rows.append(
        make_row(
            "Residual",
            [(t, r) for t, r in all_records if status_of(r) not in {"vulnerable", "filtered", "no_taint_sink"}],
        )
    )

    per_target: list[dict[str, Any]] = []
    for target, records in sorted(records_by_target.items()):
        pairs = [(target, r) for r in records]
        row = make_row(target, pairs)
        row["target"] = target
        row["injectable_records"] = sum(1 for r in records if status_of(r) == "vulnerable")
        row["injectable_sink_callsites"] = len(
            {sink_callsite_key(target, r) for r in records if status_of(r) == "vulnerable"}
        )
        row["injectable_source_sink_pairs"] = len(
            {source_sink_key(target, r) for r in records if status_of(r) == "vulnerable"}
        )
        per_target.append(row)

    aggregate = {
        "rows": rows,
        "per_target": per_target,
        "boundary": (
            "Evidence-unit deduplication over TSDS records. These are reproducible "
            "upper-bound audit units, not independently confirmed root causes."
        ),
    }
    return rows, aggregate


def markdown(aggregate: dict[str, Any]) -> str:
    lines = [
        "# TSDS Evidence-Unit Deduplication",
        "",
        aggregate["boundary"],
        "",
        "| Stratum | Records | Sink callsites | Source-sink pairs | Trace shapes | Sink funcs | Cmd templates |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in aggregate["rows"]:
        lines.append(
            "| {label} | {records} | {sink_callsites} | {source_sink_pairs} | {trace_shapes} | "
            "{sink_functions} | {command_templates} |".format(**row)
        )
    lines.extend(
        [
            "",
            "## Per Target Injectable Units",
            "",
            "| Target | Records | Inj. records | Inj. sink callsites | Inj. source-sink pairs | All trace shapes |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in aggregate["per_target"]:
        lines.append(
            "| {target} | {records} | {injectable_records} | {injectable_sink_callsites} | "
            "{injectable_source_sink_pairs} | {trace_shapes} |".format(**row)
        )
    return "\n".join(lines) + "\n"


def latex_table(aggregate: dict[str, Any]) -> str:
    lines = [
        "\\begin{table}[!t]",
        "\\centering",
        "\\caption{Record-to-evidence-unit deduplication. Units are reproducible audit keys, not independently confirmed root causes.}",
        "\\label{tab:dedup-units}",
        "\\footnotesize",
        "\\setlength{\\tabcolsep}{3.0pt}",
        "\\begin{tabular}{lrrrrr}",
        "\\toprule",
        "Stratum & Records & Sink sites & Src-sink & Traces & Sink funcs\\\\",
        "\\midrule",
    ]
    for row in aggregate["rows"]:
        lines.append(
            "{label} & {records} & {sink_callsites} & {source_sink_pairs} & {trace_shapes} & "
            "{sink_functions}\\\\".format(**row)
        )
    lines.extend(["\\bottomrule", "\\end{tabular}", "\\end{table}", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("jsonl", nargs="+", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()

    records_by_target = {target_from_path(path): load_jsonl(path) for path in args.jsonl}
    _, aggregate = summarize(records_by_target)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    (args.out_dir / "dedup_summary.json").write_text(
        json.dumps(aggregate, indent=2, sort_keys=True), encoding="utf-8"
    )
    (args.out_dir / "dedup_summary.md").write_text(markdown(aggregate), encoding="utf-8")
    (args.out_dir / "dedup_table.tex").write_text(latex_table(aggregate), encoding="utf-8")

    with (args.out_dir / "dedup_per_target.csv").open("w", newline="", encoding="utf-8") as fh:
        fieldnames = [
            "target",
            "records",
            "injectable_records",
            "injectable_sink_callsites",
            "injectable_source_sink_pairs",
            "trace_shapes",
        ]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in aggregate["per_target"]:
            writer.writerow({key: row.get(key) for key in fieldnames})

    print(markdown(aggregate))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
