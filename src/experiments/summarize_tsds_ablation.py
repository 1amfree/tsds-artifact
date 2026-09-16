#!/usr/bin/env python3
"""Summarize TSDS ablation records into paper-ready tables."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


CONFIG_LABELS = {
    "full": "Full TSDS",
    "static_only": "Static-only",
    "no_threat_matrix": "w/o threat matrix",
    "no_firmware_summaries": "w/o firmware summaries",
    "no_arch_seeding": "w/o arch seeding",
    "no_reconciliation": "w/o reconciliation",
    "no_path_control": "w/o path control",
}

CONFIG_ORDER = [
    "full",
    "static_only",
    "no_threat_matrix",
    "no_firmware_summaries",
    "no_arch_seeding",
    "no_reconciliation",
    "no_path_control",
]


def load_records(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def add_counter(dst: dict[str, int], src: dict[str, Any] | None) -> None:
    if not isinstance(src, dict):
        return
    for key, value in src.items():
        if isinstance(value, int):
            dst[key] += value


def aggregate(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if record.get("config") in CONFIG_LABELS:
            groups[record["config"]].append(record)

    rows: list[dict[str, Any]] = []
    for config in CONFIG_ORDER:
        items = groups.get(config, [])
        if not items:
            continue
        analyzed = sum(int(item.get("unique_pairs_analyzed") or 0) for item in items)
        expected = sum(int(item.get("unique_pairs_expected") or 0) for item in items)
        vulnerable = sum(int(item.get("vulnerable") or 0) for item in items)
        partial = sum(int(item.get("partial_vulnerable") or 0) for item in items)
        filtered = sum(int(item.get("filtered") or 0) for item in items)
        no_taint = sum(int(item.get("no_taint_sink") or 0) for item in items)
        unreachable = sum(int(item.get("unreachable") or 0) for item in items)
        timeout = sum(int(item.get("timeout") or 0) for item in items)
        crashed = sum(int(item.get("crashed") or 0) for item in items)
        eval_error = sum(int(item.get("eval_error") or 0) for item in items)
        residual = unreachable + timeout + crashed + eval_error
        resolved = vulnerable + filtered + no_taint
        sat_vectors = sum(int(item.get("vulnerable_vectors") or 0) for item in items)
        unsat_vectors = sum(int(item.get("secure_vectors") or 0) for item in items)
        weighted_time = sum(
            float(item.get("avg_closure_time_sec") or 0.0) * int(item.get("unique_pairs_analyzed") or 0)
            for item in items
        )
        weighted_steps = sum(
            float(item.get("avg_engine_steps") or 0.0) * int(item.get("unique_pairs_analyzed") or 0)
            for item in items
        )
        pruned_states = 0
        seed_pruned = 0
        semantic_pruned = 0
        source_liveness = 0
        ledger_classes: dict[str, int] = defaultdict(int)
        residual_classes: dict[str, int] = defaultdict(int)
        for item in items:
            totals = ((item.get("path_control_ledger") or {}).get("totals") or {})
            pruned_states += int(totals.get("path_control_pruned_states") or 0)
            seed_pruned += int(totals.get("path_control_seed_pruned") or 0)
            semantic_pruned += int(totals.get("path_control_semantic_pruned_states") or 0)
            source_liveness += int(totals.get("path_control_source_liveness_cuts") or 0)
            add_counter(ledger_classes, (item.get("path_control_ledger") or {}).get("classes"))
            add_counter(residual_classes, (item.get("residual_diagnosis_ledger") or {}).get("classes"))

        rows.append(
            {
                "config": config,
                "label": CONFIG_LABELS[config],
                "targets": len(items),
                "expected": expected,
                "analyzed": analyzed,
                "resolved": resolved,
                "resolved_pct": (100.0 * resolved / analyzed) if analyzed else 0.0,
                "injectable": vulnerable,
                "partial": partial,
                "filtered": filtered,
                "no_taint": no_taint,
                "residual": residual,
                "unreachable": unreachable,
                "timeout": timeout,
                "crashed": crashed,
                "eval_error": eval_error,
                "sat_vectors": sat_vectors,
                "unsat_vectors": unsat_vectors,
                "avg_time": (weighted_time / analyzed) if analyzed else 0.0,
                "avg_steps": (weighted_steps / analyzed) if analyzed else 0.0,
                "pruned_states": pruned_states,
                "seed_pruned": seed_pruned,
                "semantic_pruned": semantic_pruned,
                "source_liveness_cuts": source_liveness,
                "ledger_classes": dict(sorted(ledger_classes.items())),
                "residual_classes": dict(sorted(residual_classes.items())),
            }
        )
    return rows


def markdown(rows: list[dict[str, Any]]) -> str:
    lines = [
        "# TSDS Ablation Aggregate",
        "",
        "| Configuration | Rec. | Resolved | Inj. | Filt. | NoT | Resid. | SAT | UNSAT | Avg s | Steps | Pruned |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| {label} | {analyzed} | {resolved} ({resolved_pct:.1f}%) | {injectable} | {filtered} | "
            "{no_taint} | {residual} | {sat_vectors} | {unsat_vectors} | {avg_time:.1f} | "
            "{avg_steps:.1f} | {pruned_states} |".format(**row)
        )
    return "\n".join(lines) + "\n"


def latex(rows: list[dict[str, Any]]) -> str:
    lines = [
        "\\begin{table}[!t]",
        "\\centering",
        "\\caption{Full-corpus ablation over the fixed eight-firmware candidate set. Res. is resolved records; Inj. is sink-level injectable evidence; NoT is no-taint sink evidence. SAT/UNSAT count shell-vector witnesses and blocked-vector proofs.}",
        "\\label{tab:ablation-full}",
        "\\footnotesize",
        "\\setlength{\\tabcolsep}{2.3pt}",
        "\\begin{tabular}{lrrrrrrrrr}",
        "\\toprule",
        "Configuration & Rec. & Res. & Inj. & Filt. & NoT & Resid. & SAT & UNSAT & Avg s\\\\",
        "\\midrule",
    ]
    for row in rows:
        lines.append(
            "{label} & {analyzed} & {resolved} & {injectable} & {filtered} & {no_taint} & "
            "{residual} & {sat_vectors} & {unsat_vectors} & {avg_time:.1f}\\\\".format(**row)
        )
    lines.extend(
        [
            "\\bottomrule",
            "\\end{tabular}",
            "\\end{table}",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("records", type=Path)
    parser.add_argument("--out-dir", type=Path, default=None)
    args = parser.parse_args()

    records = load_records(args.records)
    rows = aggregate(records)
    out_dir = args.out_dir or args.records.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "ablation_aggregate.json").write_text(json.dumps(rows, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "ablation_aggregate.md").write_text(markdown(rows), encoding="utf-8")
    (out_dir / "ablation_table.tex").write_text(latex(rows), encoding="utf-8")
    print(markdown(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
