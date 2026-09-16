#!/usr/bin/env python3
"""Build reviewer-facing audit tables for TSDS evidence-boundary questions.

The script only re-summarizes existing JSONL ledgers. It does not add runtime
or device-confirmation claims.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEFAULT_CAMPAIGN = Path("experiment_reports/full_firmware_campaign_current_tsds_20260627")
DEFAULT_PC_INPUTS = Path("experiment_reports/path_control_record_audit_20260629/inputs")
DEFAULT_OUT = Path("experiment_reports/iceccs_reviewer_audit_pack_20260629")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


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


def short(value: Any, limit: int = 78) -> str:
    text = str(value or "").replace("\n", r"\n").replace("\r", r"\r").replace("\t", r"\t")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def load_campaign(campaign_dir: Path) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(campaign_dir.glob("*.results.jsonl")):
        out[path.name.replace(".results.jsonl", "")] = read_jsonl(path)
    return out


def recovery_mode(record: dict[str, Any]) -> str:
    return str(record.get("analysis_recovery") or "direct_observed_sink_byte")


def sv_sat_recovery_summary(targets: dict[str, list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    counts: Counter[str] = Counter()
    confidence: dict[str, Counter[str]] = defaultdict(Counter)
    detail_rows: list[dict[str, Any]] = []
    for target, rows in targets.items():
        for row in rows:
            if row.get("status") != "vulnerable":
                continue
            mode = recovery_mode(row)
            counts[mode] += 1
            confidence[mode][str(row.get("evidence_confidence") or "unknown")] += 1
            if mode != "direct_observed_sink_byte":
                detail_rows.append(
                    {
                        "target": target,
                        "closure": row.get("closure_idx"),
                        "mode": mode,
                        "recovery_confidence": row.get("recovery_confidence") or "",
                        "evidence_confidence": row.get("evidence_confidence") or "",
                        "static_strength": row.get("static_evidence_strength") or "",
                        "source": row.get("source_addr") or "",
                        "sink": row.get("sink_addr") or "",
                        "preview": short(row.get("sink_preview") or row.get("recovered_sink_template"), 120),
                    }
                )
    labels = {
        "direct_observed_sink_byte": "direct observed sink-byte",
        "static_dynamic_taint_reconciliation": "static/dynamic reconciled",
        "static_sink_template_fallback": "static sink-template fallback",
        "static_direct_source_fallback": "direct-source guarded fallback",
    }
    order = [
        "direct_observed_sink_byte",
        "static_dynamic_taint_reconciliation",
        "static_sink_template_fallback",
        "static_direct_source_fallback",
    ]
    summary_rows = []
    for key in order:
        summary_rows.append(
            {
                "tier": labels[key],
                "records": counts.get(key, 0),
                "high": confidence[key].get("high", 0),
                "medium": confidence[key].get("medium", 0),
                "low": confidence[key].get("low", 0),
                "evidence_boundary": {
                    "direct_observed_sink_byte": "source-controlled offsets observed in final sink argument",
                    "static_dynamic_taint_reconciliation": "dynamic command slot compatible with strong/static source evidence",
                    "static_sink_template_fallback": "source-bearing static command template retained as guarded evidence",
                    "static_direct_source_fallback": "strong direct-source evidence; no direct dynamic source label",
                }[key],
            }
        )
    return summary_rows, detail_rows


def nms_breakdown(targets: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows = [row for target_rows in targets.values() for row in target_rows if row.get("status") == "no_taint_sink"]
    counts: Counter[str] = Counter()
    confidence: dict[str, Counter[str]] = defaultdict(Counter)
    strength: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        diag = str(row.get("residual_diagnosis_class") or "")
        obligation = str(row.get("source_obligation_class") or "")
        if diag == "static_overapprox_no_taint" or obligation == "static_overapprox_no_taint":
            category = "static-overapprox/fixed-template NMS"
        elif diag == "mango_unbound_no_taint" or obligation == "mango_unbound_no_taint":
            category = "upstream-unbound Mango NMS"
        elif diag == "resolved_source_dead":
            category = "resolved source-dead NMS"
        else:
            category = "source-free sink-callsite NMS"
        counts[category] += 1
        confidence[category][str(row.get("evidence_confidence") or "unknown")] += 1
        strength[category][str(row.get("static_evidence_strength") or "unknown")] += 1
    order = [
        "static-overapprox/fixed-template NMS",
        "upstream-unbound Mango NMS",
        "source-free sink-callsite NMS",
        "resolved source-dead NMS",
    ]
    boundary = {
        "static-overapprox/fixed-template NMS": "reached fixed or mismatched command template with no source slot",
        "upstream-unbound Mango NMS": "Mango closure lacks a bound likely/possible source input",
        "source-free sink-callsite NMS": "sink reached, no modeled source byte observed, source obligation unknown",
        "resolved source-dead NMS": "source influence exhausted before sink under liveness ledger",
    }
    return [
        {
            "category": cat,
            "records": counts.get(cat, 0),
            "high": confidence[cat].get("high", 0),
            "medium": confidence[cat].get("medium", 0),
            "low": confidence[cat].get("low", 0),
            "strong_static": strength[cat].get("strong", 0),
            "weak_static": strength[cat].get("weak", 0),
            "absent_static": strength[cat].get("absent", 0),
            "boundary": boundary[cat],
        }
        for cat in order
    ]


def load_pc_pairs(input_dir: Path) -> dict[str, dict[str, list[dict[str, Any]]]]:
    pairs: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(dict)
    for path in sorted(input_dir.glob("*.results.jsonl")):
        stem = path.name.replace(".results.jsonl", "")
        if stem.endswith("_full"):
            pairs[stem[: -len("_full")]]["full"] = read_jsonl(path)
        elif stem.endswith("_no_path_control"):
            pairs[stem[: -len("_no_path_control")]]["no_path"] = read_jsonl(path)
    return pairs


def vector_signature(row: dict[str, Any] | None) -> tuple[Any, ...]:
    if not row:
        return ()
    return (
        row.get("status"),
        tuple(sorted(row.get("bypass_vector_categories") or [])),
        tuple(sorted(row.get("blocked_vector_categories") or [])),
        row.get("partially_filtered"),
        row.get("paper_claim_bucket"),
    )


def status(row: dict[str, Any] | None) -> str:
    return str((row or {}).get("status") or "missing")


def path_control_differences(input_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    detail_rows: list[dict[str, Any]] = []
    transition_counts: Counter[str] = Counter()
    pairs = load_pc_pairs(input_dir)
    for target, configs in sorted(pairs.items()):
        full = {r.get("closure_idx"): r for r in configs.get("full", [])}
        no_path = {r.get("closure_idx"): r for r in configs.get("no_path", [])}
        for key in sorted(set(full) | set(no_path), key=lambda x: -1 if x is None else int(x)):
            f = full.get(key)
            n = no_path.get(key)
            if vector_signature(f) == vector_signature(n):
                continue
            transition = f"{status(f)} -> {status(n)}"
            transition_counts[transition] += 1
            detail_rows.append(
                {
                    "target": target,
                    "closure": key,
                    "transition": transition,
                    "full_stop": (f or {}).get("engine_stop_reason") or "",
                    "no_path_stop": (n or {}).get("engine_stop_reason") or "",
                    "full_pc_class": (f or {}).get("path_control_class") or "",
                    "no_path_pc_class": (n or {}).get("path_control_class") or "",
                    "sink": (f or n or {}).get("sink_addr") or "",
                    "trace": short((f or n or {}).get("trace_summary"), 120),
                }
            )
    summary_rows = [
        {"transition": transition, "records": count}
        for transition, count in sorted(transition_counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    return summary_rows, detail_rows


def implementation_parameter_rows(targets: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    feature_values: dict[str, set[Any]] = defaultdict(set)
    for rows in targets.values():
        for row in rows:
            for key, value in (row.get("features") or {}).items():
                feature_values[key].add(value)
    selected = [
        ("semantic_frontier", "semantic frontier enabled"),
        ("source_liveness_limit", "source-liveness saturation limit"),
        ("source_dead_state_cap", "source-dead frontier cap"),
        ("weak_evidence_equiv_limit", "weak-evidence equivalence limit"),
        ("loop_semantic_summary", "threat-equivalent loop summaries"),
        ("loop_semantic_min_states", "loop summary minimum states"),
        ("loop_semantic_min_visits", "loop summary minimum visits"),
        ("loop_semantic_saturation_limit", "loop saturation limit"),
        ("loop_semantic_bucket_limit", "loop semantic bucket cap"),
        ("arch_seeding", "architecture-aware state seeding"),
        ("firmware_summaries", "firmware source/string summaries"),
        ("static_dynamic_reconciliation", "guarded static/dynamic reconciliation"),
        ("threat_matrix", "shell-vector matrix enabled"),
    ]
    rows = []
    for key, description in selected:
        values = sorted(feature_values.get(key, set()), key=lambda v: str(v))
        rows.append({"parameter": key, "campaign_value": ", ".join(map(str, values)), "role": description})
    rows.extend(
        [
            {"parameter": "engine_timeout", "campaign_value": "45 s", "role": "per-engine symbolic execution budget"},
            {"parameter": "closure_timeout", "campaign_value": "90 s", "role": "per-closure validation budget"},
            {"parameter": "subprocess_timeout", "campaign_value": "150 s", "role": "process-level failure containment"},
        ]
    )
    return rows


def table_tabularx(rows: list[dict[str, Any]], columns: list[str], headers: list[str], widths: str) -> str:
    lines = [rf"\begin{{tabularx}}{{\textwidth}}{{@{{}}{widths}@{{}}}}", r"\toprule"]
    lines.append(" & ".join(headers) + r"\\")
    lines.append(r"\midrule")
    for row in rows:
        lines.append(" & ".join(esc(row.get(col, "")) for col in columns) + r"\\")
    lines.extend([r"\bottomrule", r"\end{tabularx}", ""])
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign-dir", type=Path, default=DEFAULT_CAMPAIGN)
    ap.add_argument("--pc-input-dir", type=Path, default=DEFAULT_PC_INPUTS)
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    targets = load_campaign(args.campaign_dir)
    sv_summary, recovery_details = sv_sat_recovery_summary(targets)
    nms_rows = nms_breakdown(targets)
    pc_summary, pc_details = path_control_differences(args.pc_input_dir)
    params = implementation_parameter_rows(targets)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.out_dir / "sv_sat_recovery_summary.csv", sv_summary)
    write_csv(args.out_dir / "sv_sat_recovery_details.csv", recovery_details)
    write_csv(args.out_dir / "nms_breakdown_detailed.csv", nms_rows)
    write_csv(args.out_dir / "path_control_difference_summary.csv", pc_summary)
    write_csv(args.out_dir / "path_control_difference_details.csv", pc_details)
    write_csv(args.out_dir / "implementation_parameters.csv", params)

    (args.out_dir / "sv_sat_recovery_summary_table.tex").write_text(
        table_tabularx(
            sv_summary,
            ["tier", "records", "high", "medium", "low", "evidence_boundary"],
            ["SV-SAT evidence tier", "Rec.", "High", "Med.", "Low", "Boundary"],
            r"P{0.25\textwidth}rrrrY",
        ),
        encoding="utf-8",
    )
    (args.out_dir / "nms_breakdown_detailed_table.tex").write_text(
        table_tabularx(
            nms_rows,
            ["category", "records", "high", "medium", "low", "boundary"],
            ["NMS subtype", "Rec.", "High", "Med.", "Low", "Boundary"],
            r"P{0.27\textwidth}rrrrY",
        ),
        encoding="utf-8",
    )
    (args.out_dir / "path_control_difference_summary_table.tex").write_text(
        table_tabularx(
            pc_summary,
            ["transition", "records"],
            ["Full to no-path-control transition", "Records"],
            r"Y r",
        ),
        encoding="utf-8",
    )
    (args.out_dir / "implementation_parameters_table.tex").write_text(
        table_tabularx(
            params,
            ["parameter", "campaign_value", "role"],
            ["Parameter", "Value", "Role"],
            r"P{0.30\textwidth}P{0.18\textwidth}Y",
        ),
        encoding="utf-8",
    )

    summary = {
        "sv_sat_recovery_summary": sv_summary,
        "sv_sat_recovery_detail_count": len(recovery_details),
        "nms_breakdown": nms_rows,
        "path_control_difference_summary": pc_summary,
        "path_control_difference_detail_count": len(pc_details),
        "implementation_parameters": params,
        "claim_boundary": "All tables summarize analyzer-level TSDS ledgers. They do not add device-confirmed exploit claims.",
    }
    (args.out_dir / "reviewer_audit_pack.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    lines = ["# ICECCS reviewer audit pack\n", summary["claim_boundary"], "\n"]
    lines.append(f"- SV-SAT recovery detail rows: {len(recovery_details)}")
    lines.append(f"- Path-control changed vector-signature rows: {len(pc_details)}")
    lines.append(f"- NMS rows: {sum(int(r['records']) for r in nms_rows)}")
    (args.out_dir / "reviewer_audit_pack.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(args.out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
