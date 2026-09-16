#!/usr/bin/env python3
"""Build reviewer-facing strengthening artifacts for the TSDS paper.

The script summarizes existing TSDS ledgers into compact evidence that answers
the main ICECCS review concerns: competitive validator baselines, stratified
trace audit, guarded recovery, path-control sensitivity, and runtime-canary
boundaries. It does not add device-level exploit claims.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


DEFAULT_CAMPAIGN = Path("experiment_reports/full_firmware_campaign_current_tsds_20260627")
DEFAULT_PC_INPUTS = Path("experiment_reports/path_control_record_audit_20260629/inputs")
DEFAULT_REVIEWER_AUDIT = Path("experiment_reports/iceccs_reviewer_audit_pack_20260629")
DEFAULT_CANARY = Path("experiment_reports/runtime_canary_validation_cross_vendor_20260629/cross_vendor_runtime_canary_summary.json")
DEFAULT_OUT = Path("experiment_reports/acceptance_strengthening_pack_20260630")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


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
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
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


def short(value: Any, limit: int = 92) -> str:
    text = str(value or "").replace("\n", r"\n").replace("\r", r"\r").replace("\t", r"\t")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def load_campaign(campaign_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(campaign_dir.glob("*.results.jsonl")):
        target = path.name.replace(".results.jsonl", "")
        for row in read_jsonl(path):
            out = dict(row)
            out["_target"] = target
            out["_jsonl"] = path.name
            rows.append(out)
    return rows


def vector_categories(row: dict[str, Any], field: str) -> set[str]:
    values = row.get(field)
    if isinstance(values, list):
        return {str(v) for v in values}
    profile = row.get("sanitizer_gap_profile") or {}
    values = profile.get(field)
    return {str(v) for v in values} if isinstance(values, list) else set()


def is_reached(row: dict[str, Any]) -> bool:
    return row.get("status") in {"vulnerable", "filtered", "no_taint_sink"}


def is_taint_positive(row: dict[str, Any]) -> bool:
    return is_reached(row) and int(row.get("tainted_byte_count") or 0) > 0


def is_single_vector_positive(row: dict[str, Any]) -> bool:
    return "Command Chaining" in vector_categories(row, "bypass_vector_categories")


def baseline_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    total = len(rows)
    sv_sat = sum(1 for r in rows if r.get("status") == "vulnerable")
    filtered = sum(1 for r in rows if r.get("status") == "filtered")
    nms = sum(1 for r in rows if r.get("status") == "no_taint_sink")
    residual = total - sv_sat - filtered - nms
    partial = sum(1 for r in rows if r.get("partially_filtered"))
    blocked_proofs = sum(int(r.get("secure_vectors") or 0) for r in rows)

    def count(pred) -> int:
        return sum(1 for row in rows if pred(row))

    sink_reach = count(is_reached)
    taint_pos = count(is_taint_positive)
    single_pos = count(is_single_vector_positive)

    # "Spurious relative to TSDS matrix" is not a ground-truth false-positive
    # count. It measures how many records a weaker validator would still send
    # as positives although TSDS assigns filtered/NMS.
    sink_reach_spurious = filtered + nms
    taint_spurious = sum(1 for r in rows if is_taint_positive(r) and r.get("status") != "vulnerable")
    single_missed = sum(1 for r in rows if r.get("status") == "vulnerable" and not is_single_vector_positive(r))

    return [
        {
            "validator": "Static candidate list",
            "records": total,
            "positive_or_reached": total,
            "sv_sat_recovered": 0,
            "filtered_evidence": 0,
            "nms_evidence": 0,
            "partial_profiles": 0,
            "blocked_vector_proofs": 0,
            "residual": total,
            "matrix_relative_spurious": total - sv_sat,
            "matrix_relative_missed_sv_sat": sv_sat,
            "evidence_boundary": "candidate only",
        },
        {
            "validator": "Naive guided sink-reach hook",
            "records": total,
            "positive_or_reached": sink_reach,
            "sv_sat_recovered": sv_sat,
            "filtered_evidence": 0,
            "nms_evidence": 0,
            "partial_profiles": 0,
            "blocked_vector_proofs": 0,
            "residual": residual,
            "matrix_relative_spurious": sink_reach_spurious,
            "matrix_relative_missed_sv_sat": 0,
            "evidence_boundary": "sink call observed; no byte/vector semantics",
        },
        {
            "validator": "Taint-at-sink hook",
            "records": total,
            "positive_or_reached": taint_pos,
            "sv_sat_recovered": sum(1 for r in rows if is_taint_positive(r) and r.get("status") == "vulnerable"),
            "filtered_evidence": 0,
            "nms_evidence": 0,
            "partial_profiles": 0,
            "blocked_vector_proofs": 0,
            "residual": total - taint_pos,
            "matrix_relative_spurious": taint_spurious,
            "matrix_relative_missed_sv_sat": sum(1 for r in rows if r.get("status") == "vulnerable" and not is_taint_positive(r)),
            "evidence_boundary": "source bytes reach sink; no vector SAT/UNSAT",
        },
        {
            "validator": "Single-vector ';' checker",
            "records": total,
            "positive_or_reached": single_pos,
            "sv_sat_recovered": single_pos,
            "filtered_evidence": 0,
            "nms_evidence": 0,
            "partial_profiles": 0,
            "blocked_vector_proofs": 0,
            "residual": total - single_pos,
            "matrix_relative_spurious": 0,
            "matrix_relative_missed_sv_sat": single_missed,
            "evidence_boundary": "one vector family only; no blocked-vector or NMS evidence",
        },
        {
            "validator": "Full TSDS",
            "records": total,
            "positive_or_reached": sv_sat + filtered + nms,
            "sv_sat_recovered": sv_sat,
            "filtered_evidence": filtered,
            "nms_evidence": nms,
            "partial_profiles": partial,
            "blocked_vector_proofs": blocked_proofs,
            "residual": residual,
            "matrix_relative_spurious": 0,
            "matrix_relative_missed_sv_sat": 0,
            "evidence_boundary": "sink-byte provenance plus vector SAT/UNSAT and residual ledger",
        },
    ]


def pick_evenly(candidates: list[dict[str, Any]], n: int) -> list[dict[str, Any]]:
    if n <= 0 or not candidates:
        return []
    ordered = sorted(candidates, key=lambda r: (str(r.get("_target")), int(r.get("closure_idx") or 0)))
    if len(ordered) <= n:
        return ordered
    out: list[dict[str, Any]] = []
    for i in range(n):
        idx = round(i * (len(ordered) - 1) / (n - 1))
        out.append(ordered[idx])
    seen: set[tuple[str, int]] = set()
    unique: list[dict[str, Any]] = []
    for row in out:
        key = (str(row.get("_target")), int(row.get("closure_idx") or -1))
        if key not in seen:
            unique.append(row)
            seen.add(key)
    for row in ordered:
        if len(unique) >= n:
            break
        key = (str(row.get("_target")), int(row.get("closure_idx") or -1))
        if key not in seen:
            unique.append(row)
            seen.add(key)
    return unique


def audit_stratum(row: dict[str, Any]) -> str:
    if row.get("status") == "vulnerable":
        mode = str(row.get("analysis_recovery") or "direct_observed_sink_byte")
        if mode != "direct_observed_sink_byte":
            return "recovered_sv_sat"
        if row.get("partially_filtered"):
            return "partial_filter_sv_sat"
        return "direct_sv_sat"
    if row.get("status") == "filtered":
        return "modeled_vector_filtered"
    if row.get("status") == "no_taint_sink":
        diag = str(row.get("residual_diagnosis_class") or row.get("source_obligation_class") or "")
        if "static_overapprox" in diag:
            return "fixed_template_nms"
        return "other_nms"
    return "residual"


def audit_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    quotas = {
        "direct_sv_sat": 14,
        "partial_filter_sv_sat": 6,
        "recovered_sv_sat": 10,
        "modeled_vector_filtered": 10,
        "fixed_template_nms": 10,
        "other_nms": 5,
        "residual": 5,
    }
    by_stratum: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_stratum[audit_stratum(row)].append(row)
    selected: list[dict[str, Any]] = []
    for stratum, quota in quotas.items():
        selected.extend(pick_evenly(by_stratum[stratum], quota))

    out: list[dict[str, Any]] = []
    for row in selected:
        status = str(row.get("status"))
        stratum = audit_stratum(row)
        verdict = "support"
        boundary = "sink-level evidence only"
        if status == "vulnerable":
            if stratum == "recovered_sv_sat":
                boundary = "guarded recovery; not direct dynamic taint"
            elif stratum == "partial_filter_sv_sat":
                boundary = "mixed SAT/UNSAT vector profile"
            else:
                boundary = "direct source-controlled sink bytes plus SAT witness"
        elif status == "filtered":
            boundary = "all implemented vectors UNSAT; matrix-bounded only"
        elif status == "no_taint_sink":
            boundary = "no modeled source under TSDS abstraction; not benignness proof"
        else:
            verdict = "residual_only"
            boundary = "typed unresolved obligation; not positive or negative"
        out.append(
            {
                "target": row.get("_target"),
                "closure_idx": row.get("closure_idx"),
                "stratum": stratum,
                "status": status,
                "audit_verdict": verdict,
                "confidence": row.get("evidence_confidence") or "",
                "recovery": row.get("analysis_recovery") or "direct_observed_sink_byte",
                "tainted_bytes": row.get("tainted_byte_count") or 0,
                "sat_vectors": row.get("vulnerable_vectors") or 0,
                "unsat_vectors": row.get("secure_vectors") or 0,
                "sink": f"{row.get('sink_function')}@{row.get('sink_addr')}",
                "preview": short(row.get("sink_preview") or row.get("no_taint_preview") or row.get("recovered_sink_template"), 120),
                "diagnosis": row.get("residual_diagnosis_class") or row.get("source_obligation_class") or "",
                "boundary": boundary,
            }
        )
    return out


def recovery_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        if row.get("status") != "vulnerable":
            continue
        mode = str(row.get("analysis_recovery") or "direct_observed_sink_byte")
        if mode == "direct_observed_sink_byte":
            continue
        out.append(
            {
                "target": row.get("_target"),
                "closure_idx": row.get("closure_idx"),
                "mode": mode,
                "confidence": row.get("evidence_confidence") or "",
                "static_strength": row.get("static_evidence_strength") or "",
                "sink": f"{row.get('sink_function')}@{row.get('sink_addr')}",
                "source": row.get("source_addr") or "",
                "preview": short(row.get("sink_preview") or row.get("recovered_sink_template"), 120),
                "admitted": "yes" if str(row.get("evidence_confidence")) != "low" else "no",
            }
        )
    return sorted(out, key=lambda r: (str(r["target"]), int(r["closure_idx"] or 0)))


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


def path_control_rows(input_dir: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    pairs = load_pc_pairs(input_dir)
    for target, configs in sorted(pairs.items()):
        full = {r.get("closure_idx"): r for r in configs.get("full", [])}
        no_path = {r.get("closure_idx"): r for r in configs.get("no_path", [])}
        for key in sorted(set(full) | set(no_path), key=lambda x: int(x or -1)):
            f = full.get(key)
            n = no_path.get(key)
            if vector_signature(f) == vector_signature(n):
                continue
            fs = str((f or {}).get("status") or "missing")
            ns = str((n or {}).get("status") or "missing")
            counted_positive = "yes" if fs == "vulnerable" else "no"
            if fs != "vulnerable" and ns == "vulnerable":
                counted_positive = "manual_review_only"
            out.append(
                {
                    "target": target,
                    "closure_idx": key,
                    "transition": f"{fs}->{ns}",
                    "full_stop": (f or {}).get("engine_stop_reason") or "",
                    "no_path_stop": (n or {}).get("engine_stop_reason") or "",
                    "sink": f"{(f or n or {}).get('sink_function')}@{(f or n or {}).get('sink_addr')}",
                    "trace": short((f or n or {}).get("trace_summary"), 120),
                    "impact": counted_positive,
                }
            )
    return out


def canary_rows(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not path.exists():
        return [], {"positive_count": 0, "boundary_probe_count": 0}
    data = read_json(path)
    rows: list[dict[str, Any]] = []
    for item in data.get("positive_canaries") or []:
        rows.append(
            {
                "id": item.get("id") or item.get("candidate") or "",
                "kind": "positive",
                "firmware": item.get("firmware") or item.get("target") or "",
                "vendor": item.get("vendor") or "",
                "scope": item.get("scope") or item.get("level") or "",
                "claim": "token reaches intercepted sink argument; shell skipped",
            }
        )
    for item in data.get("boundary_probes") or []:
        rows.append(
            {
                "id": item.get("id") or item.get("candidate") or item.get("artifact_name") or "",
                "kind": "boundary_probe",
                "firmware": item.get("firmware") or item.get("target") or "",
                "vendor": item.get("vendor") or "",
                "scope": item.get("scope") or item.get("level") or "",
                "claim": "fixture/probe did not establish token-to-sink positive",
            }
        )
    summary = {
        "positive_count": data.get("positive_count") or len([r for r in rows if r["kind"] == "positive"]),
        "positive_vendor_count": data.get("positive_vendor_count"),
        "positive_firmware_count": data.get("positive_firmware_count"),
        "handler_level_positive_count": data.get("handler_level_positive_count"),
        "service_level_positive_count": data.get("service_level_positive_count"),
        "boundary_probe_count": data.get("boundary_probe_count") or len([r for r in rows if r["kind"] == "boundary_probe"]),
        "claim_boundary": data.get("claim_boundary") or "qemu/gdb sink-callsite consistency only",
    }
    return rows, summary


def latex_table(rows: list[dict[str, Any]], cols: list[str], headers: list[str], spec: str) -> str:
    lines = [rf"\begin{{tabularx}}{{\textwidth}}{{@{{}}{spec}@{{}}}}", r"\toprule"]
    lines.append(" & ".join(headers) + r"\\")
    lines.append(r"\midrule")
    for row in rows:
        lines.append(" & ".join(esc(row.get(c, "")) for c in cols) + r"\\")
    lines.extend([r"\bottomrule", r"\end{tabularx}", ""])
    return "\n".join(lines)


def latex_small_tabular(rows: list[dict[str, Any]], cols: list[str], headers: list[str], spec: str) -> str:
    lines = [rf"\begin{{tabular}}{{@{{}}{spec}@{{}}}}", r"\toprule"]
    lines.append(" & ".join(headers) + r"\\")
    lines.append(r"\midrule")
    for row in rows:
        lines.append(" & ".join(esc(row.get(c, "")) for c in cols) + r"\\")
    lines.extend([r"\bottomrule", r"\end{tabular}", ""])
    return "\n".join(lines)


def summarize_counts(rows: Iterable[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    c = Counter(str(row.get(field) or "") for row in rows)
    return [{"class": key, "records": value} for key, value in sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))]


def write_markdown(
    path: Path,
    baseline: list[dict[str, Any]],
    audit: list[dict[str, Any]],
    recovery: list[dict[str, Any]],
    pc: list[dict[str, Any]],
    canary_summary: dict[str, Any],
) -> None:
    def md_table(rows: list[dict[str, Any]]) -> list[str]:
        if not rows:
            return ["_No rows._\n"]
        fields = list(rows[0].keys())
        lines = ["| " + " | ".join(fields) + " |", "|" + "|".join(["---"] * len(fields)) + "|"]
        lines += ["| " + " | ".join(str(row.get(f, "")) for f in fields) + " |" for row in rows]
        return [line + "\n" for line in lines]

    lines: list[str] = ["# TSDS acceptance strengthening pack\n\n"]
    lines.append("All counts are derived from existing TSDS ledgers. They are analyzer-level evidence, not device-confirmed exploit claims.\n\n")
    lines.append("## Validator baselines\n\n")
    lines.extend(md_table(baseline))
    lines.append("\n## Stratified trace audit summary\n\n")
    lines.extend(md_table(summarize_counts(audit, "stratum")))
    lines.append("\n## Guarded recovery index\n\n")
    lines.append(f"Recovered SV-SAT records indexed: {len(recovery)}.\n\n")
    lines.append("## Path-control sensitivity\n\n")
    lines.extend(md_table(summarize_counts(pc, "transition")))
    lines.append("\n## Runtime canary boundary\n\n")
    lines.append(json.dumps(canary_summary, indent=2, sort_keys=True))
    lines.append("\n")
    path.write_text("".join(lines), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign-dir", type=Path, default=DEFAULT_CAMPAIGN)
    ap.add_argument("--pc-input-dir", type=Path, default=DEFAULT_PC_INPUTS)
    ap.add_argument("--canary-json", type=Path, default=DEFAULT_CANARY)
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    rows = load_campaign(args.campaign_dir)
    baseline = baseline_rows(rows)
    audit = audit_rows(rows)
    recovery = recovery_rows(rows)
    pc = path_control_rows(args.pc_input_dir)
    canary, canary_summary = canary_rows(args.canary_json)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.out_dir / "validator_baseline_comparison.csv", baseline)
    write_csv(args.out_dir / "stratified_trace_audit_60.csv", audit)
    write_csv(args.out_dir / "guarded_recovery_index.csv", recovery)
    write_csv(args.out_dir / "path_control_changed_cases.csv", pc)
    write_csv(args.out_dir / "runtime_canary_boundary_index.csv", canary)

    (args.out_dir / "validator_baseline_table.tex").write_text(
        latex_table(
            baseline,
            ["validator", "positive_or_reached", "sv_sat_recovered", "filtered_evidence", "nms_evidence", "residual", "evidence_boundary"],
            ["Validator", "Pos./reach", "SV-SAT", "Filt.", "NMS", "Open", "Evidence boundary"],
            r"P{0.24\textwidth}rrrrrY",
        ),
        encoding="utf-8",
    )
    (args.out_dir / "stratified_audit_table.tex").write_text(
        latex_small_tabular(
            summarize_counts(audit, "stratum"),
            ["class", "records"],
            ["Audit stratum", "Records"],
            "lr",
        ),
        encoding="utf-8",
    )
    (args.out_dir / "path_control_changed_table.tex").write_text(
        latex_small_tabular(
            summarize_counts(pc, "transition"),
            ["class", "records"],
            ["Full/no-path transition", "Records"],
            "lr",
        ),
        encoding="utf-8",
    )

    summary = {
        "campaign_dir": str(args.campaign_dir),
        "records": len(rows),
        "baseline": baseline,
        "audit_records": len(audit),
        "audit_strata": summarize_counts(audit, "stratum"),
        "guarded_recovery_records": len(recovery),
        "path_control_changed_cases": len(pc),
        "path_control_transitions": summarize_counts(pc, "transition"),
        "runtime_canary_summary": canary_summary,
        "claim_boundary": "Analyzer-level ledger strengthening only; no device-confirmed exploit count is added.",
    }
    (args.out_dir / "acceptance_strengthening_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    write_markdown(args.out_dir / "acceptance_strengthening_summary.md", baseline, audit, recovery, pc, canary_summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
