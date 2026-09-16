#!/usr/bin/env python3
"""Build urgent reviewer-response experiments for the TSDS ICECCS submission.

This pack focuses on the highest-risk review concerns left after the main
acceptance-strengthening pack:

* all admitted guarded/recovered SV-SAT records and rejected recovery attempts,
* all 24 full-vs-no-path-control changed cases with claim impact labels, and
* a compact index to the executable threat-matrix boundary suite.

The script derives evidence from existing TSDS ledgers. It does not add
device-confirmed exploit claims.
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
DEFAULT_OUT = Path("experiment_reports/iceccs_urgent_validation_pack_20260702")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


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


def short(value: Any, limit: int = 130) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\n", r"\n").replace("\r", r"\r").replace("\t", r"\t")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def joined(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return "; ".join(str(v) for v in value)
    return str(value)


def load_campaign(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in sorted(path.glob("*.results.jsonl")):
        target = item.name.replace(".results.jsonl", "")
        for row in read_jsonl(item):
            out = dict(row)
            out["_target"] = target
            rows.append(out)
    return rows


def compatibility_gate(row: dict[str, Any]) -> str:
    mode = str(row.get("analysis_recovery") or "")
    if mode == "static_dynamic_taint_reconciliation":
        return "dynamic sink reached; no-taint preview has source slot; static source evidence binds the slot"
    if mode == "static_sink_template_fallback":
        return "source-bearing static command template is retained; sink wrapper/callsite is compatible"
    if mode == "static_direct_source_fallback":
        return "direct static source expression is present; dynamic byte label was not materialized"
    return "direct dynamic sink-byte observation"


def compatibility_facts(row: dict[str, Any]) -> list[str]:
    facts: list[str] = []
    if row.get("sink_addr") and row.get("sink_function"):
        facts.append("same_sink_callsite")
    if row.get("dynamic_no_taint_preview") or row.get("no_taint_preview"):
        facts.append("dynamic_preview_available")
    if row.get("recovered_sink_template"):
        facts.append("recovered_template")
    if row.get("static_sink_template"):
        facts.append("static_template")
    if row.get("static_evidence_strength") == "strong":
        facts.append("strong_static_evidence")
    if row.get("static_likely_inputs"):
        facts.append("ranked_likely_input")
    preview = str(row.get("dynamic_no_taint_preview") or row.get("no_taint_preview") or "")
    recovered = str(row.get("recovered_sink_template") or "")
    if "%s" in preview or "<recovered_" in recovered or "<source>" in recovered:
        facts.append("source_slot_marker")
    return facts


def build_recovery_admission_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        if row.get("status") != "vulnerable":
            continue
        mode = str(row.get("analysis_recovery") or "")
        if not mode:
            continue
        out.append(
            {
                "target": row.get("_target"),
                "closure_idx": row.get("closure_idx"),
                "mode": mode,
                "evidence_confidence": row.get("evidence_confidence") or "",
                "recovery_confidence": row.get("recovery_confidence") or "",
                "static_strength": row.get("static_evidence_strength") or "",
                "compatibility_gate": compatibility_gate(row),
                "compatibility_facts": joined(compatibility_facts(row)),
                "sink": f"{row.get('sink_function')}@{row.get('sink_addr')}",
                "source": f"{row.get('source_function')}@{row.get('source_addr')}",
                "dynamic_preview": short(row.get("dynamic_no_taint_preview") or row.get("no_taint_preview")),
                "recovered_template": short(row.get("recovered_sink_template") or row.get("sink_preview")),
                "static_template": short(row.get("static_sink_template")),
                "minimal_vector": (row.get("minimal_bypass_vector") or {}).get("vector", ""),
                "bypass_categories": joined(row.get("bypass_vector_categories")),
                "admission": "admitted_to_sv_sat",
                "claim_boundary": "guarded sink-level evidence; not direct device exploit proof",
            }
        )
    return sorted(out, key=lambda r: (str(r["target"]), int(r["closure_idx"] or 0)))


def build_recovery_rejected_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        reason = row.get("recovery_blocked_reason")
        if not reason:
            continue
        out.append(
            {
                "target": row.get("_target"),
                "closure_idx": row.get("closure_idx"),
                "status": row.get("status"),
                "blocked_reason": reason,
                "static_strength": row.get("static_evidence_strength") or "",
                "static_possible_inputs": joined(row.get("static_possible_inputs")),
                "static_likely_inputs": joined(row.get("static_likely_inputs")),
                "sink": f"{row.get('sink_function')}@{row.get('sink_addr')}",
                "dynamic_preview": short(row.get("dynamic_no_taint_preview") or row.get("no_taint_preview") or row.get("sink_preview")),
                "static_template": short(row.get("static_sink_template")),
                "decision": "not_promoted_to_sv_sat",
                "claim_boundary": "rejected recovery remains NMS/residual unless direct source-byte evidence appears",
            }
        )
    return sorted(out, key=lambda r: (str(r["target"]), int(r["closure_idx"] or 0)))


def load_pc_pairs(input_dir: Path) -> dict[str, dict[str, list[dict[str, Any]]]]:
    pairs: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(dict)
    for path in sorted(input_dir.glob("*.results.jsonl")):
        name = path.name.replace(".results.jsonl", "")
        if name.endswith("_full"):
            pairs[name[: -len("_full")]]["full"] = read_jsonl(path)
        elif name.endswith("_no_path_control"):
            pairs[name[: -len("_no_path_control")]]["no_path"] = read_jsonl(path)
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


def pc_claim_impact(full: dict[str, Any] | None, no_path: dict[str, Any] | None) -> tuple[str, str]:
    f = status(full)
    n = status(no_path)
    if f == "vulnerable" and n != "vulnerable":
        return (
            "full_positive_no_path_residual",
            "path-control-enabled run reached direct sink evidence; no-path run did not refute it",
        )
    if f != "vulnerable" and n == "vulnerable":
        return (
            "manual_review_only_extra_positive",
            "excluded from TSDS positive aggregate until the path-control discrepancy is resolved",
        )
    if f in {"timeout", "unreachable"} and n in {"timeout", "unreachable"}:
        return (
            "residual_boundary_shift",
            "changes residual subtype only; does not affect positive or filtered aggregate",
        )
    if f == "timeout" and n == "no_taint_sink":
        return (
            "no_path_resolves_to_nms",
            "no-path run produced NMS, but full run remains conservative residual",
        )
    if f == "unreachable" and n == "filtered":
        return (
            "no_path_resolves_to_filtered",
            "no-path run produced matrix-bounded negative evidence, but full run remains conservative residual",
        )
    if f == "no_taint_sink" and n in {"timeout", "unreachable"}:
        return (
            "full_nms_no_path_residual",
            "path-control-enabled run reached NMS evidence; no-path run did not refute it",
        )
    return (
        "resolved_signature_change",
        "requires ledger inspection before using in aggregate claims",
    )


def build_pc_rows(input_dir: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for target, pair in sorted(load_pc_pairs(input_dir).items()):
        full = {row.get("closure_idx"): row for row in pair.get("full", [])}
        no_path = {row.get("closure_idx"): row for row in pair.get("no_path", [])}
        for idx in sorted(set(full) | set(no_path), key=lambda x: int(x or -1)):
            f = full.get(idx)
            n = no_path.get(idx)
            if vector_signature(f) == vector_signature(n):
                continue
            impact, interpretation = pc_claim_impact(f, n)
            out.append(
                {
                    "target": target,
                    "closure_idx": idx,
                    "transition": f"{status(f)}->{status(n)}",
                    "claim_impact": impact,
                    "interpretation": interpretation,
                    "full_stop": (f or {}).get("engine_stop_reason") or "",
                    "no_path_stop": (n or {}).get("engine_stop_reason") or "",
                    "full_pc_class": (f or {}).get("path_control_class") or "",
                    "no_path_pc_class": (n or {}).get("path_control_class") or "",
                    "sink": f"{(f or n or {}).get('sink_function')}@{(f or n or {}).get('sink_addr')}",
                    "trace": short((f or n or {}).get("trace_summary")),
                    "full_vectors": joined((f or {}).get("bypass_vector_categories")),
                    "no_path_vectors": joined((n or {}).get("bypass_vector_categories")),
                    "review_action": "manual_review" if impact == "manual_review_only_extra_positive" else "documented_sensitivity",
                }
            )
    return out


def write_markdown(
    path: Path,
    recovery: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    pc_rows: list[dict[str, Any]],
    matrix_summary: dict[str, Any],
) -> None:
    recovery_modes = Counter(row["mode"] for row in recovery)
    rejected_reasons = Counter(row["blocked_reason"] for row in rejected)
    pc_impacts = Counter(row["claim_impact"] for row in pc_rows)
    lines = [
        "# ICECCS urgent validation pack",
        "",
        "This pack targets the highest-risk review concerns without adding device-level exploit claims.",
        "",
        "## Guarded recovery",
        "",
        f"- Admitted recovered SV-SAT records: `{len(recovery)}`",
        f"- Modes: `{dict(recovery_modes)}`",
        f"- Rejected recovery attempts recorded in final ledgers: `{len(rejected)}`",
        f"- Rejection reasons: `{dict(rejected_reasons)}`",
        "",
        "## Path-control sensitivity",
        "",
        f"- Changed full/no-path-control cases: `{len(pc_rows)}`",
        f"- Claim impacts: `{dict(pc_impacts)}`",
        "",
        "## Executable threat-matrix boundary suite",
        "",
        f"- Cases: `{matrix_summary.get('total_cases', 0)}`",
        f"- Passed: `{matrix_summary.get('passed_cases', 0)}`",
        f"- Boundary: `{matrix_summary.get('claim_boundary', 'not run')}`",
        "",
        "## Non-claims",
        "",
        "- No device-confirmed exploit count is added.",
        "- Runtime canary count is not increased by this pack.",
        "- Path-control analysis is sensitivity evidence, not a completeness proof.",
        "- Threat-matrix tests exercise byte predicates, not a full shell parser.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign-dir", type=Path, default=DEFAULT_CAMPAIGN)
    ap.add_argument("--pc-input-dir", type=Path, default=DEFAULT_PC_INPUTS)
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    rows = load_campaign(args.campaign_dir)
    recovery = build_recovery_admission_rows(rows)
    rejected = build_recovery_rejected_rows(rows)
    pc_rows = build_pc_rows(args.pc_input_dir)
    matrix_summary = read_json(args.out_dir / "threat_matrix_executable_summary.json")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.out_dir / "guarded_recovery_admission_audit.csv", recovery)
    write_csv(args.out_dir / "guarded_recovery_rejected_attempts.csv", rejected)
    write_csv(args.out_dir / "path_control_claim_impact_analysis.csv", pc_rows)

    summary = {
        "records": len(rows),
        "guarded_recovery_admitted": len(recovery),
        "guarded_recovery_modes": dict(Counter(row["mode"] for row in recovery)),
        "guarded_recovery_rejected_attempts": len(rejected),
        "guarded_recovery_rejection_reasons": dict(Counter(row["blocked_reason"] for row in rejected)),
        "path_control_changed_cases": len(pc_rows),
        "path_control_claim_impacts": dict(Counter(row["claim_impact"] for row in pc_rows)),
        "threat_matrix_executable_summary": matrix_summary,
        "claim_boundary": "Analyzer-level reviewer-response experiments only; no device exploit claims.",
    }
    (args.out_dir / "urgent_validation_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    write_markdown(args.out_dir / "urgent_validation_summary.md", recovery, rejected, pc_rows, matrix_summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
