#!/usr/bin/env python3
"""Build non-paper evidence artifacts for an ICECCS revision.

This script prepares reviewer-response material from existing TSDS ledgers. It
does not edit the paper and does not create new exploit or device-confirmation
claims. The output is meant to make later paper revisions auditable:

* all recovered SV-SAT positives with manual-audit linkage when available,
* all full-vs-no-path-control changed cases,
* NMS confidence and boundary stratification,
* runtime/performance distributions,
* external-front-end adapter readiness,
* future runtime-validation candidate prioritization, and
* matrix-bounded threat-model coverage notes.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEFAULT_CAMPAIGN = Path("experiment_reports/full_firmware_campaign_current_tsds_20260627")
DEFAULT_PC_INPUTS = Path("experiment_reports/path_control_record_audit_20260629/inputs")
DEFAULT_CANARIES = Path("experiment_reports/runtime_canary_validation_cross_vendor_20260629/cross_vendor_runtime_canary_summary.json")
DEFAULT_MANUAL_TRACE_AUDIT = Path("experiment_reports/manual_trace_audit_v9_20260626/manual_trace_audit.csv")
DEFAULT_MANUAL_EVIDENCE_AUDIT = Path("experiment_reports/manual_evidence_audit_20260628/manual_evidence_audit.csv")
DEFAULT_OUT = Path("experiment_reports/iceccs_revision_preparation_pack_20260629")

DIRECT_MODE = "direct_observed_sink_byte"

RECOVERY_BOUNDARIES = {
    "static_dynamic_taint_reconciliation": (
        "dynamic sink callsite reached; command slot is reconciled with strong static source evidence"
    ),
    "static_sink_template_fallback": (
        "source-bearing static command template is retained as guarded sink-level evidence"
    ),
    "static_direct_source_fallback": (
        "direct source evidence is strong, but dynamic sink-byte source labels were not materialized"
    ),
}

KNOWN_MATRIX_LIMITS = [
    "quote-context and nested quoting semantics",
    "URL/double-decoding and multi-stage decoder chains",
    "option injection into non-shell command parsers",
    "vendor wrapper dialects beyond modeled system/popen-like shell invocation",
    "shell-dialect differences outside POSIX/BusyBox-ash-like token predicates",
    "payload meaning after command-specific length truncation",
]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_campaign(campaign_dir: Path) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(campaign_dir.glob("*.results.jsonl")):
        out[path.name.replace(".results.jsonl", "")] = read_jsonl(path)
    return out


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def load_csv_by_key(path: Path, key_fields: tuple[str, ...]) -> dict[tuple[str, ...], dict[str, str]]:
    if not path.exists():
        return {}
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        out: dict[tuple[str, ...], dict[str, str]] = {}
        for row in reader:
            key = tuple(str(row.get(field, "")) for field in key_fields)
            out[key] = row
        return out


def short(value: Any, limit: int = 140) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\n", r"\n").replace("\r", r"\r").replace("\t", r"\t")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def joined(values: Any, sep: str = "; ") -> str:
    if values is None:
        return ""
    if isinstance(values, (list, tuple, set)):
        return sep.join(str(v) for v in values)
    return str(values)


def tainted_span(row: dict[str, Any]) -> str:
    offsets = row.get("tainted_offsets") or []
    if not offsets:
        return ""
    try:
        values = [int(v) for v in offsets]
    except (TypeError, ValueError):
        return joined(offsets)
    return f"{min(values)}..{max(values)} ({len(values)} bytes)"


def record_key(target: str, row: dict[str, Any]) -> tuple[str, str]:
    return (f"{target}.results.jsonl", str(row.get("closure_idx")))


def manual_trace_row(
    target: str,
    row: dict[str, Any],
    manual_trace: dict[tuple[str, str], dict[str, str]],
) -> dict[str, str] | None:
    return manual_trace.get(record_key(target, row))


def manual_evidence_row(
    target: str,
    row: dict[str, Any],
    manual_evidence: dict[tuple[str, str], dict[str, str]],
) -> dict[str, str] | None:
    return manual_evidence.get((target, str(row.get("closure_idx"))))


def compatibility_facts(row: dict[str, Any]) -> list[str]:
    facts: list[str] = []
    if row.get("sink_addr") and row.get("sink_function"):
        facts.append("same_sink_callsite")
    if row.get("dynamic_no_taint_preview") or row.get("no_taint_preview"):
        facts.append("dynamic_template_observed")
    if row.get("recovered_sink_template"):
        facts.append("recovered_template_available")
    if str(row.get("static_evidence_strength") or "") == "strong":
        facts.append("strong_static_source_binding")
    if row.get("static_likely_inputs"):
        facts.append("ranked_likely_input")
    if row.get("tainted_byte_count"):
        facts.append("tainted_sink_offsets_reported")
    preview = str(row.get("dynamic_no_taint_preview") or row.get("no_taint_preview") or "")
    recovered = str(row.get("recovered_sink_template") or "")
    if "%s" in preview or "<recovered_" in recovered:
        facts.append("source_slot_alignment_marker")
    return facts


def recovery_risk(row: dict[str, Any], trace_audit: dict[str, str] | None) -> str:
    if trace_audit and trace_audit.get("audit_verdict") in {"PASS", "PASS_WITH_BOUNDARY"}:
        return "audited_low_under_sink_level_contract"
    if row.get("static_evidence_strength") == "strong" and row.get("evidence_confidence") == "high":
        return "ledger_low_pending_independent_audit"
    if row.get("static_evidence_strength") == "strong":
        return "ledger_medium_pending_independent_audit"
    return "high_review_priority"


def recovered_positive_rows(
    targets: dict[str, list[dict[str, Any]]],
    manual_trace: dict[tuple[str, str], dict[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    audit_counts: Counter[str] = Counter()
    for target, target_rows in targets.items():
        for row in target_rows:
            if row.get("status") != "vulnerable":
                continue
            mode = str(row.get("analysis_recovery") or DIRECT_MODE)
            if mode == DIRECT_MODE:
                continue
            audit = manual_trace_row(target, row, manual_trace)
            audit_label = (
                f"manual_trace_{audit.get('audit_verdict')}"
                if audit
                else "not_in_manual_trace_audit"
            )
            counts[mode] += 1
            audit_counts[audit_label] += 1
            minimal = row.get("minimal_bypass_vector") or {}
            rows.append(
                {
                    "target": target,
                    "closure_idx": row.get("closure_idx"),
                    "recovery_mode": mode,
                    "status": row.get("status"),
                    "evidence_confidence": row.get("evidence_confidence") or "",
                    "confidence_score": row.get("evidence_confidence_score") or "",
                    "recovery_confidence": row.get("recovery_confidence") or "",
                    "static_strength": row.get("static_evidence_strength") or "",
                    "static_reasons": joined(row.get("static_evidence_reasons")),
                    "static_likely_inputs": joined(row.get("static_likely_inputs")),
                    "static_possible_inputs": joined(row.get("static_possible_inputs")),
                    "source": row.get("source_addr") or "",
                    "source_function": row.get("source_function") or "",
                    "source_kinds": joined(row.get("source_kinds")),
                    "sink": row.get("sink_addr") or "",
                    "sink_function": row.get("sink_function") or "",
                    "trace": short(row.get("trace_summary"), 180),
                    "sink_preview": short(row.get("sink_preview"), 180),
                    "dynamic_preview": short(row.get("dynamic_no_taint_preview") or row.get("no_taint_preview"), 180),
                    "recovered_template": short(row.get("recovered_sink_template"), 180),
                    "tainted_span": tainted_span(row),
                    "bypass_categories": joined(row.get("bypass_vector_categories")),
                    "blocked_categories": joined(row.get("blocked_vector_categories")),
                    "minimal_vector": minimal.get("vector", ""),
                    "minimal_category": minimal.get("category", ""),
                    "compatibility_facts": joined(compatibility_facts(row)),
                    "manual_trace_audit": audit_label,
                    "manual_trace_outcome": (audit or {}).get("review_outcome", ""),
                    "risk_for_rebuttal": recovery_risk(row, audit),
                    "claim_boundary": RECOVERY_BOUNDARIES.get(mode, "guarded recovered sink-level evidence"),
                    "non_claim": "not device exploit proof; not shell execution confirmation",
                }
            )
    summary = [
        {"recovery_mode": mode, "records": count}
        for mode, count in sorted(counts.items(), key=lambda item: item[0])
    ]
    summary.extend(
        {"recovery_mode": f"audit::{label}", "records": count}
        for label, count in sorted(audit_counts.items(), key=lambda item: item[0])
    )
    return rows, summary


def nms_subtype(row: dict[str, Any]) -> str:
    diag = str(row.get("residual_diagnosis_class") or row.get("source_obligation_class") or "")
    if diag == "static_overapprox_no_taint":
        return "fixed_template_or_static_overapprox_nms"
    if diag == "mango_unbound_no_taint":
        return "upstream_unbound_candidate_nms"
    if diag == "resolved_source_dead":
        return "source_dead_after_liveness_nms"
    return "model_limited_source_free_callsite_nms"


def nms_confidence_band(row: dict[str, Any]) -> str:
    subtype = nms_subtype(row)
    confidence = str(row.get("evidence_confidence") or "unknown")
    if subtype == "fixed_template_or_static_overapprox_nms" and confidence in {"high", "medium"}:
        return "higher_confidence_for_tsds_contract"
    if subtype in {"upstream_unbound_candidate_nms", "source_dead_after_liveness_nms"} and confidence in {"high", "medium"}:
        return "medium_confidence_for_tsds_contract"
    return "model_limited_or_low_confidence"


def nms_rows(
    targets: dict[str, list[dict[str, Any]]],
    manual_evidence: dict[tuple[str, str], dict[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    summary_counts: Counter[tuple[str, str]] = Counter()
    manual_counts: Counter[str] = Counter()
    for target, target_rows in targets.items():
        for row in target_rows:
            if row.get("status") != "no_taint_sink":
                continue
            subtype = nms_subtype(row)
            band = nms_confidence_band(row)
            audit = manual_evidence_row(target, row, manual_evidence)
            audit_label = (
                f"manual_evidence_{audit.get('reviewer_verdict')}"
                if audit
                else "not_in_manual_evidence_sample"
            )
            summary_counts[(subtype, band)] += 1
            manual_counts[audit_label] += 1
            rows.append(
                {
                    "target": target,
                    "closure_idx": row.get("closure_idx"),
                    "subtype": subtype,
                    "confidence_band": band,
                    "evidence_confidence": row.get("evidence_confidence") or "",
                    "static_strength": row.get("static_evidence_strength") or "",
                    "diagnosis": row.get("residual_diagnosis_class") or row.get("source_obligation_class") or "",
                    "sink": row.get("sink_addr") or "",
                    "sink_function": row.get("sink_function") or "",
                    "source": row.get("source_addr") or "",
                    "trace": short(row.get("trace_summary"), 160),
                    "sink_preview": short(row.get("sink_preview") or row.get("no_taint_preview"), 180),
                    "stop_reason": row.get("engine_stop_reason") or "",
                    "manual_evidence_audit": audit_label,
                    "manual_checks": (audit or {}).get("checks", ""),
                    "claim_boundary": "no modeled source under TSDS abstraction; not a benignness proof",
                    "followup_if_challenged": nms_followup(subtype),
                }
            )
    summary = [
        {"subtype": subtype, "confidence_band": band, "records": count}
        for (subtype, band), count in sorted(summary_counts.items(), key=lambda item: (item[0][0], item[0][1]))
    ]
    summary.extend(
        {"subtype": f"audit::{label}", "confidence_band": "", "records": count}
        for label, count in sorted(manual_counts.items(), key=lambda item: item[0])
    )
    return rows, summary


def nms_followup(subtype: str) -> str:
    if subtype == "fixed_template_or_static_overapprox_nms":
        return "sample reverse engineering to confirm fixed command template or static over-approximation"
    if subtype == "upstream_unbound_candidate_nms":
        return "inspect front-end source binding and add source summary only if a real input exists"
    if subtype == "source_dead_after_liveness_nms":
        return "check path-control liveness ledger for premature source-dead classification"
    return "treat as model-limited until source/wrapper/parser summaries are audited"


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


def status_of(row: dict[str, Any] | None) -> str:
    return str((row or {}).get("status") or "missing")


def classify_pc_change(full: dict[str, Any] | None, no_path: dict[str, Any] | None) -> str:
    full_status = status_of(full)
    no_path_status = status_of(no_path)
    if full_status == "vulnerable" and no_path_status != "vulnerable":
        return "positive_lost_without_path_control"
    if full_status != "vulnerable" and no_path_status == "vulnerable":
        return "no_path_extra_positive_requires_review"
    if full_status in {"timeout", "unreachable"} or no_path_status in {"timeout", "unreachable"}:
        return "budget_or_reachability_boundary_change"
    return "resolved_semantic_signature_change"


def pc_changed_rows(input_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    summary_counts: Counter[tuple[str, str]] = Counter()
    for target, configs in sorted(load_pc_pairs(input_dir).items()):
        full = {r.get("closure_idx"): r for r in configs.get("full", [])}
        no_path = {r.get("closure_idx"): r for r in configs.get("no_path", [])}
        keys = sorted(set(full) | set(no_path), key=lambda x: -1 if x is None else int(x))
        for key in keys:
            f = full.get(key)
            n = no_path.get(key)
            if vector_signature(f) == vector_signature(n):
                continue
            change_class = classify_pc_change(f, n)
            transition = f"{status_of(f)} -> {status_of(n)}"
            summary_counts[(change_class, transition)] += 1
            rows.append(
                {
                    "target": target,
                    "closure_idx": key,
                    "change_class": change_class,
                    "transition_full_to_no_path": transition,
                    "full_stop": (f or {}).get("engine_stop_reason") or "",
                    "no_path_stop": (n or {}).get("engine_stop_reason") or "",
                    "full_pc_class": (f or {}).get("path_control_class") or "",
                    "no_path_pc_class": (n or {}).get("path_control_class") or "",
                    "full_bypass_categories": joined((f or {}).get("bypass_vector_categories")),
                    "no_path_bypass_categories": joined((n or {}).get("bypass_vector_categories")),
                    "full_blocked_categories": joined((f or {}).get("blocked_vector_categories")),
                    "no_path_blocked_categories": joined((n or {}).get("blocked_vector_categories")),
                    "sink": (f or n or {}).get("sink_addr") or "",
                    "sink_function": (f or n or {}).get("sink_function") or "",
                    "trace": short((f or n or {}).get("trace_summary"), 180),
                    "reviewer_soundness_note": pc_soundness_note(change_class),
                }
            )
    summary = [
        {"change_class": cls, "transition": transition, "records": count}
        for (cls, transition), count in sorted(summary_counts.items(), key=lambda item: (item[0][0], item[0][1]))
    ]
    return rows, summary


def pc_soundness_note(change_class: str) -> str:
    if change_class == "positive_lost_without_path_control":
        return "path control recovered sink-level evidence that the no-path run failed to reach"
    if change_class == "no_path_extra_positive_requires_review":
        return "review required before claiming path-control pruning preserved this candidate"
    if change_class == "budget_or_reachability_boundary_change":
        return "changed case is budget/reachability-sensitive, not a formal soundness proof"
    return "resolved signature changed; inspect vector sets before using in claims"


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    pos = (len(ordered) - 1) * pct / 100.0
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return ordered[int(pos)]
    return ordered[lo] * (hi - pos) + ordered[hi] * (pos - lo)


def distribution_row(scope: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    times = [float(r.get("elapsed_sec")) for r in rows if isinstance(r.get("elapsed_sec"), (int, float))]
    steps = [float(r.get("engine_steps_total") or r.get("engine_steps") or 0.0) for r in rows]
    statuses = Counter(str(r.get("status") or "") for r in rows)
    if not times:
        times = [0.0]
    return {
        "scope": scope,
        "records": len(rows),
        "mean_sec": round(sum(times) / len(times), 4),
        "median_sec": round(percentile(times, 50), 4),
        "p75_sec": round(percentile(times, 75), 4),
        "p90_sec": round(percentile(times, 90), 4),
        "p95_sec": round(percentile(times, 95), 4),
        "p99_sec": round(percentile(times, 99), 4),
        "max_sec": round(max(times), 4),
        "sv_sat": statuses.get("vulnerable", 0),
        "filtered": statuses.get("filtered", 0),
        "nms": statuses.get("no_taint_sink", 0),
        "unreachable": statuses.get("unreachable", 0),
        "timeout": statuses.get("timeout", 0),
        "mean_steps": round(sum(steps) / len(steps), 2) if steps else 0,
        "p95_steps": round(percentile(steps, 95), 2) if steps else 0,
    }


def performance_rows(targets: dict[str, list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    all_rows = [row for rows in targets.values() for row in rows]
    distribution = [distribution_row("all", all_rows)]
    for target, rows in sorted(targets.items()):
        distribution.append(distribution_row(target, rows))
    by_status: list[dict[str, Any]] = []
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in all_rows:
        grouped[str(row.get("status") or "unknown")].append(row)
    for status, rows in sorted(grouped.items()):
        by_status.append(distribution_row(f"status::{status}", rows))
    return distribution, by_status


def load_canary_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "positive_canaries": [],
            "boundary_probes": [],
            "positive_count": 0,
            "claim_boundary": "runtime canary summary missing",
        }
    return read_json(path)


def canary_callsite_set(canaries: dict[str, Any]) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for item in canaries.get("positive_canaries") or []:
        firmware = str(item.get("firmware") or "").lower().replace("-", "_")
        callsite = str(item.get("callsite") or "")
        if firmware and callsite:
            out.add((firmware, callsite.lower()))
    return out


def validation_candidate_score(row: dict[str, Any], mode: str) -> int:
    score = 0
    if mode == DIRECT_MODE:
        score += 25
    if row.get("evidence_confidence") == "high":
        score += 20
    elif row.get("evidence_confidence") == "medium":
        score += 10
    if row.get("closure_reachable_from_main") is True:
        score += 10
    if str(row.get("sink_function") or "").lower() in {"system", "popen", "twsystem", "dosystemcmd"}:
        score += 8
    trace_len = int(row.get("trace_len") or len(row.get("trace_nodes") or []) or 0)
    if trace_len <= 2:
        score += 8
    if len(row.get("bypass_vector_categories") or []) >= 5:
        score += 6
    elapsed = row.get("elapsed_sec")
    if isinstance(elapsed, (int, float)) and elapsed < 10:
        score += 5
    return score


def runtime_validation_candidates(
    targets: dict[str, list[dict[str, Any]]],
    canaries: dict[str, Any],
    limit: int = 25,
) -> list[dict[str, Any]]:
    existing = canary_callsite_set(canaries)
    rows: list[dict[str, Any]] = []
    for target, target_rows in targets.items():
        for row in target_rows:
            if row.get("status") != "vulnerable":
                continue
            mode = str(row.get("analysis_recovery") or DIRECT_MODE)
            sink = str(row.get("sink_addr") or "").lower()
            already_has_canary = (target.lower(), sink) in existing
            score = validation_candidate_score(row, mode) - (20 if already_has_canary else 0)
            level = "handler-level candidate" if row.get("closure_reachable_from_main") is True else "service-level/direct-entry candidate"
            rows.append(
                {
                    "priority_score": score,
                    "target": target,
                    "closure_idx": row.get("closure_idx"),
                    "suggested_level": level,
                    "recovery_mode": mode,
                    "evidence_confidence": row.get("evidence_confidence") or "",
                    "sink": row.get("sink_addr") or "",
                    "sink_function": row.get("sink_function") or "",
                    "source": row.get("source_addr") or "",
                    "trace": short(row.get("trace_summary"), 160),
                    "preview": short(row.get("sink_preview") or row.get("recovered_sink_template"), 180),
                    "bypass_categories": joined(row.get("bypass_vector_categories")),
                    "already_has_runtime_canary_callsite": already_has_canary,
                    "next_experiment": "qemu/gdb sink-callsite canary first; promote to rehosted handler/device only after fixture alignment",
                    "non_claim": "candidate selection only; not a completed validation",
                }
            )
    rows.sort(key=lambda r: (-int(r["priority_score"]), str(r["target"]), int(r["closure_idx"])))
    return rows[:limit]


def matrix_boundary_rows(targets: dict[str, list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    profile_rows: list[dict[str, Any]] = []
    summary_counts: Counter[str] = Counter()
    blocked_counter: Counter[str] = Counter()
    bypass_counter: Counter[str] = Counter()
    for target, target_rows in targets.items():
        for row in target_rows:
            if row.get("status") not in {"filtered", "vulnerable"} and not row.get("partially_filtered"):
                continue
            blocked = row.get("blocked_vector_categories") or []
            bypass = row.get("bypass_vector_categories") or []
            if row.get("status") == "filtered":
                cls = "all_modeled_vectors_unsat"
            elif row.get("partially_filtered"):
                cls = "mixed_sat_unsat_profile"
            else:
                cls = "sat_profile"
            summary_counts[cls] += 1
            blocked_counter.update(blocked)
            bypass_counter.update(bypass)
            if row.get("status") == "filtered" or row.get("partially_filtered"):
                profile_rows.append(
                    {
                        "target": target,
                        "closure_idx": row.get("closure_idx"),
                        "matrix_class": cls,
                        "status": row.get("status"),
                        "secure_vectors": row.get("secure_vectors") or 0,
                        "vulnerable_vectors": row.get("vulnerable_vectors") or 0,
                        "blocked_categories": joined(blocked),
                        "bypass_categories": joined(bypass),
                        "sink": row.get("sink_addr") or "",
                        "sink_function": row.get("sink_function") or "",
                        "preview": short(row.get("sink_preview"), 180),
                        "boundary": "matrix-bounded shell-vector feasibility only",
                    }
                )
    summary_rows = [{"metric": f"profile::{key}", "records": value} for key, value in sorted(summary_counts.items())]
    summary_rows.extend({"metric": f"blocked::{key}", "records": value} for key, value in sorted(blocked_counter.items()))
    summary_rows.extend({"metric": f"bypass::{key}", "records": value} for key, value in sorted(bypass_counter.items()))
    return profile_rows, summary_rows


def run_satc_smoke(root: Path, enabled: bool) -> dict[str, Any]:
    if not enabled:
        return {
            "run": False,
            "boundary": "SaTC adapter smoke test was not requested.",
        }
    cmd = [sys.executable, "-m", "unittest", "experiments.test_satc_adapter", "-v"]
    completed = subprocess.run(cmd, cwd=root, text=True, capture_output=True, timeout=90)
    return {
        "run": True,
        "command": " ".join(cmd),
        "returncode": completed.returncode,
        "passed": completed.returncode == 0,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "boundary": (
            "Smoke test validates SaTC-style closure normalization fixtures only; "
            "it is not an alternate-front-end accuracy study."
        ),
    }


def write_frontend_readiness(path: Path, satc: dict[str, Any]) -> None:
    lines = [
        "# External front-end readiness",
        "",
        satc["boundary"],
        "",
    ]
    if satc.get("run"):
        status = "passed" if satc.get("passed") else "failed"
        lines.extend(
            [
                f"- SaTC adapter smoke test: {status}",
                f"- Command: `{satc.get('command')}`",
                f"- Return code: {satc.get('returncode')}",
                "",
            ]
        )
    else:
        lines.append("- SaTC adapter smoke test was not run in this pack.")
    lines.extend(
        [
            "",
            "Required before a paper claim about front-end independence:",
            "- collect real SaTC/HermeScan/Karonte/LARA command-injection closures for the same firmware or a comparable firmware set;",
            "- normalize them into TSDS closure JSON without manually repairing source/sink addresses;",
            "- run TSDS and a naive guided sink-hook validator on the same candidates;",
            "- report per-front-end verdict rate, positive rate, residual causes, and manual-audit disagreements.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_runtime_gap_plan(path: Path, canaries: dict[str, Any], candidates: list[dict[str, Any]]) -> None:
    lines = [
        "# Runtime validation gap plan",
        "",
        str(canaries.get("claim_boundary") or "Runtime canaries are sink-callsite consistency checks only."),
        "",
        f"- Existing positive runtime canaries: {canaries.get('positive_count', 0)}",
        f"- Existing boundary probes: {len(canaries.get('boundary_probes') or [])}",
        "- Device-confirmed exploit claims prepared by this pack: 0",
        "",
        "Top future validation candidates are listed in `runtime_validation_candidate_plan.csv`.",
        "They are prioritized for fixture engineering; they are not completed validations.",
    ]
    if candidates:
        lines.extend(["", "Highest-priority candidates:"])
        for row in candidates[:8]:
            lines.append(
                f"- {row['target']} closure {row['closure_idx']} ({row['sink_function']}@{row['sink']}), "
                f"score {row['priority_score']}: {row['suggested_level']}"
            )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_matrix_boundary(path: Path, summary_rows: list[dict[str, Any]]) -> None:
    lines = [
        "# Matrix-bounded shell-vector profile",
        "",
        "The generated tables support a bounded claim: SAT/UNSAT is defined only for implemented POSIX/BusyBox-ash-like token predicates under the reached command template and TSDS path constraints.",
        "",
        "Known non-claims:",
    ]
    lines.extend(f"- {item}" for item in KNOWN_MATRIX_LIMITS)
    lines.extend(["", "Summary counters:", "", "| Metric | Records |", "|---|---:|"])
    for row in summary_rows:
        lines.append(f"| `{row['metric']}` | {row['records']} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_pack_summary(
    path: Path,
    recovered: list[dict[str, Any]],
    pc_rows: list[dict[str, Any]],
    nms: list[dict[str, Any]],
    perf: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    satc: dict[str, Any],
) -> None:
    global_perf = next((row for row in perf if row["scope"] == "all"), {})
    pc_counts = Counter(row["change_class"] for row in pc_rows)
    nms_counts = Counter(row["subtype"] for row in nms)
    rec_audit_counts = Counter(row["manual_trace_audit"] for row in recovered)
    lines = [
        "# ICECCS revision preparation pack",
        "",
        "This pack prepares evidence for a future paper revision. It does not modify paper files and does not add device-confirmed exploit claims.",
        "",
        "## Reviewer concern coverage",
        "",
        f"- Recovered positives: {len(recovered)} rows; audit linkage: {dict(rec_audit_counts)}.",
        f"- Path-control changed cases: {len(pc_rows)} rows; classes: {dict(pc_counts)}.",
        f"- NMS rows: {len(nms)} rows; subtypes: {dict(nms_counts)}.",
        f"- Runtime distribution: median {global_perf.get('median_sec')}s, p95 {global_perf.get('p95_sec')}s, max {global_perf.get('max_sec')}s over {global_perf.get('records')} records.",
        f"- Runtime validation candidates prepared: {len(candidates)}.",
        f"- SaTC adapter smoke: {'passed' if satc.get('passed') else ('not run' if not satc.get('run') else 'failed')}.",
        "",
        "## Remaining evidence gaps",
        "",
        "- Physical-device exploit confirmations remain 0 unless separate real-device or high-fidelity rehosting experiments are run.",
        "- SaTC adapter smoke testing does not establish full alternate-front-end accuracy.",
        "- NMS remains a no-modeled-source statement under TSDS abstraction, not benignness proof.",
        "- Path-control changed cases are empirical stability/sensitivity evidence, not a formal completeness proof.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_reviewer_question_map(path: Path) -> None:
    rows = [
        (
            "Real exploit/device ground truth",
            "runtime_validation_gap_plan.md; runtime_validation_candidate_plan.csv",
            "Prepared candidate prioritization and preserved the 6 qemu/gdb canary boundary.",
            "No physical-device exploit claim; device-confirmed exploit count remains 0.",
        ),
        (
            "Recovered SV-SAT false-positive risk",
            "recovered_positive_full_audit.csv; recovered_positive_summary.csv",
            "All 33 recovered positives are listed with source/sink/template facts and manual trace-audit linkage.",
            "Audit is sink-level PASS_WITH_BOUNDARY, not exploit confirmation.",
        ),
        (
            "Path-control soundness/sensitivity",
            "path_control_24_case_analysis.csv; path_control_24_case_summary.csv",
            "All 24 full-vs-no-path-control changed cases are categorized by transition and review risk.",
            "Empirical stability/sensitivity evidence only; not a formal completeness proof.",
        ),
        (
            "NMS ambiguity",
            "nms_confidence_grounding.csv; nms_confidence_summary.csv",
            "All 146 NMS records are split into fixed-template/static-overapprox, upstream-unbound, source-dead, and model-limited rows.",
            "NMS remains no modeled source under TSDS abstraction, not benignness proof.",
        ),
        (
            "Runtime/scalability distribution",
            "performance_distribution.csv; performance_by_status.csv",
            "Adds median, p75, p90, p95, p99, max, status counts, and step distribution.",
            "Distribution describes current corpus only.",
        ),
        (
            "Shell-vector matrix boundary",
            "matrix_boundary_profile.md; matrix_boundary_profile.csv; matrix_boundary_summary.csv",
            "Separates all-modeled-vectors-UNSAT, mixed SAT/UNSAT, and SAT profiles with modeled-category counters.",
            "Does not cover quote context, decoder chains, option injection, or unmodeled shell dialects.",
        ),
        (
            "External front-end readiness",
            "external_frontend_readiness.md; satc_adapter_smoke.json",
            "SaTC fixture converter smoke test is run and recorded.",
            "Smoke test is not a SaTC/HermeScan/Karonte/LARA accuracy study.",
        ),
        (
            "Competitive baselines",
            "../iceccs_strengthening_pack_20260629/validator_baselines.csv",
            "Existing evidence pack contains static-only, no-summary sink hook, coarse metacharacter, direct-only, no-path, and full TSDS comparisons.",
            "Still not a full external-tool comparison.",
        ),
    ]
    lines = [
        "# Reviewer question to artifact map",
        "",
        "| Reviewer concern | Prepared artifacts | What this supports | Boundary still to state |",
        "|---|---|---|---|",
    ]
    for concern, artifacts, support, boundary in rows:
        lines.append(f"| {concern} | `{artifacts}` | {support} | {boundary} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, default=DEFAULT_CAMPAIGN)
    parser.add_argument("--pc-input-dir", type=Path, default=DEFAULT_PC_INPUTS)
    parser.add_argument("--runtime-canary-summary", type=Path, default=DEFAULT_CANARIES)
    parser.add_argument("--manual-trace-audit", type=Path, default=DEFAULT_MANUAL_TRACE_AUDIT)
    parser.add_argument("--manual-evidence-audit", type=Path, default=DEFAULT_MANUAL_EVIDENCE_AUDIT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--run-satc-adapter-smoke", action="store_true")
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    targets = load_campaign(args.campaign_dir)
    manual_trace = load_csv_by_key(args.manual_trace_audit, ("jsonl_file", "closure_idx"))
    manual_evidence = load_csv_by_key(args.manual_evidence_audit, ("target", "closure_idx"))
    canaries = load_canary_summary(args.runtime_canary_summary)

    recovered, recovered_summary = recovered_positive_rows(targets, manual_trace)
    nms_detail, nms_summary = nms_rows(targets, manual_evidence)
    pc_detail, pc_summary = pc_changed_rows(args.pc_input_dir)
    perf_target, perf_status = performance_rows(targets)
    candidates = runtime_validation_candidates(targets, canaries)
    matrix_detail, matrix_summary = matrix_boundary_rows(targets)
    satc = run_satc_smoke(args.root, args.run_satc_adapter_smoke)

    write_csv(args.out_dir / "recovered_positive_full_audit.csv", recovered)
    write_csv(args.out_dir / "recovered_positive_summary.csv", recovered_summary)
    write_csv(args.out_dir / "nms_confidence_grounding.csv", nms_detail)
    write_csv(args.out_dir / "nms_confidence_summary.csv", nms_summary)
    write_csv(args.out_dir / "path_control_24_case_analysis.csv", pc_detail)
    write_csv(args.out_dir / "path_control_24_case_summary.csv", pc_summary)
    write_csv(args.out_dir / "performance_distribution.csv", perf_target)
    write_csv(args.out_dir / "performance_by_status.csv", perf_status)
    write_csv(args.out_dir / "runtime_validation_candidate_plan.csv", candidates)
    write_csv(args.out_dir / "matrix_boundary_profile.csv", matrix_detail)
    write_csv(args.out_dir / "matrix_boundary_summary.csv", matrix_summary)
    (args.out_dir / "satc_adapter_smoke.json").write_text(json.dumps(satc, indent=2), encoding="utf-8")

    write_frontend_readiness(args.out_dir / "external_frontend_readiness.md", satc)
    write_runtime_gap_plan(args.out_dir / "runtime_validation_gap_plan.md", canaries, candidates)
    write_matrix_boundary(args.out_dir / "matrix_boundary_profile.md", matrix_summary)
    write_reviewer_question_map(args.out_dir / "reviewer_question_to_artifact_map.md")
    write_pack_summary(
        args.out_dir / "revision_preparation_summary.md",
        recovered,
        pc_detail,
        nms_detail,
        perf_target,
        candidates,
        satc,
    )

    combined = {
        "claim_boundary": "Analyzer-level evidence preparation only; no paper files edited; device-confirmed exploits remain 0.",
        "records": sum(len(rows) for rows in targets.values()),
        "recovered_positive_rows": len(recovered),
        "path_control_changed_rows": len(pc_detail),
        "nms_rows": len(nms_detail),
        "runtime_candidate_rows": len(candidates),
        "satc_adapter_smoke": satc,
        "performance_global": next((row for row in perf_target if row["scope"] == "all"), {}),
    }
    (args.out_dir / "revision_preparation_pack.json").write_text(
        json.dumps(combined, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(args.out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
