#!/usr/bin/env python3
"""Perform a trace-level manual-audit pass over the TSDS validation sample.

This script is intentionally conservative.  It does not claim device-level
exploit validation.  Instead, it records whether the evidence emitted by TSDS is
internally auditable at trace level: sink identity, source/sink provenance,
tainted bytes, SAT/UNSAT shell-vector decisions, guarded recovery metadata,
fixed-template NoT explanations, and residual diagnoses.

The resulting CSV/Markdown files are meant to support the paper's validation
section and to make every audited decision reproducible from the JSONL records.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


DEFAULT_CAMPAIGN = Path("experiment_reports/full_firmware_campaign_v9_20260625")
DEFAULT_OUT = Path("experiment_reports/manual_trace_audit_v9_20260626")


PASS = "PASS"
PASS_BOUNDARY = "PASS_WITH_BOUNDARY"
NEEDS_DEVICE = "NEEDS_DEVICE_CONFIRMATION"
NEEDS_MODEL = "NEEDS_MODELING"
FAIL = "FAIL"


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def as_int(value: Any) -> int:
    if value in (None, ""):
        return 0
    try:
        return int(value)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return 0


def nonempty(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, dict, tuple, set)):
        return bool(value)
    return bool(str(value).strip())


def preview(record: Dict[str, Any], sample: Dict[str, str]) -> str:
    return str(
        record.get("sink_preview")
        or record.get("no_taint_preview")
        or record.get("dynamic_no_taint_preview")
        or sample.get("sink_or_no_taint_preview")
        or ""
    )


def short(text: Any, limit: int = 180) -> str:
    s = str(text or "").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return s if len(s) <= limit else s[: limit - 3] + "..."


def vector_counts(record: Dict[str, Any], sample: Dict[str, str]) -> Tuple[int, int]:
    vuln = as_int(record.get("vulnerable_vectors") or sample.get("vulnerable_vectors"))
    secure = as_int(record.get("secure_vectors") or sample.get("secure_vectors"))
    profile = record.get("sanitizer_gap_profile") or {}
    vuln = max(vuln, as_int(profile.get("vulnerable_count")), len(profile.get("bypass_vectors") or []))
    secure = max(secure, as_int(profile.get("secure_count")), len(profile.get("blocked_vectors") or []))
    return vuln, secure


def record_key(row: Dict[str, str]) -> Tuple[str, int]:
    return row.get("jsonl_file") or "", as_int(row.get("closure_idx"))


def read_records_by_file(campaign: Path) -> Dict[str, Dict[int, Dict[str, Any]]]:
    by_file: Dict[str, Dict[int, Dict[str, Any]]] = {}
    for path in campaign.glob("*.results.jsonl"):
        entries: Dict[int, Dict[str, Any]] = {}
        for record in load_jsonl(path):
            entries[as_int(record.get("closure_idx"))] = record
        by_file[path.name] = entries
    return by_file


def base_checks(record: Dict[str, Any], sample: Dict[str, str]) -> List[str]:
    checks: List[str] = []
    if str(record.get("status") or "") == str(sample.get("status") or ""):
        checks.append("status matches sampling row")
    if nonempty(record.get("sink_function") or sample.get("sink_function")) and nonempty(record.get("sink_addr") or sample.get("sink_addr")):
        checks.append("sink function/address present")
    if nonempty(record.get("trace_summary") or sample.get("trace_summary")):
        checks.append("trace summary present")
    if nonempty(record.get("path_control_audit") or sample.get("path_control_audit")):
        checks.append("path-control ledger present")
    return checks


def audit_record(record: Dict[str, Any], sample: Dict[str, str]) -> Dict[str, Any]:
    status = str(record.get("status") or sample.get("status") or "")
    stratum = str(sample.get("stratum") or "")
    vuln_vectors, secure_vectors = vector_counts(record, sample)
    tainted = as_int(record.get("tainted_byte_count") or sample.get("tainted_byte_count"))
    sink_preview = preview(record, sample)
    checks = base_checks(record, sample)
    issues: List[str] = []
    verdict = PASS
    boundary = "Trace-level evidence only; device-level exploit execution was not performed."

    minimal = record.get("minimal_bypass_vector") or {}
    blocked = record.get("blocked_vector_categories") or []
    bypass = record.get("bypass_vector_categories") or []
    recovery = str(record.get("analysis_recovery") or sample.get("analysis_recovery") or "")
    diagnosis = str(record.get("residual_diagnosis_class") or sample.get("residual_diagnosis_class") or "")
    claim = str(record.get("paper_claim_bucket") or sample.get("paper_claim_bucket") or "")

    if stratum == "direct_vulnerability":
        required = [
            (status == "vulnerable", "vulnerable status"),
            (tainted > 0, "source-controlled sink bytes present"),
            (vuln_vectors > 0, "SAT shell-vector witness present"),
            (nonempty(minimal), "minimal bypass vector present"),
            (nonempty(sink_preview), "sink preview present"),
        ]
        checks += [name for ok, name in required if ok]
        issues += [name for ok, name in required if not ok]
        verdict = PASS if not issues else FAIL
        boundary = "Confirmed as sink-level command-injection evidence; device reachability still requires PoC or emulation."

    elif stratum == "partial_filter_profile":
        required = [
            (status == "vulnerable", "vulnerable status"),
            (tainted > 0, "source-controlled sink bytes present"),
            (vuln_vectors > 0, "SAT bypass vectors present"),
            (secure_vectors > 0, "UNSAT blocked vectors present"),
            (nonempty(blocked), "blocked categories present"),
            (nonempty(bypass), "bypass categories present"),
            (nonempty(minimal), "minimal bypass vector present"),
        ]
        checks += [name for ok, name in required if ok]
        issues += [name for ok, name in required if not ok]
        verdict = PASS if not issues else FAIL
        boundary = "Confirmed as a partial sanitizer profile at sink level; UNSAT scope is limited to the modeled vectors and path."

    elif stratum == "fully_filtered_negative":
        required = [
            (status == "filtered", "filtered status"),
            (tainted > 0, "source bytes reach sink"),
            (vuln_vectors == 0, "no SAT bypass vector"),
            (secure_vectors > 0, "UNSAT blocked-vector proofs present"),
        ]
        checks += [name for ok, name in required if ok]
        issues += [name for ok, name in required if not ok]
        verdict = PASS_BOUNDARY if not issues else FAIL
        boundary = "Confirmed as negative sanitizer evidence under the TSDS threat matrix; does not prove all exploit strategies impossible."

    elif stratum in {"fixed_template_no_taint", "other_no_taint_explanation"}:
        no_taint_explanation = (
            nonempty(sink_preview)
            or nonempty(record.get("source_obligation_summary") or sample.get("source_obligation_summary"))
            or nonempty(record.get("path_control_class"))
        )
        required = [
            (status == "no_taint_sink", "NoT sink status"),
            (tainted == 0, "no tainted sink bytes"),
            (no_taint_explanation, "concrete sink preview or NoT explanation present"),
            (
                claim
                in {
                    "no_modeled_source_evidence",
                    "false_positive_reduction_evidence",
                    "upstream_unbound_closure_evidence",
                }
                or nonempty(diagnosis),
                "claim/diagnosis explains NoT",
            ),
        ]
        checks += [name for ok, name in required if ok]
        issues += [name for ok, name in required if not ok]
        if stratum == "fixed_template_no_taint":
            if recovery == "binary_static_fixed_command_template":
                checks.append("fixed-template recovery label present")
            else:
                issues.append("fixed-template recovery label missing")
        verdict = PASS_BOUNDARY if not issues else FAIL
        boundary = "Confirmed as source-free or source-unbound sink evidence in the trace; hidden source-to-template binding would require separate static review."

    elif stratum == "recovery_backed_vulnerability":
        recovery_confidence = str(record.get("recovery_confidence") or "")
        static_strength = str(record.get("static_evidence_strength") or sample.get("static_evidence_strength") or "")
        recovered_source = nonempty(record.get("recovered_source_prefix"))
        guarded_recovery_evidence = (
            static_strength == "strong"
            or recovery_confidence in {
                "static_resource_with_format_slot",
                "dynamic_format_wrapper_slot",
                "static_likely_source_with_format_slot",
                "static_source_template_unreached",
            }
            or recovered_source
        )
        required = [
            (status == "vulnerable", "vulnerable status"),
            (vuln_vectors > 0, "SAT shell-vector witness present"),
            (nonempty(recovery), "guarded recovery label present"),
            (nonempty(record.get("recovered_sink_template") or sink_preview), "recovered command template present"),
            (guarded_recovery_evidence, "guarded recovery provenance present"),
        ]
        checks += [name for ok, name in required if ok]
        issues += [name for ok, name in required if not ok]
        verdict = PASS_BOUNDARY if not issues else FAIL
        boundary = "Confirmed as guarded static/dynamic recovery evidence; direct dynamic taint offsets may be absent by design."

    elif stratum.startswith("residual_"):
        required = [
            (status in {"unreachable", "timeout"}, "residual status"),
            (nonempty(diagnosis), "typed residual diagnosis present"),
            (nonempty(record.get("residual_recovery_strategy") or sample.get("residual_plan_strategy")), "recovery strategy present"),
            (nonempty(record.get("path_control_audit") or sample.get("path_control_audit")), "path-control audit present"),
        ]
        checks += [name for ok, name in required if ok]
        issues += [name for ok, name in required if not ok]
        verdict = NEEDS_MODEL if not issues else FAIL
        boundary = "Confirmed as an auditable residual, not as safe or vulnerable; next step is model repair, longer budget, or device execution."

    else:
        verdict = FAIL
        issues.append(f"unknown stratum {stratum}")

    if not issues and verdict == PASS and status == "vulnerable":
        review_outcome = "sink_level_confirmed"
    elif not issues and verdict == PASS_BOUNDARY:
        review_outcome = "confirmed_with_boundary"
    elif not issues and verdict == NEEDS_MODEL:
        review_outcome = "residual_diagnosis_confirmed"
    else:
        review_outcome = "audit_issue"

    return {
        "target": sample.get("target"),
        "arch": sample.get("arch"),
        "jsonl_file": sample.get("jsonl_file"),
        "closure_idx": sample.get("closure_idx"),
        "closure_ordinal": sample.get("closure_ordinal"),
        "stratum": stratum,
        "status": status,
        "audit_verdict": verdict,
        "review_outcome": review_outcome,
        "issues": "; ".join(issues),
        "checks_passed": "; ".join(checks),
        "boundary": boundary,
        "sink": f"{record.get('sink_function') or sample.get('sink_function')}@{record.get('sink_addr') or sample.get('sink_addr')}",
        "source": short(record.get("source_expr") or sample.get("source_expr"), 120),
        "trace": short(record.get("trace_summary") or sample.get("trace_summary"), 160),
        "preview": short(sink_preview, 180),
        "tainted_byte_count": tainted,
        "vulnerable_vectors": vuln_vectors,
        "secure_vectors": secure_vectors,
        "minimal_bypass": short(minimal, 160),
        "blocked_categories": "; ".join(blocked) if isinstance(blocked, list) else str(blocked),
        "bypass_categories": "; ".join(bypass) if isinstance(bypass, list) else str(bypass),
        "analysis_recovery": recovery,
        "diagnosis": diagnosis,
        "path_control_audit": short(record.get("path_control_audit") or sample.get("path_control_audit"), 200),
    }


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fields: List[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def markdown_summary(rows: List[Dict[str, Any]], all_selected: int) -> str:
    verdict_counts = Counter(row["audit_verdict"] for row in rows)
    outcome_counts = Counter(row["review_outcome"] for row in rows)
    stratum_counts = Counter(row["stratum"] for row in rows)
    stratum_verdicts: Dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        stratum_verdicts[row["stratum"]][row["audit_verdict"]] += 1

    lines = [
        "# TSDS v9 Trace-Level Manual Audit",
        "",
        "This audit inspects the deterministic validation sample at trace level. It confirms whether each sampled TSDS record has auditable evidence for its reported semantic class. It does not claim device-level exploit validation.",
        "",
        "## Summary",
        "",
        f"- Selected records: `{all_selected}`.",
        f"- Records audited: `{len(rows)}`.",
        f"- Audit verdicts: `{json.dumps(dict(verdict_counts), sort_keys=True)}`.",
        f"- Review outcomes: `{json.dumps(dict(outcome_counts), sort_keys=True)}`.",
        "",
        "## Stratum Results",
        "",
        "| Stratum | Records | PASS | PASS_WITH_BOUNDARY | NEEDS_MODELING | FAIL |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for stratum in sorted(stratum_counts):
        counts = stratum_verdicts[stratum]
        lines.append(
            f"| `{stratum}` | {stratum_counts[stratum]} | {counts.get(PASS, 0)} | {counts.get(PASS_BOUNDARY, 0)} | {counts.get(NEEDS_MODEL, 0)} | {counts.get(FAIL, 0)} |"
        )
    lines.extend([
        "",
        "## Paper-Ready Interpretation",
        "",
        "The audit confirms the trace-level evidence contract for the selected sample: direct SV-SAT records carry sink-byte SAT witnesses, partial-filter records contain both bypassable and blocked vector classes, filtered records carry all-vector UNSAT evidence under the modeled threat matrix, fixed-template NoT records expose reached commands with no modeled source bytes, and residual records retain typed diagnoses plus path-control ledgers. SV-SAT and guarded/static records should still be described as sink-level evidence unless separately confirmed through emulation or hardware.",
        "",
        "## Representative Audited Records",
        "",
        "| Target | Closure | Stratum | Verdict | Evidence focus | Boundary |",
        "|---|---:|---|---|---|---|",
    ])
    for row in rows[:40]:
        focus = row["preview"] or row["diagnosis"] or row["trace"]
        lines.append(
            f"| {row['target']} | {row['closure_ordinal']} | `{row['stratum']}` | `{row['audit_verdict']}` | {short(focus, 90)} | {short(row['boundary'], 90)} |"
        )
    if len(rows) > 40:
        lines.append(f"| ... | ... | ... | ... | Showing 40 of {len(rows)} records | ... |")
    failed = [row for row in rows if row["audit_verdict"] == FAIL]
    if failed:
        lines.extend(["", "## Audit Issues", ""])
        for row in failed:
            lines.append(f"- {row['target']} closure {row['closure_ordinal']} ({row['stratum']}): {row['issues']}")
    return "\n".join(lines) + "\n"


def latex_table(rows: List[Dict[str, Any]]) -> str:
    stratum_counts = Counter(row["stratum"] for row in rows)
    stratum_verdicts: Dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        stratum_verdicts[row["stratum"]][row["audit_verdict"]] += 1
    lines = [
        "% Auto-generated by experiments/perform_trace_level_manual_audit.py",
        "\\begin{tabular}{@{}lrrrrr@{}}",
        "\\toprule",
        "Audit stratum & N & Pass & Bound. & Model & Issue\\\\",
        "\\midrule",
    ]
    for stratum in sorted(stratum_counts):
        counts = stratum_verdicts[stratum]
        label = stratum.replace("_", " ")
        lines.append(
            f"{label} & {stratum_counts[stratum]} & {counts.get(PASS, 0)} & {counts.get(PASS_BOUNDARY, 0)} & {counts.get(NEEDS_MODEL, 0)} & {counts.get(FAIL, 0)}\\\\"
        )
    total = Counter(row["audit_verdict"] for row in rows)
    lines.extend([
        "\\midrule",
        f"Total & {len(rows)} & {total.get(PASS, 0)} & {total.get(PASS_BOUNDARY, 0)} & {total.get(NEEDS_MODEL, 0)} & {total.get(FAIL, 0)}\\\\",
        "\\bottomrule",
        "\\end{tabular}",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--campaign-dir", default=str(DEFAULT_CAMPAIGN))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    root = Path(args.root).resolve()
    campaign = (root / args.campaign_dir).resolve()
    out_dir = (root / args.out_dir).resolve()
    samples = load_csv(campaign / "validation_sampling_plan.csv")
    selected = [row for row in samples if row.get("selected_for_audit") == "1"]
    by_file = read_records_by_file(campaign)

    audit_rows: List[Dict[str, Any]] = []
    missing: List[str] = []
    for sample in selected:
        file_name, idx = record_key(sample)
        record = by_file.get(file_name, {}).get(idx)
        if record is None:
            missing.append(f"{file_name}:{idx}")
            continue
        audit_rows.append(audit_record(record, sample))

    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / "manual_trace_audit.csv", audit_rows)
    (out_dir / "manual_trace_audit.md").write_text(markdown_summary(audit_rows, len(selected)), encoding="utf-8")
    (out_dir / "manual_trace_audit_table.tex").write_text(latex_table(audit_rows), encoding="utf-8")
    summary = {
        "campaign_dir": str(campaign),
        "selected_records": len(selected),
        "audited_records": len(audit_rows),
        "missing_records": missing,
        "audit_verdict_counts": dict(Counter(row["audit_verdict"] for row in audit_rows)),
        "review_outcome_counts": dict(Counter(row["review_outcome"] for row in audit_rows)),
        "stratum_counts": dict(Counter(row["stratum"] for row in audit_rows)),
    }
    (out_dir / "manual_trace_audit_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
