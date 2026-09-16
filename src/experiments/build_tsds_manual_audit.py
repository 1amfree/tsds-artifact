#!/usr/bin/env python3
"""Build a stratified TSDS evidence-audit package.

The generated package is an author-side manual/evidence audit, not a
device-level exploit validation.  It samples records from the full campaign and
checks whether each sampled trace contains the evidence required by its
reported sink-level verdict.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List


DEFAULT_STRATA = {
    "injectable": ("vulnerable", 50),
    "no_taint": ("no_taint_sink", 50),
    "filtered": ("filtered", 50),
    "residual": ("__residual__", 30),
}


def load_records(campaign_dir: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for path in sorted(campaign_dir.glob("*.results.jsonl")):
        target = path.name.replace(".results.jsonl", "")
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                record["_target"] = target
                record["_jsonl"] = path.name
                records.append(record)
    return records


def pick_stratified(records: List[Dict[str, Any]], limit: int, status: str) -> List[Dict[str, Any]]:
    if status == "__residual__":
        candidates = [r for r in records if r.get("status") in {"unreachable", "timeout"}]
    else:
        candidates = [r for r in records if r.get("status") == status]
    buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for record in sorted(candidates, key=lambda r: (r["_target"], int(r.get("closure_idx") or 0))):
        buckets[record["_target"]].append(record)
    selected: List[Dict[str, Any]] = []
    while len(selected) < limit:
        progressed = False
        for target in sorted(buckets):
            if buckets[target] and len(selected) < limit:
                selected.append(buckets[target].pop(0))
                progressed = True
        if not progressed:
            break
    return selected


def truthy_count(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, list):
        return len(value)
    return 0


def short(value: Any, limit: int = 180) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def audit_record(record: Dict[str, Any], stratum: str) -> Dict[str, Any]:
    status = record.get("status")
    tainted = int(record.get("tainted_byte_count") or len(record.get("tainted_offsets") or []))
    vulnerable_vectors = truthy_count(record.get("vulnerable_vectors"))
    secure_vectors = truthy_count(record.get("secure_vectors"))
    bypass = record.get("bypass_vector_categories") or []
    blocked = record.get("blocked_vector_categories") or []
    minimal = record.get("minimal_bypass_vector") or {}
    residual = record.get("residual_diagnosis_class") or ""
    stop = record.get("engine_stop_reason") or record.get("timeout_kind") or record.get("dynamic_unresolved_stop_reason") or ""
    source_obligation = record.get("source_obligation_class") or ""
    paper_bucket = record.get("paper_claim_bucket") or ""
    guarded_static = (
        str(record.get("analysis_recovery") or "").startswith("static_")
        and record.get("static_evidence_strength") == "strong"
        and bool(record.get("recovered_sink_template") or record.get("static_sink_template"))
    )

    checks: List[str] = []
    missing: List[str] = []

    def require(condition: bool, name: str) -> None:
        checks.append(name if condition else f"!{name}")
        if not condition:
            missing.append(name)

    if stratum == "injectable":
        require(status == "vulnerable", "status_vulnerable")
        require(tainted > 0 or guarded_static, "source_controlled_or_guarded_static_sink_bytes")
        require(vulnerable_vectors > 0, "sat_vector_witnesses")
        require(bool(minimal), "minimal_bypass_vector")
        require(bool(record.get("sink_preview")), "sink_preview")
    elif stratum == "filtered":
        require(status == "filtered", "status_filtered")
        require(tainted > 0, "source_controlled_sink_bytes")
        require(secure_vectors > 0 or bool(blocked), "blocked_vector_evidence")
        require(vulnerable_vectors == 0 and not bypass, "no_sat_vectors")
        require((record.get("sanitizer_gap_strength") == "fully_filtered") or secure_vectors > 0, "filtered_profile")
    elif stratum == "no_taint":
        require(status == "no_taint_sink", "status_no_taint")
        require(tainted == 0, "no_source_controlled_sink_bytes")
        require(vulnerable_vectors == 0 and not bypass, "no_sat_vectors")
        require(bool(record.get("no_taint_preview") or record.get("dynamic_no_taint_preview") or source_obligation or residual), "not_explanation")
        require(
            paper_bucket in {
                "no_modeled_source_evidence",
                "false_positive_reduction_evidence",
                "upstream_unbound_closure_evidence",
            }
            or bool(source_obligation),
            "not_bucket",
        )
    elif stratum == "residual":
        require(status in {"unreachable", "timeout"}, "residual_status")
        require(bool(residual), "residual_diagnosis")
        require(bool(stop or residual), "stop_reason")
        require(bool(record.get("residual_next_actions") or record.get("residual_plan_strategy") or record.get("model_gap_requests") or residual), "followup_obligation")
    else:
        raise ValueError(stratum)

    reviewer_verdict = "supports_tsds_verdict" if not missing else "needs_followup"
    return {
        "target": record["_target"],
        "closure_idx": record.get("closure_idx"),
        "stratum": stratum,
        "status": status,
        "reviewer_verdict": reviewer_verdict,
        "missing_checks": ";".join(missing),
        "checks": ";".join(checks),
        "confidence": record.get("evidence_confidence"),
        "paper_claim_bucket": paper_bucket,
        "tainted_byte_count": tainted,
        "vulnerable_vectors": vulnerable_vectors,
        "secure_vectors": secure_vectors,
        "bypass_categories": ",".join(bypass),
        "blocked_categories": ",".join(blocked),
        "minimal_bypass": short(minimal.get("poc") if isinstance(minimal, dict) else minimal, 80),
        "sink": short(record.get("sink_function") or record.get("sink_addr"), 80),
        "source": short(record.get("source_function") or record.get("source_addr"), 80),
        "trace": short(record.get("trace_summary"), 180),
        "sink_preview": short(record.get("sink_preview") or record.get("no_taint_preview") or record.get("dynamic_no_taint_preview"), 160),
        "residual_diagnosis": residual,
        "residual_summary": short(record.get("residual_diagnosis_summary"), 180),
        "stop_reason": short(stop, 120),
        "jsonl": record["_jsonl"],
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


def markdown_report(rows: List[Dict[str, Any]], campaign_dir: Path) -> str:
    total = Counter(row["reviewer_verdict"] for row in rows)
    by_stratum = Counter((row["stratum"], row["reviewer_verdict"]) for row in rows)
    lines = [
        "# TSDS Manual Evidence Audit",
        "",
        f"- Campaign directory: `{campaign_dir}`",
        "- Boundary: author-side sink-level evidence audit; not device-level exploit confirmation.",
        f"- Sampled records: `{len(rows)}`",
        f"- Verdict summary: `{dict(total)}`",
        "",
        "## Stratum Summary",
        "",
        "| Stratum | Supports | Needs follow-up |",
        "|---|---:|---:|",
    ]
    for stratum in ["injectable", "filtered", "no_taint", "residual"]:
        lines.append(
            f"| {stratum} | {by_stratum[(stratum, 'supports_tsds_verdict')]} | {by_stratum[(stratum, 'needs_followup')]} |"
        )
    lines.extend([
        "",
        "## Follow-up Items",
        "",
        "| Target | Closure | Stratum | Status | Missing checks | Trace |",
        "|---|---:|---|---|---|---|",
    ])
    followups = [row for row in rows if row["reviewer_verdict"] != "supports_tsds_verdict"]
    if not followups:
        lines.append("| -- | -- | -- | -- | -- | -- |")
    for row in followups[:80]:
        lines.append(
            f"| {row['target']} | {row['closure_idx']} | {row['stratum']} | {row['status']} | {row['missing_checks']} | {row['trace']} |"
        )
    lines.extend([
        "",
        "## Audited Sample",
        "",
        "| Target | Closure | Stratum | Verdict | Evidence | Trace |",
        "|---|---:|---|---|---|---|",
    ])
    for row in rows[:120]:
        evidence = f"taint={row['tainted_byte_count']}; sat={row['vulnerable_vectors']}; unsat={row['secure_vectors']}; bucket={row['paper_claim_bucket']}"
        lines.append(
            f"| {row['target']} | {row['closure_idx']} | {row['stratum']} | {row['reviewer_verdict']} | {evidence} | {row['trace']} |"
        )
    if len(rows) > 120:
        lines.append(f"| ... | ... | ... | ... | showing 120 of {len(rows)} | ... |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", default="experiment_reports/full_firmware_campaign_current_tsds_20260627")
    parser.add_argument("--out-dir", default="experiment_reports/manual_evidence_audit_20260628")
    parser.add_argument("--injectable", type=int, default=50)
    parser.add_argument("--no-taint", type=int, default=50)
    parser.add_argument("--filtered", type=int, default=50)
    parser.add_argument("--residual", type=int, default=30)
    args = parser.parse_args()

    campaign_dir = Path(args.campaign_dir)
    out_dir = Path(args.out_dir)
    records = load_records(campaign_dir)
    plan = {
        "injectable": ("vulnerable", args.injectable),
        "no_taint": ("no_taint_sink", args.no_taint),
        "filtered": ("filtered", args.filtered),
        "residual": ("__residual__", args.residual),
    }
    rows: List[Dict[str, Any]] = []
    for stratum, (status, limit) in plan.items():
        for record in pick_stratified(records, limit, status):
            rows.append(audit_record(record, stratum))
    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / "manual_evidence_audit.csv", rows)
    (out_dir / "manual_evidence_audit.md").write_text(markdown_report(rows, campaign_dir), encoding="utf-8")
    (out_dir / "manual_evidence_audit_summary.json").write_text(
        json.dumps(
            {
                "campaign_dir": str(campaign_dir),
                "sampled_records": len(rows),
                "verdicts": dict(Counter(row["reviewer_verdict"] for row in rows)),
                "by_stratum": {
                    stratum: dict(Counter(row["reviewer_verdict"] for row in rows if row["stratum"] == stratum))
                    for stratum in plan
                },
                "boundary": "author-side sink-level evidence audit; not device-level exploit confirmation",
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    print(out_dir / "manual_evidence_audit_summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
