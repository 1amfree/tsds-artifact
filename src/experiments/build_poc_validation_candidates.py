#!/usr/bin/env python3
"""Select high-value TSDS findings for emulation or device-level validation.

The output is a validation worklist, not an exploit pack.  It preserves the
paper's evidence boundary: TSDS currently proves sink-level command-injection
semantics.  Device or emulation validation must be performed in an isolated
lab with benign canary commands only.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


DEFAULT_CAMPAIGN = Path("experiment_reports/full_firmware_campaign_v9_20260625")
DEFAULT_AUDIT = Path("experiment_reports/manual_trace_audit_v9_20260626/manual_trace_audit.csv")
DEFAULT_OUT = Path("experiment_reports/poc_validation_candidates_v9_20260626")


TARGET_DISPLAY = {
    "asus_rt_be57": "ASUS RT-BE57",
    "dir878": "D-Link DIR-878",
    "r6400v2": "Netgear R6400v2",
    "r7000": "Netgear R7000",
    "tenda_ac15": "Tenda AC15",
    "tenda_ac18": "Tenda AC18",
    "tenda_w20e": "Tenda W20E",
    "xr300": "Netgear XR300",
}


def load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


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


def short(text: Any, limit: int = 160) -> str:
    s = printable(text)
    return s if len(s) <= limit else s[: limit - 3] + "..."


def printable(text: Any) -> str:
    """Render arbitrary analyzer strings without raw control characters."""
    if text is None:
        return ""
    out: List[str] = []
    for ch in str(text):
        code = ord(ch)
        if ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif code < 32 or code == 127:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


def md_text(text: Any, limit: int = 160) -> str:
    return html.escape(short(text, limit)).replace("|", "&#124;")


def md_code(text: Any, limit: int = 160) -> str:
    s = short(text, limit)
    if not s:
        s = "<empty>"
    return f"<code>{html.escape(s)}</code>"


def latex_escape(text: Any, limit: int = 160) -> str:
    s = short(text, limit)
    mapping = {
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
        "<": r"\textless{}",
        ">": r"\textgreater{}",
    }
    return "".join(mapping.get(ch, ch) for ch in s)


def load_records_by_key(campaign: Path) -> Dict[Tuple[str, int], Dict[str, Any]]:
    records: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for path in campaign.glob("*.results.jsonl"):
        for record in load_jsonl(path):
            records[(path.name, as_int(record.get("closure_idx")))] = record
    return records


def list_value(record: Dict[str, Any], *keys: str) -> List[str]:
    values: List[str] = []
    for key in keys:
        raw = record.get(key)
        if isinstance(raw, list):
            values.extend(str(item) for item in raw if str(item).strip())
        elif raw:
            values.append(str(raw))
    return values


def source_clues(record: Dict[str, Any]) -> List[str]:
    clues = list_value(
        record,
        "static_likely_inputs",
        "static_possible_inputs",
        "static_source_markers",
        "static_likely_source_markers",
        "static_possible_source_markers",
    )
    static = record.get("static_evidence") or {}
    if isinstance(static, dict):
        for key in [
            "static_likely_inputs",
            "static_possible_inputs",
            "static_source_markers",
            "static_likely_source_markers",
            "static_possible_source_markers",
        ]:
            raw = static.get(key)
            if isinstance(raw, list):
                clues.extend(str(item) for item in raw if str(item).strip())
    deduped: List[str] = []
    for item in clues:
        if item not in deduped:
            deduped.append(item)
    return deduped


def candidate_score(record: Dict[str, Any], audit: Dict[str, str]) -> int:
    score = 0
    stratum = audit.get("stratum") or ""
    confidence = str(record.get("evidence_confidence") or "")
    source_fn = str(record.get("source_function") or "")
    sink_fn = str(record.get("sink_function") or "")
    preview = str(record.get("sink_preview") or audit.get("preview") or "")
    recovery = str(record.get("analysis_recovery") or "")
    static_strength = str(record.get("static_evidence_strength") or "")
    vuln_vectors = as_int(record.get("vulnerable_vectors") or audit.get("vulnerable_vectors"))
    secure_vectors = as_int(record.get("secure_vectors") or audit.get("secure_vectors"))

    if stratum == "partial_filter_profile":
        score += 45
    elif stratum == "recovery_backed_vulnerability":
        score += 38
    elif stratum == "direct_vulnerability":
        score += 32
    if confidence == "high":
        score += 18
    elif confidence == "medium":
        score += 8
    if static_strength == "strong":
        score += 16
    elif static_strength == "weak":
        score += 5
    if source_fn.startswith("form"):
        score += 15
    if source_fn.startswith("start_") or "DDNS" in source_fn:
        score += 10
    if "doSystemCmd" in sink_fn or sink_fn == "system":
        score += 8
    if preview and "<recovered" not in preview:
        score += 8
    if recovery:
        score += 8
    if vuln_vectors >= 8:
        score += 6
    if secure_vectors > 0:
        score += 6
    if source_clues(record):
        score += 6
    return score


def validation_readiness(record: Dict[str, Any], audit: Dict[str, str]) -> Tuple[str, str]:
    source_fn = str(record.get("source_function") or "")
    trace = str(record.get("trace_summary") or "")
    clues = source_clues(record)
    recovery = str(record.get("analysis_recovery") or "")
    if source_fn.startswith("form") and clues:
        return "high", "web-handler style source with named configuration/input clues"
    if "DDNS" in trace or "DDNS" in ";".join(clues):
        return "high", "service-specific DDNS path with named NVRAM/config clues"
    if recovery in {"static_sink_template_fallback", "static_direct_source_fallback"} and clues:
        return "medium", "guarded static recovery has named source clues but needs endpoint mapping"
    if recovery == "static_dynamic_taint_reconciliation":
        return "medium", "dynamic format/template recovery is strong enough for harness validation"
    return "medium", "sink-level evidence is strong, but external trigger mapping must be recovered"


def safe_validation_goal(record: Dict[str, Any]) -> str:
    minimal = record.get("minimal_bypass_vector") or {}
    category = minimal.get("category") or "shell metacharacter"
    return (
        "In isolated emulation only, replace the symbolic payload class "
        f"({category}) with a benign canary command that writes a unique marker "
        "under /tmp; confirm marker creation and command template context."
    )


def validation_family(record: Dict[str, Any], audit: Dict[str, str]) -> str:
    source = printable(record.get("source_function") or audit.get("trace") or "")
    sink = printable(record.get("sink_function") or audit.get("sink") or "")
    evidence = printable(audit.get("stratum") or "")
    preview = printable(record.get("sink_preview") or audit.get("preview") or "")
    preview = preview.replace("<recovered_config>", "<recovered>").replace("<recovered_source>", "<recovered>")
    preview = " ".join(preview.split())[:72]
    return "|".join([audit.get("target") or "", evidence, source, sink, preview])


def functional_theme(record: Dict[str, Any], audit: Dict[str, str]) -> str:
    text = " ".join(
        printable(item).lower()
        for item in [
            record.get("source_function"),
            record.get("trace_summary"),
            record.get("sink_preview"),
            audit.get("trace"),
            audit.get("preview"),
            ";".join(source_clues(record)),
        ]
    )
    checks = [
        ("ddns", ["ddns"]),
        ("firewall-iptables", ["iptables", "firewall", "icmp-type", "pingwan"]),
        ("samba", ["samba"]),
        ("iptv", ["iptv", "stballvlan", "stbpvid"]),
        ("macfilter", ["macfilter"]),
        ("webpush-image", ["webpush", ".jpg", "/var/wewifi"]),
        ("firmware-version-check", ["ver_check", "https_svr", "stringtable", "ftp_username"]),
        ("ftpc-process-cleanup", ["ftpc.pid", "/var/run/ftpc.pid"]),
        ("wget-process-cleanup", ["wget.pid", "wget-log"]),
        ("guest-lan", ["wlan_guest", "lan0_port_member", "lan1_port_member", "lan2_port_member", "lan3_port_member"]),
        ("routing-web", ["static_route", "str_routes", "ripd"]),
        ("user-file", ["fgets", "fread", "udiskname"]),
    ]
    for theme, needles in checks:
        if any(needle in text for needle in needles):
            return theme
    return "unmapped-service"


def functional_family(record: Dict[str, Any], audit: Dict[str, str]) -> str:
    return "|".join([
        audit.get("target") or "",
        printable(audit.get("stratum") or ""),
        functional_theme(record, audit),
    ])


def make_candidate(record: Dict[str, Any], audit: Dict[str, str], rank: int) -> Dict[str, Any]:
    readiness, readiness_reason = validation_readiness(record, audit)
    minimal = record.get("minimal_bypass_vector") or {}
    blocked = record.get("blocked_vector_categories") or []
    bypass = record.get("bypass_vector_categories") or []
    clues = source_clues(record)
    target = audit.get("target") or TARGET_DISPLAY.get(Path(audit.get("jsonl_file", "")).stem.replace(".results", ""), "")
    return {
        "rank": rank,
        "candidate_id": f"poc-{rank:02d}",
        "target": target,
        "arch": printable(audit.get("arch")),
        "jsonl_file": printable(audit.get("jsonl_file")),
        "closure_ordinal": printable(audit.get("closure_ordinal")),
        "closure_idx": printable(audit.get("closure_idx")),
        "evidence_type": printable(audit.get("stratum")),
        "audit_verdict": printable(audit.get("audit_verdict")),
        "confidence": printable(record.get("evidence_confidence")),
        "readiness": readiness,
        "readiness_reason": readiness_reason,
        "source_function": printable(record.get("source_function")),
        "sink_function": printable(record.get("sink_function")),
        "sink_addr": printable(record.get("sink_addr")),
        "trace": short(record.get("trace_summary") or audit.get("trace"), 180),
        "command_preview": short(record.get("sink_preview") or audit.get("preview"), 220),
        "minimal_bypass_category": printable(minimal.get("category")),
        "minimal_bypass_vector": printable(minimal.get("vector")),
        "minimal_bypass_poc_preview": short(minimal.get("poc"), 220),
        "vulnerable_vectors": as_int(record.get("vulnerable_vectors") or audit.get("vulnerable_vectors")),
        "secure_vectors": as_int(record.get("secure_vectors") or audit.get("secure_vectors")),
        "blocked_categories": printable("; ".join(blocked) if isinstance(blocked, list) else str(blocked)),
        "bypass_categories": printable("; ".join(bypass) if isinstance(bypass, list) else str(bypass)),
        "analysis_recovery": printable(record.get("analysis_recovery") or ""),
        "static_evidence_strength": printable(record.get("static_evidence_strength") or ""),
        "source_clues": printable("; ".join(clues[:12])),
        "validation_family": validation_family(record, audit),
        "functional_theme": functional_theme(record, audit),
        "functional_family": functional_family(record, audit),
        "safe_validation_goal": safe_validation_goal(record),
        "emulation_prerequisites": "firmware service boot/rehost, endpoint or IPC trigger mapping, NVRAM/filesystem fixture, benign canary command only",
        "paper_boundary": "Report as device/emulation-confirmed only after observing a benign canary in an isolated lab.",
        "score": candidate_score(record, audit),
    }


def choose_diverse(candidates: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    per_target = Counter()
    per_type = Counter()
    used_family = set()
    used_functional = set()

    def add(cand: Dict[str, Any], *, cover_target: bool = False) -> bool:
        if cand["validation_family"] in used_family:
            return False
        if not cover_target and cand["functional_family"] in used_functional:
            return False
        if not cover_target and per_target[cand["target"]] >= 2:
            return False
        if not cover_target and per_type[cand["evidence_type"]] >= 4:
            return False
        selected.append(cand)
        per_target[cand["target"]] += 1
        per_type[cand["evidence_type"]] += 1
        used_family.add(cand["validation_family"])
        used_functional.add(cand["functional_family"])
        return True

    # Phase 1: cover every firmware that has an audited vulnerable candidate.
    for target in sorted({cand["target"] for cand in candidates}):
        for cand in candidates:
            if cand["target"] == target and add(cand, cover_target=True):
                break
        if len(selected) >= limit:
            return selected

    # Phase 2: fill remaining slots with high-scoring, type/target-diverse cases.
    for cand in candidates:
        if len(selected) >= limit:
            break
        add(cand)
    return selected


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


def markdown_report(candidates: List[Dict[str, Any]], all_candidates: int) -> str:
    lines = [
        "# TSDS PoC/Emulation Validation Candidate Worklist",
        "",
        "This worklist selects representative TSDS findings for the next validation step. It is not an exploit package. All validation should use isolated firmware emulation or owned hardware and benign canary commands only.",
        "",
        f"- Candidate pool: `{all_candidates}` audited vulnerable records.",
        f"- Selected representatives: `{len(candidates)}`.",
        "",
        "## Selected Candidates",
        "",
        "| ID | Target | Type | Theme | Closure | Readiness | Sink | Evidence focus |",
        "|---|---|---|---|---:|---|---|---|",
    ]
    for cand in candidates:
        focus = cand["command_preview"] or cand["minimal_bypass_poc_preview"]
        lines.append(
            f"| {md_code(cand['candidate_id'])} | {md_text(cand['target'])} | {md_code(cand['evidence_type'])} | {md_text(cand['functional_theme'])} | {md_text(cand['closure_ordinal'])} | {md_text(cand['readiness'])} | {md_code(str(cand['sink_function']) + '@' + str(cand['sink_addr']))} | {md_text(focus, 90)} |"
        )
    lines.extend([
        "",
        "## Candidate Details",
        "",
    ])
    for cand in candidates:
        lines.extend([
            f"### {md_text(cand['candidate_id'])} -- {md_text(cand['target'])} closure {md_text(cand['closure_ordinal'])}",
            "",
            f"- Evidence type: {md_code(cand['evidence_type'])}; audit verdict: {md_code(cand['audit_verdict'])}; confidence: {md_code(cand['confidence'])}.",
            f"- Functional theme: {md_code(cand['functional_theme'])}.",
            f"- Trace: {md_code(cand['trace'], 220)}.",
            f"- Sink: {md_code(cand['sink_function'])} at {md_code(cand['sink_addr'])}.",
            f"- Command preview: {md_code(cand['command_preview'], 240)}.",
            f"- Minimal bypass class: {md_code(cand['minimal_bypass_category'])}; symbolic vector: {md_code(cand['minimal_bypass_vector'])}.",
            f"- Vector profile: {md_code(cand['vulnerable_vectors'])} SAT, {md_code(cand['secure_vectors'])} UNSAT; blocked categories: {md_code(cand['blocked_categories'])}.",
            f"- Source clues: {md_code(cand['source_clues'], 260)}.",
            f"- Readiness: {md_code(cand['readiness'])} -- {md_text(cand['readiness_reason'])}.",
            f"- Safe validation goal: {md_text(cand['safe_validation_goal'], 260)}",
            f"- Prerequisites: {md_text(cand['emulation_prerequisites'], 260)}.",
            "",
        ])
    lines.extend([
        "## Paper Use",
        "",
        "These candidates should not be counted as device-confirmed vulnerabilities until the benign canary is observed in emulation or on owned hardware. Until then, they support a reproducible validation plan and justify why selected sink-level findings are suitable for follow-up confirmation.",
        "",
    ])
    return "\n".join(lines)


def latex_table(candidates: List[Dict[str, Any]]) -> str:
    lines = [
        "% Auto-generated by experiments/build_poc_validation_candidates.py",
        "\\begin{tabularx}{\\textwidth}{@{}lP{0.15\\textwidth}P{0.16\\textwidth}P{0.16\\textwidth}rP{0.12\\textwidth}Y@{}}",
        "\\toprule",
        "ID & Target & Evidence & Theme & Cl. & Ready & Validation focus\\\\",
        "\\midrule",
    ]
    for cand in candidates:
        focus = cand["command_preview"] or cand["minimal_bypass_poc_preview"]
        lines.append(
            "{} & {} & {} & {} & {} & {} & {}\\\\".format(
                cand["candidate_id"],
                latex_escape(cand["target"], 80),
                latex_escape(str(cand["evidence_type"]).replace("_", " "), 80),
                latex_escape(cand["functional_theme"], 80),
                cand["closure_ordinal"],
                latex_escape(cand["readiness"], 40),
                latex_escape(focus, 90),
            )
        )
    lines.extend(["\\bottomrule", "\\end{tabularx}", ""])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--campaign-dir", default=str(DEFAULT_CAMPAIGN))
    parser.add_argument("--audit-csv", default=str(DEFAULT_AUDIT))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    campaign = (root / args.campaign_dir).resolve()
    audit_csv = (root / args.audit_csv).resolve()
    out_dir = (root / args.out_dir).resolve()
    records_by_key = load_records_by_key(campaign)
    audit_rows = load_csv(audit_csv)
    pool: List[Dict[str, Any]] = []
    for audit in audit_rows:
        if audit.get("status") != "vulnerable":
            continue
        if audit.get("audit_verdict") not in {"PASS", "PASS_WITH_BOUNDARY"}:
            continue
        key = (audit.get("jsonl_file") or "", as_int(audit.get("closure_idx")))
        record = records_by_key.get(key)
        if record is None:
            continue
        pool.append(make_candidate(record, audit, 0))
    pool.sort(key=lambda row: (-as_int(row["score"]), row["target"], as_int(row["closure_idx"])))
    selected = choose_diverse(pool, args.limit)
    for idx, cand in enumerate(selected, 1):
        cand["rank"] = idx
        cand["candidate_id"] = f"poc-{idx:02d}"

    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / "poc_validation_candidates.csv", selected)
    (out_dir / "poc_validation_candidates.md").write_text(markdown_report(selected, len(pool)), encoding="utf-8")
    (out_dir / "poc_validation_candidates_table.tex").write_text(latex_table(selected), encoding="utf-8")
    summary = {
        "candidate_pool": len(pool),
        "selected": len(selected),
        "selected_by_target": dict(Counter(c["target"] for c in selected)),
        "selected_by_type": dict(Counter(c["evidence_type"] for c in selected)),
        "selected_by_readiness": dict(Counter(c["readiness"] for c in selected)),
        "selected_by_functional_theme": dict(Counter(c["functional_theme"] for c in selected)),
        "selection_strategy": "cover every firmware first, then fill high-scoring candidates while avoiding duplicate target/type/function families",
        "out_dir": str(out_dir),
    }
    (out_dir / "poc_validation_candidates_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
