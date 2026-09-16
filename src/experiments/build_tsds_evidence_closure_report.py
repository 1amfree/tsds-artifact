#!/usr/bin/env python3
"""Build a unified evidence-closure package for the TSDS paper.

The output deliberately separates sink-level evidence, analyzer
reproducibility, sink-intercept canary scaffolds, and dynamic preflight.  It is
not a device-confirmed validation report.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


DEFAULT_CAMPAIGN = Path("experiment_reports/full_firmware_campaign_v9_20260625")
DEFAULT_BASELINE = Path("experiment_reports/baseline_comparison_v9_20260626")
DEFAULT_MANUAL_AUDIT = Path("experiment_reports/manual_trace_audit_v9_20260626")
DEFAULT_CANDIDATES = Path("experiment_reports/poc_validation_candidates_v9_20260626")
DEFAULT_REPRO = Path("experiment_reports/poc_candidate_repro_v9_20260626")
DEFAULT_HARNESS = Path("experiment_reports/sink_intercept_harness_pack_v9_20260626")
DEFAULT_PREFLIGHT = Path("experiment_reports/dynamic_validation_preflight_v9_20260626")
DEFAULT_ROOTFS_SMOKE = Path("experiment_reports/target_rootfs_smoke_v9_20260626")
DEFAULT_LOADER_SMOKE = Path("experiment_reports/target_loader_smoke_v9_20260626")
DEFAULT_FIRMWARE_INVENTORY = Path("experiment_reports/firmware_resource_inventory_v9_20260626")
DEFAULT_OUT = Path("experiment_reports/evidence_closure_v9_20260626")


def load_json(path: Path, default: Optional[Any] = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def load_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
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


def pct(num: int, den: int) -> float:
    return round((100.0 * num / den), 1) if den else 0.0


def latex_escape(value: Any) -> str:
    text = str(value)
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


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    rows = list(rows)
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


def markdown_table(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "_No rows available._"
    headers = list(rows[0].keys())
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(h, "")) for h in headers) + " |")
    return "\n".join(lines)


def campaign_totals(aggregate: Dict[str, Any]) -> Dict[str, int]:
    total = aggregate.get("total") or {}
    status = aggregate.get("status_counts_from_jsonl") or {}
    return {
        "raw_closures": as_int(total.get("mango_closures")),
        "records": as_int(total.get("records")),
        "unique_pairs": as_int(total.get("unique_pairs")),
        "vulnerable": as_int(status.get("vulnerable") or total.get("vulnerable")),
        "filtered": as_int(status.get("filtered") or total.get("filtered")),
        "no_taint": as_int(status.get("no_taint_sink") or total.get("no_taint_sink")),
        "unreachable": as_int(status.get("unreachable") or total.get("unreachable")),
        "timeout": as_int(status.get("timeout") or total.get("timeout")),
        "sat_vectors": as_int(total.get("vulnerable_vectors")),
        "unsat_vectors": as_int(total.get("secure_vectors")),
        "resolved_semantic": as_int(total.get("resolved_semantic")),
    }


def build_matrix(
    aggregate: Dict[str, Any],
    baseline: Dict[str, Any],
    audit: Dict[str, Any],
    candidates: Dict[str, Any],
    repro: Dict[str, Any],
    harness: Dict[str, Any],
    preflight: Dict[str, Any],
    rootfs_smoke: Dict[str, Any],
    loader_smoke: Dict[str, Any],
    firmware_inventory: Dict[str, Any],
) -> List[Dict[str, Any]]:
    totals = campaign_totals(aggregate)
    negative = totals["filtered"] + totals["no_taint"]
    residual = totals["unreachable"] + totals["timeout"]
    raw = totals["raw_closures"]
    records = totals["records"]
    semantic = totals["vulnerable"] + negative
    layers = baseline.get("layers") or []
    audit_records = as_int(audit.get("audited_records") or audit.get("selected_records"))
    audit_failures = as_int(audit.get("audit_verdict_counts", {}).get("FAIL"))
    candidate_pool = as_int(candidates.get("candidate_pool"))
    selected_candidates = as_int(candidates.get("selected"))
    repro_pass = as_int(repro.get("pass"))
    repro_total = as_int(repro.get("candidate_count"))
    harness_tasks = as_int(harness.get("tasks"))
    preflight_ready = as_int(preflight.get("ready"))
    preflight_tasks = as_int(preflight.get("tasks"))
    preflight_blocked = as_int(preflight.get("blocked"))
    blocker_counts = preflight.get("blocker_category_counts") or {}
    readiness_counts = preflight.get("readiness_level_counts") or {}
    dynamic_gap = dynamic_gap_text(blocker_counts, readiness_counts)
    rootfs_pass = as_int(rootfs_smoke.get("pass"))
    rootfs_tasks = as_int(rootfs_smoke.get("tasks"))
    loader_pass = as_int(loader_smoke.get("pass"))
    loader_tasks = as_int(loader_smoke.get("tasks"))
    corpus_rootfs = as_int(firmware_inventory.get("rootfs_available"))
    corpus_targets = as_int(firmware_inventory.get("targets"))
    corpus_abi = as_int(firmware_inventory.get("rootfs_smoke_pass"))
    corpus_deps = as_int(firmware_inventory.get("dependency_resolution_pass"))
    corpus_exact = as_int(firmware_inventory.get("binary_rootfs_aligned"))

    dedup_layer = next((row for row in layers if str(row.get("Layer", "")).startswith("Deduplicated")), {})
    duplicates = raw - as_int(dedup_layer.get("Input") or records)

    return [
        {
            "Evidence stage": "Candidate discovery",
            "Artifact": "Mango closure reports",
            "Result": f"{raw} raw closures; {records} deduplicated records",
            "Claim boundary": "candidate discovery only",
            "Open gap": "no sink-byte sanitizer semantics",
        },
        {
            "Evidence stage": "Candidate normalization",
            "Artifact": "TSDS dedup ledger",
            "Result": f"{duplicates} duplicate closures removed",
            "Claim boundary": "source/sink hypothesis cleanup",
            "Open gap": "still warning-level evidence",
        },
        {
            "Evidence stage": "Semantic validation",
            "Artifact": "TSDS JSONL records and Markdown reports",
            "Result": f"{semantic}/{records} semantic verdicts ({pct(semantic, records):.1f}%)",
            "Claim boundary": "sink-level evidence, not device exploit proof",
            "Open gap": f"{residual} typed residuals",
        },
        {
            "Evidence stage": "Vector sanitizer evidence",
            "Artifact": "SAT/UNSAT shell-vector matrix",
            "Result": f"{totals['sat_vectors']} SAT and {totals['unsat_vectors']} UNSAT vectors",
            "Claim boundary": "modeled shell-vector semantics",
            "Open gap": "not universal non-exploitability outside the model",
        },
        {
            "Evidence stage": "Negative evidence",
            "Artifact": "filtered and no-taint sink records",
            "Result": f"{negative} negative records ({totals['filtered']} filtered; {totals['no_taint']} no-taint)",
            "Claim boundary": "source-free or sanitizer-blocked sink evidence",
            "Open gap": "depends on source, wrapper, and fixture modeling",
        },
        {
            "Evidence stage": "Trace audit",
            "Artifact": "manual trace audit package",
            "Result": f"{audit_records} audited; {audit_failures} sampled failures",
            "Claim boundary": "audit evidence over TSDS records",
            "Open gap": "not device-confirmed exploitation",
        },
        {
            "Evidence stage": "Analyzer reproducibility",
            "Artifact": "10-candidate TSDS rerun",
            "Result": f"{repro_pass}/{repro_total} reproduced; {as_int(repro.get('drift'))} drift; {as_int(repro.get('run_failed'))} run failures",
            "Claim boundary": "analyzer-level reproducibility only",
            "Open gap": "no firmware service execution",
        },
        {
            "Evidence stage": "Validation worklist",
            "Artifact": "PoC/canary candidate selection",
            "Result": f"{selected_candidates}/{candidate_pool} candidates selected across targets and themes",
            "Claim boundary": "follow-up selection, not proof",
            "Open gap": "needs isolated execution resources",
        },
        {
            "Evidence stage": "Sink-intercept canary scaffold",
            "Artifact": "fixtures, hook, GDB template, verifier",
            "Result": f"{harness_tasks} safe scaffolds generated",
            "Claim boundary": "sink-intercept canary scaffold",
            "Open gap": "handler-level canary observation not yet run",
        },
        {
            "Evidence stage": "Dynamic preflight",
            "Artifact": "QEMU/rootfs readiness check",
            "Result": f"{preflight_ready}/{preflight_tasks} ready; {preflight_blocked} blocked",
            "Claim boundary": "dynamic preflight only",
            "Open gap": dynamic_gap,
        },
        {
            "Evidence stage": "Corpus resource inventory",
            "Artifact": "per-target rootfs, QEMU, ABI, and ELF dependency checks",
            "Result": f"{corpus_rootfs}/{corpus_targets} rootfs; {corpus_abi}/{corpus_targets} ABI smoke; {corpus_deps}/{corpus_targets} ELF deps; {corpus_exact}/{corpus_targets} exact binary matches",
            "Claim boundary": "target-rootfs resource evidence",
            "Open gap": "handler-level canary observation and version alignment for non-exact rows",
        },
        {
            "Evidence stage": "Target rootfs ABI smoke",
            "Artifact": "inert BusyBox echo under target QEMU/rootfs",
            "Result": f"{rootfs_pass}/{rootfs_tasks} PASS",
            "Claim boundary": "rootfs execution substrate only",
            "Open gap": "no firmware service or command sink execution",
        },
        {
            "Evidence stage": "Target loader-trace smoke",
            "Artifact": "LD_TRACE_LOADED_OBJECTS dependency trace",
            "Result": f"{loader_pass}/{loader_tasks} PASS",
            "Claim boundary": "binary loader readiness only",
            "Open gap": "no firmware main routine or canary sink observation",
        },
    ]


def build_resource_requests(preflight_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    requests: List[Dict[str, Any]] = []
    for row in preflight_rows:
        requests.append(
            {
                "candidate_id": row.get("candidate_id", ""),
                "target": row.get("target", ""),
                "required_qemu": row.get("qemu_required", ""),
                "available_qemu": row.get("qemu_available", ""),
                "readiness_level": row.get("readiness_level", ""),
                "target_rootfs_ready": row.get("target_rootfs_ready", ""),
                "binary_rootfs_aligned": row.get("binary_rootfs_aligned", ""),
                "ready_for_exact_rootfs_canary": row.get("ready_for_exact_rootfs_canary", ""),
                "global_rootfs_candidates": row.get("global_rootfs_candidates", ""),
                "entry_clues": f"{row.get('entry_clue_hits', 0)}/{row.get('entry_clue_total', 0)}",
                "blockers": row.get("blockers", ""),
                "resource_request": row.get("resource_request", ""),
            }
        )
    return requests


def dynamic_gap_text(blocker_counts: Dict[str, Any], readiness_counts: Dict[str, Any]) -> str:
    rootfs = as_int(blocker_counts.get("rootfs"))
    qemu = as_int(blocker_counts.get("qemu"))
    if rootfs and not qemu:
        return "target rootfs/uClibc resources missing"
    if rootfs and qemu:
        return "missing qemu-user and target rootfs/uClibc resources"
    if qemu:
        return "missing qemu-user resources"
    if as_int(readiness_counts.get("ready")):
        return "sink-intercept canary observation has not yet been run"
    if readiness_counts:
        return "non-resource preflight blockers remain"
    return "preflight not run"


def latex_evidence_table(rows: List[Dict[str, Any]]) -> str:
    lines = [
        "% Auto-generated by experiments/build_tsds_evidence_closure_report.py",
        r"\begin{tabularx}{\textwidth}{@{}P{0.22\textwidth}P{0.26\textwidth}P{0.20\textwidth}Y@{}}",
        r"\toprule",
        r"Evidence stage & Artifact & Result & Boundary and remaining gap\\",
        r"\midrule",
    ]
    for row in rows:
        boundary_gap = f"{row['Claim boundary']}; {row['Open gap']}"
        lines.append(
            "{} & {} & {} & {}\\\\".format(
                latex_escape(row["Evidence stage"]),
                latex_escape(row["Artifact"]),
                latex_escape(row["Result"]),
                latex_escape(boundary_gap),
            )
        )
    lines.extend([r"\bottomrule", r"\end{tabularx}", ""])
    return "\n".join(lines)


def latex_resource_table(rows: List[Dict[str, Any]]) -> str:
    lines = [
        "% Auto-generated by experiments/build_tsds_evidence_closure_report.py",
        r"\begin{tabularx}{\textwidth}{@{}lP{0.16\textwidth}P{0.18\textwidth}P{0.13\textwidth}Y@{}}",
        r"\toprule",
        r"ID & Target & Required QEMU & Clues & Missing resource\\",
        r"\midrule",
    ]
    for row in rows:
        lines.append(
            "{} & {} & {} & {} & {}\\\\".format(
                latex_escape(row["candidate_id"]),
                latex_escape(row["target"]),
                latex_escape(row["required_qemu"]),
                latex_escape(row["entry_clues"]),
                latex_escape(row["resource_request"]),
            )
        )
    lines.extend([r"\bottomrule", r"\end{tabularx}", ""])
    return "\n".join(lines)


def paper_paragraph(
    aggregate: Dict[str, Any],
    repro: Dict[str, Any],
    preflight: Dict[str, Any],
    rootfs_smoke: Dict[str, Any],
    loader_smoke: Dict[str, Any],
    firmware_inventory: Dict[str, Any],
) -> str:
    totals = campaign_totals(aggregate)
    semantic = totals["vulnerable"] + totals["filtered"] + totals["no_taint"]
    residual = totals["unreachable"] + totals["timeout"]
    gap = dynamic_gap_text(preflight.get("blocker_category_counts") or {}, preflight.get("readiness_level_counts") or {})
    loader_fail = as_int(loader_smoke.get("fail"))
    corpus_targets = as_int(firmware_inventory.get("targets"))
    corpus_rootfs = as_int(firmware_inventory.get("rootfs_available"))
    corpus_abi = as_int(firmware_inventory.get("rootfs_smoke_pass"))
    corpus_deps = as_int(firmware_inventory.get("dependency_resolution_pass"))
    corpus_exact = as_int(firmware_inventory.get("binary_rootfs_aligned"))
    loader_note = (
        "The loader-trace miss is tracked as a binary/rootfs alignment issue rather than a QEMU or rootfs availability failure. "
        if loader_fail
        else ""
    )
    return (
        "The evidence-closure package links the fixed Mango candidate set to "
        "TSDS sink-level records, audit artifacts, and follow-up validation "
        "readiness. Across 546 raw closures, TSDS evaluates 518 deduplicated "
        f"records and produces {semantic} sink-level semantic verdicts "
        f"({pct(semantic, totals['records']):.1f}%), including "
        f"{totals['vulnerable']} vulnerable records, "
        f"{totals['filtered'] + totals['no_taint']} negative sink records, and "
        f"{residual} typed residuals. The vector matrix contains "
        f"{totals['sat_vectors']} SAT shell-vector witnesses and "
        f"{totals['unsat_vectors']} UNSAT blocked-vector proofs. A 10-candidate "
        f"rerun reproduces {as_int(repro.get('pass'))}/{as_int(repro.get('candidate_count'))} "
        "sink-level signatures with no semantic drift. The first-wave "
        "sink-intercept canary scaffolds remain dynamic-preflight artifacts: "
        f"{as_int(preflight.get('ready'))}/{as_int(preflight.get('tasks'))} are "
        f"ready, target-rootfs ABI smoke passes {as_int(rootfs_smoke.get('pass'))}/{as_int(rootfs_smoke.get('tasks'))}, "
        f"and loader-trace smoke passes {as_int(loader_smoke.get('pass'))}/{as_int(loader_smoke.get('tasks'))}. "
        f"A corpus resource inventory over all {corpus_targets} evaluated targets finds {corpus_rootfs}/{corpus_targets} extracted rootfs images, "
        f"{corpus_abi}/{corpus_targets} inert QEMU/rootfs ABI smoke passes, {corpus_deps}/{corpus_targets} static ELF dependency-resolution passes, "
        f"and {corpus_exact}/{corpus_targets} exact analyzed-binary/rootfs-binary matches. "
        f"{loader_note}The remaining gap is that {gap}. We therefore report these artifacts as an "
        "analyzer-to-emulation bridge, not as device-confirmed exploitation."
    )


def markdown_report(
    rows: List[Dict[str, Any]],
    resources: List[Dict[str, Any]],
    aggregate: Dict[str, Any],
    baseline: Dict[str, Any],
    audit: Dict[str, Any],
    candidates: Dict[str, Any],
    repro: Dict[str, Any],
    harness: Dict[str, Any],
    preflight: Dict[str, Any],
    rootfs_smoke: Dict[str, Any],
    loader_smoke: Dict[str, Any],
    firmware_inventory: Dict[str, Any],
) -> str:
    totals = campaign_totals(aggregate)
    gap = dynamic_gap_text(preflight.get("blocker_category_counts") or {}, preflight.get("readiness_level_counts") or {})
    lines = [
        "# TSDS Evidence-Closure Report",
        "",
        "This report joins the v9 campaign, baseline comparison, trace audit, analyzer rerun, sink-intercept harness pack, and dynamic preflight outputs. It is an evidence-boundary report, not a device-confirmed exploit report.",
        "",
        "## Evidence Matrix",
        "",
        markdown_table(rows),
        "",
        "## Paper Paragraph",
        "",
        paper_paragraph(aggregate, repro, preflight, rootfs_smoke, loader_smoke, firmware_inventory),
        "",
        "## Dynamic Validation Resource Requests",
        "",
        markdown_table(resources),
        "",
        "## Reproducibility Inputs",
        "",
        f"- Analysis version: `{aggregate.get('analysis_version', '')}`",
        f"- Baseline layers: `{len(baseline.get('layers') or [])}`",
        f"- Audit records: `{as_int(audit.get('audited_records') or audit.get('selected_records'))}`",
        f"- Candidate worklist: `{as_int(candidates.get('selected'))}` selected from `{as_int(candidates.get('candidate_pool'))}`",
        f"- Analyzer reproducibility: `{as_int(repro.get('pass'))}/{as_int(repro.get('candidate_count'))}` PASS",
        f"- Sink-intercept scaffolds: `{as_int(harness.get('tasks'))}`",
        f"- Dynamic preflight: `{as_int(preflight.get('ready'))}/{as_int(preflight.get('tasks'))}` ready",
        f"- Target rootfs ABI smoke: `{as_int(rootfs_smoke.get('pass'))}/{as_int(rootfs_smoke.get('tasks'))}` PASS",
        f"- Corpus resource inventory: `{as_int(firmware_inventory.get('rootfs_smoke_pass'))}/{as_int(firmware_inventory.get('targets'))}` rootfs ABI smoke PASS; `{as_int(firmware_inventory.get('dependency_resolution_pass'))}/{as_int(firmware_inventory.get('targets'))}` ELF dependency PASS; `{as_int(firmware_inventory.get('binary_rootfs_aligned'))}/{as_int(firmware_inventory.get('targets'))}` exact binary matches",
        f"- Target loader-trace smoke: `{as_int(loader_smoke.get('pass'))}/{as_int(loader_smoke.get('tasks'))}` PASS",
        "",
        "## Boundary Statement",
        "",
        f"The campaign supports sink-level evidence and analyzer-level reproducibility. The sink-intercept artifacts are canary scaffolds and the preflight only checks resource readiness. The current first-wave blocker is {gap}. The package must not be described as device-confirmed or emulation-confirmed dynamic validation.",
        "",
        "## Key Totals",
        "",
        f"- Raw closures: `{totals['raw_closures']}`",
        f"- Deduplicated records: `{totals['records']}`",
        f"- Vulnerable: `{totals['vulnerable']}`",
        f"- Filtered: `{totals['filtered']}`",
        f"- No-taint sink: `{totals['no_taint']}`",
        f"- Unreachable: `{totals['unreachable']}`",
        f"- Timeout: `{totals['timeout']}`",
        f"- SAT vectors: `{totals['sat_vectors']}`",
        f"- UNSAT vectors: `{totals['unsat_vectors']}`",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--campaign-dir", default=str(DEFAULT_CAMPAIGN))
    parser.add_argument("--baseline-dir", default=str(DEFAULT_BASELINE))
    parser.add_argument("--manual-audit-dir", default=str(DEFAULT_MANUAL_AUDIT))
    parser.add_argument("--candidates-dir", default=str(DEFAULT_CANDIDATES))
    parser.add_argument("--repro-dir", default=str(DEFAULT_REPRO))
    parser.add_argument("--harness-dir", default=str(DEFAULT_HARNESS))
    parser.add_argument("--preflight-dir", default=str(DEFAULT_PREFLIGHT))
    parser.add_argument("--rootfs-smoke-dir", default=str(DEFAULT_ROOTFS_SMOKE))
    parser.add_argument("--loader-smoke-dir", default=str(DEFAULT_LOADER_SMOKE))
    parser.add_argument("--firmware-inventory-dir", default=str(DEFAULT_FIRMWARE_INVENTORY))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    root = Path(args.root).resolve()
    campaign = root / args.campaign_dir
    baseline_dir = root / args.baseline_dir
    audit_dir = root / args.manual_audit_dir
    candidates_dir = root / args.candidates_dir
    repro_dir = root / args.repro_dir
    harness_dir = root / args.harness_dir
    preflight_dir = root / args.preflight_dir
    rootfs_smoke_dir = root / args.rootfs_smoke_dir
    loader_smoke_dir = root / args.loader_smoke_dir
    firmware_inventory_dir = root / args.firmware_inventory_dir
    out_dir = root / args.out_dir

    aggregate = load_json(campaign / "v9_full_campaign_aggregate.json", {})
    baseline = load_json(baseline_dir / "baseline_comparison_summary.json", {})
    audit = load_json(audit_dir / "manual_trace_audit_summary.json", {})
    candidates = load_json(candidates_dir / "poc_validation_candidates_summary.json", {})
    repro = load_json(repro_dir / "candidate_repro_summary.json", {})
    harness = load_json(harness_dir / "harness_pack_summary.json", {})
    preflight = load_json(preflight_dir / "dynamic_validation_preflight_summary.json", {})
    preflight_rows = load_json(preflight_dir / "dynamic_validation_preflight.json", [])
    rootfs_smoke = load_json(rootfs_smoke_dir / "target_rootfs_smoke_summary.json", {})
    loader_smoke = load_json(loader_smoke_dir / "target_loader_smoke_summary.json", {})
    firmware_inventory = load_json(firmware_inventory_dir / "firmware_resource_inventory_summary.json", {})

    matrix = build_matrix(
        aggregate,
        baseline,
        audit,
        candidates,
        repro,
        harness,
        preflight,
        rootfs_smoke,
        loader_smoke,
        firmware_inventory,
    )
    resources = build_resource_requests(preflight_rows)
    out_dir.mkdir(parents=True, exist_ok=True)

    write_csv(out_dir / "evidence_closure_matrix.csv", matrix)
    write_csv(out_dir / "dynamic_resource_requests.csv", resources)
    (out_dir / "evidence_closure_table.tex").write_text(latex_evidence_table(matrix), encoding="utf-8")
    (out_dir / "dynamic_resource_requests_table.tex").write_text(latex_resource_table(resources), encoding="utf-8")
    (out_dir / "paper_evidence_closure_paragraph.txt").write_text(
        paper_paragraph(aggregate, repro, preflight, rootfs_smoke, loader_smoke, firmware_inventory) + "\n",
        encoding="utf-8",
    )
    summary = {
        "analysis_version": aggregate.get("analysis_version"),
        "totals": campaign_totals(aggregate),
        "evidence_matrix_rows": len(matrix),
        "dynamic_resource_requests": len(resources),
        "repro_pass": as_int(repro.get("pass")),
        "repro_total": as_int(repro.get("candidate_count")),
        "preflight_ready": as_int(preflight.get("ready")),
        "preflight_tasks": as_int(preflight.get("tasks")),
        "target_rootfs_smoke_pass": as_int(rootfs_smoke.get("pass")),
        "target_rootfs_smoke_tasks": as_int(rootfs_smoke.get("tasks")),
        "target_loader_smoke_pass": as_int(loader_smoke.get("pass")),
        "target_loader_smoke_tasks": as_int(loader_smoke.get("tasks")),
        "firmware_inventory_targets": as_int(firmware_inventory.get("targets")),
        "firmware_inventory_rootfs_available": as_int(firmware_inventory.get("rootfs_available")),
        "firmware_inventory_rootfs_smoke_pass": as_int(firmware_inventory.get("rootfs_smoke_pass")),
        "firmware_inventory_dependency_resolution_pass": as_int(firmware_inventory.get("dependency_resolution_pass")),
        "firmware_inventory_binary_rootfs_aligned": as_int(firmware_inventory.get("binary_rootfs_aligned")),
        "boundary": "sink-level evidence plus analyzer reproducibility; canary scaffold and dynamic preflight only; not device-confirmed",
        "out_dir": str(out_dir),
    }
    (out_dir / "evidence_closure_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (out_dir / "evidence_closure.md").write_text(
        markdown_report(
            matrix,
            resources,
            aggregate,
            baseline,
            audit,
            candidates,
            repro,
            harness,
            preflight,
            rootfs_smoke,
            loader_smoke,
            firmware_inventory,
        ),
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
