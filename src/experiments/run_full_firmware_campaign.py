#!/usr/bin/env python3
"""Run the current TSDS evaluator over the full firmware campaign.

The script is intended to be executed on the Ubuntu analysis VM from
``/home/ubuntu/work/sanitizer``.  It keeps each firmware result in a single
campaign directory and disables the evidence cache by default so reruns cannot
reuse stale callsite-level evidence from earlier evaluator revisions.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List


TARGETS: List[Dict[str, str]] = [
    {
        "name": "asus_rt_be57",
        "label": "ASUS RT-BE57",
        "binary": "ASUS_RT-BE57/httpd",
        "mango": "ASUS_RT-BE57/result/cmdi_results.json",
    },
    {
        "name": "dir878",
        "label": "D-Link DIR-878",
        "binary": "DIR-878/rc",
        "mango": "DIR-878/DIR_878_results/cmdi_results.json",
    },
    {
        "name": "r6400v2",
        "label": "Netgear R6400v2",
        "binary": "R6400v2/httpd",
        "mango": "R6400v2/R6400v2_result/cmdi_results.json",
    },
    {
        "name": "r7000",
        "label": "Netgear R7000",
        "binary": "R7000/httpd",
        "mango": "R7000/R7000_result/cmdi_results.json",
    },
    {
        "name": "tenda_ac15",
        "label": "Tenda AC15",
        "binary": "Tenda_AC15/httpd",
        "mango": "Tenda_AC15/Tenda_AC15_results/cmdi_results.json",
    },
    {
        "name": "tenda_ac18",
        "label": "Tenda AC18",
        "binary": "Tenda_AC18/httpd",
        "mango": "Tenda_AC18/results/cmdi_results.json",
    },
    {
        "name": "tenda_w20e",
        "label": "Tenda W20E",
        "binary": "Tenda_W20E/httpd",
        "mango": "Tenda_W20E/results/cmdi_results.json",
    },
    {
        "name": "xr300",
        "label": "Netgear XR300",
        "binary": "XR300/httpd",
        "mango": "XR300/results/cmdi_results.json",
    },
]

DETERMINISTIC_WORKER_ENVIRONMENT = {
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "LC_ALL": "C",
    "LANG": "C",
    "TZ": "UTC",
}


GNU_TIME_FIELDS = {
    "User time (seconds)": ("user_cpu_sec", float),
    "System time (seconds)": ("system_cpu_sec", float),
    "Percent of CPU this job got": ("cpu_percent", lambda text: float(text.rstrip("%"))),
    "Maximum resident set size (kbytes)": ("peak_rss_kb", int),
    "Major (requiring I/O) page faults": ("major_page_faults", int),
    "Minor (reclaiming a frame) page faults": ("minor_page_faults", int),
    "Voluntary context switches": ("voluntary_context_switches", int),
    "Involuntary context switches": ("involuntary_context_switches", int),
}


def parse_gnu_time_file(path: Path) -> Dict[str, Any]:
    """Parse locale-stable ``/usr/bin/time -v`` output."""
    if not path.is_file():
        return {}
    metrics: Dict[str, Any] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        text = raw.strip()
        for label, (name, converter) in GNU_TIME_FIELDS.items():
            prefix = label + ":"
            if not text.startswith(prefix):
                continue
            value = text[len(prefix):].strip()
            try:
                metrics[name] = converter(value)
            except (TypeError, ValueError):
                pass
            break
    if "peak_rss_kb" in metrics:
        metrics["peak_rss_mb"] = round(float(metrics["peak_rss_kb"]) / 1024.0, 2)
    return metrics


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact_fingerprint(path: Path, *, allow_missing: bool = False) -> Dict[str, Any]:
    """Return an explicit file identity without weakening real-run validation."""
    exists = path.is_file()
    if not exists and not allow_missing:
        raise FileNotFoundError(path)
    return {
        "path": str(path),
        "exists": exists,
        "sha256": sha256_file(path) if exists else None,
    }


def refinement_bundle_for_target(
    args: argparse.Namespace, target: Dict[str, str]
) -> Path | None:
    bundle_dir = getattr(args, "refinement_bundle_dir", None)
    if bundle_dir:
        return Path(bundle_dir) / f"{target['name']}.refinement.json"
    bundle = getattr(args, "refinement_bundle", None)
    return Path(bundle) if bundle else None


def target_configuration_record(
    args: argparse.Namespace,
    target: Dict[str, str],
) -> Dict[str, Any]:
    binary = artifact_fingerprint(
        args.root / target["binary"], allow_missing=args.dry_run
    )
    mango = artifact_fingerprint(
        args.root / target["mango"], allow_missing=args.dry_run
    )
    value: Dict[str, Any] = {
        **target,
        "binary_exists": binary["exists"],
        "binary_sha256": binary["sha256"],
        "mango_exists": mango["exists"],
        "mango_sha256": mango["sha256"],
    }
    refinement = refinement_bundle_for_target(args, target)
    if refinement is not None:
        fingerprint = artifact_fingerprint(refinement, allow_missing=args.dry_run)
        value.update(
            {
                "refinement_bundle": str(refinement),
                "refinement_bundle_exists": fingerprint["exists"],
                "refinement_bundle_sha256": fingerprint["sha256"],
            }
        )
    return value


def result_count(summary: Dict[str, Any], key: str) -> int:
    return int(((summary.get("results") or summary).get(key)) or 0)


def build_command(args: argparse.Namespace, out_dir: Path, target: Dict[str, str]) -> List[str]:
    summary = out_dir / f"{target['name']}.summary.json"
    jsonl = out_dir / f"{target['name']}.results.jsonl"
    report = out_dir / f"{target['name']}.report.md"
    cmd = [
        str(args.python),
        str(args.evaluator),
        str(args.root / target["binary"]),
        str(args.root / target["mango"]),
        "--engine-timeout",
        str(args.engine_timeout),
        "--max-steps",
        str(args.max_steps),
        "--closure-timeout",
        str(args.closure_timeout),
        "--subprocess-timeout",
        str(args.subprocess_timeout),
        "--subprocess-memory-limit-mib",
        str(args.subprocess_memory_limit_mib),
        "--execution-backend",
        str(args.execution_backend),
        # Make the evidence-generation policy explicit in every campaign
        # command.  Relying on the evaluator's default makes a manifest harder
        # to audit and can silently reintroduce the historical first-Ready mode.
        "--multi-state-audit",
        "--scheduler-base-active-cap",
        str(args.scheduler_base_active_cap),
        "--scheduler-min-active-cap",
        str(args.scheduler_min_active_cap),
        "--scheduler-max-active-cap",
        str(args.scheduler_max_active_cap),
        "--scheduler-constraint-soft-limit",
        str(args.scheduler_constraint_soft_limit),
        "--scheduler-escape-quota",
        str(args.scheduler_escape_quota),
        "--constraint-projection-cache-size",
        str(args.constraint_projection_cache_size),
        "--online-refinement-rounds",
        str(args.online_refinement_rounds),
        "--online-refinement-candidates",
        str(args.online_refinement_candidates),
        "--summary-json",
        str(summary),
        "--results-jsonl",
        str(jsonl),
        "--report-file",
        str(report),
    ]
    if args.no_evidence_cache:
        cmd.append("--no-evidence-cache")
    if args.no_evidence_aware_scheduler:
        cmd.append("--no-evidence-aware-scheduler")
    if args.no_sink_corridor:
        cmd.append("--no-sink-corridor")
    if args.no_source_projected_constraints:
        cmd.append("--no-source-projected-constraints")
    if args.no_byte_provenance:
        cmd.append("--no-byte-provenance")
    if args.no_sink_semantic_plugins:
        cmd.append("--no-sink-semantic-plugins")
    if args.summary_database:
        cmd.extend(["--summary-database", str(args.summary_database)])
    refinement_bundle = refinement_bundle_for_target(args, target)
    if refinement_bundle:
        cmd.extend(["--refinement-bundle", str(refinement_bundle)])
    if args.generate_refinement_bundles:
        cmd.extend([
            "--refinement-bundle-output",
            str(out_dir / f"{target['name']}.refinement.json"),
        ])
    if args.export_solver_queries:
        # Keep query bundles namespaced per target so a replay can bind each
        # SMT artifact to the corresponding campaign configuration and sink
        # snapshot without collisions across binaries.
        cmd.extend([
            "--export-solver-queries",
            str(out_dir / f"{target['name']}.solver_queries"),
        ])
    if args.max_closures is not None:
        cmd.extend(["--max-closures", str(args.max_closures)])
    return cmd


def write_campaign_log(path: Path, message: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(message.rstrip() + "\n")


def summarize_campaign(out_dir: Path, rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = list(rows)
    candidate_closures = sum(
        int(row.get("candidate_closures", row.get("closures")) or 0)
        for row in rows
    )
    selected_closures = sum(
        int(row.get("selected_closures", row.get("evaluated")) or 0)
        for row in rows
    )
    totals: Dict[str, Any] = {
        "target": "TOTAL",
        # Retain closures as a compatibility alias for candidate inputs. New
        # artifacts expose both counts explicitly so a bounded soak cannot be
        # misread as a full campaign.
        "closures": candidate_closures,
        "candidate_closures": candidate_closures,
        "selected_closures": selected_closures,
        "evaluated": selected_closures,
        # Paper-facing counts come from the evidence-contract verdict ledger.
        # The legacy status counters below remain available for migration and
        # operational debugging, but must not drive new result tables.
        "vector_sat": sum(int(row.get("vector_sat") or 0) for row in rows),
        "matrix_unsat": sum(int(row.get("matrix_unsat") or 0) for row in rows),
        "no_modeled_source": sum(int(row.get("no_modeled_source") or 0) for row in rows),
        "contract_residual": sum(int(row.get("contract_residual") or 0) for row in rows),
        "resource_metrics_available": sum(1 for row in rows if row.get("peak_rss_kb") is not None),
        "peak_rss_kb": max((int(row.get("peak_rss_kb") or 0) for row in rows), default=0),
        "user_cpu_sec": round(sum(float(row.get("user_cpu_sec") or 0.0) for row in rows), 4),
        "system_cpu_sec": round(sum(float(row.get("system_cpu_sec") or 0.0) for row in rows), 4),
        "major_page_faults": sum(int(row.get("major_page_faults") or 0) for row in rows),
        "minor_page_faults": sum(int(row.get("minor_page_faults") or 0) for row in rows),
        "voluntary_context_switches": sum(
            int(row.get("voluntary_context_switches") or 0) for row in rows
        ),
        "involuntary_context_switches": sum(
            int(row.get("involuntary_context_switches") or 0) for row in rows
        ),
        "vulnerable": sum(int(row.get("vulnerable") or 0) for row in rows),
        "partial_vulnerable": sum(int(row.get("partial_vulnerable") or 0) for row in rows),
        "filtered": sum(int(row.get("filtered") or 0) for row in rows),
        "no_taint_sink": sum(int(row.get("no_taint_sink") or 0) for row in rows),
        "static_source_inference": sum(int(row.get("static_source_inference") or 0) for row in rows),
        "static_warning_reduction": sum(int(row.get("static_warning_reduction") or 0) for row in rows),
        "residual": sum(int(row.get("residual") or 0) for row in rows),
        "unreachable": sum(int(row.get("unreachable") or 0) for row in rows),
        "timeout": sum(int(row.get("timeout") or 0) for row in rows),
        "crashed": sum(int(row.get("crashed") or 0) for row in rows),
        "eval_error": sum(int(row.get("eval_error") or 0) for row in rows),
        "state_error": sum(int(row.get("state_error") or 0) for row in rows),
        "vulnerable_vectors": sum(int(row.get("vulnerable_vectors") or 0) for row in rows),
        "secure_vectors": sum(int(row.get("secure_vectors") or 0) for row in rows),
        "contract_valid": sum(int(row.get("contract_valid") or 0) for row in rows),
        "contract_downgraded": sum(int(row.get("contract_downgraded") or 0) for row in rows),
        "negative_confirmation_required": sum(
            int(row.get("negative_confirmation_required") or 0) for row in rows
        ),
        "wall_time_sec": round(sum(float(row.get("wall_time_sec") or 0.0) for row in rows), 4),
    }
    totals["peak_rss_mb"] = round(float(totals["peak_rss_kb"]) / 1024.0, 2)
    totals["selection_rate_pct"] = round(
        100.0 * selected_closures / candidate_closures, 2
    ) if candidate_closures else 0.0
    if totals["evaluated"]:
        totals["vector_sat_rate_pct"] = round(100.0 * totals["vector_sat"] / totals["evaluated"], 2)
        totals["nms_rate_pct"] = round(100.0 * totals["no_modeled_source"] / totals["evaluated"], 2)
        totals["vulnerable_rate_pct"] = round(100.0 * totals["vulnerable"] / totals["evaluated"], 2)
        totals["no_taint_rate_pct"] = round(100.0 * totals["no_taint_sink"] / totals["evaluated"], 2)
    else:
        totals["vector_sat_rate_pct"] = 0.0
        totals["nms_rate_pct"] = 0.0
        totals["vulnerable_rate_pct"] = 0.0
        totals["no_taint_rate_pct"] = 0.0

    fieldnames = [
        "target",
        "label",
        "returncode",
        "closures",
        "candidate_closures",
        "selected_closures",
        "evaluated",
        "vector_sat",
        "matrix_unsat",
        "no_modeled_source",
        "contract_residual",
        "resource_metrics_available",
        "peak_rss_kb",
        "peak_rss_mb",
        "user_cpu_sec",
        "system_cpu_sec",
        "cpu_percent",
        "major_page_faults",
        "minor_page_faults",
        "voluntary_context_switches",
        "involuntary_context_switches",
        "vulnerable",
        "partial_vulnerable",
        "filtered",
        "no_taint_sink",
        "static_source_inference",
        "static_warning_reduction",
        "residual",
        "unreachable",
        "timeout",
        "crashed",
        "eval_error",
        "state_error",
        "vulnerable_vectors",
        "secure_vectors",
        "contract_valid",
        "contract_downgraded",
        "negative_confirmation_required",
        "avg_closure_time_sec",
        "wall_time_sec",
        "selection_rate_pct",
        "vector_sat_rate_pct",
        "nms_rate_pct",
        "vulnerable_rate_pct",
        "no_taint_rate_pct",
        "summary_path",
        "jsonl_path",
        "report_path",
    ]
    with (out_dir / "full_campaign_per_target.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        writer.writerow(totals)

    aggregate = {"generated_at": datetime.now().isoformat(timespec="seconds"), "targets": rows, "total": totals}
    (out_dir / "full_campaign_aggregate.json").write_text(
        json.dumps(aggregate, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    lines = [
        "# Full Firmware Campaign Aggregate",
        "",
        "Candidate closures are the front-end inputs; Eval is the selected, de-duplicated record count actually analyzed in this run.",
        "Paper-facing columns below are derived from `evidence_contract_ledger.verdicts`; legacy status fields are not used.",
        "",
        "| Target | Candidates | Selected | Eval | SV-SAT | Partial | M-Filt | NMS | Static-src | Static-red. | Contract residual | Contract invalid | Witnesses | Avg(s) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows + [totals]:
        lines.append(
            "| {target} | {candidates} | {selected} | {eval} | {vuln} | {partial} | {filt} | {notaint} | {static_src} | {static_red} | {residual} | {invalid} | {vectors} | {avg} |".format(
                target=row.get("target"),
                candidates=row.get(
                    "candidate_closures", row.get("closures", 0)
                ),
                selected=row.get(
                    "selected_closures", row.get("evaluated", 0)
                ),
                eval=row.get("evaluated", 0),
                vuln=row.get("vector_sat", 0),
                partial=row.get("partial_vulnerable", 0),
                filt=row.get("matrix_unsat", 0),
                notaint=row.get("no_modeled_source", 0),
                static_src=row.get("static_source_inference", 0),
                static_red=row.get("static_warning_reduction", 0),
                residual=row.get("contract_residual", 0),
                invalid=row.get("contract_downgraded", 0),
                vectors=row.get("vulnerable_vectors", 0),
                avg=row.get("avg_closure_time_sec", ""),
            )
        )
    lines.extend(
        [
            "",
            "## Resource profile",
            "",
            "Peak RSS is the maximum resident set reported by GNU time for each target process tree.",
            "",
            "| Target | Peak RSS (MiB) | User CPU (s) | System CPU (s) | CPU (%) | Major faults | Minor faults |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in rows + [totals]:
        lines.append(
            "| {target} | {rss} | {user} | {system} | {cpu} | {major} | {minor} |".format(
                target=row.get("target"),
                rss=row.get("peak_rss_mb", 0),
                user=row.get("user_cpu_sec", 0),
                system=row.get("system_cpu_sec", 0),
                cpu=row.get("cpu_percent", "") if row.get("target") != "TOTAL" else "--",
                major=row.get("major_page_faults", 0),
                minor=row.get("minor_page_faults", 0),
            )
        )
    lines.extend(
        [
            "",
            "## Operational stop breakdown",
            "",
            "These counters explain contract residuals; they are not negative verdicts.",
            "",
            "| Target | Explicit residual | Unreachable | Timeout | Crash | Eval error | State error |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in rows + [totals]:
        lines.append(
            "| {target} | {residual} | {unreach} | {timeout} | {crash} | {eval_error} | {state_error} |".format(
                target=row.get("target"),
                residual=row.get("residual", 0),
                unreach=row.get("unreachable", 0),
                timeout=row.get("timeout", 0),
                crash=row.get("crashed", 0),
                eval_error=row.get("eval_error", 0),
                state_error=row.get("state_error", 0),
            )
        )
    (out_dir / "full_campaign_aggregate.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return aggregate


def row_from_summary(
    out_dir: Path,
    target: Dict[str, str],
    returncode: int,
    elapsed: float,
    resource_metrics: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    summary_path = out_dir / f"{target['name']}.summary.json"
    jsonl_path = out_dir / f"{target['name']}.results.jsonl"
    report_path = out_dir / f"{target['name']}.report.md"
    row: Dict[str, Any] = {
        "target": target["name"],
        "label": target["label"],
        "returncode": returncode,
        "summary_path": str(summary_path),
        "jsonl_path": str(jsonl_path),
        "report_path": str(report_path),
        "wall_time_sec": round(elapsed, 4),
    }
    row.update(resource_metrics or {})
    row["resource_metrics_available"] = 1 if row.get("peak_rss_kb") is not None else 0
    if not summary_path.exists():
        row.update(
            {
                "closures": 0,
                "candidate_closures": 0,
                "selected_closures": 0,
                "evaluated": 0,
                "selection_rate_pct": 0.0,
            }
        )
        return row
    summary = load_json(summary_path)
    row["candidate_closures"] = int(summary.get("total_closures") or 0)
    row["closures"] = row["candidate_closures"]
    row["selected_closures"] = int(
        summary.get("unique_pairs_analyzed") or row["candidate_closures"] or 0
    )
    row["evaluated"] = row["selected_closures"]
    row["selection_rate_pct"] = round(
        100.0 * row["selected_closures"] / row["candidate_closures"], 2
    ) if row["candidate_closures"] else 0.0
    for key in [
        "vulnerable",
        "partial_vulnerable",
        "filtered",
        "no_taint_sink",
        "static_source_inference",
        "static_warning_reduction",
        "residual",
        "unreachable",
        "timeout",
        "crashed",
        "eval_error",
        "state_error",
        "vulnerable_vectors",
        "secure_vectors",
    ]:
        row[key] = result_count(summary, key)
    row["avg_closure_time_sec"] = float(summary.get("avg_closure_time_sec") or 0.0)
    contract = summary.get("evidence_contract_ledger") or {}
    verdicts = contract.get("verdicts") or {}

    def strict_verdict_count(name: str, legacy_fallback: int) -> int:
        if name in verdicts:
            return int(verdicts.get(name) or 0)
        return int(legacy_fallback or 0)

    # Prefer the normalized evidence-contract vocabulary. Fallbacks preserve
    # compatibility with pre-v10 summaries while making the provenance of a
    # migrated row explicit through contract_downgraded.
    row["vector_sat"] = strict_verdict_count("VECTOR_SAT", row["vulnerable"])
    row["matrix_unsat"] = strict_verdict_count("MATRIX_UNSAT", row["filtered"])
    row["no_modeled_source"] = strict_verdict_count(
        "NO_MODELED_SOURCE", row["no_taint_sink"]
    )
    row["static_source_inference"] = strict_verdict_count(
        "STATIC_SOURCE_INFERENCE", row["static_source_inference"]
    )
    row["static_warning_reduction"] = strict_verdict_count(
        "STATIC_WARNING_REDUCTION", row["static_warning_reduction"]
    )
    row["contract_residual"] = strict_verdict_count(
        "RESIDUAL",
        (
            row["residual"]
            + row["unreachable"]
            + row["timeout"]
            + row["crashed"]
            + row["eval_error"]
            + row["state_error"]
        ),
    )
    row["contract_valid"] = int(contract.get("contract_valid") or 0)
    row["contract_downgraded"] = int(contract.get("contract_downgraded") or 0)
    row["negative_confirmation_required"] = int(
        contract.get("negative_confirmation_required") or 0
    )
    if row["evaluated"]:
        row["vector_sat_rate_pct"] = round(100.0 * row["vector_sat"] / row["evaluated"], 2)
        row["nms_rate_pct"] = round(100.0 * row["no_modeled_source"] / row["evaluated"], 2)
        row["vulnerable_rate_pct"] = round(100.0 * row["vulnerable"] / row["evaluated"], 2)
        row["no_taint_rate_pct"] = round(100.0 * row["no_taint_sink"] / row["evaluated"], 2)
    else:
        row["vector_sat_rate_pct"] = 0.0
        row["nms_rate_pct"] = 0.0
        row["vulnerable_rate_pct"] = 0.0
        row["no_taint_rate_pct"] = 0.0
    return row


def select_targets(requested: Iterable[str] | None = None) -> tuple[List[Dict[str, str]], List[str]]:
    """Select a deterministic campaign subset without changing target order."""
    requested_names = [str(name).strip() for name in (requested or []) if str(name).strip()]
    if not requested_names:
        return list(TARGETS), []
    known = {target["name"] for target in TARGETS}
    unknown = sorted(set(requested_names) - known)
    selected = [target for target in TARGETS if target["name"] in set(requested_names)]
    return selected, unknown


def validate_inputs(
    root: Path, targets: Iterable[Dict[str, str]] | None = None
) -> List[str]:
    missing: List[str] = []
    for target in (targets if targets is not None else TARGETS):
        for key in ("binary", "mango"):
            path = root / target[key]
            if not path.exists():
                missing.append(f"{target['name']}:{key}:{path}")
    return missing


def prepare_fresh_output_dir(out_dir: Path) -> None:
    """Create an immutable campaign directory or reject accidental reuse."""
    if out_dir.exists() and any(out_dir.iterdir()):
        raise RuntimeError(f"refusing to reuse non-empty campaign directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/home/ubuntu/work/sanitizer"))
    parser.add_argument(
        "--python",
        type=Path,
        default=Path("/home/ubuntu/work/sanitizer/operation-mango-public/.venv/bin/python"),
    )
    parser.add_argument(
        "--evaluator",
        type=Path,
        default=Path("/home/ubuntu/work/sanitizer/Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py"),
    )
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--engine-timeout", type=int, default=45)
    parser.add_argument("--max-steps", type=int, default=500)
    parser.add_argument("--closure-timeout", type=int, default=90)
    parser.add_argument("--subprocess-timeout", type=int, default=150)
    parser.add_argument(
        "--subprocess-memory-limit-mib",
        type=int,
        default=0,
        help="Per-closure POSIX address-space ceiling forwarded to the evaluator; 0 disables it.",
    )
    parser.add_argument("--target-timeout", type=int, default=7200)
    parser.add_argument(
        "--execution-backend",
        choices=("spawn", "forkserver", "auto"),
        default="forkserver",
    )
    parser.add_argument("--scheduler-base-active-cap", type=int, default=60)
    parser.add_argument("--scheduler-min-active-cap", type=int, default=20)
    parser.add_argument("--scheduler-max-active-cap", type=int, default=120)
    parser.add_argument("--scheduler-constraint-soft-limit", type=int, default=800)
    parser.add_argument("--scheduler-escape-quota", type=int, default=4)
    parser.add_argument("--constraint-projection-cache-size", type=int, default=2048)
    parser.add_argument("--online-refinement-rounds", type=int, default=1)
    parser.add_argument("--online-refinement-candidates", type=int, default=3)
    parser.add_argument("--no-evidence-aware-scheduler", action="store_true")
    parser.add_argument("--no-sink-corridor", action="store_true")
    parser.add_argument("--no-source-projected-constraints", action="store_true")
    parser.add_argument("--no-byte-provenance", action="store_true")
    parser.add_argument("--no-sink-semantic-plugins", action="store_true")
    parser.add_argument("--summary-database", type=Path, default=None)
    refinement_group = parser.add_mutually_exclusive_group()
    refinement_group.add_argument("--refinement-bundle", type=Path, default=None)
    refinement_group.add_argument(
        "--refinement-bundle-dir",
        type=Path,
        default=None,
        help=(
            "Directory containing one <target>.refinement.json file per selected "
            "target; each file is bound and hashed independently."
        ),
    )
    parser.add_argument("--generate-refinement-bundles", action="store_true")
    parser.add_argument(
        "--export-solver-queries",
        action="store_true",
        help=(
            "Export exact full/projected SMT-LIB bundles for independently "
            "replayable matrix queries; disabled by default."
        ),
    )
    parser.add_argument("--max-closures", type=int, default=None)
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="Run only this canonical target name; repeat for a deterministic subset.",
    )
    parser.add_argument("--use-evidence-cache", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.subprocess_memory_limit_mib < 0:
        parser.error("--subprocess-memory-limit-mib must be non-negative")

    args.no_evidence_cache = not args.use_evidence_cache
    if args.refinement_bundle_dir and not args.refinement_bundle_dir.is_absolute():
        args.refinement_bundle_dir = args.root / args.refinement_bundle_dir
    selected_targets, unknown_targets = select_targets(args.target)
    if unknown_targets:
        print(
            "Unknown target name(s): " + ", ".join(unknown_targets),
            file=sys.stderr,
        )
        return 2
    out_dir = args.out_dir or (
        args.root
        / "experiment_reports"
        / f"full_firmware_campaign_current_tsds_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    out_dir = out_dir if out_dir.is_absolute() else args.root / out_dir
    try:
        prepare_fresh_output_dir(out_dir)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 3

    missing = [] if args.dry_run else validate_inputs(args.root, selected_targets)
    if not args.dry_run:
        for target in selected_targets:
            refinement = refinement_bundle_for_target(args, target)
            if refinement is not None and not refinement.is_file():
                missing.append(f"{target['name']}:refinement_bundle:{refinement}")
    if missing:
        print("Missing campaign inputs:", file=sys.stderr)
        for item in missing:
            print(f"  - {item}", file=sys.stderr)
        return 2

    log_path = out_dir / "campaign.log"
    evaluator_fingerprint = artifact_fingerprint(
        args.evaluator,
        allow_missing=args.dry_run,
    )
    aggregation_module = args.root / "tsds" / "multi_state_aggregation.py"
    matrix_spec_module = args.root / "tsds" / "shell_matrix_spec.py"
    aggregation_fingerprint = artifact_fingerprint(
        aggregation_module,
        allow_missing=args.dry_run,
    )
    matrix_spec_fingerprint = artifact_fingerprint(
        matrix_spec_module,
        allow_missing=args.dry_run,
    )
    configuration = {
        "schema": "tsds-v19-campaign-configuration-v1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "python": str(args.python),
        "python_version": sys.version,
        "evaluator": str(args.evaluator),
        "evaluator_exists": evaluator_fingerprint["exists"],
        "evaluator_sha256": evaluator_fingerprint["sha256"],
        "campaign_driver_sha256": sha256_file(Path(__file__).resolve()),
        "aggregation_module": str(aggregation_module),
        "aggregation_module_exists": aggregation_fingerprint["exists"],
        "aggregation_module_sha256": aggregation_fingerprint["sha256"],
        "matrix_spec_module": str(matrix_spec_module),
        "matrix_spec_module_exists": matrix_spec_fingerprint["exists"],
        "matrix_spec_module_sha256": matrix_spec_fingerprint["sha256"],
        "arguments": {
            key: str(value) if isinstance(value, Path) else value
            for key, value in sorted(vars(args).items())
            if key not in {"root", "python", "evaluator", "out_dir"}
        },
        "targets": [
            target_configuration_record(args, target)
            for target in selected_targets
        ],
    }
    (out_dir / "campaign_configuration.json").write_text(
        json.dumps(configuration, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_campaign_log(log_path, f"[{datetime.now().isoformat(timespec='seconds')}] CAMPAIGN_DIR {out_dir}")
    rows: List[Dict[str, Any]] = []
    for target in selected_targets:
        cmd = build_command(args, out_dir, target)
        stdout_path = out_dir / f"{target['name']}.stdout.log"
        stderr_path = out_dir / f"{target['name']}.stderr.log"
        resource_path = out_dir / f"{target['name']}.resource.txt"
        write_campaign_log(log_path, f"[{datetime.now().isoformat(timespec='seconds')}] START {target['name']}")
        write_campaign_log(log_path, "COMMAND " + " ".join(str(part) for part in cmd))
        if args.dry_run:
            print(" ".join(str(part) for part in cmd))
            rows.append(row_from_summary(out_dir, target, 0, 0.0))
            continue
        start = time.time()
        timed_cmd = cmd
        if Path("/usr/bin/time").is_file():
            timed_cmd = ["/usr/bin/time", "-v", "-o", str(resource_path)] + cmd
        write_campaign_log(log_path, "EXEC_COMMAND " + " ".join(str(part) for part in timed_cmd))
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
            try:
                completed = subprocess.run(
                    timed_cmd,
                    cwd=str(args.root),
                    stdout=stdout,
                    stderr=stderr,
                    env={**os.environ, **DETERMINISTIC_WORKER_ENVIRONMENT},
                    timeout=args.target_timeout,
                    check=False,
                )
                returncode = int(completed.returncode)
            except subprocess.TimeoutExpired:
                returncode = 124
                stderr.write(f"\nTARGET_TIMEOUT after {args.target_timeout}s\n")
        elapsed = time.time() - start
        write_campaign_log(
            log_path,
            f"[{datetime.now().isoformat(timespec='seconds')}] END {target['name']} code={returncode} elapsed={elapsed:.2f}s",
        )
        rows.append(
            row_from_summary(
                out_dir,
                target,
                returncode,
                elapsed,
                parse_gnu_time_file(resource_path),
            )
        )

    aggregate = summarize_campaign(out_dir, rows)
    print(json.dumps({"out_dir": str(out_dir), "total": aggregate["total"]}, indent=2, sort_keys=True))
    return 0 if all(int(row.get("returncode") or 0) == 0 for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
