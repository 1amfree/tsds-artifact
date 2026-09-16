#!/usr/bin/env python3
"""Run reproducible TSDS ablation campaigns.

This script is intentionally lightweight so it can run inside the Ubuntu VM
without extra dependencies. It executes the evaluator over a target manifest,
writes per-run TSDS artifacts, and creates compact JSON/Markdown summaries that
can be copied into the paper tables.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import time


DEFAULT_TARGETS = {
    "asus_rt_be57": ("ASUS_RT-BE57/httpd", "ASUS_RT-BE57/result/cmdi_results.json"),
    "dir878": ("DIR-878/rc", "DIR-878/DIR_878_results/cmdi_results.json"),
    "tenda_ac15": ("Tenda_AC15/httpd", "Tenda_AC15/Tenda_AC15_results/cmdi_results.json"),
    "r6400v2": ("R6400v2/httpd", "R6400v2/R6400v2_result/cmdi_results.json"),
    "r7000": ("R7000/httpd", "R7000/R7000_result/cmdi_results.json"),
}


DEFAULT_CONFIGS = {
    "full": [],
    "static_only": ["--mode", "static-only"],
    "no_threat_matrix": ["--mode", "no-threat-matrix"],
    "no_firmware_summaries": ["--mode", "no-firmware-summaries"],
    "no_arch_seeding": ["--mode", "no-arch-seeding"],
    "no_reconciliation": ["--no-reconciliation"],
    "no_path_control": ["--no-semantic-frontier", "--no-loop-semantic-summary", "--source-liveness-limit", "0"],
    "no_semantic_frontier": ["--no-semantic-frontier"],
    "no_loop_summary": ["--no-loop-semantic-summary"],
    "no_source_liveness": ["--source-liveness-limit", "0"],
    "no_memo_cache": ["--closure-memo-limit", "0", "--no-evidence-cache"],
}


def load_manifest(path: pathlib.Path | None) -> dict[str, tuple[str, str]]:
    if not path:
        return DEFAULT_TARGETS
    data = json.loads(path.read_text())
    targets = {}
    for name, item in data.items():
        if isinstance(item, dict):
            targets[name] = (item["binary"], item["json"])
        else:
            targets[name] = (item[0], item[1])
    return targets


def read_summary(path: pathlib.Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        return {"summary_error": f"{type(exc).__name__}: {exc}"}


def first_record_analysis_version(path: pathlib.Path) -> str:
    if not path.exists():
        return ""
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line).get("analysis_version")
        except json.JSONDecodeError:
            continue
        if value:
            return str(value)
    return ""


def summarize_run(target: str, config: str, elapsed: float, returncode: int, summary: dict) -> dict:
    results = summary.get("results", {}) or {}
    contract = summary.get("evidence_contract_ledger", {}) or {}
    verdicts = contract.get("verdicts", {}) or {}
    return {
        "target": target,
        "config": config,
        "returncode": returncode,
        "analysis_version": summary.get("analysis_version") or "",
        "elapsed_wall_sec": round(elapsed, 4),
        "total_closures": summary.get("total_closures"),
        "unique_pairs_expected": summary.get("unique_pairs_expected"),
        "unique_pairs_analyzed": summary.get("unique_pairs_analyzed"),
        "vulnerable": results.get("vulnerable", 0),
        "partial_vulnerable": results.get("partial_vulnerable", 0),
        "filtered": results.get("filtered", 0),
        "no_taint_sink": results.get("no_taint_sink", 0),
        "unreachable": results.get("unreachable", 0),
        "timeout": results.get("timeout", 0),
        "crashed": results.get("crashed", 0),
        "eval_error": results.get("eval_error", 0),
        "secure_vectors": results.get("secure_vectors", 0),
        "vulnerable_vectors": results.get("vulnerable_vectors", 0),
        "vector_sat": verdicts.get("VECTOR_SAT", results.get("vulnerable", 0)),
        "matrix_unsat": verdicts.get("MATRIX_UNSAT", results.get("filtered", 0)),
        "no_modeled_source": verdicts.get("NO_MODELED_SOURCE", results.get("no_taint_sink", 0)),
        "contract_residual": verdicts.get("RESIDUAL", 0),
        "contract_valid": contract.get("contract_valid", 0),
        "contract_downgraded": contract.get("contract_downgraded", 0),
        "matrix_solver_queries": results.get("matrix_solver_queries_sum", 0),
        "sanitizer_gap_strengths": results.get("sanitizer_gap_strengths", {}),
        "bypass_vector_categories": results.get("bypass_vector_categories", {}),
        "blocked_vector_categories": results.get("blocked_vector_categories", {}),
        "avg_closure_time_sec": summary.get("avg_closure_time_sec"),
        "avg_engine_steps": summary.get("avg_engine_steps"),
        "semantic_frontier_pruned_sum": results.get("semantic_frontier_pruned_sum", 0),
        "loop_semantic_pruned_sum": results.get("loop_semantic_pruned_sum", 0),
        "source_liveness_cuts": results.get("source_liveness_cuts", 0),
        "memoized_closures": results.get("memoized_closures", 0),
        "path_control_ledger": summary.get("path_control_ledger", {}),
        "residual_diagnosis_ledger": summary.get("residual_diagnosis_ledger", {}),
    }


def markdown_table(records: list[dict], max_closures: int | None) -> str:
    lines = [
        "# TSDS Ablation Results",
        "",
        f"- max closures per target: {max_closures if max_closures is not None else 'all'}",
        "",
        "| Target | Config | SV-SAT | M-Filt | NMS | Strict residual | Contract invalid | Solver queries | Avg s | Steps | Legacy gap | Path classes |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---|",
    ]
    for record in records:
        classes = ((record.get("path_control_ledger") or {}).get("classes") or {})
        class_text = ", ".join(f"{key}:{value}" for key, value in sorted(classes.items()))
        gap_text = ", ".join(
            f"{key}:{value}"
            for key, value in sorted((record.get("sanitizer_gap_strengths") or {}).items())
        )
        bypass_text = ", ".join(
            f"{key}:{value}"
            for key, value in sorted((record.get("bypass_vector_categories") or {}).items())
        )
        residual_classes = (((record.get("residual_diagnosis_ledger") or {}).get("classes")) or {})
        residual_text = ", ".join(f"{key}:{value}" for key, value in sorted(residual_classes.items()))
        lines.append(
            "| {target} | {config} | {vector_sat} | {matrix_unsat} | "
            "{no_modeled_source} | {contract_residual} | {contract_downgraded} | "
            "{matrix_solver_queries} | {avg_closure_time_sec} | {avg_engine_steps} | "
            "{gap} | {classes} |".format(
                residual=residual_text,
                gap=gap_text,
                bypass=bypass_text,
                classes=class_text,
                **record,
            )
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TSDS ablation experiments.")
    parser.add_argument("--root", default="/home/ubuntu/work/sanitizer", help="Sanitizer workspace root.")
    parser.add_argument("--python", default=None, help="Python interpreter. Defaults to operation-mango-public venv.")
    parser.add_argument("--evaluator", default=None, help="Path to advanced_sanitizer_evaluator.py.")
    parser.add_argument("--manifest", default=None, help="Optional JSON target manifest.")
    parser.add_argument("--out-dir", default="experiment_reports/ablation", help="Output directory under root unless absolute.")
    parser.add_argument("--max-closures", type=int, default=6, help="Maximum closures per target/config. Use 0 for all.")
    parser.add_argument("--targets", default="", help="Comma-separated target names. Default: all manifest targets.")
    parser.add_argument("--configs", default="", help="Comma-separated config names. Default: all configs.")
    parser.add_argument("--engine-timeout", type=int, default=30)
    parser.add_argument("--closure-timeout", type=int, default=60)
    parser.add_argument("--subprocess-timeout", type=int, default=90)
    parser.add_argument("--run-timeout", type=int, default=900)
    args = parser.parse_args()

    root = pathlib.Path(args.root)
    python = pathlib.Path(args.python) if args.python else root / "operation-mango-public/.venv/bin/python"
    evaluator = pathlib.Path(args.evaluator) if args.evaluator else root / "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py"
    out_dir = pathlib.Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = root / out_dir
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(f"refusing to reuse non-empty ablation directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)

    targets = load_manifest(pathlib.Path(args.manifest) if args.manifest else None)
    if args.targets:
        wanted = {name.strip() for name in args.targets.split(",") if name.strip()}
        targets = {name: value for name, value in targets.items() if name in wanted}

    configs = DEFAULT_CONFIGS
    if args.configs:
        wanted = {name.strip() for name in args.configs.split(",") if name.strip()}
        configs = {name: value for name, value in configs.items() if name in wanted}

    records = []
    max_closures = None if args.max_closures == 0 else args.max_closures
    for target, (binary_rel, json_rel) in targets.items():
        binary = root / binary_rel
        trace_json = root / json_rel
        if not binary.exists() or not trace_json.exists():
            records.append({
                "target": target,
                "config": "missing",
                "returncode": -1,
                "error": f"missing binary or json: {binary} {trace_json}",
            })
            continue

        for config, extra in configs.items():
            prefix = out_dir / f"{target}_{config}"
            summary_path = prefix.with_suffix(".summary.json")
            jsonl_path = prefix.with_suffix(".results.jsonl")
            report_path = prefix.with_suffix(".report.md")
            log_path = prefix.with_suffix(".log")
            cmd = [
                str(python),
                str(evaluator),
                str(binary),
                str(trace_json),
                "--engine-timeout",
                str(args.engine_timeout),
                "--closure-timeout",
                str(args.closure_timeout),
                "--subprocess-timeout",
                str(args.subprocess_timeout),
                "--report-max-records",
                "0",
            ]
            if max_closures is not None:
                cmd += ["--max-closures", str(max_closures)]
            cmd += extra
            if "--no-evidence-cache" not in extra:
                cmd += ["--no-evidence-cache"]
            cmd += [
                "--summary-json",
                str(summary_path),
                "--results-jsonl",
                str(jsonl_path),
                "--report-file",
                str(report_path),
            ]

            print("RUN", target, config, flush=True)
            start = time.perf_counter()
            timed_out = False
            output = ""
            try:
                with log_path.open("w", errors="ignore") as log_file:
                    proc = subprocess.run(
                        cmd,
                        cwd=str(binary.parent),
                        text=True,
                        stdout=log_file,
                        stderr=subprocess.STDOUT,
                        timeout=args.run_timeout,
                    )
                    returncode = proc.returncode
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                with log_path.open("a", errors="ignore") as log_file:
                    log_file.write(f"\n[HARNESS_TIMEOUT] run exceeded {args.run_timeout}s\n")
                returncode = 124
            elapsed = time.perf_counter() - start
            summary = read_summary(summary_path)
            record = summarize_run(target, config, elapsed, returncode, summary)
            record["analysis_version"] = first_record_analysis_version(jsonl_path)
            if timed_out:
                record["harness_timeout"] = args.run_timeout
            records.append(record)
            print("DONE", json.dumps(record, sort_keys=True), flush=True)

    (out_dir / "ablation_records.json").write_text(json.dumps(records, indent=2, sort_keys=True))
    (out_dir / "ablation_summary.md").write_text(markdown_table(records, max_closures))
    print("WROTE", out_dir / "ablation_records.json", out_dir / "ablation_summary.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
