#!/usr/bin/env python3
"""Run resumable low-concurrency TSDS ablation campaigns.

The single-process ablation runner is deliberately simple, but full-corpus
ablation over several firmware/configuration pairs can take many hours.  This
wrapper preserves the same evaluator command line while adding two properties
needed for paper-grade experiments: completed runs are not repeated, and a
small worker pool keeps independent target/configuration runs moving without
overloading the VM.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import pathlib
import subprocess
import time
from typing import Any

from run_tsds_ablation import DEFAULT_CONFIGS, load_manifest, markdown_table, read_summary, summarize_run


def build_jobs(args: argparse.Namespace) -> list[dict[str, Any]]:
    root = pathlib.Path(args.root)
    targets = load_manifest(pathlib.Path(args.manifest) if args.manifest else None)
    if args.targets:
        wanted = {name.strip() for name in args.targets.split(",") if name.strip()}
        targets = {name: value for name, value in targets.items() if name in wanted}

    configs = DEFAULT_CONFIGS
    if args.configs:
        wanted = {name.strip() for name in args.configs.split(",") if name.strip()}
        configs = {name: value for name, value in configs.items() if name in wanted}

    out_dir = pathlib.Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = root / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    jobs: list[dict[str, Any]] = []
    for target, (binary_rel, json_rel) in targets.items():
        for config, extra in configs.items():
            prefix = out_dir / f"{target}_{config}"
            jobs.append(
                {
                    "root": root,
                    "target": target,
                    "config": config,
                    "binary": root / binary_rel,
                    "trace_json": root / json_rel,
                    "extra": extra,
                    "prefix": prefix,
                    "summary_path": prefix.with_suffix(".summary.json"),
                    "jsonl_path": prefix.with_suffix(".results.jsonl"),
                    "report_path": prefix.with_suffix(".report.md"),
                    "log_path": prefix.with_suffix(".log"),
                    "python": pathlib.Path(args.python)
                    if args.python
                    else root / "operation-mango-public/.venv/bin/python",
                    "evaluator": pathlib.Path(args.evaluator)
                    if args.evaluator
                    else root / "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py",
                    "engine_timeout": args.engine_timeout,
                    "closure_timeout": args.closure_timeout,
                    "subprocess_timeout": args.subprocess_timeout,
                    "run_timeout": args.run_timeout,
                    "max_closures": None if args.max_closures == 0 else args.max_closures,
                    "skip_existing": args.skip_existing,
                }
            )
    return jobs


def run_one(job: dict[str, Any]) -> dict[str, Any]:
    target = job["target"]
    config = job["config"]
    summary_path = job["summary_path"]
    jsonl_path = job["jsonl_path"]
    report_path = job["report_path"]
    log_path = job["log_path"]

    if not job["binary"].exists() or not job["trace_json"].exists():
        return {
            "target": target,
            "config": "missing",
            "returncode": -1,
            "error": f"missing binary or json: {job['binary']} {job['trace_json']}",
        }

    if job["skip_existing"] and summary_path.exists() and jsonl_path.exists():
        summary = read_summary(summary_path)
        record = summarize_run(target, config, 0.0, 0, summary)
        record["skipped_existing"] = True
        return record

    cmd = [
        str(job["python"]),
        str(job["evaluator"]),
        str(job["binary"]),
        str(job["trace_json"]),
        "--engine-timeout",
        str(job["engine_timeout"]),
        "--closure-timeout",
        str(job["closure_timeout"]),
        "--subprocess-timeout",
        str(job["subprocess_timeout"]),
        "--report-max-records",
        "0",
    ]
    if job["max_closures"] is not None:
        cmd += ["--max-closures", str(job["max_closures"])]
    cmd += list(job["extra"])
    if "--no-evidence-cache" not in job["extra"]:
        cmd += ["--no-evidence-cache"]
    cmd += [
        "--summary-json",
        str(summary_path),
        "--results-jsonl",
        str(jsonl_path),
        "--report-file",
        str(report_path),
    ]

    start = time.perf_counter()
    timed_out = False
    returncode = 0
    try:
        with log_path.open("w", errors="ignore") as log_file:
            proc = subprocess.run(
                cmd,
                cwd=str(job["binary"].parent),
                text=True,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                timeout=job["run_timeout"],
            )
            returncode = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        returncode = 124
        with log_path.open("a", errors="ignore") as log_file:
            log_file.write(f"\n[HARNESS_TIMEOUT] run exceeded {job['run_timeout']}s\n")
    elapsed = time.perf_counter() - start
    summary = read_summary(summary_path)
    record = summarize_run(target, config, elapsed, returncode, summary)
    if timed_out:
        record["harness_timeout"] = job["run_timeout"]
    return record


def write_records(out_dir: pathlib.Path, records: list[dict[str, Any]], max_closures: int | None) -> None:
    ordered = sorted(records, key=lambda item: (item.get("target", ""), item.get("config", "")))
    (out_dir / "ablation_records.partial.json").write_text(json.dumps(ordered, indent=2, sort_keys=True))
    (out_dir / "ablation_summary.partial.md").write_text(markdown_table(ordered, max_closures))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run resumable parallel TSDS ablation experiments.")
    parser.add_argument("--root", default="/home/ubuntu/work/sanitizer")
    parser.add_argument("--python", default=None)
    parser.add_argument("--evaluator", default=None)
    parser.add_argument("--manifest", default=None)
    parser.add_argument("--out-dir", default="experiment_reports/ablation")
    parser.add_argument("--max-closures", type=int, default=6, help="Use 0 for all closures.")
    parser.add_argument("--targets", default="")
    parser.add_argument("--configs", default="")
    parser.add_argument("--engine-timeout", type=int, default=30)
    parser.add_argument("--closure-timeout", type=int, default=60)
    parser.add_argument("--subprocess-timeout", type=int, default=90)
    parser.add_argument("--run-timeout", type=int, default=900)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--no-skip-existing", dest="skip_existing", action="store_false")
    parser.set_defaults(skip_existing=True)
    args = parser.parse_args()

    root = pathlib.Path(args.root)
    out_dir = pathlib.Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = root / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    max_closures = None if args.max_closures == 0 else args.max_closures

    jobs = build_jobs(args)
    records: list[dict[str, Any]] = []
    print(f"JOBS {len(jobs)} WORKERS {args.workers}", flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        future_to_job = {}
        for job in jobs:
            future = executor.submit(run_one, job)
            future_to_job[future] = job
            print(f"SUBMIT {job['target']} {job['config']}", flush=True)

        for future in concurrent.futures.as_completed(future_to_job):
            job = future_to_job[future]
            try:
                record = future.result()
            except Exception as exc:  # pragma: no cover - harness failure path
                record = {
                    "target": job["target"],
                    "config": job["config"],
                    "returncode": -2,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            records.append(record)
            print("DONE", json.dumps(record, sort_keys=True), flush=True)
            write_records(out_dir, records, max_closures)

    ordered = sorted(records, key=lambda item: (item.get("target", ""), item.get("config", "")))
    (out_dir / "ablation_records.json").write_text(json.dumps(ordered, indent=2, sort_keys=True))
    (out_dir / "ablation_summary.md").write_text(markdown_table(ordered, max_closures))
    print("WROTE", out_dir / "ablation_records.json", out_dir / "ablation_summary.md", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
