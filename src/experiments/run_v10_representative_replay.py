#!/usr/bin/env python3
"""Replay representative historical evidence tiers with TSDS v10."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.run_full_firmware_campaign import TARGETS


SAMPLES = [
    ("asus_rt_be57", 0, "historical_direct_positive"),
    ("asus_rt_be57", 6, "historical_filtered"),
    ("asus_rt_be57", 18, "historical_dynamic_nms"),
    ("r6400v2", 62, "historical_sink_reconciled"),
    ("r6400v2", 3, "historical_static_reduction"),
    ("tenda_ac15", 4, "historical_static_positive"),
]


def load_record(path: Path, closure_idx: int) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            if int(record.get("closure_idx") or 0) == closure_idx:
                return record
    raise KeyError(f"closure {closure_idx} not found in {path}")


def read_single_jsonl(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                return json.loads(line)
    raise ValueError(f"no result record in {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--baseline-dir",
        type=Path,
        default=Path(
            "experiment_reports/full_firmware_campaign_current_tsds_20260627"
        ),
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--python",
        type=Path,
        default=Path(
            "/home/ubuntu/work/sanitizer/operation-mango-public/.venv/bin/python"
        ),
    )
    parser.add_argument(
        "--evaluator",
        type=Path,
        default=Path(
            "/home/ubuntu/work/sanitizer/Taint_demo/sanitizer_demo/"
            "advanced_sanitizer_evaluator.py"
        ),
    )
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()

    args.root = args.root.resolve()
    args.baseline_dir = (
        args.baseline_dir
        if args.baseline_dir.is_absolute()
        else args.root / args.baseline_dir
    ).resolve()
    args.out_dir = args.out_dir.resolve()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    target_map = {item["name"]: item for item in TARGETS}
    rows = []

    for target, closure_idx, sample_class in SAMPLES:
        target_meta = target_map[target]
        baseline = load_record(
            args.baseline_dir / f"{target}.results.jsonl", closure_idx
        )
        stem = f"{target}.closure_{closure_idx:04d}"
        summary_path = args.out_dir / f"{stem}.summary.json"
        result_path = args.out_dir / f"{stem}.results.jsonl"
        report_path = args.out_dir / f"{stem}.report.md"
        log_path = args.out_dir / f"{stem}.stdout.log"
        command = [
            str(args.python),
            str(args.evaluator),
            str(args.root / target_meta["binary"]),
            str(args.root / target_meta["mango"]),
            "--closure-idx",
            str(closure_idx),
            "--mode",
            "full",
            "--engine-timeout",
            "60",
            "--max-steps",
            "700",
            "--closure-timeout",
            "120",
            "--closure-memo-limit",
            "0",
            "--no-evidence-cache",
            "--summary-json",
            str(summary_path),
            "--results-jsonl",
            str(result_path),
            "--report-file",
            str(report_path),
        ]
        start = time.perf_counter()
        try:
            proc = subprocess.run(
                command,
                cwd=args.root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=args.timeout,
                check=False,
            )
            output = proc.stdout
            returncode = proc.returncode
        except subprocess.TimeoutExpired as exc:
            output = (exc.stdout or "") + "\nREPRESENTATIVE_REPLAY_TIMEOUT"
            returncode = 124
        log_path.write_text(output, encoding="utf-8", errors="replace")
        current = read_single_jsonl(result_path) if result_path.exists() else {}
        rows.append(
            {
                "target": target,
                "closure_idx": closure_idx,
                "sample_class": sample_class,
                "baseline_status": baseline.get("status"),
                "baseline_recovery": baseline.get("analysis_recovery") or "",
                "v10_status": current.get("status") or "",
                "v10_verdict": current.get("verdict") or "",
                "v10_provenance": current.get("evidence_provenance") or "",
                "contract_valid": current.get("evidence_contract_valid"),
                "sat_vectors": int(current.get("vulnerable_vectors") or 0),
                "unsat_vectors": int(current.get("secure_vectors") or 0),
                "inconclusive_vectors": int(
                    current.get("inconclusive_vectors") or 0
                ),
                "controlled_bytes": int(current.get("tainted_byte_count") or 0),
                "returncode": returncode,
                "elapsed_sec": round(time.perf_counter() - start, 4),
                "log": str(log_path),
            }
        )

    fields = list(rows[0]) if rows else []
    with (args.out_dir / "representative_replay.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    summary = {
        "schema": "tsds-v10-representative-replay-v1",
        "samples": len(rows),
        "contract_valid": sum(
            1 for row in rows if row.get("contract_valid") is True
        ),
        "transitions": {
            f"{row['baseline_status']}->{row['v10_status']}": sum(
                1
                for other in rows
                if other["baseline_status"] == row["baseline_status"]
                and other["v10_status"] == row["v10_status"]
            )
            for row in rows
        },
        "rows": rows,
    }
    (args.out_dir / "representative_replay_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lines = [
        "# TSDS v10 representative replay",
        "",
        "| Target | Closure | Historical tier | Old status | v10 status | Provenance | Contract | SAT/UNSAT/? |",
        "|---|---:|---|---|---|---|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| {target} | {closure_idx} | {sample_class} | {baseline_status} | "
            "{v10_status} | {v10_provenance} | {contract_valid} | "
            "{sat_vectors}/{unsat_vectors}/{inconclusive_vectors} |".format(**row)
        )
    (args.out_dir / "README.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["contract_valid"] == summary["samples"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
