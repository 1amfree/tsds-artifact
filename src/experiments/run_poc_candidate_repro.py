#!/usr/bin/env python3
"""Re-run TSDS on PoC/emulation candidate closures and compare evidence.

This script produces an analyzer-reproducibility package.  It does not execute
candidate payloads, start firmware services, or confirm device-level exploits.
Each record remains sink-level TSDS evidence unless a separate isolated
emulation or owned-hardware canary run observes the command effect.
"""

from __future__ import annotations

import argparse
import csv
import json
import shlex
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


DEFAULT_CANDIDATES = Path("experiment_reports/poc_validation_candidates_v9_20260626/poc_validation_candidates.csv")
DEFAULT_CAMPAIGN = Path("experiment_reports/full_firmware_campaign_v9_20260625")
DEFAULT_OUT = Path("experiment_reports/poc_candidate_repro_v9_20260626")

REMOTE_ROOT = "/home/ubuntu/work/sanitizer"
REMOTE_PYTHON = f"{REMOTE_ROOT}/operation-mango-public/.venv/bin/python"
REMOTE_EVALUATOR = f"{REMOTE_ROOT}/Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py"
REMOTE_OUT = f"{REMOTE_ROOT}/experiment_reports/poc_candidate_repro_v9_20260626"


TARGETS: Dict[str, Dict[str, str]] = {
    "ASUS RT-BE57": {
        "binary": f"{REMOTE_ROOT}/ASUS_RT-BE57/httpd",
        "json": f"{REMOTE_ROOT}/ASUS_RT-BE57/result/cmdi_results.json",
    },
    "D-Link DIR-878": {
        "binary": f"{REMOTE_ROOT}/DIR-878/rc",
        "json": f"{REMOTE_ROOT}/DIR-878/DIR_878_results/cmdi_results.json",
    },
    "Netgear R6400v2": {
        "binary": f"{REMOTE_ROOT}/R6400v2/httpd",
        "json": f"{REMOTE_ROOT}/R6400v2/R6400v2_result/cmdi_results.json",
    },
    "Netgear R7000": {
        "binary": f"{REMOTE_ROOT}/R7000/httpd",
        "json": f"{REMOTE_ROOT}/R7000/R7000_result/cmdi_results.json",
    },
    "Netgear XR300": {
        "binary": f"{REMOTE_ROOT}/XR300/httpd",
        "json": f"{REMOTE_ROOT}/XR300/results/cmdi_results.json",
    },
    "Tenda AC15": {
        "binary": f"{REMOTE_ROOT}/Tenda_AC15/httpd",
        "json": f"{REMOTE_ROOT}/Tenda_AC15/Tenda_AC15_results/cmdi_results.json",
    },
    "Tenda AC18": {
        "binary": f"{REMOTE_ROOT}/Tenda_AC18/httpd",
        "json": f"{REMOTE_ROOT}/Tenda_AC18/results/cmdi_results.json",
    },
    "Tenda W20E": {
        "binary": f"{REMOTE_ROOT}/Tenda_W20E/httpd",
        "json": f"{REMOTE_ROOT}/Tenda_W20E/results/cmdi_results.json",
    },
}


def load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


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


def short(value: Any, limit: int = 120) -> str:
    text = str(value or "").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def load_campaign_records(campaign_dir: Path) -> Dict[Tuple[str, int], Dict[str, Any]]:
    records: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for path in campaign_dir.glob("*.results.jsonl"):
        for row in load_jsonl(path):
            records[(path.name, as_int(row.get("closure_idx")))] = row
    return records


def evidence_signature(row: Dict[str, Any]) -> Dict[str, Any]:
    minimal = row.get("minimal_bypass_vector") or {}
    return {
        "status": row.get("status") or "",
        "sink_function": row.get("sink_function") or "",
        "sink_addr": row.get("sink_addr") or "",
        "trace_summary": row.get("trace_summary") or "",
        "vulnerable_vectors": as_int(row.get("vulnerable_vectors")),
        "secure_vectors": as_int(row.get("secure_vectors")),
        "partially_filtered": bool(row.get("partially_filtered")),
        "analysis_recovery": row.get("analysis_recovery") or "",
        "minimal_bypass_category": minimal.get("category") or "",
        "static_evidence_strength": row.get("static_evidence_strength") or "",
        "paper_claim_bucket": row.get("paper_claim_bucket") or "",
    }


def compare(expected: Dict[str, Any], actual: Dict[str, Any]) -> Tuple[str, List[str]]:
    exp = evidence_signature(expected)
    act = evidence_signature(actual)
    mismatches: List[str] = []
    for key in [
        "status",
        "sink_function",
        "sink_addr",
        "partially_filtered",
        "analysis_recovery",
        "minimal_bypass_category",
        "paper_claim_bucket",
    ]:
        if exp.get(key) != act.get(key):
            mismatches.append(f"{key}: expected={exp.get(key)!r} actual={act.get(key)!r}")
    if exp["vulnerable_vectors"] != act["vulnerable_vectors"]:
        mismatches.append(
            f"vulnerable_vectors: expected={exp['vulnerable_vectors']} actual={act['vulnerable_vectors']}"
        )
    if exp["secure_vectors"] != act["secure_vectors"]:
        mismatches.append(f"secure_vectors: expected={exp['secure_vectors']} actual={act['secure_vectors']}")
    return ("PASS" if not mismatches else "DRIFT"), mismatches


def shell_quote(value: str) -> str:
    return shlex.quote(value)


def build_command(candidate: Dict[str, str], remote_out: str, timeout_sec: int) -> Tuple[str, str]:
    target = candidate["target"]
    if target not in TARGETS:
        raise KeyError(f"no remote mapping for target {target}")
    cid = candidate["candidate_id"]
    closure_idx = as_int(candidate["closure_idx"])
    out_dir = f"{remote_out}/{cid}"
    paths = TARGETS[target]
    summary = f"{out_dir}/{cid}.summary.json"
    jsonl = f"{out_dir}/{cid}.results.jsonl"
    report = f"{out_dir}/{cid}.report.md"
    stdout_log = f"{out_dir}/{cid}.stdout.log"
    stderr_log = f"{out_dir}/{cid}.stderr.log"
    argv = [
        REMOTE_PYTHON,
        REMOTE_EVALUATOR,
        paths["binary"],
        paths["json"],
        "--closure-idx",
        str(closure_idx),
        "--engine-timeout",
        "45",
        "--max-steps",
        "500",
        "--closure-timeout",
        "90",
        "--subprocess-timeout",
        "150",
        "--summary-json",
        summary,
        "--results-jsonl",
        jsonl,
        "--report-file",
        report,
        "--no-evidence-cache",
    ]
    command = (
        f"mkdir -p {shell_quote(out_dir)} && "
        f"cd {shell_quote(REMOTE_ROOT)} && "
        f"timeout {int(timeout_sec)}s "
        + " ".join(shell_quote(x) for x in argv)
        + f" > {shell_quote(stdout_log)} 2> {shell_quote(stderr_log)}"
    )
    return command, out_dir


def ssh_connect(host: str, user: str, password: str):
    try:
        import paramiko
    except Exception as exc:  # pragma: no cover - dependency check path
        raise SystemExit(f"paramiko is required for SSH execution: {exc}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=password, timeout=15, banner_timeout=15, auth_timeout=15)
    return client


def run_remote(client: Any, command: str, timeout: int) -> Tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def sftp_fetch_dir(client: Any, remote_dir: str, local_dir: Path) -> None:
    local_dir.mkdir(parents=True, exist_ok=True)
    sftp = client.open_sftp()
    try:
        for item in sftp.listdir_attr(remote_dir):
            if item.filename in {".", ".."}:
                continue
            remote_path = f"{remote_dir}/{item.filename}"
            local_path = local_dir / item.filename
            sftp.get(remote_path, str(local_path))
    finally:
        sftp.close()


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


def markdown(rows: List[Dict[str, Any]], remote_out: str) -> str:
    pass_count = sum(1 for row in rows if row["repro_verdict"] == "PASS")
    drift_count = sum(1 for row in rows if row["repro_verdict"] == "DRIFT")
    fail_count = sum(1 for row in rows if row["repro_verdict"] == "RUN_FAILED")
    lines = [
        "# TSDS Candidate Reproducibility Pack",
        "",
        "This package re-runs TSDS on selected validation candidates. It does not perform emulation, trigger firmware services, or confirm device-level vulnerabilities.",
        "",
        f"- Remote output: `{remote_out}`",
        f"- Candidates: `{len(rows)}`",
        f"- Reproduced exactly: `{pass_count}`",
        f"- Semantic drift: `{drift_count}`",
        f"- Run failures: `{fail_count}`",
        "",
        "| ID | Target | Theme | Expected | Actual | Verdict | Notes |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        expected = f"{row['expected_status']}/{row['expected_vulnerable_vectors']} SAT/{row['expected_secure_vectors']} UNSAT"
        actual = f"{row['actual_status']}/{row['actual_vulnerable_vectors']} SAT/{row['actual_secure_vectors']} UNSAT"
        lines.append(
            f"| `{row['candidate_id']}` | {row['target']} | `{row['functional_theme']}` | `{expected}` | `{actual}` | `{row['repro_verdict']}` | {short(row.get('mismatch_summary'), 100)} |"
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "A PASS row means the latest TSDS implementation reproduced the sink-level evidence signature from the v9 campaign for that closure. It must not be reported as emulation-confirmed or device-confirmed unless a separate isolated canary run observes the command effect.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--candidate-csv", default=str(DEFAULT_CANDIDATES))
    parser.add_argument("--campaign-dir", default=str(DEFAULT_CAMPAIGN))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--host", default="192.168.206.137")
    parser.add_argument("--user", default="ubuntu")
    parser.add_argument("--password", default="ubuntu")
    parser.add_argument("--remote-out", default=REMOTE_OUT)
    parser.add_argument("--timeout-sec", type=int, default=260)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    candidates = load_csv((root / args.candidate_csv).resolve())
    if args.limit:
        candidates = candidates[: args.limit]
    baseline = load_campaign_records((root / args.campaign_dir).resolve())
    out_dir = (root / args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    commands: List[Dict[str, str]] = []
    for candidate in candidates:
        command, remote_case_dir = build_command(candidate, args.remote_out, args.timeout_sec)
        commands.append(
            {
                "candidate_id": candidate["candidate_id"],
                "target": candidate["target"],
                "closure_idx": candidate["closure_idx"],
                "remote_case_dir": remote_case_dir,
                "command": command,
            }
        )
    (out_dir / "candidate_repro_commands.json").write_text(json.dumps(commands, indent=2), encoding="utf-8")
    if args.dry_run:
        print(json.dumps({"commands": commands, "out_dir": str(out_dir)}, indent=2))
        return

    client = ssh_connect(args.host, args.user, args.password)
    rows: List[Dict[str, Any]] = []
    try:
        for idx, candidate in enumerate(candidates, 1):
            cid = candidate["candidate_id"]
            key = (candidate["jsonl_file"], as_int(candidate["closure_idx"]))
            expected = baseline.get(key)
            if expected is None:
                raise KeyError(f"missing baseline record for {key}")
            command, remote_case_dir = build_command(candidate, args.remote_out, args.timeout_sec)
            start = time.time()
            code, out, err = run_remote(client, command, timeout=args.timeout_sec + 60)
            elapsed = time.time() - start
            case_local = out_dir / cid
            try:
                sftp_fetch_dir(client, remote_case_dir, case_local)
            except Exception as exc:
                (case_local / "fetch_error.txt").write_text(str(exc), encoding="utf-8")

            result_rows = load_jsonl(case_local / f"{cid}.results.jsonl")
            actual = result_rows[0] if result_rows else {}
            if code != 0 or not actual:
                verdict = "RUN_FAILED"
                mismatches = [f"exit_code={code}", "missing result JSONL" if not actual else ""]
            else:
                verdict, mismatches = compare(expected, actual)
            exp_sig = evidence_signature(expected)
            act_sig = evidence_signature(actual)
            row = {
                "candidate_id": cid,
                "target": candidate["target"],
                "functional_theme": candidate.get("functional_theme", ""),
                "evidence_type": candidate.get("evidence_type", ""),
                "closure_idx": candidate["closure_idx"],
                "closure_ordinal": candidate.get("closure_ordinal", ""),
                "exit_code": code,
                "elapsed_sec": round(elapsed, 3),
                "repro_verdict": verdict,
                "expected_status": exp_sig["status"],
                "actual_status": act_sig["status"],
                "expected_vulnerable_vectors": exp_sig["vulnerable_vectors"],
                "actual_vulnerable_vectors": act_sig["vulnerable_vectors"],
                "expected_secure_vectors": exp_sig["secure_vectors"],
                "actual_secure_vectors": act_sig["secure_vectors"],
                "expected_sink": f"{exp_sig['sink_function']}@{exp_sig['sink_addr']}",
                "actual_sink": f"{act_sig['sink_function']}@{act_sig['sink_addr']}",
                "expected_recovery": exp_sig["analysis_recovery"],
                "actual_recovery": act_sig["analysis_recovery"],
                "mismatch_summary": "; ".join(item for item in mismatches if item),
                "remote_case_dir": remote_case_dir,
                "local_case_dir": str(case_local),
            }
            rows.append(row)
            print(json.dumps({"progress": f"{idx}/{len(candidates)}", **row}, ensure_ascii=False))
    finally:
        client.close()

    write_csv(out_dir / "candidate_repro.csv", rows)
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "candidate_count": len(rows),
        "pass": sum(1 for row in rows if row["repro_verdict"] == "PASS"),
        "drift": sum(1 for row in rows if row["repro_verdict"] == "DRIFT"),
        "run_failed": sum(1 for row in rows if row["repro_verdict"] == "RUN_FAILED"),
        "remote_out": args.remote_out,
        "out_dir": str(out_dir),
        "boundary": "Analyzer reproducibility only; not emulation-confirmed or device-confirmed.",
    }
    (out_dir / "candidate_repro_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "candidate_repro.md").write_text(markdown(rows, args.remote_out), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
