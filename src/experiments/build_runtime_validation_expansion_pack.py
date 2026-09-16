#!/usr/bin/env python3
"""Build an expanded runtime-validation evidence pack for TSDS.

This script consolidates qemu/gdb canary summaries and logs, validates whether
tokens are actually present in intercepted sink arguments, and prepares the
next runtime-validation worklist across direct SV-SAT, guarded SV-SAT,
modeled-filtered, NMS, and path-control changed records.

It does not execute a shell and does not add device-confirmed exploit claims.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SCHEMA = "tsds-runtime-validation-expansion-v2"


DEFAULT_CAMPAIGN = Path("experiment_reports/full_firmware_campaign_current_tsds_20260627")
DEFAULT_PC = Path("experiment_reports/iceccs_urgent_validation_pack_20260702/path_control_claim_impact_analysis.csv")
DEFAULT_CANARY_ROOTS = [
    Path("experiment_reports/runtime_canary_validation_20260629"),
    Path("experiment_reports/rehosting_canary_20260628"),
    Path("experiment_reports/rehosting_canary_20260629"),
]
DEFAULT_OUT = Path("experiment_reports/runtime_validation_expansion_pack_20260702")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_rows_sha256(rows: list[dict[str, Any]]) -> str:
    payload = json.dumps(
        rows,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def campaign_identity(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    files = sorted(path.glob("*.results.jsonl"))
    for item in files:
        payload = item.read_bytes()
        digest.update(item.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).digest())
        digest.update(b"\0")
    return {
        "path": str(path.resolve()),
        "result_files": len(files),
        "results_identity_sha256": digest.hexdigest(),
    }


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        return list(csv.DictReader(fh))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def short(value: Any, limit: int = 140) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\n", r"\n").replace("\r", r"\r").replace("\t", r"\t")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def joined(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return "; ".join(str(v) for v in value)
    return str(value)


def load_campaign(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in sorted(path.glob("*.results.jsonl")):
        target = item.name.replace(".results.jsonl", "")
        for row in read_jsonl(item):
            out = dict(row)
            out["_target"] = target
            rows.append(out)
    return rows


def find_logs(directory: Path) -> list[Path]:
    names = [
        "gdb.log",
        "gdb.final.log",
        "gdb_direct.log",
        "gdb_chroot_static_success.log",
        "status.txt",
    ]
    return [directory / name for name in names if (directory / name).exists()]


def log_text(paths: list[Path]) -> str:
    parts: list[str] = []
    for path in paths:
        try:
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return "\n".join(parts)


def token_from_summary(summary: dict[str, Any]) -> str:
    for key in ("token", "canary_token"):
        if summary.get(key):
            return str(summary[key])
    return ""


def sink_from_summary(summary: dict[str, Any]) -> str:
    return str(summary.get("sink") or summary.get("sink_callsite") or summary.get("callsite") or "")


def firmware_from_summary(summary: dict[str, Any]) -> str:
    return str(summary.get("firmware") or summary.get("target") or "")


def is_positive_summary(summary: dict[str, Any], logs: str) -> bool:
    token = token_from_summary(summary)
    if not token:
        return False
    observed = str(summary.get("observed_command") or "")
    direct_flags = [
        bool(summary.get("canary_observed_in_gdb")),
        bool(summary.get("token_observed_in_gdb")),
    ]
    if any(direct_flags) and (token in observed or token in logs):
        return True
    # Several service-level summaries are distilled from gdb logs and record the
    # intercepted command directly rather than repeating a boolean flag.
    return bool(observed and token in observed and (summary.get("evidence_log") or summary.get("callsite")))


def attempt_class(summary: dict[str, Any], logs: str) -> str:
    if is_positive_summary(summary, logs):
        return "positive_token_to_sink"
    if int(summary.get("sink_hit_count") or 0) > 0 or "TSDS_GDB_HIT" in logs:
        return "boundary_sink_hit_no_token"
    if summary.get("login_result_forced") or summary.get("auth_bypass_hits") is not None:
        return "boundary_auth_or_fixture"
    return "boundary_no_sink_hit"


def observed_command(summary: dict[str, Any], logs: str) -> str:
    if summary.get("observed_command"):
        return short(summary.get("observed_command"), 220)
    # Best-effort extraction of the string printed by gdb after x/s.
    for line in logs.splitlines():
        if re.search(r"0x[0-9a-fA-F]+:\s+\"", line):
            return short(line.split(":", 1)[1].strip().strip('"'), 220)
    return ""


def collect_attempts(roots: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for root in roots:
        if not root.exists():
            continue
        for summary_path in sorted(root.rglob("canary_summary.json")):
            summary = read_json(summary_path)
            directory = summary_path.parent
            logs = log_text(find_logs(directory))
            token = token_from_summary(summary)
            cls = attempt_class(summary, logs)
            log_paths = find_logs(directory)
            evidence_digest = hashlib.sha256()
            for log_path in log_paths:
                evidence_digest.update(log_path.name.encode("utf-8"))
                evidence_digest.update(b"\0")
                evidence_digest.update(bytes.fromhex(sha256_file(log_path)))
                evidence_digest.update(b"\0")
            rows.append(
                {
                    "id": summary.get("id") or summary.get("candidate") or directory.name,
                    "target": firmware_from_summary(summary),
                    "vendor": summary.get("vendor") or "",
                    "level": summary.get("level") or summary.get("boundary") or "",
                    "handler_or_entry": summary.get("handler") or summary.get("entry") or "",
                    "sink": sink_from_summary(summary),
                    "callsite": summary.get("callsite") or summary.get("sink_callsite") or "",
                    "token": token,
                    "attempt_class": cls,
                    "token_in_logs": bool(token and token in logs),
                    "token_in_observed_command": bool(token and token in str(summary.get("observed_command") or "")),
                    "gdb_hit": bool(summary.get("gdb_hit")) or "TSDS_GDB_HIT" in logs,
                    "sink_hit_count": summary.get("sink_hit_count") or "",
                    "observed_command": observed_command(summary, logs),
                    "evidence_dir": str(directory),
                    "summary_sha256": sha256_file(summary_path),
                    "evidence_log_count": len(log_paths),
                    "evidence_logs_identity_sha256": evidence_digest.hexdigest(),
                    "claim_boundary": summary.get("claim_boundary") or summary.get("boundary") or "qemu/gdb sink-callsite evidence only",
                }
            )
    return rows


def unique_positive_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("target") or "").lower(),
        str(row.get("callsite") or row.get("sink") or "").lower(),
        str(row.get("token") or "").lower(),
    )


def classify_record(row: dict[str, Any]) -> str:
    verdict = str(row.get("verdict") or "")
    if verdict == "VECTOR_SAT":
        mode = str(row.get("analysis_recovery") or "")
        if mode:
            return "guarded_sv_sat"
        if row.get("partially_filtered") or (
            int(row.get("vulnerable_vectors") or 0) > 0
            and int(row.get("secure_vectors") or 0) > 0
        ):
            return "partial_sv_sat"
        return "direct_sv_sat"
    if verdict == "MATRIX_UNSAT":
        return "modeled_vector_filtered"
    if verdict == "NO_MODELED_SOURCE":
        return "nms"
    if verdict == "STATIC_SOURCE_INFERENCE":
        return "static_source_inference"
    if verdict == "STATIC_WARNING_REDUCTION":
        return "static_warning_reduction"
    if verdict == "RESIDUAL":
        return "residual"
    # Legacy ledgers predate the verdict contract. Keep them ingestible while
    # ensuring current v20 records are classified solely by the contract field.
    if row.get("status") == "vulnerable":
        mode = str(row.get("analysis_recovery") or "")
        if mode:
            return "guarded_sv_sat"
        if row.get("partially_filtered"):
            return "partial_sv_sat"
        return "direct_sv_sat"
    if row.get("status") == "filtered":
        return "modeled_vector_filtered"
    if row.get("status") == "no_taint_sink":
        return "nms"
    return "residual"


def candidate_score(row: dict[str, Any], stratum: str) -> int:
    score = 0
    if stratum == "guarded_sv_sat":
        score += 70
    elif stratum == "direct_sv_sat":
        score += 65
    elif stratum == "modeled_vector_filtered":
        score += 60
    elif stratum == "nms":
        score += 55
    elif stratum == "partial_sv_sat":
        score += 50
    elif stratum == "static_source_inference":
        score += 35
    elif stratum == "static_warning_reduction":
        score += 25
    else:
        score += 30
    if row.get("evidence_confidence") == "high":
        score += 15
    if row.get("closure_reachable_from_main") is True:
        score += 10
    if str(row.get("sink_function") or "").lower() in {"system", "popen", "twsystem", "dosystemcmd"}:
        score += 8
    if int(row.get("trace_len") or 0) <= 2:
        score += 5
    if row.get("_target") in {"tenda_w20e", "tenda_ac15", "tenda_ac18", "dir878"}:
        score += 5
    return score


def select_candidates(rows: list[dict[str, Any]], limit_per_class: int = 8) -> list[dict[str, Any]]:
    by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_class[classify_record(row)].append(row)
    selected: list[dict[str, Any]] = []
    for stratum in [
        "direct_sv_sat",
        "guarded_sv_sat",
        "modeled_vector_filtered",
        "nms",
        "partial_sv_sat",
        "static_source_inference",
        "static_warning_reduction",
        "residual",
    ]:
        pool = sorted(
            by_class.get(stratum, []),
            key=lambda r: (-candidate_score(r, stratum), str(r.get("_target")), int(r.get("closure_idx") or 0)),
        )
        for row in pool[:limit_per_class]:
            selected.append(
                {
                    "stratum": stratum,
                    "priority_score": candidate_score(row, stratum),
                    "target": row.get("_target"),
                    "closure_idx": row.get("closure_idx"),
                    "status": row.get("status"),
                    "recovery_mode": row.get("analysis_recovery") or "direct",
                    "sink": f"{row.get('sink_function')}@{row.get('sink_addr')}",
                    "source": f"{row.get('source_function')}@{row.get('source_addr')}",
                    "trace": short(row.get("trace_summary"), 160),
                    "preview": short(row.get("sink_preview") or row.get("no_taint_preview") or row.get("recovered_sink_template"), 180),
                    "canary_token": f"TSDS_RT_{str(row.get('_target')).upper()}_{row.get('closure_idx')}",
                    "next_experiment": next_experiment_for(stratum),
                    "success_condition": success_condition_for(stratum),
                    "non_claim": "sink-intercept consistency target only; not device exploit proof",
                }
            )
    return selected


def next_experiment_for(stratum: str) -> str:
    if stratum in {"direct_sv_sat", "partial_sv_sat"}:
        return "qemu/gdb sink-callsite canary with source token in intercepted command argument"
    if stratum == "guarded_sv_sat":
        return "qemu/gdb sink-callsite canary targeted at recovered template/source slot"
    if stratum == "modeled_vector_filtered":
        return "negative sink-intercept probe: handler reaches sink but modeled shell-vector token is absent or blocked"
    if stratum == "nms":
        return "negative sink-intercept probe: reached sink command remains fixed or source token stays outside sink"
    if stratum == "static_source_inference":
        return "targeted dynamic replay before any sink-level claim; static source provenance is not a reached-sink result"
    if stratum == "static_warning_reduction":
        return "optional low-priority dynamic replay of a static fixed-template reduction"
    return "boundary replay or high-budget symbolic rerun before dynamic fixture investment"


def success_condition_for(stratum: str) -> str:
    if stratum in {"direct_sv_sat", "partial_sv_sat", "guarded_sv_sat"}:
        return "token observed in gdb-captured sink argument; shell call skipped"
    if stratum == "modeled_vector_filtered":
        return "sink reached and token/source slot does not satisfy any implemented vector predicate"
    if stratum == "nms":
        return "sink reached and submitted token is absent from final sink argument"
    if stratum in {"static_source_inference", "static_warning_reduction"}:
        return "typed runtime outcome recorded without promoting static evidence to sink-level evidence"
    return "typed boundary reason recorded"


def path_control_targets(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in read_csv(path):
        out.append(
            {
                "stratum": "path_control_changed",
                "priority_score": 75 if row.get("claim_impact") == "manual_review_only_extra_positive" else 50,
                "target": row.get("target"),
                "closure_idx": row.get("closure_idx"),
                "status": row.get("transition"),
                "recovery_mode": "",
                "sink": row.get("sink"),
                "source": "",
                "trace": short(row.get("trace")),
                "preview": "",
                "canary_token": f"TSDS_PC_{str(row.get('target')).upper()}_{row.get('closure_idx')}",
                "next_experiment": "qemu/gdb or high-budget symbolic replay of path-control changed case",
                "success_condition": row.get("interpretation") or "claim-impact boundary recorded",
                "non_claim": "path-control sensitivity target; not a positive unless manually confirmed",
            }
        )
    return sorted(out, key=lambda r: (-int(r["priority_score"]), str(r["target"]), int(r["closure_idx"] or 0)))[:8]


def write_markdown(path: Path, attempts: list[dict[str, Any]], candidates: list[dict[str, Any]], pc: list[dict[str, Any]]) -> None:
    attempt_counts = Counter(row["attempt_class"] for row in attempts)
    unique_positive = {unique_positive_key(row) for row in attempts if row["attempt_class"] == "positive_token_to_sink"}
    lines = [
        "# Runtime validation expansion pack",
        "",
        "This pack consolidates qemu/gdb sink-intercept evidence and prepares the next validation wave. It does not execute shell payloads and does not add device-confirmed exploit claims.",
        "",
        f"- Runtime attempt summaries parsed: `{len(attempts)}`",
        f"- Positive token-to-sink attempts: `{attempt_counts.get('positive_token_to_sink', 0)}`",
        f"- Unique positive token/callsite keys: `{len(unique_positive)}`",
        f"- Boundary or negative attempts: `{len(attempts) - attempt_counts.get('positive_token_to_sink', 0)}`",
        f"- New candidate rows prepared: `{len(candidates)}`",
        f"- Path-control changed candidate rows prepared: `{len(pc)}`",
        "",
        "## Attempt Classes",
        "",
        "| Class | Records |",
        "|---|---:|",
    ]
    for key, count in sorted(attempt_counts.items()):
        lines.append(f"| `{key}` | {count} |")
    lines.extend(
        [
            "",
            "## Priority Candidate Mix",
            "",
            "| Stratum | Records |",
            "|---|---:|",
        ]
    )
    for key, count in sorted(Counter(row["stratum"] for row in candidates).items()):
        lines.append(f"| `{key}` | {count} |")
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "Positive rows mean only that a configured token was observed in a gdb-captured sink argument under qemu-user or direct service-routine execution, with shell execution skipped. Boundary rows are retained when the handler or sink is reached without the token, or when auth/fixture alignment prevents sink observation.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign-dir", type=Path, default=DEFAULT_CAMPAIGN)
    ap.add_argument("--path-control-csv", type=Path, default=DEFAULT_PC)
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--canary-root", action="append", type=Path)
    ap.add_argument("--limit-per-class", type=int, default=8)
    args = ap.parse_args()

    roots = args.canary_root or DEFAULT_CANARY_ROOTS
    rows = load_campaign(args.campaign_dir)
    attempts = collect_attempts(roots)
    candidates = select_candidates(rows, limit_per_class=args.limit_per_class)
    pc_candidates = path_control_targets(args.path_control_csv)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.out_dir / "runtime_attempt_replay.csv", attempts)
    write_csv(args.out_dir / "runtime_validation_candidate_expansion.csv", candidates)
    write_csv(args.out_dir / "path_control_runtime_targets.csv", pc_candidates)

    attempt_counts = Counter(row["attempt_class"] for row in attempts)
    unique_positive = {unique_positive_key(row) for row in attempts if row["attempt_class"] == "positive_token_to_sink"}
    campaign = campaign_identity(args.campaign_dir)
    summary = {
        "schema": SCHEMA,
        "valid": bool(campaign["result_files"] > 0 and attempts),
        "campaign_identity": campaign,
        "canary_roots": [str(path.resolve()) for path in roots],
        "runtime_attempts": len(attempts),
        "runtime_attempts_identity_sha256": canonical_rows_sha256(attempts),
        "attempt_classes": dict(attempt_counts),
        "positive_token_to_sink_attempts": attempt_counts.get("positive_token_to_sink", 0),
        "unique_positive_token_callsite_keys": len(unique_positive),
        "candidate_rows": len(candidates),
        "candidate_rows_identity_sha256": canonical_rows_sha256(candidates),
        "candidate_strata": dict(Counter(row["stratum"] for row in candidates)),
        "path_control_target_rows": len(pc_candidates),
        "path_control_rows_identity_sha256": canonical_rows_sha256(pc_candidates),
        "claim_boundary": "qemu/gdb sink-intercept evidence only; no shell execution or device-confirmed exploit claims.",
    }
    (args.out_dir / "runtime_validation_expansion_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    write_markdown(args.out_dir / "runtime_validation_expansion_summary.md", attempts, candidates, pc_candidates)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
