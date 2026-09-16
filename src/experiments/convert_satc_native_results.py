#!/usr/bin/env python3
"""Convert raw SaTC result files into the strict native-front-end schema."""

from __future__ import annotations

import argparse
import json
import platform
import re
import shlex
from collections import defaultdict
from pathlib import Path
from typing import Any


RESULT_RE = re.compile(
    r"^(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+"
    r"(?:(found)\s*:\s*(.*)|(not\s+found))\s*$"
)


def normalize_addr(value: Any) -> str:
    text = str(value or "").strip().lower()
    try:
        return hex(int(text, 16 if text.startswith("0x") else 0))
    except ValueError:
        return text


def parse_addr_list(text: str) -> list[str]:
    return [
        normalize_addr(token)
        for token in text.split()
        if re.fullmatch(r"0x[0-9a-fA-F]+", token)
    ]


def parse_satc_config(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    issues = []
    if len(lines) % 3:
        issues.append("config_line_count_not_multiple_of_three")
    cases = []
    for offset in range(0, len(lines) - 2, 3):
        header = lines[offset].split()
        if len(header) < 2:
            issues.append(f"config_case_{offset // 3}_invalid_header")
            continue
        source_addr = normalize_addr(header[0])
        start_addr = normalize_addr(header[1])
        sink_addrs = parse_addr_list(lines[offset + 2])
        if not source_addr or not start_addr or not sink_addrs:
            issues.append(f"config_case_{offset // 3}_missing_identity")
        cases.append(
            {
                "case_idx": offset // 3,
                "source_addr": source_addr,
                "start_addr": start_addr,
                "follow_trace": parse_addr_list(lines[offset + 1]),
                "expected_sinks": sink_addrs,
            }
        )
    return cases, issues


def parse_satc_result(path: Path) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    cases = []
    issues = []
    totals: dict[str, int] = {}
    for line_no, raw in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("binary:"):
            metadata["binary"] = line.split(":", 1)[1].strip()
            continue
        if line.startswith("configfile:"):
            metadata["configfile"] = line.split(":", 1)[1].strip()
            continue
        if line.startswith("total cases:"):
            try:
                totals["total_cases"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                issues.append(f"line_{line_no}_invalid_total_cases")
            continue
        if line.startswith("find cases:"):
            try:
                totals["find_cases"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                issues.append(f"line_{line_no}_invalid_find_cases")
            continue
        match = RESULT_RE.match(line)
        if not match:
            issues.append(f"line_{line_no}_unparsed")
            continue
        found = bool(match.group(3))
        cases.append(
            {
                "result_idx": len(cases),
                "source_addr": normalize_addr(match.group(1)),
                "start_addr": normalize_addr(match.group(2)),
                "outcome": "found" if found else "not_found",
                "found_sinks": parse_addr_list(match.group(4) or ""),
            }
        )
    if "total_cases" not in totals:
        issues.append("missing_total_cases")
    if "find_cases" not in totals:
        issues.append("missing_find_cases")
    if totals.get("find_cases") != sum(row["outcome"] == "found" for row in cases):
        issues.append("find_case_count_mismatch")
    if totals.get("total_cases", len(cases)) < len(cases):
        issues.append("result_rows_exceed_total_cases")
    return {"metadata": metadata, "cases": cases, "totals": totals, "issues": issues}


def align_cases(
    config_cases: list[dict[str, Any]], result_cases: list[dict[str, Any]]
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[dict[str, Any]], list[str]]:
    by_identity: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for case in config_cases:
        by_identity[(case["source_addr"], case["start_addr"])].append(case)
    aligned = []
    used_config_indices = set()
    issues = []
    unmatched_results = []
    for result in result_cases:
        key = (result["source_addr"], result["start_addr"])
        candidates = [
            case for case in by_identity.get(key, []) if case["case_idx"] not in used_config_indices
        ]
        if len(candidates) == 1:
            config = candidates[0]
            used_config_indices.add(config["case_idx"])
            aligned.append((config, result))
        else:
            unmatched_results.append(result)

    remaining_configs = [
        case for case in config_cases if case["case_idx"] not in used_config_indices
    ]
    if unmatched_results and len(unmatched_results) == len(remaining_configs):
        issues.append("case_identity_order_fallback")
        for config, result in zip(remaining_configs, unmatched_results):
            used_config_indices.add(config["case_idx"])
            aligned.append((config, result))
        remaining_configs = []
    elif unmatched_results:
        issues.append("unmatched_result_cases")
    return aligned, remaining_configs, issues


def convert_records(
    target: str,
    config_cases: list[dict[str, Any]],
    result_cases: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    aligned, missing_cases, issues = align_cases(config_cases, result_cases)
    raw_records = []
    for config, result in aligned:
        expected = set(config["expected_sinks"])
        found = set(result["found_sinks"])
        if result["outcome"] == "found" and not found:
            issues.append(f"case_{config['case_idx']}_found_without_sink")
        if result["outcome"] == "found":
            for sink in sorted(found):
                raw_records.append(
                    {
                        "target": target,
                        "source_addr": result["source_addr"],
                        "sink_addr": sink,
                        "verdict": "POSITIVE",
                        "stop_reason": "satc_found_taint_to_sink",
                        "satc_case_idx": config["case_idx"],
                    }
                )
            for sink in sorted(expected - found):
                raw_records.append(
                    {
                        "target": target,
                        "source_addr": result["source_addr"],
                        "sink_addr": sink,
                        "verdict": "UNRESOLVED",
                        "stop_reason": "expected_sink_not_reported_after_positive_case",
                        "satc_case_idx": config["case_idx"],
                    }
                )
        else:
            for sink in sorted(expected):
                raw_records.append(
                    {
                        "target": target,
                        "source_addr": result["source_addr"],
                        "sink_addr": sink,
                        "verdict": "NEGATIVE",
                        "stop_reason": "satc_not_found",
                        "satc_case_idx": config["case_idx"],
                    }
                )
    for config in missing_cases:
        for sink in config["expected_sinks"]:
            raw_records.append(
                {
                    "target": target,
                    "source_addr": config["source_addr"],
                    "sink_addr": sink,
                    "verdict": "UNRESOLVED",
                    "stop_reason": "satc_case_missing_from_result_file",
                    "satc_case_idx": config["case_idx"],
                }
            )

    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in raw_records:
        grouped[(record["target"], record["source_addr"], record["sink_addr"])].append(record)
    records = []
    for key, group in sorted(grouped.items()):
        verdicts = {record["verdict"] for record in group}
        if "POSITIVE" in verdicts:
            verdict = "POSITIVE"
        elif verdicts == {"NEGATIVE"}:
            verdict = "NEGATIVE"
        else:
            verdict = "UNRESOLVED"
        if len(verdicts) > 1:
            issues.append("conflicting_duplicate_pair:" + "|".join(key))
        records.append(
            {
                "target": key[0],
                "source_addr": key[1],
                "sink_addr": key[2],
                "verdict": verdict,
                "stop_reason": ";".join(sorted({row["stop_reason"] for row in group})),
                "satc_case_indices": sorted({row["satc_case_idx"] for row in group}),
                "ground_truth": None,
            }
        )
    return records, sorted(set(issues))


def git_commit(root: Path) -> str:
    head = root / ".git" / "HEAD"
    if not head.is_file():
        return "UNKNOWN"
    text = head.read_text(encoding="utf-8").strip()
    if text.startswith("ref:"):
        ref = root / ".git" / text.split(None, 1)[1]
        if ref.is_file():
            return ref.read_text(encoding="utf-8").strip()
    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--result-file", type=Path, required=True)
    parser.add_argument("--config-file", type=Path, required=True)
    parser.add_argument("--satc-root", type=Path, required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--input-hash", action="append", required=True)
    parser.add_argument("--shared-input-hash", action="append", required=True)
    parser.add_argument("--out-file", type=Path, required=True)
    parser.add_argument("--per-record-timeout-sec", type=int, default=90)
    parser.add_argument("--max-memory-mb", type=int, default=2048)
    parser.add_argument("--host", default=platform.node())
    parser.add_argument("--architecture", default=platform.machine())
    parser.add_argument("--cpu-count", type=int, default=1)
    parser.add_argument("--cache-policy", default="cold")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    config_cases, config_issues = parse_satc_config(args.config_file)
    parsed = parse_satc_result(args.result_file)
    records, conversion_issues = convert_records(
        args.target, config_cases, parsed["cases"]
    )
    issues = sorted(set(config_issues + parsed["issues"] + conversion_issues))
    document = {
        "schema": "firmware-validator-baseline-v2",
        "comparison_mode": "native_frontend",
        "tool": {
            "name": "SaTC",
            "version": "USENIX-Security-2021-artifact",
            "commit": git_commit(args.satc_root),
            "command": args.command,
        },
        "budget": {
            "per_record_timeout_sec": args.per_record_timeout_sec,
            "max_memory_mb": args.max_memory_mb,
            "host": args.host,
            "architecture": args.architecture,
            "cpu_count": args.cpu_count,
            "cache_policy": args.cache_policy,
        },
        "input_hashes": args.input_hash,
        "shared_input_hashes": args.shared_input_hash,
        "identity_semantics": {
            "source_addr": "SaTC taint_addr",
            "sink_addr": "SaTC reported or configured sink target",
            "unit": "unique target/source/sink pair",
        },
        "conversion_audit": {
            "config_cases": len(config_cases),
            "result_cases": len(parsed["cases"]),
            "declared_total_cases": parsed["totals"].get("total_cases"),
            "declared_find_cases": parsed["totals"].get("find_cases"),
            "records": len(records),
            "issues": issues,
            "valid": not issues,
        },
        "records": records,
    }
    args.out_file.parent.mkdir(parents=True, exist_ok=True)
    if args.out_file.exists():
        raise ValueError(f"refusing to overwrite {args.out_file}")
    args.out_file.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(document["conversion_audit"], indent=2, sort_keys=True))
    return 2 if args.strict and issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
