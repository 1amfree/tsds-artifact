#!/usr/bin/env python3
"""Audit the bounded current-campaign witness replay receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "tsds-current-campaign-witness-replay-audit-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def audit(output: Path, source_ledger: Path) -> dict[str, Any]:
    summary = load_json(output / "summary.json")
    records = load_json(output / "witness_replay_records.json")
    if not isinstance(records, list):
        raise ValueError("witness_replay_records.json must contain a list")
    issues: list[str] = []
    result_files = sorted(source_ledger.glob("*.results.jsonl"))
    expected_hashes = {
        path.name: sha256_file(path)
        for path in result_files
    }
    if summary.get("input_file_sha256") != expected_hashes:
        issues.append("source_ledger_hashes_changed")
    if int(summary.get("current_record_count", -1)) != sum(
        1 for path in result_files for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()
    ):
        issues.append("current_record_count_mismatch")
    if int(summary.get("vector_sat_entries", -1)) != len(records):
        issues.append("vector_sat_entry_count_mismatch")
    commands = [str(row.get("decoded_witness")) for row in records]
    if len(set(commands)) != int(summary.get("unique_rendered_witnesses", -1)):
        issues.append("unique_witness_count_mismatch")
    if any(row.get("controlled_witness_offsets_subset") is not True for row in records):
        issues.append("controlled_offset_subset_failure")
    receipt_sets: dict[str, dict[str, dict[str, Any]]] = {}
    for receipt_path in sorted(output.glob("receipts_*.json")):
        shell = receipt_path.stem.removeprefix("receipts_")
        receipts = load_json(receipt_path)
        if not isinstance(receipts, list):
            issues.append(f"invalid_receipt_list:{shell}")
            continue
        receipt_sets[shell] = {str(item.get("command")): item for item in receipts if isinstance(item, dict)}
        if len(receipts) != int(summary.get("unique_rendered_witnesses", -1)):
            issues.append(f"receipt_count_mismatch:{shell}")
        for item in receipts:
            if item.get("safety_gate") == "PASS":
                if "execution" not in item:
                    issues.append(f"admitted_execution_missing:{shell}")
            elif "execution" in item:
                issues.append(f"rejected_command_was_executed:{shell}")
            if item.get("no_unexpected_files") is not True:
                issues.append(f"unexpected_file:{shell}")
    if not receipt_sets:
        issues.append("no_shell_receipts")
    for shell, receipts in receipt_sets.items():
        if set(receipts) != set(commands):
            issues.append(f"receipt_command_set_mismatch:{shell}")
        observed = {
            "unique_witnesses": len(receipts),
            "safety_gate_pass": sum(item.get("safety_gate") == "PASS" for item in receipts.values()),
            "syntax_pass": sum(bool(item.get("syntax_pass")) for item in receipts.values()),
            "execution_admitted": sum(item.get("safety_gate") == "PASS" for item in receipts.values()),
            "execution_pass": sum(bool(item.get("execution_pass")) for item in receipts.values()),
            "execution_not_run": sum(bool(item.get("execution_not_run")) for item in receipts.values()),
            "unexpected_files": sum(not item.get("no_unexpected_files") for item in receipts.values()),
        }
        if summary.get("shells", {}).get(f"/usr/bin/{shell}") != observed:
            issues.append(f"shell_summary_mismatch:{shell}")
    if len(receipt_sets) >= 2:
        shell_names = sorted(receipt_sets)
        for command in commands:
            statuses = [
                (
                    receipt_sets[shell][command].get("syntax_pass"),
                    receipt_sets[shell][command].get("safety_gate"),
                )
                for shell in shell_names
            ]
            if len(set(statuses)) != 1:
                issues.append("shell_syntax_or_gate_disagreement")
                break
    return {
        "schema": SCHEMA,
        "output": str(output.resolve()),
        "source_ledger": str(source_ledger.resolve()),
        "source_ledger_sha256": {name: digest for name, digest in sorted(expected_hashes.items())},
        "record_count": len(records),
        "shell_count": len(receipt_sets),
        "shells": sorted(receipt_sets),
        "issues": sorted(set(issues)),
        "valid": not issues,
        "claim_boundary": "Structural audit of bounded shell-interface replay receipts from the current campaign; it does not prove source realizability, firmware-wide accuracy, or device-level exploitability.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-ledger", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.output.resolve(), args.source_ledger.resolve())
    path = args.output.resolve() / "audit.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"valid": result["valid"], "issues": len(result["issues"]), "record_count": result["record_count"]}, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
