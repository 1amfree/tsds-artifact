#!/usr/bin/env python3
"""Replay current-campaign witnesses under a narrowly allowlisted shell.

The input is the current TSDS result ledger, rather than the synthetic
benchmark.  Only grammar-complete VECTOR_SAT witnesses are admitted, and the
shared replay helper constrains commands to inert templates and an isolated
temporary directory.  This is an interface calibration, not firmware
execution or a source-realizability oracle.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from .run_saner2027_witness_replay import (
        decode_rendered_witness,
        run_shell,
    )
except ImportError:  # pragma: no cover - direct script invocation
    from run_saner2027_witness_replay import decode_rendered_witness, run_shell


SCHEMA = "tsds-current-campaign-witness-replay-v1"

# The current ledger serializes a command-prefix witness followed only by an
# A-filled symbolic tail.  Keep this language separate from the older
# benchmark's ``echo``-prefixed language.  Every admitted prefix uses shell
# builtins or /dev/null and cannot name an external executable or a writable
# path.
_FILL = r"A+ ?"
_CURRENT_WITNESS_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        rf"^:;:;#{_FILL}$",
        rf"^:\n:;#{_FILL}$",
        rf"^:\|:;#{_FILL}$",
        rf"^:&:;#{_FILL}$",
        rf"^`:`{_FILL}$",
        rf"^\$\(:\){_FILL}$",
        rf"^\$A+ ?$",
        rf"^>/dev/null{_FILL}$",
        rf"^</dev/null{_FILL}$",
        rf"^\$\{{IFS\}}:{_FILL}$",
        rf"^\t:{_FILL}$",
    )
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def load_rows(input_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(input_dir.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no} is not an object")
            row["_source_path"] = str(path.resolve())
            row["_target"] = target
            rows.append(row)
    return rows


def extract_entries(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for row in rows:
        if row.get("verdict") != "VECTOR_SAT" or row.get("evidence_provenance") != "DIRECT_SINK_BYTE":
            continue
        controlled_values = row.get("controlled_offsets") or []
        try:
            controlled = {int(value) for value in controlled_values}
        except (TypeError, ValueError):
            controlled = set()
        decisions = row.get("vector_decisions") or []
        if not isinstance(decisions, list):
            continue
        for vector_index, vector in enumerate(decisions):
            if not isinstance(vector, dict) or vector.get("decision") != "VECTOR_SAT":
                continue
            witness = vector.get("witness") or vector.get("poc") or ""
            if not witness or vector.get("grammar_complete") is not True:
                continue
            witness_offsets = vector.get("controlled_witness_offsets") or []
            try:
                offset_subset = set(int(value) for value in witness_offsets).issubset(controlled)
            except (TypeError, ValueError):
                offset_subset = False
            decoded = decode_rendered_witness(str(witness))
            entries.append(
                {
                    "target": row.get("_target"),
                    "closure_idx": row.get("closure_idx"),
                    "source_addr": row.get("source_addr"),
                    "sink_addr": row.get("sink_addr"),
                    "sink_snapshot_digest": row.get("sink_snapshot_digest"),
                    "source_result": row.get("_source_path"),
                    "vector_index": vector_index,
                    "vector_id": vector.get("vector_id"),
                    "vector": vector.get("vector"),
                    "category": vector.get("category"),
                    "quote_context": vector.get("quote_context"),
                    "grammar_complete": True,
                    "witness": str(witness),
                    "decoded_witness": decoded,
                    "controlled_witness_offsets": list(witness_offsets),
                    "controlled_witness_offsets_subset": offset_subset,
                }
            )
    return entries


def current_safety_gate(command: str) -> tuple[bool, str]:
    """Admit only the exact inert witness language emitted by current TSDS."""
    if not command:
        return False, "empty_witness"
    if "\x00" in command:
        return False, "embedded_nul"
    if "\r" in command:
        return False, "carriage_return"
    if "\\" in command:
        return False, "undecoded_backslash"
    if any(ord(char) >= 0x80 for char in command):
        return False, "non_ascii"
    if not any(pattern.fullmatch(command) for pattern in _CURRENT_WITNESS_PATTERNS):
        return False, "outside_current_inert_template_language"
    return True, "current_inert_template"


def replay_current_commands(commands: list[str], shell: str) -> list[dict[str, Any]]:
    """Run only allowlisted current witnesses in the shared bounded harness."""
    receipts: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="tsds-current-witness-replay-") as temporary:
        cwd = Path(temporary)
        for command in commands:
            admitted, reason = current_safety_gate(command)
            receipt: dict[str, Any] = {
                "command": command,
                "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
                "safety_gate": "PASS" if admitted else "REJECT",
                "safety_reason": reason,
            }
            # Syntax checking is safe for the complete serialized command: the
            # shell is invoked with ``-n`` and never executes it.  Keep this
            # separate from the narrower execution allowlist below.
            syntax = run_shell(shell, "syntax", command, cwd)
            receipt["syntax"] = syntax
            receipt["syntax_pass"] = syntax["returncode"] == 0 and not syntax["timed_out"]
            if admitted:
                execution = run_shell(shell, "execution", command, cwd)
                receipt["execution"] = execution
                receipt["execution_pass"] = execution["returncode"] == 0 and not execution["timed_out"]
                receipt["directory_entries_after"] = sorted(path.name for path in cwd.iterdir())
                receipt["no_unexpected_files"] = not receipt["directory_entries_after"]
            else:
                receipt["execution_pass"] = None
                receipt["execution_not_run"] = True
                receipt["directory_entries_after"] = []
                receipt["no_unexpected_files"] = True
            receipt["receipt_sha256"] = sha256_json(receipt)
            receipts.append(receipt)
    return receipts


def write_outputs(
    out_dir: Path,
    *,
    input_dir: Path,
    rows: list[dict[str, Any]],
    entries: list[dict[str, Any]],
    shell_results: dict[str, list[dict[str, Any]]],
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    by_shell_and_command = {
        shell: {str(receipt["command"]): receipt for receipt in receipts}
        for shell, receipts in shell_results.items()
    }
    unique_commands = sorted({entry["decoded_witness"] for entry in entries})
    records: list[dict[str, Any]] = []
    for entry in entries:
        record = dict(entry)
        record["command_sha256"] = hashlib.sha256(entry["decoded_witness"].encode()).hexdigest()
        record["shells"] = {}
        for shell, receipts in by_shell_and_command.items():
            receipt = receipts[entry["decoded_witness"]]
            record["shells"][shell] = {
                "safety_gate": receipt.get("safety_gate"),
                "safety_reason": receipt.get("safety_reason"),
                "syntax_pass": receipt.get("syntax_pass"),
                "execution_pass": receipt.get("execution_pass"),
                "execution_returncode": (receipt.get("execution") or {}).get("returncode"),
                "execution_timed_out": (receipt.get("execution") or {}).get("timed_out"),
                "no_unexpected_files": receipt.get("no_unexpected_files"),
                "receipt_sha256": receipt.get("receipt_sha256"),
            }
        record["record_sha256"] = sha256_json(record)
        records.append(record)
    (out_dir / "witness_replay_records.json").write_text(
        json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    fields = sorted({key for record in records for key in record if key != "shells"})
    with (out_dir / "witness_replay_records.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(records)
    for shell, receipts in shell_results.items():
        name = Path(shell).name.replace("/", "_")
        (out_dir / f"receipts_{name}.json").write_text(
            json.dumps(receipts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    shell_summary: dict[str, Any] = {}
    for shell, receipts in shell_results.items():
        shell_summary[shell] = {
                "unique_witnesses": len(receipts),
                "safety_gate_pass": sum(receipt.get("safety_gate") == "PASS" for receipt in receipts),
                "syntax_pass": sum(bool(receipt.get("syntax_pass")) for receipt in receipts),
            "execution_admitted": sum(receipt.get("safety_gate") == "PASS" for receipt in receipts),
            "execution_pass": sum(bool(receipt.get("execution_pass")) for receipt in receipts),
            "execution_not_run": sum(bool(receipt.get("execution_not_run")) for receipt in receipts),
            "unexpected_files": sum(not receipt.get("no_unexpected_files") for receipt in receipts),
        }
    summary = {
        "schema": SCHEMA,
        "input_dir": str(input_dir.resolve()),
        "input_file_sha256": {
            str(path.relative_to(input_dir)).replace("\\", "/"): sha256_file(path)
            for path in sorted(input_dir.glob("*.results.jsonl"))
        },
        "current_record_count": len(rows),
        "direct_positive_record_count": sum(
            row.get("verdict") == "VECTOR_SAT" and row.get("evidence_provenance") == "DIRECT_SINK_BYTE"
            for row in rows
        ),
        "vector_sat_entries": len(entries),
        "unique_rendered_witnesses": len(unique_commands),
        "controlled_offset_subset_failures": sum(
            entry["controlled_witness_offsets_subset"] is not True for entry in entries
        ),
        "shells": shell_summary,
        "claim_boundary": (
            "Finite replay of serialized grammar-complete witnesses from the current "
            "eight-target TSDS ledger. Commands are restricted to the existing inert "
            "template allowlist, run under empty environment and isolated temporary "
            "directories. This calibrates shell syntax and interface return behavior; "
            "it does not establish original-program source realizability, firmware "
            "precision/recall, human ground truth, or device-level exploitability."
        ),
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# Current campaign witness replay",
        "",
        summary["claim_boundary"],
        "",
        f"- Current records: `{summary['current_record_count']}`.",
        f"- Direct positive records: `{summary['direct_positive_record_count']}`.",
        f"- Grammar-complete VECTOR_SAT entries: `{summary['vector_sat_entries']}`.",
        f"- Unique witnesses: `{summary['unique_rendered_witnesses']}`.",
        f"- Controlled-offset subset failures: `{summary['controlled_offset_subset_failures']}`.",
        "",
        "| Shell | Safety-gate pass | Syntax pass | Execution admitted | Zero-return replay | Execution not run | Unexpected files |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for shell, facts in sorted(shell_summary.items()):
        lines.append(
            f"| `{shell}` | {facts['safety_gate_pass']} | {facts['syntax_pass']} | "
            f"{facts['execution_admitted']} | {facts['execution_pass']} | "
            f"{facts['execution_not_run']} | {facts['unexpected_files']} |"
        )
    lines.extend(
        [
            "",
            "The replay never invokes a target firmware process and does not execute any generated witness on a device.",
        ]
    )
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    sums: list[str] = []
    for path in sorted(out_dir.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            sums.append(f"{sha256_file(path)}  {path.name}")
    (out_dir / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


def main() -> int:
    if os.name != "posix":
        print("run this replay on the Ubuntu analysis VM", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--shell", action="append", default=["/bin/dash", "/bin/bash"])
    args = parser.parse_args()
    input_dir = args.input_dir.resolve()
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(f"refusing to overwrite non-empty output: {out_dir}")
    shells = []
    for shell in args.shell:
        resolved = str(Path(shell).resolve())
        if resolved not in shells and Path(resolved).is_file() and os.access(resolved, os.X_OK):
            shells.append(resolved)
    if not shells:
        raise SystemExit("no executable shell available")
    rows = load_rows(input_dir)
    entries = extract_entries(rows)
    if not entries:
        raise SystemExit("no direct grammar-complete VECTOR_SAT witnesses found")
    commands = sorted({entry["decoded_witness"] for entry in entries})
    shell_results = {shell: replay_current_commands(commands, shell) for shell in shells}
    write_outputs(out_dir, input_dir=input_dir, rows=rows, entries=entries, shell_results=shell_results)
    result = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["controlled_offset_subset_failures"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
