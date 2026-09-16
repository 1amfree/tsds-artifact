#!/usr/bin/env python3
"""Replay generated TSDS witnesses inside a narrowly allowlisted shell.

This is a bounded shell-interface calibration for the controlled 24-case ELF
artifact.  It is deliberately separate from the original-program run: the
replay executes only the serialized witness string, under an empty environment
and a strict lexical allowlist.  It does not execute a firmware command and
does not establish source realizability or device exploitability.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

try:
    import resource
except ImportError:  # pragma: no cover - the replay is Ubuntu-only
    resource = None


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = PROJECT_ROOT / "experiment_reports" / "saner2027_controlled_benchmark_20260913"
DEFAULT_OUTPUT = PROJECT_ROOT / "experiment_reports" / "saner2027_witness_replay_20260913"
HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
FILLER = r"A+"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(encoded)


def decode_rendered_witness(value: str) -> str:
    """Decode the byte escapes emitted by TSDS, stopping at the C-string NUL."""
    decoded = HEX_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), str(value or ""))
    nul = decoded.find("\x00")
    return decoded if nul < 0 else decoded[:nul]


def iter_result_records(input_root: Path) -> Iterable[tuple[Path, dict[str, Any]]]:
    paths = sorted(input_root.rglob("result.jsonl"))
    if not paths:
        raise FileNotFoundError(f"no result.jsonl files under {input_root}")
    for path in paths:
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no} is not a JSON object")
            yield path, value


def iter_witness_entries(input_root: Path) -> Iterable[dict[str, Any]]:
    for source_path, record in iter_result_records(input_root):
        profile = record.get("sanitizer_gap_profile") or {}
        if not isinstance(profile, dict):
            continue
        controlled_values = record.get("controlled_offsets")
        if controlled_values is None:
            controlled_values = profile.get("controlled_offsets") or []
        try:
            controlled = {int(value) for value in controlled_values}
        except (TypeError, ValueError):
            controlled = set()
        decision_rows = {
            str(row.get("vector_id")): row
            for row in (record.get("vector_decisions") or [])
            if isinstance(row, dict) and row.get("vector_id")
        }
        vectors = profile.get("bypass_vectors") or []
        if not isinstance(vectors, list):
            continue
        for vector_index, vector in enumerate(vectors):
            if not isinstance(vector, dict):
                continue
            if vector.get("decision") != "VECTOR_SAT":
                continue
            witness = vector.get("witness") or vector.get("poc") or ""
            if not witness or vector.get("grammar_complete") is not True:
                continue
            decision = decision_rows.get(str(vector.get("vector_id")), {})
            witness_offsets = vector.get("controlled_witness_offsets")
            if witness_offsets is None:
                witness_offsets = decision.get("controlled_witness_offsets")
            offset_check = None
            if witness_offsets is not None:
                try:
                    offset_check = set(int(value) for value in witness_offsets).issubset(controlled)
                except (TypeError, ValueError):
                    offset_check = False
            yield {
                "source_result": str(source_path),
                "target": record.get("source_function") or source_path.parent.name,
                "closure_idx": record.get("closure_idx"),
                "vector_index": vector_index,
                "vector_id": vector.get("vector_id") or "",
                "vector": vector.get("vector") or "",
                "category": vector.get("category") or "",
                "quote_context": vector.get("quote_context") or "",
                "witness": str(witness),
                "grammar_complete": bool(vector.get("grammar_complete")),
                "controlled_offsets_present": bool(controlled),
                "controlled_witness_offsets": list(witness_offsets or []),
                "controlled_witness_offsets_subset": offset_check,
            }


def _payload_alternatives() -> list[str]:
    return [
        ":;:;#",
        ":\n:;#",
        ":|:;#",
        ":&:;#",
        "`:`",
        "$(:)",
        "$",
        ">/dev/null",
        "</dev/null",
        "${IFS}:",
        "\t:",
    ]


def _compiled_patterns() -> list[re.Pattern[str]]:
    payloads = _payload_alternatives()
    patterns: list[re.Pattern[str]] = []
    for prefix in (r"echo ", r"printf fixed && echo "):
        for payload in payloads:
            patterns.append(re.compile(r"^" + re.escape(prefix) + re.escape(payload) + FILLER + r"$"))
    single = [
        "''" + ":;:;#",
        "''" + ":\n:;#",
        "''" + ":|:;#",
        "''" + ":&:;#",
        "''" + "`:`;#",
        "''" + "$(:);#",
        "''" + "$A;#",
        "''" + ">/dev/null;#",
        "''" + "</dev/null;#",
        "''" + "${IFS}:;#",
        "''" + "\t:;#",
    ]
    double = [
        "\"\"" + ":;:;#",
        "\"\"" + ":\n:;#",
        "\"\"" + ":|:;#",
        "\"\"" + ":&:;#",
        "\"\"" + ">/dev/null;#",
        "\"\"" + "</dev/null;#",
        "\"\"" + "${IFS}:;#",
        "\"\"" + "\t:;#",
    ]
    for body in single + double:
        patterns.append(re.compile(r"^" + re.escape("echo ") + re.escape(body) + FILLER + r"$"))
    return patterns


KNOWN_PATTERNS = _compiled_patterns()


def safety_gate(command: str) -> tuple[bool, str]:
    """Admit only the exact inert witness language used by the benchmark."""
    if not command:
        return False, "empty_witness"
    if "\x00" in command:
        return False, "embedded_nul"
    if "\r" in command:
        return False, "carriage_return"
    if any(ord(char) >= 0x80 for char in command):
        return False, "non_ascii"
    if "\\" in command:
        return False, "undecoded_backslash"
    if not any(pattern.fullmatch(command) for pattern in KNOWN_PATTERNS):
        return False, "outside_controlled_witness_language"
    if command.count("$(") and command.count("$(") != command.count("$(:)"):
        return False, "unexpected_command_substitution"
    if command.count("`") and command.count("`") != 2:
        return False, "unexpected_backtick_shape"
    for marker in (">", "<"):
        if marker in command:
            # The trailing A filler is part of the redirection word in the
            # serialized witness; it remains confined to /dev and is inert.
            if not re.search(r"[<>]/dev/null(?:A+|;#A+)", command):
                return False, "unexpected_redirection_target"
    return True, "allowlisted_controlled_template"


def _limit_child() -> None:
    """Apply small child limits before invoking the allowlisted shell."""
    if resource is not None:
        resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024, 64 * 1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)


def run_shell(shell: str, mode: str, command: str, cwd: Path) -> dict[str, Any]:
    started = time.monotonic()
    env = {
        "PATH": "/nonexistent",
        "LC_ALL": "C",
        "LANG": "C",
        "IFS": " \t\n",
    }
    try:
        completed = subprocess.run(
            [shell, "-n", "-c", command] if mode == "syntax" else [shell, "-c", command],
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2,
            check=False,
            preexec_fn=_limit_child,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "mode": mode,
            "returncode": 124,
            "timed_out": True,
            "elapsed_sec": round(time.monotonic() - started, 6),
            "stdout": (exc.stdout or b"").decode("utf-8", "replace")[:512]
            if isinstance(exc.stdout, bytes)
            else str(exc.stdout or "")[:512],
            "stderr": (exc.stderr or b"").decode("utf-8", "replace")[:512]
            if isinstance(exc.stderr, bytes)
            else str(exc.stderr or "")[:512],
        }
    return {
        "mode": mode,
        "returncode": completed.returncode,
        "timed_out": False,
        "elapsed_sec": round(time.monotonic() - started, 6),
        "stdout": (completed.stdout or b"").decode("utf-8", "replace")[:512],
        "stderr": (completed.stderr or b"").decode("utf-8", "replace")[:512],
    }


def replay_unique_commands(commands: list[str], shell: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="tsds-witness-replay-") as temporary:
        cwd = Path(temporary)
        for command in commands:
            admitted, gate_reason = safety_gate(command)
            row: dict[str, Any] = {
                "command": command,
                "command_sha256": sha256_bytes(command.encode("utf-8")),
                "safety_gate": "PASS" if admitted else "REJECT",
                "safety_reason": gate_reason,
            }
            if admitted:
                syntax = run_shell(shell, "syntax", command, cwd)
                execution = run_shell(shell, "execution", command, cwd)
                row["syntax"] = syntax
                row["execution"] = execution
                row["syntax_pass"] = syntax["returncode"] == 0 and not syntax["timed_out"]
                row["execution_pass"] = execution["returncode"] == 0 and not execution["timed_out"]
                row["directory_entries_after"] = sorted(path.name for path in cwd.iterdir())
                row["no_unexpected_files"] = not row["directory_entries_after"]
            else:
                row["syntax_pass"] = False
                row["execution_pass"] = False
                row["directory_entries_after"] = []
                row["no_unexpected_files"] = True
            row["receipt_sha256"] = sha256_json(row)
            rows.append(row)
    return rows


def write_outputs(out_dir: Path, entries: list[dict[str, Any]], receipts: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    receipt_by_command = {row["command"]: row for row in receipts}
    rows: list[dict[str, Any]] = []
    for entry in entries:
        command = decode_rendered_witness(entry["witness"])
        receipt = receipt_by_command[command]
        rows.append(
            {
                **entry,
                "decoded_witness": command,
                "command_sha256": receipt["command_sha256"],
                "safety_gate": receipt["safety_gate"],
                "safety_reason": receipt["safety_reason"],
                "syntax_pass": receipt["syntax_pass"],
                "execution_pass": receipt["execution_pass"],
                "execution_returncode": (receipt.get("execution") or {}).get("returncode"),
                "execution_timed_out": (receipt.get("execution") or {}).get("timed_out"),
                "no_unexpected_files": receipt["no_unexpected_files"],
                "receipt_sha256": receipt["receipt_sha256"],
            }
        )
    (out_dir / "witness_replay_receipts.json").write_text(
        json.dumps(receipts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "witness_replay_records.json").write_text(
        json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if rows:
        fields = sorted({key for row in rows for key in row})
        with (out_dir / "witness_replay_records.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
    (out_dir / "witness_replay_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# TSDS generated-witness replay",
        "",
        summary["claim_boundary"],
        "",
        f"- VECTOR_SAT entries: `{summary['vector_sat_entries']}`.",
        f"- Unique rendered witnesses: `{summary['unique_rendered_witnesses']}`.",
        f"- Safety-gate admissions: `{summary['safety_gate_pass']}`; rejected: `{summary['safety_gate_reject']}`.",
        f"- `/bin/dash -n` syntax passes: `{summary['syntax_pass']}`.",
        f"- `/bin/dash -c` zero-return replays: `{summary['execution_pass']}`.",
        f"- Replays with unexpected files in the isolated working directory: `{summary['unexpected_files']}`.",
        "",
        "A zero return code is an execution-interface observation only. It does not prove that the witness is realizable by the original program or firmware.",
        "",
        "## Execution outcomes",
        "",
        "| Outcome | Unique witnesses |",
        "|---|---:|",
    ]
    for name, count in sorted(summary["execution_outcomes"].items()):
        lines.append(f"| `{name}` | {count} |")
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    sums = []
    for path in sorted(out_dir.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            sums.append(f"{sha256_bytes(path.read_bytes())}  {path.name}")
    (out_dir / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


def main() -> int:
    if os.name != "posix":
        print("This replay must run on the Ubuntu VM, not on the Windows host.", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--shell", default="/bin/dash")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    shell = str(Path(args.shell).resolve())
    if not Path(shell).is_file() or not os.access(shell, os.X_OK):
        print(f"missing executable shell: {shell}", file=sys.stderr)
        return 2
    if args.self_test:
        safe_cases = ["echo :;:;#AAAA", "echo $(:)AAAA", "echo >/dev/nullAAAA"]
        unsafe_cases = ["echo $(cat /etc/passwd)", "echo > /tmp/tsds-danger", "rm -rf /"]
        failures = [case for case in safe_cases if not safety_gate(case)[0]]
        failures.extend(case for case in unsafe_cases if safety_gate(case)[0])
        if failures:
            print(json.dumps({"self_test": "FAIL", "failures": failures}, indent=2))
            return 1
        print(json.dumps({"self_test": "PASS", "patterns": len(KNOWN_PATTERNS)}, indent=2))
        return 0
    input_root = args.input_dir.resolve()
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to overwrite non-empty output: {out_dir}", file=sys.stderr)
        return 2
    entries = list(iter_witness_entries(input_root))
    if not entries:
        print("no grammar-complete VECTOR_SAT witness entries found", file=sys.stderr)
        return 2
    bad_offsets = sum(entry["controlled_witness_offsets_subset"] is not True for entry in entries)
    commands = []
    seen: set[str] = set()
    for entry in entries:
        command = decode_rendered_witness(entry["witness"])
        if command not in seen:
            seen.add(command)
            commands.append(command)
    receipts = replay_unique_commands(commands, shell)
    execution_outcomes = Counter()
    for receipt in receipts:
        if receipt["safety_gate"] != "PASS":
            outcome = "safety_rejected"
        elif not receipt["syntax_pass"]:
            outcome = "syntax_failed"
        elif receipt["execution_pass"] and receipt["no_unexpected_files"]:
            outcome = "executed_zero_return_no_files"
        elif receipt["execution_pass"]:
            outcome = "executed_zero_return_unexpected_files"
        elif (receipt.get("execution") or {}).get("timed_out"):
            outcome = "execution_timeout"
        elif (receipt.get("execution") or {}).get("returncode") not in (None, 0):
            outcome = "executed_nonzero_return"
        else:
            outcome = "execution_unknown"
        execution_outcomes[outcome] += 1
    summary = {
        "schema": "tsds-saner2027-generated-witness-replay-v1",
        "input_dir": str(input_root),
        "shell": shell,
        "vector_sat_entries": len(entries),
        "unique_rendered_witnesses": len(commands),
        "controlled_offset_subset_failures": bad_offsets,
        "safety_gate_pass": sum(row["safety_gate"] == "PASS" for row in receipts),
        "safety_gate_reject": sum(row["safety_gate"] != "PASS" for row in receipts),
        "syntax_pass": sum(bool(row["syntax_pass"]) for row in receipts),
        "execution_pass": sum(bool(row["execution_pass"]) for row in receipts),
        "unexpected_files": sum(not row["no_unexpected_files"] for row in receipts),
        "execution_outcomes": dict(sorted(execution_outcomes.items())),
        "claim_boundary": (
            "Bounded replay of serialized VECTOR_SAT witnesses from the controlled "
            "24-case ELF under an empty environment and an exact inert-template "
            "allowlist. This calibrates shell syntax and return behavior only; it "
            "does not prove original-program source realizability, firmware ground "
            "truth, or device-level exploitability."
        ),
    }
    write_outputs(out_dir, entries, receipts, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if not bad_offsets and summary["safety_gate_reject"] == 0 and summary["unexpected_files"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
