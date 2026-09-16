#!/usr/bin/env python3
"""Parse-check TSDS shell-token witnesses without executing them.

The current threat matrix establishes byte-token satisfiability. This audit
asks a narrower follow-up question: does each rendered witness form syntactically
valid shell input under independent POSIX-like parsers? It invokes shells only
with ``-n`` after a no-execution preflight and never runs target commands.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


DEFAULT_INPUT = Path(
    "experiment_reports/full_firmware_campaign_current_tsds_20260627"
)
DEFAULT_OUTPUT = Path("experiment_reports/shell_witness_syntax_audit_current")
HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
CONTROL_FLOW_VECTORS = {";", "\\n", "|", "&", "`", "$("}


def decode_rendered_command(text: str) -> str:
    """Decode byte escapes emitted by TSDS while preserving shell backslashes."""
    decoded = HEX_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), str(text or ""))
    nul = decoded.find("\x00")
    return decoded if nul < 0 else decoded[:nul]


def verify_parser_noexec(shell: str, timeout: float = 3.0) -> dict[str, Any]:
    """Fail closed unless ``shell -n`` suppresses commands and substitutions."""
    with tempfile.TemporaryDirectory(prefix="tsds-parser-preflight-") as tmp:
        marker_a = Path(tmp) / "simple.marker"
        marker_b = Path(tmp) / "substitution.marker"
        command = (
            f"printf X > '{marker_a}'; "
            f"printf '%s' \"$(printf Y > '{marker_b}')\""
        )
        result = subprocess.run(
            [shell, "-n", "-c", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        safe = not marker_a.exists() and not marker_b.exists()
        return {
            "shell": shell,
            "returncode": result.returncode,
            "noexec_verified": safe,
            "stderr": result.stderr[:240],
        }


def parse_command(shell: str, command: str, timeout: float = 3.0) -> dict[str, Any]:
    if "\x00" in command:
        return {"returncode": 126, "valid": False, "stderr": "embedded NUL"}
    try:
        result = subprocess.run(
            [shell, "-n", "-c", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "valid": False, "stderr": "parser timeout"}
    return {
        "returncode": result.returncode,
        "valid": result.returncode == 0,
        "stderr": result.stderr.strip()[:400],
    }


def iter_sat_witnesses(input_dir: Path) -> Iterable[dict[str, Any]]:
    files = sorted(input_dir.glob("*.results.jsonl"))
    if not files:
        raise FileNotFoundError(f"no *.results.jsonl files found under {input_dir}")
    for path in files:
        target = path.name.removesuffix(".results.jsonl")
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("status") != "vulnerable":
                    continue
                profile = record.get("sanitizer_gap_profile") or {}
                minimal = record.get("minimal_bypass_vector") or profile.get(
                    "minimal_bypass_vector"
                ) or {}
                for witness in profile.get("bypass_vectors") or []:
                    yield {
                        "target": target,
                        "closure_idx": record.get("closure_idx"),
                        "recovery": record.get("analysis_recovery") or "direct",
                        "vector": witness.get("vector") or "",
                        "category": witness.get("category") or "",
                        "rendered_witness": witness.get("poc") or "",
                        "is_minimal": bool(
                            witness.get("vector") == minimal.get("vector")
                            and witness.get("category") == minimal.get("category")
                        ),
                    }


def audit_witnesses(
    witnesses: Iterable[dict[str, Any]], shells: list[str]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    preflight = [verify_parser_noexec(shell) for shell in shells]
    unsafe = [item for item in preflight if not item["noexec_verified"]]
    if unsafe:
        names = ", ".join(item["shell"] for item in unsafe)
        raise RuntimeError(f"parser no-execution preflight failed for: {names}")

    cache: dict[tuple[str, str], dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    per_vector: dict[str, Counter[str]] = defaultdict(Counter)
    per_recovery: dict[str, Counter[str]] = defaultdict(Counter)
    outcomes: Counter[str] = Counter()
    minimal_outcomes: Counter[str] = Counter()

    for witness in witnesses:
        command = decode_rendered_command(witness["rendered_witness"])
        results: dict[str, dict[str, Any]] = {}
        for shell in shells:
            key = (shell, command)
            if key not in cache:
                cache[key] = parse_command(shell, command)
            results[shell] = cache[key]

        valid_count = sum(1 for item in results.values() if item["valid"])
        if valid_count == len(shells):
            outcome = "valid_all_parsers"
        elif valid_count == 0:
            outcome = "invalid_all_parsers"
        else:
            outcome = "parser_disagreement"
        outcomes[outcome] += 1
        if witness.get("is_minimal"):
            minimal_outcomes[outcome] += 1
        per_vector[witness["vector"]][outcome] += 1
        per_recovery[witness["recovery"]][outcome] += 1

        row = dict(witness)
        row["decoded_witness"] = command
        row["outcome"] = outcome
        for index, shell in enumerate(shells, 1):
            item = results[shell]
            row[f"parser_{index}"] = shell
            row[f"parser_{index}_valid"] = item["valid"]
            row[f"parser_{index}_returncode"] = item["returncode"]
            row[f"parser_{index}_stderr"] = item["stderr"]
        rows.append(row)

    def nested(counter_map: dict[str, Counter[str]]) -> dict[str, dict[str, int]]:
        return {
            key: dict(sorted(counter.items()))
            for key, counter in sorted(counter_map.items())
        }

    records: dict[tuple[str, Any], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        records[(str(row["target"]), row["closure_idx"])].append(row)
    record_counts = Counter()
    for record_rows in records.values():
        any_valid = any(row["outcome"] == "valid_all_parsers" for row in record_rows)
        any_control_flow_valid = any(
            row["outcome"] == "valid_all_parsers"
            and row["vector"] in CONTROL_FLOW_VECTORS
            for row in record_rows
        )
        record_counts["records_any_syntax_valid"] += int(any_valid)
        record_counts["records_all_witnesses_invalid"] += int(not any_valid)
        record_counts["records_any_control_flow_syntax_valid"] += int(
            any_control_flow_valid
        )
        record_counts["records_no_control_flow_syntax_valid"] += int(
            not any_control_flow_valid
        )

    summary = {
        "schema": "tsds-shell-witness-syntax-audit-v1",
        "witnesses": len(rows),
        "unique_rendered_commands": len({row["decoded_witness"] for row in rows}),
        "parsers": preflight,
        "outcomes": dict(sorted(outcomes.items())),
        "minimal_witness_outcomes": dict(sorted(minimal_outcomes.items())),
        "record_outcomes": dict(sorted(record_counts.items())),
        "records": len(records),
        "per_vector": nested(per_vector),
        "per_recovery": nested(per_recovery),
        "claim_boundary": (
            "Parser acceptance is a syntax calibration only. It neither proves "
            "command execution nor device-level exploitability."
        ),
    }
    return rows, summary


def write_outputs(out_dir: Path, rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "shell_witness_syntax_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    fields = list(rows[0]) if rows else []
    with (out_dir / "shell_witness_syntax_records.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# TSDS shell-witness syntax audit",
        "",
        summary["claim_boundary"],
        "",
        f"- Witnesses: `{summary['witnesses']}`",
        f"- Unique rendered commands: `{summary['unique_rendered_commands']}`",
        f"- Positive records: `{summary['records']}`",
        "",
        "## Outcomes",
        "",
        "| Outcome | Witnesses |",
        "|---|---:|",
    ]
    for name, count in summary["outcomes"].items():
        lines.append(f"| `{name}` | {count} |")
    lines.extend(["", "## Per vector", "", "| Vector | Valid | Invalid | Disagreement |", "|---|---:|---:|---:|"])
    for vector, counts in summary["per_vector"].items():
        lines.append(
            "| `{}` | {} | {} | {} |".format(
                vector.replace("\n", "\\n").replace("\t", "\\t"),
                counts.get("valid_all_parsers", 0),
                counts.get("invalid_all_parsers", 0),
                counts.get("parser_disagreement", 0),
            )
        )
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--shell",
        action="append",
        dest="shells",
        help="parser shell supporting -n -c; repeat for multiple parsers",
    )
    parser.add_argument(
        "--fail-on-invalid-minimal",
        action="store_true",
        help="return exit code 2 unless every minimal witness is accepted by all parsers",
    )
    args = parser.parse_args()
    shells = args.shells or ["/bin/bash", "/bin/dash"]

    rows, summary = audit_witnesses(iter_sat_witnesses(args.input_dir), shells)
    write_outputs(args.out_dir, rows, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    invalid_minimal = sum(
        count
        for outcome, count in summary["minimal_witness_outcomes"].items()
        if outcome != "valid_all_parsers"
    )
    if args.fail_on_invalid_minimal and invalid_minimal:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
