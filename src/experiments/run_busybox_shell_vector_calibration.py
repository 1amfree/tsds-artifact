#!/usr/bin/env python3
"""Calibrate TSDS token predicates against target BusyBox ash builds.

Only generated, harmless commands are executed. Every case runs in a fresh
temporary directory with an empty PATH and a short timeout. The suite compares
the current token-plus-filler form across common command contexts with a
grammar-complete canary for the same shell feature.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    import resource
except ImportError:  # Windows can collect/generate the suite but cannot run qemu cases.
    resource = None


DEFAULT_OUTPUT = Path("experiment_reports/busybox_shell_vector_calibration_current")
CANARY = "TSDS_CANARY"
SYNTAX_ERROR = re.compile(
    r"syntax error|unexpected|unterminated|unclosed|bad substitution|missing [`'\")}]",
    re.IGNORECASE,
)

TARGETS = [
    {
        "target": "asus_rt_be57",
        "qemu": "qemu-arm",
        "root": "_RT-BE57_3.0.0.6_102_58491-g1262a8f_598-g65a76_Q7PB.trx.extracted/squashfs-root",
    },
    {
        "target": "dir878",
        "qemu": "qemu-mipsel",
        "root": "DIR-878/extracted_rootfs/_DIR_878_FW120B05_decode.BIN.extracted/_A0.extracted/_8957DC.extracted/cpio-root",
    },
    {
        "target": "r6400v2",
        "qemu": "qemu-arm",
        "root": "R6400v2/extracted_rootfs/_R6400v2-V1.0.5.128_10.0.104.chk.extracted/squashfs-root",
    },
    {
        "target": "r7000",
        "qemu": "qemu-arm",
        "root": "R7000/extracted_rootfs/_R7000-V1.0.11.100_10.2.100.chk.extracted/squashfs-root",
    },
    {
        "target": "tenda_ac15",
        "qemu": "qemu-arm",
        "root": "Tenda_AC15/extracted_rootfs/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root",
    },
    {
        "target": "tenda_ac18",
        "qemu": "qemu-arm",
        "root": "Tenda_AC18/extracted_rootfs/_ac18_kf_V15.03.05.19_cn.bin.extracted/squashfs-root",
    },
    {
        "target": "tenda_w20e",
        "qemu": "qemu-arm",
        "root": "Tenda_W20E/extracted_rootfs/_US_W20EV4.0br_V15.11.0.6.bin.extracted/squashfs-root",
    },
    {
        "target": "xr300",
        "qemu": "qemu-arm",
        "root": "XR300/extracted_rootfs/_XR300-V1.0.3.38_10.3.30.chk.extracted/squashfs-root",
    },
]

VECTORS = [
    ("semicolon", ";", "control_flow", ":; : > marker"),
    ("newline", "\n", "control_flow", ":\n: > marker"),
    (
        "pipe",
        "|",
        "control_flow",
        ": | { : > marker; }",
    ),
    (
        "ampersand",
        "&",
        "control_flow",
        ": & : > marker; wait",
    ),
    (
        "backtick",
        "`",
        "command_substitution",
        ": \"`: > marker`\"",
    ),
    (
        "dollar_paren",
        "$(",
        "command_substitution",
        ": \"$(: > marker)\"",
    ),
    (
        "dollar_expansion",
        "$",
        "data_expansion",
        "TSDS_PATH=marker; : > \"$TSDS_PATH\"",
    ),
    ("output_redirection", ">", "output_redirection", ": > marker"),
    (
        "input_redirection",
        "<",
        "input_redirection",
        ": < input > marker",
    ),
    ("ifs_spacing", "${IFS}", "word_splitting", "TSDS_CMD=:; $TSDS_CMD${IFS}> marker"),
    ("tab_spacing", "\t", "word_splitting", ":\t> marker"),
]

V2_WITNESSES = {
    "semicolon": ":;:;#",
    "newline": ":\n:;#",
    "pipe": ":|:;#",
    "ampersand": ":&:;#",
    "backtick": chr(0x60) + ":" + chr(0x60),
    "dollar_paren": "$(:)",
    "dollar_expansion": "$A",
    "output_redirection": ">/dev/null",
    "input_redirection": "</dev/null",
    "ifs_spacing": "$" + "{IFS}:",
    "tab_spacing": "\t:",
}


def generated_cases() -> list[dict[str, str]]:
    cases: list[dict[str, str]] = []
    filler = "AAAAAAAA"
    for name, token, impact, complete in VECTORS:
        token_witness = token + filler
        witness = V2_WITNESSES[name]
        contexts = {
            "current_bare": token_witness,
            "current_unquoted_argument": ": " + token_witness,
            "current_single_quoted": ": '" + token_witness + "'",
            "current_double_quoted": ": \"" + token_witness + "\"",
            "v2_unquoted_witness": ": " + witness,
            "v2_single_quote_breakout": (
                ": '" + "'" + witness
                + ("" if witness.endswith("#") else ";#") + "'"
            ),
            "v2_double_quote_breakout": (
                ': "' + '"' + witness
                + ("" if witness.endswith("#") else ";#") + '"'
            ),
            "complete_canary": complete,
        }
        for context, command in contexts.items():
            cases.append(
                {
                    "vector": name,
                    "token": token,
                    "impact_class": impact,
                    "context": context,
                    "command": command,
                    "v2_witness": witness,
                    "expects_marker": context == "complete_canary",
                }
            )
    return cases


def _limit_child() -> None:
    if resource is None:
        return
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def run_case(workspace: Path, target: dict[str, str], case: dict[str, Any]) -> dict[str, Any]:
    root = (workspace / target["root"]).resolve()
    busybox = root / "bin/busybox"
    qemu = shutil.which(target["qemu"])
    if not busybox.is_file() or not qemu:
        return {
            **target,
            **case,
            "available": False,
            "parse_ok": False,
            "marker_observed": False,
            "returncode": 127,
            "stderr": "target BusyBox or qemu unavailable",
            "unexpected_files": "",
        }

    with tempfile.TemporaryDirectory(prefix="tsds-busybox-calibration-") as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "input").write_text(CANARY + "\n", encoding="ascii")
        env = {
            "HOME": tmp,
            "TMPDIR": tmp,
            "PATH": "/nonexistent",
            "LC_ALL": "C",
        }
        command = [qemu, "-L", str(root), str(busybox), "ash", "-c", case["command"]]
        try:
            result = subprocess.run(
                command,
                cwd=tmp,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=4,
                check=False,
                preexec_fn=_limit_child if os.name == "posix" else None,
            )
            returncode = result.returncode
            stderr = result.stderr.strip()
        except subprocess.TimeoutExpired as exc:
            returncode = 124
            stderr = "timeout: " + str(exc)

        marker = tmp_path / "marker"
        marker_exists = marker.exists()
        unexpected = sorted(
            path.name for path in tmp_path.iterdir() if path.name not in {"input", "marker"}
        )
        parse_ok = not bool(SYNTAX_ERROR.search(stderr)) and returncode not in {2, 124}
        return {
            **target,
            **case,
            "available": True,
            "parse_ok": parse_ok,
            "marker_observed": marker_exists,
            "returncode": returncode,
            "stderr": stderr[:400],
            "unexpected_files": ";".join(unexpected),
        }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    outcomes: Counter[str] = Counter()
    by_context: dict[str, Counter[str]] = defaultdict(Counter)
    by_vector: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        if not row["available"]:
            outcome = "unavailable"
        elif row["context"] == "complete_canary":
            outcome = "complete_marker_observed" if row["marker_observed"] else "complete_marker_missing"
        else:
            outcome = "current_form_parsed" if row["parse_ok"] else "current_form_syntax_error"
        outcomes[outcome] += 1
        by_context[row["context"]][outcome] += 1
        by_vector[row["vector"]][outcome] += 1

    def nested(values: dict[str, Counter[str]]) -> dict[str, dict[str, int]]:
        return {key: dict(sorted(value.items())) for key, value in sorted(values.items())}

    v2_rows = [
        row for row in rows
        if str(row.get("context") or "").startswith("v2_")
    ]
    complete_rows = [
        row for row in rows if row.get("context") == "complete_canary"
    ]
    v2_parse_ok = sum(
        1 for row in v2_rows if row.get("available") and row.get("parse_ok")
    )
    complete_effect_ok = sum(
        1
        for row in complete_rows
        if row.get("available") and row.get("marker_observed")
    )
    calibration_pass = (
        bool(rows)
        and v2_parse_ok == len(v2_rows)
        and complete_effect_ok == len(complete_rows)
    )
    return {
        "schema": "tsds-busybox-shell-vector-calibration-v2",
        "targets": len({row["target"] for row in rows if row["available"]}),
        "vectors": len(VECTORS),
        "cases": len(rows),
        "v2_witness_cases": len(v2_rows),
        "v2_witness_parse_ok": v2_parse_ok,
        "complete_effect_cases": len(complete_rows),
        "complete_effect_observed": complete_effect_ok,
        "calibration_pass": calibration_pass,
        "outcomes": dict(sorted(outcomes.items())),
        "per_context": nested(by_context),
        "per_vector": nested(by_vector),
        "claim_boundary": (
            "Generated canaries calibrate target BusyBox shell behavior in temporary "
            "directories. They do not execute firmware ledger commands or establish exploits."
        ),
    }


def write_outputs(out_dir: Path, rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "busybox_calibration_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    fields = list(rows[0]) if rows else []
    with (out_dir / "busybox_calibration_cases.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# Target BusyBox shell-vector calibration",
        "",
        summary["claim_boundary"],
        "",
        f"- Target BusyBox builds: `{summary['targets']}`",
        f"- Vector classes: `{summary['vectors']}`",
        f"- Cases: `{summary['cases']}`",
        f"- v2 grammar-complete witnesses parsed: `{summary['v2_witness_parse_ok']}/{summary['v2_witness_cases']}`",
        f"- Feature effects observed: `{summary['complete_effect_observed']}/{summary['complete_effect_cases']}`",
        f"- Calibration pass: `{summary['calibration_pass']}`",
        "",
        "| Outcome | Cases |",
        "|---|---:|",
    ]
    for name, count in summary["outcomes"].items():
        lines.append(f"| `{name}` | {count} |")
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--target", action="append", dest="targets")
    args = parser.parse_args()

    selected = [
        target for target in TARGETS if not args.targets or target["target"] in args.targets
    ]
    rows = [
        run_case(args.workspace, target, case)
        for target in selected
        for case in generated_cases()
    ]
    summary = summarize(rows)
    write_outputs(args.out_dir, rows, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    if summary["targets"] != len(selected):
        return 2
    return 0 if summary["calibration_pass"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
