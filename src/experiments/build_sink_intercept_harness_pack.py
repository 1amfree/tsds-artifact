#!/usr/bin/env python3
"""Build safe sink-intercept canary harness artifacts for TSDS candidates.

The generated package is deliberately a validation scaffold, not an exploit
pack.  It prepares isolated emulation or owned-hardware canary runs where
command sinks are intercepted and logged before a shell can be executed.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List


DEFAULT_TASKS = Path("experiment_reports/canary_validation_plan_v9_20260626/canary_validation_tasks.json")
DEFAULT_OUT = Path("experiment_reports/sink_intercept_harness_pack_v9_20260626")


TARGET_ARCH_HINTS: Dict[str, Dict[str, str]] = {
    "D-Link DIR-878": {
        "arch": "mips",
        "arg0": "$a0",
        "return_reg": "$v0",
        "qemu": "qemu-mipsel or qemu-mips, selected after file(1) confirms endian.",
    },
    "Tenda AC15": {
        "arch": "arm",
        "arg0": "$r0",
        "return_reg": "$r0",
        "qemu": "qemu-arm, selected after file(1) confirms ABI.",
    },
    "Tenda AC18": {
        "arch": "arm",
        "arg0": "$r0",
        "return_reg": "$r0",
        "qemu": "qemu-arm, selected after file(1) confirms ABI.",
    },
}


def load_tasks(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise TypeError(f"expected task list in {path}")
    return data


def slug(text: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "_", text.strip().lower()).strip("_")
    return value or "unknown"


def split_semicolon(value: Any) -> List[str]:
    return [item.strip() for item in str(value or "").split(";") if item.strip()]


def sink_function(task: Dict[str, Any]) -> str:
    sink = str(task.get("sink", ""))
    return sink.split("@", 1)[0].strip() if "@" in sink else sink.strip()


def sink_address(task: Dict[str, Any]) -> str:
    sink = str(task.get("sink", ""))
    return sink.split("@", 1)[1].strip() if "@" in sink else ""


def c_string(value: str) -> str:
    return json.dumps(value)


def render_intercept_c() -> str:
    return r'''/*
 * TSDS sink-intercept logger.
 *
 * Safety contract:
 * - Log command sink arguments.
 * - Return success-like values to the caller.
 * - Never invoke /bin/sh, execve, popen, or the real firmware wrapper.
 *
 * This file is a scaffold.  Build it for an isolated emulation environment
 * when the target sink is dynamically interposable.  For internal firmware
 * functions, use the generated debugger breakpoint template instead.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static FILE *tsds_log_file(void) {
    const char *path = getenv("TSDS_INTERCEPT_LOG");
    if (path == NULL || path[0] == '\0') {
        path = "/tmp/tsds_sink_intercept.log";
    }
    FILE *fp = fopen(path, "a");
    return fp != NULL ? fp : stderr;
}

static void tsds_log(const char *sink, const char *arg) {
    FILE *fp = tsds_log_file();
    time_t now = time(NULL);
    fprintf(fp,
            "{\"ts\":%ld,\"sink\":\"%s\",\"arg\":\"",
            (long)now,
            sink == NULL ? "" : sink);
    const unsigned char *p = (const unsigned char *)(arg == NULL ? "" : arg);
    for (; *p; ++p) {
        if (*p == '\\' || *p == '"') {
            fputc('\\', fp);
            fputc(*p, fp);
        } else if (*p == '\n') {
            fputs("\\n", fp);
        } else if (*p == '\r') {
            fputs("\\r", fp);
        } else if (*p == '\t') {
            fputs("\\t", fp);
        } else if (*p < 32 || *p == 127) {
            fprintf(fp, "\\u%04x", *p);
        } else {
            fputc(*p, fp);
        }
    }
    fputs("\",\"executed\":false}\n", fp);
    if (fp != stderr) {
        fclose(fp);
    }
}

int system(const char *command) {
    tsds_log("system", command);
    return 0;
}

FILE *popen(const char *command, const char *type) {
    (void)type;
    tsds_log("popen", command);
    errno = EPERM;
    return NULL;
}

int execl(const char *path, const char *arg, ...) {
    tsds_log("execl", path);
    (void)arg;
    errno = EPERM;
    return -1;
}

int execv(const char *path, char *const argv[]) {
    (void)argv;
    tsds_log("execv", path);
    errno = EPERM;
    return -1;
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    (void)argv;
    (void)envp;
    tsds_log("execve", path);
    errno = EPERM;
    return -1;
}

int doSystemCmd(const char *fmt, ...) {
    char buffer[4096];
    va_list ap;
    va_start(ap, fmt);
    if (fmt != NULL) {
        vsnprintf(buffer, sizeof(buffer), fmt, ap);
    } else {
        buffer[0] = '\0';
    }
    va_end(ap);
    tsds_log("doSystemCmd", buffer);
    return 0;
}
'''


def render_gdb_template(task: Dict[str, Any], arch: Dict[str, str]) -> str:
    addr = sink_address(task) or "<sink-address>"
    arg0 = arch["arg0"]
    ret = arch["return_reg"]
    token = task.get("canary_token", "")
    return f"""# TSDS sink-intercept debugger template for {task.get('candidate_id')}
# Boundary: log sink argument containing {token}; skip shell execution.
# Fill in image base / relocated address when ASLR or PIE is enabled.
set pagination off
set confirm off
set logging file tsds_sink_intercept_gdb.log
set logging overwrite on
set logging enabled on

break *{addr}
commands
  silent
  printf "TSDS_INTERCEPT candidate={task.get('candidate_id')} sink={task.get('sink')} token={token}\\n"
  printf "arg0_ptr=%p\\n", {arg0}
  x/s {arg0}
  set {ret}=0
  return
  continue
end
"""


def render_fixture_env(task: Dict[str, Any]) -> str:
    token = str(task.get("canary_token", "TSDS_CANARY"))
    lines = [
        "# TSDS inert canary fixture.",
        "# Values are benign markers for source propagation checks, not shell payloads.",
        f"TSDS_CANARY_TOKEN={token}",
        f"TSDS_CANDIDATE_ID={task.get('candidate_id', '')}",
    ]
    for key in split_semicolon(task.get("source_keys")):
        safe_name = "TSDS_KEY_" + re.sub(r"[^A-Za-z0-9]", "_", key).upper()
        lines.append(f"{safe_name}={token}")
    return "\n".join(lines) + "\n"


def render_runbook(task: Dict[str, Any], arch: Dict[str, str]) -> str:
    keys = split_semicolon(task.get("source_keys"))
    clues = split_semicolon(task.get("entry_clues"))
    return "\n".join(
        [
            f"# Sink-Intercept Canary Runbook: {task.get('candidate_id')}",
            "",
            "## Evidence Boundary",
            "",
            "This runbook is for isolated lab validation. It logs command-sink arguments and prevents shell execution. A successful run supports analyzer-level-to-emulation consistency only; it is not a public-device test and not device-confirmed exploitation.",
            "",
            "## Target",
            "",
            f"- Firmware target: `{task.get('target')}`",
            f"- Functional theme: `{task.get('functional_theme')}`",
            f"- Source function: `{task.get('source_function')}`",
            f"- Sink: `{task.get('sink')}`",
            f"- Expected token: `{task.get('canary_token')}`",
            f"- Architecture hint: `{arch['arch']}` ({arch['qemu']})",
            "",
            "## Fixture Inputs",
            "",
            "Seed the following configuration keys with the inert canary token, using the firmware's local NVRAM/configuration mechanism or a rehosted fixture shim:",
            "",
            *(f"- `{key}`" for key in keys),
            "",
            "Relevant entry clues from static strings and TSDS records:",
            "",
            *(f"- `{clue}`" for clue in clues),
            "",
            "## Safe Interception Procedure",
            "",
            "1. Prepare an isolated firmware rootfs or service harness with no access to public networks.",
            "2. Build `hooks/sink_intercept.c` for the target ABI when the sink is dynamically interposable.",
            "3. If the sink is an internal firmware function, use `hooks/qemu_gdb_sink_intercept.gdb` as a breakpoint template and resolve the relocated sink address before execution.",
            "4. Set `TSDS_INTERCEPT_LOG` to a writable file inside the isolated environment.",
            "5. Load `fixtures/config_fixture.env` or translate `fixtures/config_fixture.json` into the firmware configuration store.",
            "6. Trigger only the local handler/routine required to reach the listed source function.",
            "7. Stop after the intercepted sink logs its argument; do not allow command execution.",
            "",
            "## Pass Criteria",
            "",
            f"- The intercept log contains `{task.get('canary_token')}` in the argument recorded for `{task.get('sink')}`.",
            "- The log entry has `executed=false` or an equivalent debugger transcript showing that the sink was skipped.",
            "- The observed command template is consistent with the TSDS preview and the selected closure.",
            "",
            "## Fail / Inconclusive Criteria",
            "",
            "- No sink invocation is observed under the fixture.",
            "- The sink argument is observed but does not contain the canary token.",
            "- The harness cannot guarantee that shell execution was prevented.",
            "- The run requires public-device interaction or non-isolated network effects.",
            "",
        ]
    )


def manifest(task: Dict[str, Any], arch: Dict[str, str]) -> Dict[str, Any]:
    return {
        "candidate_id": task.get("candidate_id"),
        "target": task.get("target"),
        "functional_theme": task.get("functional_theme"),
        "evidence_boundary": "sink-intercept canary validation only; not device-confirmed",
        "source_function": task.get("source_function"),
        "sink": task.get("sink"),
        "sink_function": sink_function(task),
        "sink_address": sink_address(task),
        "canary_token": task.get("canary_token"),
        "source_keys": split_semicolon(task.get("source_keys")),
        "entry_clues": split_semicolon(task.get("entry_clues")),
        "tsds_preview": task.get("tsds_preview"),
        "repro_signature": task.get("repro_signature"),
        "architecture_hint": arch,
        "safety_contract": {
            "public_device_testing": False,
            "shell_execution": False,
            "network_effects": False,
            "required_observation": "canary token appears in intercepted sink argument",
        },
        "generated_files": [
            "README.md",
            "manifest.json",
            "fixtures/config_fixture.env",
            "fixtures/config_fixture.json",
            "hooks/sink_intercept.c",
            "hooks/qemu_gdb_sink_intercept.gdb",
            "verification_log_template.json",
        ],
    }


def verification_template(task: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "candidate_id": task.get("candidate_id"),
        "target": task.get("target"),
        "run_id": "",
        "operator": "",
        "timestamp_utc": "",
        "environment": {
            "mode": "isolated-emulation-or-owned-hardware",
            "public_network_disabled": None,
            "shell_execution_prevented": None,
            "intercept_method": "",
        },
        "observation": {
            "sink": task.get("sink"),
            "canary_token": task.get("canary_token"),
            "sink_invoked": None,
            "token_observed_in_sink_argument": None,
            "executed": False,
            "log_path": "",
            "command_preview_observed": "",
        },
        "verdict": "unrun",
        "notes": "",
    }


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    rows = list(rows)
    fields: List[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def render_pack_readme(rows: List[Dict[str, Any]]) -> str:
    lines = [
        "# TSDS Sink-Intercept Canary Harness Pack",
        "",
        "This package turns selected TSDS validation candidates into safe, reproducible sink-intercept scaffolds. It does not execute payloads, start public-device tests, or claim device-confirmed vulnerabilities.",
        "",
        "| ID | Target | Theme | Sink | Token | Boundary |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| `{row['candidate_id']}` | {row['target']} | `{row['functional_theme']}` | `{row['sink']}` | `{row['canary_token']}` | sink-intercept only |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A completed run is useful when it shows that an isolated firmware harness reaches the same command sink and that the benign canary token appears in the intercepted argument while shell execution is blocked. This supports analyzer-level reproducibility and emulation consistency. It remains separate from device-confirmed vulnerability validation.",
            "",
        ]
    )
    return "\n".join(lines)


def render_latex(rows: List[Dict[str, Any]]) -> str:
    lines = [
        "% Auto-generated by experiments/build_sink_intercept_harness_pack.py",
        "\\begin{tabularx}{\\textwidth}{@{}lP{0.18\\textwidth}P{0.15\\textwidth}P{0.22\\textwidth}Y@{}}",
        "\\toprule",
        "ID & Target & Theme & Intercept target & Success criterion\\\\",
        "\\midrule",
    ]
    for row in rows:
        criterion = f"Token {row['canary_token']} logged at {row['sink']}; no shell execution."
        lines.append(
            "{} & {} & {} & {} & {}\\\\".format(
                row["candidate_id"].replace("_", "\\_"),
                row["target"].replace("&", "\\&"),
                row["functional_theme"].replace("_", "\\_"),
                row["sink"].replace("_", "\\_"),
                criterion.replace("_", "\\_").replace("&", "\\&"),
            )
        )
    lines.extend(["\\bottomrule", "\\end{tabularx}", ""])
    return "\n".join(lines)


def render_log_validator() -> str:
    return r'''#!/usr/bin/env python3
"""Validate a TSDS sink-intercept canary log without executing anything."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("log")
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    token = manifest["canary_token"]
    sink = manifest["sink_function"]
    hits = []
    executed = []
    for line_no, line in enumerate(Path(args.log).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            row = {"raw": line}
        text = json.dumps(row, ensure_ascii=False)
        if token in text and sink in text:
            hits.append({"line": line_no, "record": row})
        if '"executed": true' in text.lower() or row.get("executed") is True:
            executed.append({"line": line_no, "record": row})
    result = {
        "candidate_id": manifest["candidate_id"],
        "sink": manifest["sink"],
        "token": token,
        "token_hits": len(hits),
        "executed_true_records": len(executed),
        "verdict": "PASS" if hits and not executed else "FAIL",
        "boundary": "sink-intercept log validation only",
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
'''


def build_pack(tasks: List[Dict[str, Any]], out_dir: Path) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, Any]] = []
    for task in tasks:
        arch = TARGET_ARCH_HINTS.get(str(task.get("target")), {
            "arch": "unknown",
            "arg0": "$arg0",
            "return_reg": "$ret",
            "qemu": "confirm target ABI with file(1).",
        })
        dirname = f"{task.get('candidate_id')}_{slug(str(task.get('target', 'target')))}_{slug(str(task.get('functional_theme', 'theme')))}"
        task_dir = out_dir / dirname
        (task_dir / "fixtures").mkdir(parents=True, exist_ok=True)
        (task_dir / "hooks").mkdir(parents=True, exist_ok=True)

        task_manifest = manifest(task, arch)
        (task_dir / "README.md").write_text(render_runbook(task, arch), encoding="utf-8")
        write_json(task_dir / "manifest.json", task_manifest)
        (task_dir / "fixtures" / "config_fixture.env").write_text(render_fixture_env(task), encoding="utf-8")
        write_json(
            task_dir / "fixtures" / "config_fixture.json",
            {
                "candidate_id": task.get("candidate_id"),
                "canary_token": task.get("canary_token"),
                "values": {key: task.get("canary_token") for key in split_semicolon(task.get("source_keys"))},
            },
        )
        (task_dir / "hooks" / "sink_intercept.c").write_text(render_intercept_c(), encoding="utf-8")
        (task_dir / "hooks" / "qemu_gdb_sink_intercept.gdb").write_text(
            render_gdb_template(task, arch), encoding="utf-8"
        )
        write_json(task_dir / "verification_log_template.json", verification_template(task))

        rows.append(
            {
                "candidate_id": task.get("candidate_id"),
                "target": task.get("target"),
                "functional_theme": task.get("functional_theme"),
                "source_function": task.get("source_function"),
                "sink": task.get("sink"),
                "canary_token": task.get("canary_token"),
                "artifact_dir": dirname,
                "boundary": "sink-intercept canary only",
            }
        )

    (out_dir / "README.md").write_text(render_pack_readme(rows), encoding="utf-8")
    write_csv(out_dir / "harness_pack_index.csv", rows)
    write_json(out_dir / "harness_pack_index.json", rows)
    (out_dir / "harness_pack_table.tex").write_text(render_latex(rows), encoding="utf-8")
    (out_dir / "validate_intercept_log.py").write_text(render_log_validator(), encoding="utf-8")
    summary = {
        "tasks": len(rows),
        "candidate_ids": [row["candidate_id"] for row in rows],
        "targets": sorted({str(row["target"]) for row in rows}),
        "artifact_boundary": "safe sink-intercept canary harnesses; no shell execution; not device-confirmed",
        "out_dir": str(out_dir.resolve()),
    }
    write_json(out_dir / "harness_pack_summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--tasks-json", default=str(DEFAULT_TASKS))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--ids", nargs="*", default=None)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    tasks = load_tasks(root / args.tasks_json)
    if args.ids:
        requested = set(args.ids)
        tasks = [task for task in tasks if task.get("candidate_id") in requested]
    if not tasks:
        raise SystemExit("no canary tasks selected")
    summary = build_pack(tasks, root / args.out_dir)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
