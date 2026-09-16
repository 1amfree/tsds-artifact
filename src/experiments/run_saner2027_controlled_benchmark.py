#!/usr/bin/env python3
"""Run a small, independently labelled final-byte calibration benchmark.

The benchmark is intentionally separate from the firmware ledger.  It compiles
one native ELF containing semantically distinct source-to-system cases, runs
only fixed benign inputs under a logging system interposer, and then invokes
TSDS on the same callsite closures.  The labels are written in this script and
are not inferred from TSDS output.

This is an implementation calibration and original-program chain check.  It
is not a firmware ground-truth set, a vulnerability prevalence estimate, or a
claim about exploitability of the firmware corpus.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVALUATOR = PROJECT_ROOT / "Taint_demo" / "sanitizer_demo" / "advanced_sanitizer_evaluator.py"


CASES: list[dict[str, Any]] = [
    {
        "id": "direct_format",
        "body": r'''char command[256]; snprintf(command, sizeof(command), "echo %s", input); system(command);''',
        "expected": "POSITIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "direct_copy",
        "body": r'''char command[256]; strcpy(command, "echo "); strncat(command, input, sizeof(command) - strlen(command) - 1); system(command);''',
        "expected": "POSITIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "direct_append",
        "body": r'''char command[256]; command[0] = 0; strcat(command, "echo "); strcat(command, input); system(command);''',
        "expected": "POSITIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "fixed_prefix_format",
        "body": r'''char command[256]; snprintf(command, sizeof(command), "printf fixed && echo %s", input); system(command);''',
        "expected": "POSITIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "single_quote_breakout",
        "body": r'''char command[256]; snprintf(command, sizeof(command), "echo '%s'", input); system(command);''',
        "expected": "POSITIVE",
        "input": "SAFE';: > \"$TSDS_TRIGGER_PATH\";#",
    },
    {
        "id": "double_quote_breakout",
        "body": r'''char command[256]; snprintf(command, sizeof(command), "echo \"%s\"", input); system(command);''',
        "expected": "POSITIVE",
        "input": "SAFE\";: > \"$TSDS_TRIGGER_PATH\";#",
    },
    {
        "id": "command_substitution",
        "body": r'''char command[256]; snprintf(command, sizeof(command), "echo %s", input); system(command);''',
        "expected": "POSITIVE",
        "input": "$( : > \"$TSDS_TRIGGER_PATH\" )",
    },
    {
        "id": "pipe_control",
        "body": r'''char command[256]; snprintf(command, sizeof(command), "echo %s", input); system(command);''',
        "expected": "POSITIVE",
        "input": "SAFE|: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "ifs_context",
        "body": r'''char command[256]; snprintf(command, sizeof(command), "echo %s", input); system(command);''',
        "expected": "POSITIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "newline_control",
        "body": r'''char command[256]; snprintf(command, sizeof(command), "echo %s", input); system(command);''',
        "expected": "POSITIVE",
        "input": "SAFE\n: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "alnum_filter",
        "body": r'''char clean[128]; char command[256]; tsds_copy_alnum(clean, sizeof(clean), input); snprintf(command, sizeof(command), "echo %s", clean); system(command);''',
        "expected": "NEGATIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "meta_escape",
        "body": r'''char clean[128]; char command[256]; tsds_escape_meta(clean, sizeof(clean), input); snprintf(command, sizeof(command), "echo %s", clean); system(command);''',
        "expected": "NEGATIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "quoted_alnum_filter",
        "body": r'''char clean[128]; char command[256]; tsds_copy_alnum(clean, sizeof(clean), input); snprintf(command, sizeof(command), "echo '%s'", clean); system(command);''',
        "expected": "NEGATIVE",
        "input": "SAFE';: > \"$TSDS_TRIGGER_PATH\";#",
    },
    {
        "id": "fixed_command_observed_input",
        "body": r'''char command[256]; tsds_observe(input); snprintf(command, sizeof(command), "echo fixed && echo fixed2"); system(command);''',
        "expected": "NEGATIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "unused_copy_fixed_sink",
        "body": r'''char scratch[128]; char command[256]; strcpy(scratch, input); snprintf(command, sizeof(command), "echo fixed"); system(command);''',
        "expected": "NEGATIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "double_quote_dollar_filter",
        "body": r'''char clean[128]; char command[256]; tsds_escape_meta(clean, sizeof(clean), input); snprintf(command, sizeof(command), "echo \"%s\"", clean); system(command);''',
        "expected": "NEGATIVE",
        "input": "SAFE$( : > \"$TSDS_TRIGGER_PATH\" )",
    },
    {
        "id": "prefix_truncation",
        "body": r'''char command[256]; snprintf(command, sizeof(command), "echo %.48s", input); system(command);''',
        "expected": "POSITIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "truncated_alnum_filter",
        "body": r'''char clean[16]; char command[256]; tsds_copy_alnum_prefix(clean, sizeof(clean), input, 8); snprintf(command, sizeof(command), "echo %s", clean); system(command);''',
        "expected": "NEGATIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "conditional_unquoted",
        "body": r'''char command[256]; if (input[0] == 'A') snprintf(command, sizeof(command), "echo %s", input); else snprintf(command, sizeof(command), "echo '%s'", input); system(command);''',
        "expected": "POSITIVE",
        "input": "A;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "conditional_fixed",
        "body": r'''char command[256]; if (input[0] == 'A') snprintf(command, sizeof(command), "echo fixed-A"); else snprintf(command, sizeof(command), "echo fixed-B"); system(command);''',
        "expected": "NEGATIVE",
        "input": "A;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "two_source_fields",
        "body": r'''char command[256]; snprintf(command, sizeof(command), "echo %s-%s", input, input); system(command);''',
        "expected": "POSITIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "wrapped_render",
        "body": r'''char command[256]; tsds_render(command, sizeof(command), input); system(command);''',
        "expected": "POSITIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "numeric_projection",
        "body": r'''char command[256]; snprintf(command, sizeof(command), "echo %u", (unsigned int)(unsigned char)input[0]); system(command);''',
        "expected": "NEGATIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
    {
        "id": "space_only_filter",
        "body": r'''char clean[128]; char command[256]; tsds_copy_space_safe(clean, sizeof(clean), input); snprintf(command, sizeof(command), "echo %s", clean); system(command);''',
        "expected": "NEGATIVE",
        "input": "SAFE;: > \"$TSDS_TRIGGER_PATH\"",
    },
]


BENCHMARK_C = r'''#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

volatile size_t tsds_observed_length;

__attribute__((noinline))
void tsds_observe(const char *input) {
    tsds_observed_length = strlen(input);
}

__attribute__((noinline))
void tsds_copy_alnum(char *dst, size_t cap, const char *src) {
    size_t out = 0;
    if (cap == 0) return;
    for (size_t i = 0; src[i] != '\0' && out + 1 < cap; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (isalnum(c) || c == '_') dst[out++] = (char)c;
    }
    dst[out] = '\0';
}

__attribute__((noinline))
void tsds_copy_alnum_prefix(char *dst, size_t cap, const char *src, size_t limit) {
    size_t out = 0;
    if (cap == 0) return;
    for (size_t i = 0; src[i] != '\0' && i < limit && out + 1 < cap; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (isalnum(c) || c == '_') dst[out++] = (char)c;
    }
    dst[out] = '\0';
}

__attribute__((noinline))
void tsds_escape_meta(char *dst, size_t cap, const char *src) {
    size_t out = 0;
    if (cap == 0) return;
    for (size_t i = 0; src[i] != '\0' && out + 1 < cap; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c == ';' || c == '|' || c == '&' || c == '$' || c == '`' ||
            c == '\n' || c == '\t' || c == '>' || c == '<') c = '_';
        dst[out++] = (char)c;
    }
    dst[out] = '\0';
}

__attribute__((noinline))
void tsds_copy_space_safe(char *dst, size_t cap, const char *src) {
    size_t out = 0;
    if (cap == 0) return;
    for (size_t i = 0; src[i] != '\0' && out + 1 < cap; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c != ';' && c != '|' && c != '&' && c != '$' && c != '`' &&
            c != '\n' && c != '\t' && c != '>' && c != '<') dst[out++] = (char)c;
    }
    dst[out] = '\0';
}

__attribute__((noinline))
void tsds_render(char *dst, size_t cap, const char *input) {
    snprintf(dst, cap, "echo %s", input);
}

'''


INTERPOSER_C = r'''#define _GNU_SOURCE
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int system(const char *command) {
    const char *log_path = getenv("TSDS_NATIVE_COMMAND_LOG");
    if (log_path != NULL) {
        int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd >= 0) {
            dprintf(fd, "LEN=%zu\n", command == NULL ? 0UL : strlen(command));
            if (command != NULL) dprintf(fd, "%s", command);
            dprintf(fd, "\n---\n");
            close(fd);
        }
    }
    if (command == NULL) return 0;
    const char *effect_path = getenv("TSDS_NATIVE_EFFECT_LOG");
    if (effect_path == NULL) return 127;
    pid_t child = fork();
    if (child < 0) return 127;
    if (child == 0) {
        int fd = open(effect_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        const char *trigger_path = getenv("TSDS_NATIVE_TRIGGER_PATH");
        clearenv();
        setenv("PATH", "/usr/bin:/bin", 1);
        setenv("LC_ALL", "C", 1);
        if (trigger_path != NULL) setenv("TSDS_TRIGGER_PATH", trigger_path, 1);
        execl("/bin/dash", "dash", "-c", command, (char *)NULL);
        _exit(127);
    }
    int status = 127;
    if (waitpid(child, &status, 0) < 0) return 127;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 128;
}
'''


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_checked(command: list[str], *, cwd: Path, stdout: Path, stderr: Path, timeout: int) -> dict[str, Any]:
    stdout.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            stdout=stdout.open("w", encoding="utf-8"),
            stderr=stderr.open("w", encoding="utf-8"),
            env={**os.environ, "LC_ALL": "C", "LANG": "C", "PYTHONHASHSEED": "0"},
            timeout=timeout,
            check=False,
        )
        return {
            "command": command,
            "returncode": completed.returncode,
            "timed_out": False,
            "elapsed_sec": round(time.monotonic() - started, 6),
            "stdout": str(stdout),
            "stderr": str(stderr),
        }
    except subprocess.TimeoutExpired:
        return {
            "command": command,
            "returncode": 124,
            "timed_out": True,
            "elapsed_sec": round(time.monotonic() - started, 6),
            "stdout": str(stdout),
            "stderr": str(stderr),
        }


def symbol_addresses(binary: Path) -> dict[str, int]:
    output = subprocess.check_output(["nm", "-an", str(binary)], text=True)
    result: dict[str, int] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2].startswith("tsds_case_"):
            result[fields[2]] = int(fields[0], 16)
    return result


def system_callsites(binary: Path, addresses: dict[str, int]) -> dict[str, int]:
    output = subprocess.check_output(["objdump", "-d", "-M", "intel", str(binary)], text=True)
    ordered = sorted(addresses.items(), key=lambda item: item[1])
    ends = {name: (ordered[i + 1][1] if i + 1 < len(ordered) else 1 << 63) for i, (name, _) in enumerate(ordered)}
    result: dict[str, int] = {}
    current: str | None = None
    for line in output.splitlines():
        match = re.match(r"^([0-9a-fA-F]+) <([^>]+)>:$", line.strip())
        if match:
            current = match.group(2)
            continue
        if current not in addresses or current not in ends or "<system@plt>" not in line:
            continue
        address_match = re.match(r"\s*([0-9a-fA-F]+):", line)
        if address_match:
            callsite = int(address_match.group(1), 16)
            if addresses[current] <= callsite < ends[current]:
                result[current] = callsite
    return result


def build_source() -> str:
    chunks = [BENCHMARK_C]
    for index, spec in enumerate(CASES):
        chunks.append(
            "__attribute__((noinline)) void tsds_case_{:02d}(const char *input) {{ {} }}\n".format(
                index, spec["body"]
            )
        )
    chunks.append("int main(int argc, char **argv) {\n")
    chunks.append("    if (argc < 3) return 2;\n    int id = atoi(argv[1]);\n    const char *input = argv[2];\n    switch (id) {\n")
    for index in range(len(CASES)):
        chunks.append("        case {}: tsds_case_{:02d}(input); break;\n".format(index, index))
    chunks.append("        default: return 3;\n    }\n    return 0;\n}\n")
    return "".join(chunks)


def build_closure(path: Path, source_name: str, source_addr: int, sink_addr: int) -> None:
    write_json(
        path,
        {
            "closures": [
                {
                    "trace": [
                        {
                            "function": source_name,
                            "ins_addr": hex(source_addr),
                            "string": f"{source_name}(<symbolic-input>)",
                        }
                    ],
                    "sink": {
                        "function": "system",
                        "ins_addr": hex(sink_addr),
                        "string": "system(<symbolic-command>)",
                    },
                }
            ]
        },
    )


def classify_tsds(record: dict[str, Any] | None) -> tuple[str, bool]:
    if not record:
        return "UNRESOLVED", False
    status = str(record.get("status") or record.get("verdict") or "").lower()
    positive = status in {"vulnerable", "vector_sat"} or int(record.get("vulnerable_vectors") or 0) > 0
    if positive:
        return "POSITIVE", True
    if status in {
        "filtered",
        "matrix_unsat",
        "no_taint_sink",
        "no_modeled_source",
        "static_warning_reduction",
        "static_candidate",
    }:
        return "NEGATIVE_PROFILE", False
    return "UNRESOLVED", False


def read_last_jsonl(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return None
    try:
        value = json.loads(lines[-1])
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def native_run(binary: Path, interposer: Path, spec: dict[str, Any], index: int, out_dir: Path) -> dict[str, Any]:
    native_dir = out_dir / "native"
    native_dir.mkdir(parents=True, exist_ok=True)
    command_log = native_dir / f"{index:02d}_{spec['id']}.command"
    effect_log = native_dir / f"{index:02d}_{spec['id']}.effect"
    trigger_path = native_dir / f"{index:02d}_{spec['id']}.trigger"
    if trigger_path.exists():
        trigger_path.unlink()
    env = {
        **os.environ,
        "LD_PRELOAD": str(interposer),
        "TSDS_NATIVE_COMMAND_LOG": str(command_log),
        "TSDS_NATIVE_EFFECT_LOG": str(effect_log),
        "TSDS_NATIVE_TRIGGER_PATH": str(trigger_path),
        "LC_ALL": "C",
        "LANG": "C",
    }
    started = time.monotonic()
    try:
        completed = subprocess.run(
            [str(binary), str(index), spec["input"]],
            cwd=str(native_dir),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        completed = None
        timed_out = True
        stdout = (exc.stdout or b"") if isinstance(exc.stdout, bytes) else str(exc.stdout or "").encode()
        stderr = (exc.stderr or b"") if isinstance(exc.stderr, bytes) else str(exc.stderr or "").encode()
    else:
        stdout = completed.stdout or b""
        stderr = completed.stderr or b""
    effect = effect_log.read_bytes() if effect_log.is_file() else b""
    command_bytes = command_log.read_bytes() if command_log.is_file() else b""
    trigger_observed = trigger_path.is_file()
    return {
        "case_id": spec["id"],
        "returncode": 124 if timed_out else completed.returncode,
        "timed_out": timed_out,
        "elapsed_sec": round(time.monotonic() - started, 6),
        "input_sha256": hashlib.sha256(spec["input"].encode()).hexdigest(),
        "command_log": str(command_log),
        "command_log_sha256": hashlib.sha256(command_bytes).hexdigest(),
        "effect_log": str(effect_log),
        "effect_log_sha256": hashlib.sha256(effect).hexdigest(),
        "trigger_path": str(trigger_path),
        "trigger_observed": trigger_observed,
        "marker": "TSDS_TRIGGER_CREATED",
        "marker_observed": trigger_observed,
        "stdout": stdout.decode("utf-8", "replace"),
        "stderr": stderr.decode("utf-8", "replace"),
        "native_expected": spec["expected"],
        "claim_boundary": "Safe fixed input executed through the original benchmark program and an allowlisted dash child; no generated TSDS witness was executed.",
    }


def tsds_run(binary: Path, evaluator_python: str, spec: dict[str, Any], index: int, source_addr: int, sink_addr: int, out_dir: Path) -> dict[str, Any]:
    case_dir = out_dir / "tsds" / f"{index:02d}_{spec['id']}"
    case_dir.mkdir(parents=True, exist_ok=True)
    closure = case_dir / "closure.json"
    build_closure(closure, f"tsds_case_{index:02d}", source_addr, sink_addr)
    result_path = case_dir / "result.jsonl"
    summary_path = case_dir / "summary.json"
    stdout_path = case_dir / "stdout.log"
    stderr_path = case_dir / "stderr.log"
    command = [
        evaluator_python,
        str(EVALUATOR),
        str(binary),
        str(closure),
        "--closure-idx",
        "0",
        "--engine-timeout",
        "25",
        "--max-steps",
        "260",
        "--closure-timeout",
        "60",
        "--no-evidence-cache",
        "--summary-json",
        str(summary_path),
        "--results-jsonl",
        str(result_path),
    ]
    receipt = run_checked(command, cwd=PROJECT_ROOT, stdout=stdout_path, stderr=stderr_path, timeout=95)
    record = read_last_jsonl(result_path)
    tsds_class, tsds_positive = classify_tsds(record)
    expected_positive = spec["expected"] == "POSITIVE"
    if tsds_class == "UNRESOLVED":
        comparison = "UNRESOLVED"
    elif tsds_positive == expected_positive:
        comparison = "MATCH"
    elif expected_positive:
        comparison = "MISMATCH_FALSE_NEGATIVE"
    else:
        comparison = "MISMATCH_FALSE_POSITIVE"
    return {
        "case_id": spec["id"],
        "source_addr": hex(source_addr),
        "sink_addr": hex(sink_addr),
        "tsds_class": tsds_class,
        "tsds_positive": tsds_positive,
        "comparison": comparison,
        "returncode": receipt["returncode"],
        "timed_out": receipt["timed_out"],
        "elapsed_sec": receipt["elapsed_sec"],
        "result_path": str(result_path),
        "summary_path": str(summary_path),
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
        "record": record,
        "claim_boundary": "TSDS result on the controlled ELF closure; residual is unresolved rather than a negative label.",
    }


def write_sha256sums(root: Path) -> None:
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            rows.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")


def main() -> int:
    if os.name != "posix":
        print("This benchmark must run on the Ubuntu VM, not on the Windows host.", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, default=Path("experiment_reports/saner2027_controlled_benchmark_20260913"))
    parser.add_argument("--python", default=sys.executable, help="Ubuntu Python used to invoke TSDS")
    args = parser.parse_args()
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to overwrite non-empty output: {out_dir}", file=sys.stderr)
        return 2
    if not EVALUATOR.is_file():
        print(f"missing evaluator: {EVALUATOR}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)
    build_dir = out_dir / "build"
    build_dir.mkdir()
    source = build_dir / "controlled_benchmark.c"
    interposer = build_dir / "tsds_system_interposer.c"
    binary = build_dir / "controlled_benchmark"
    interposer_so = build_dir / "libtsds_system_interposer.so"
    source.write_text(build_source(), encoding="utf-8")
    interposer.write_text(INTERPOSER_C, encoding="utf-8")
    compile_receipts = []
    compile_receipts.append(run_checked(
        ["gcc", "-O0", "-g", "-fno-inline", "-fno-builtin", "-fno-omit-frame-pointer", "-no-pie", str(source), "-o", str(binary)],
        cwd=PROJECT_ROOT,
        stdout=build_dir / "compile.stdout.log",
        stderr=build_dir / "compile.stderr.log",
        timeout=30,
    ))
    compile_receipts.append(run_checked(
        ["gcc", "-shared", "-fPIC", "-O0", "-Wall", "-Wextra", str(interposer), "-o", str(interposer_so)],
        cwd=PROJECT_ROOT,
        stdout=build_dir / "interposer_compile.stdout.log",
        stderr=build_dir / "interposer_compile.stderr.log",
        timeout=30,
    ))
    if any(receipt["returncode"] != 0 for receipt in compile_receipts) or not binary.is_file() or not interposer_so.is_file():
        print("benchmark compilation failed", file=sys.stderr)
        return 1
    addresses = symbol_addresses(binary)
    callsites = system_callsites(binary, addresses)
    missing = [f"tsds_case_{i:02d}" for i in range(len(CASES)) if f"tsds_case_{i:02d}" not in addresses or f"tsds_case_{i:02d}" not in callsites]
    if missing:
        write_json(out_dir / "build_failure.json", {"missing": missing, "addresses": addresses, "callsites": callsites})
        print(f"missing source/sink symbols: {missing}", file=sys.stderr)
        return 1
    native_rows = []
    tsds_rows = []
    for index, spec in enumerate(CASES):
        native_rows.append(native_run(binary, interposer_so, spec, index, out_dir))
        name = f"tsds_case_{index:02d}"
        tsds_rows.append(tsds_run(binary, args.python, spec, index, addresses[name], callsites[name], out_dir))
    matches = sum(row["comparison"] == "MATCH" for row in tsds_rows)
    unresolved = sum(row["comparison"] == "UNRESOLVED" for row in tsds_rows)
    positive_expected = sum(spec["expected"] == "POSITIVE" for spec in CASES)
    positive_native = sum(row["marker_observed"] for row in native_rows)
    summary = {
        "schema": "tsds-saner2027-controlled-benchmark-v1",
        "generated_at_utc": utc_now(),
        "case_count": len(CASES),
        "expected_positive_cases": positive_expected,
        "expected_negative_cases": len(CASES) - positive_expected,
        "native_marker_observed": positive_native,
        "tsds_matches": matches,
        "tsds_unresolved": unresolved,
        "tsds_mismatches": len(CASES) - matches - unresolved,
        "source_sha256": sha256_file(source),
        "interposer_source_sha256": sha256_file(interposer),
        "binary_sha256": sha256_file(binary),
        "interposer_sha256": sha256_file(interposer_so),
        "compiler": compile_receipts,
        "cases": [
            {
                "index": i,
                "id": spec["id"],
                "expected": spec["expected"],
                "input_sha256": hashlib.sha256(spec["input"].encode()).hexdigest(),
                "source_addr": hex(addresses[f"tsds_case_{i:02d}"]),
                "sink_addr": hex(callsites[f"tsds_case_{i:02d}"]),
                "native": native_rows[i],
                "tsds": tsds_rows[i],
            }
            for i, spec in enumerate(CASES)
        ],
        "claim_boundary": (
            "Independent native execution of 24 fixed benign inputs and TSDS comparison on one synthetic ELF. "
            "Labels are semantic benchmark labels, not firmware ground truth or device exploitability."
        ),
    }
    write_json(out_dir / "summary.json", summary)
    with (out_dir / "cases.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = ["index", "case_id", "expected", "native_returncode", "marker_observed", "tsds_class", "tsds_positive", "comparison", "tsds_elapsed_sec"]
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for i, spec in enumerate(CASES):
            native = native_rows[i]
            tsds = tsds_rows[i]
            writer.writerow({
                "index": i,
                "case_id": spec["id"],
                "expected": spec["expected"],
                "native_returncode": native["returncode"],
                "marker_observed": native["marker_observed"],
                "tsds_class": tsds["tsds_class"],
                "tsds_positive": tsds["tsds_positive"],
                "comparison": tsds["comparison"],
                "tsds_elapsed_sec": tsds["elapsed_sec"],
            })
    lines = [
        "# SANER 2027 controlled benchmark",
        "",
        "This artifact is an Ubuntu-only implementation calibration, not a firmware ground-truth study.",
        "",
        f"- Cases: `{len(CASES)}` ({positive_expected} independently labelled positive, {len(CASES) - positive_expected} negative).",
        f"- Native marker observations: `{positive_native}`.",
        f"- TSDS: `{matches}` matches, `{unresolved}` unresolved, `{len(CASES) - matches - unresolved}` mismatches.",
        "- Native commands are logged by an interposer and executed only with fixed benign marker inputs through `/bin/dash`; no generated TSDS witness is executed.",
        "- An unresolved TSDS result is not counted as a negative label.",
        "",
        "All source, binary, closure, command, effect, evaluator logs, and hashes are retained below this directory.",
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_sha256sums(out_dir)
    print(json.dumps({"out_dir": str(out_dir), "cases": len(CASES), "matches": matches, "unresolved": unresolved, "mismatches": len(CASES) - matches - unresolved}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
