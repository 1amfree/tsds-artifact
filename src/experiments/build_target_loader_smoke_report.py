#!/usr/bin/env python3
"""Run safe loader-trace smoke checks for TSDS canary target binaries.

The checker uses QEMU's guest environment option `-E LD_TRACE_LOADED_OBJECTS=1`
to ask the target dynamic loader
to print shared-library dependencies and exit before the firmware program's
main routine.  It never starts services or command sinks.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
from pathlib import Path
from typing import Any, Dict, Iterable, List


DEFAULT_PREFLIGHT = Path("experiment_reports/dynamic_validation_preflight_v9_20260626/dynamic_validation_preflight.json")
DEFAULT_OUT = Path("experiment_reports/target_loader_smoke_v9_20260626")


class Remote:
    def __init__(self, host: str, user: str, password: str, timeout: int = 30) -> None:
        try:
            import paramiko  # type: ignore
        except ImportError as exc:
            raise SystemExit("paramiko is required for SSH loader checks") from exc
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            host,
            username=user,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )

    def run(self, command: str, timeout: int = 60) -> Dict[str, Any]:
        _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        return {"returncode": rc, "stdout": out, "stderr": err, "command": command}

    def close(self) -> None:
        self.client.close()


def quote(value: str) -> str:
    return shlex.quote(value)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    rows = list(rows)
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


def qemu_for_row(row: Dict[str, Any]) -> str:
    available = str(row.get("qemu_available") or "")
    if available and available != "none":
        return available.split(";", 1)[0].strip()
    return str(row.get("qemu_required") or "").split(";", 1)[0].strip()


def run_loader(remote: Remote, row: Dict[str, Any]) -> Dict[str, Any]:
    qemu = qemu_for_row(row)
    rootfs = str(row.get("target_rootfs_path") or "")
    binary = str(row.get("binary_path") or "")
    command = f"""
set -u
qemu={quote(qemu)}
root={quote(rootfs)}
binary={quote(binary)}
printf 'qemu_path='
command -v "$qemu" || true
printf 'binary_file='
file "$binary" 2>&1 || true
printf 'loader_output='
loader_output=$(timeout 20s "$qemu" -L "$root" -E LD_TRACE_LOADED_OBJECTS=1 "$binary" 2>&1)
loader_rc=$?
printf '%s' "$loader_output" | tr '\\n' '|'
printf '\\nloader_rc=%s\\n' "$loader_rc"
"""
    result = remote.run(command, timeout=60)
    parsed: Dict[str, Any] = {
        "candidate_id": row.get("candidate_id"),
        "target": row.get("target"),
        "binary_path": binary,
        "rootfs": rootfs,
        "rootfs_binary_path": row.get("rootfs_binary_path", ""),
        "analysis_binary_md5": row.get("analysis_binary_md5", ""),
        "rootfs_binary_md5": row.get("rootfs_binary_md5", ""),
        "binary_rootfs_aligned": row.get("binary_rootfs_aligned", False),
        "qemu": qemu,
        "boundary": "loader-trace smoke only; no firmware main routine; no service or command sink execution",
        "returncode": result["returncode"],
    }
    for line in result["stdout"].splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            parsed[key] = value
    output = str(parsed.get("loader_output") or "")
    loader_rc = str(parsed.get("loader_rc") or "")
    parsed["pass"] = (
        result["returncode"] == 0
        and loader_rc == "0"
        and "not found" not in output.lower()
        and "x86_64-linux-gnu" not in output.lower()
        and ("lib" in output.lower() or "ld-uclibc" in output.lower())
    )
    if parsed["pass"]:
        parsed["failure_reason"] = ""
    elif not parsed.get("binary_rootfs_aligned"):
        parsed["failure_reason"] = "analysis binary differs from rootfs binary"
    elif "x86_64-linux-gnu" in output.lower():
        parsed["failure_reason"] = "host loader trace detected"
    elif str(parsed.get("loader_rc")) != "0":
        parsed["failure_reason"] = f"guest loader trace exited with {parsed.get('loader_rc')}"
    elif not output:
        parsed["failure_reason"] = "empty guest loader trace"
    else:
        parsed["failure_reason"] = "guest loader trace did not contain expected dependency evidence"
    parsed["stdout"] = result["stdout"]
    parsed["stderr"] = result["stderr"]
    return parsed


def markdown(rows: List[Dict[str, Any]]) -> str:
    passed = sum(1 for row in rows if row.get("pass"))
    lines = [
        "# TSDS Target Loader Smoke Report",
        "",
        "This report checks whether preflight-ready target binaries can be resolved by the target rootfs dynamic linker. It uses QEMU guest environment `-E LD_TRACE_LOADED_OBJECTS=1` and does not enter firmware main routines.",
        "",
        f"- Tasks checked: `{len(rows)}`",
        f"- PASS: `{passed}`",
        f"- FAIL: `{len(rows) - passed}`",
        "",
        "| ID | Target | QEMU | Binary match | Verdict | Reason |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        verdict = "PASS" if row.get("pass") else "FAIL"
        aligned = "yes" if row.get("binary_rootfs_aligned") else "no"
        lines.append(
            f"| `{row.get('candidate_id')}` | {row.get('target')} | `{row.get('qemu')}` | {aligned} | `{verdict}` | {row.get('failure_reason', '')} |"
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "A PASS row is dynamic environment evidence for ABI and shared-library readiness. It is not a sink-intercept canary observation and not device-confirmed vulnerability evidence.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--preflight-json", default=str(DEFAULT_PREFLIGHT))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--host", default=os.environ.get("TSDS_SSH_HOST", "192.168.206.137"))
    parser.add_argument("--user", default=os.environ.get("TSDS_SSH_USER", "ubuntu"))
    parser.add_argument("--password", default=os.environ.get("TSDS_SSH_PASSWORD", "ubuntu"))
    args = parser.parse_args()

    root = Path(args.root).resolve()
    rows = [row for row in load_json(root / args.preflight_json) if row.get("ready_for_isolated_run")]
    remote = Remote(args.host, args.user, args.password)
    try:
        results = [run_loader(remote, row) for row in rows]
    finally:
        remote.close()

    out_dir = root / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "target_loader_smoke.json", results)
    write_csv(out_dir / "target_loader_smoke.csv", results)
    (out_dir / "target_loader_smoke.md").write_text(markdown(results), encoding="utf-8")
    summary = {
        "tasks": len(results),
        "pass": sum(1 for row in results if row.get("pass")),
        "fail": sum(1 for row in results if not row.get("pass")),
        "boundary": "loader-trace smoke only; no firmware main routine; no service or command sink execution",
        "out_dir": str(out_dir),
    }
    write_json(out_dir / "target_loader_smoke_summary.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
