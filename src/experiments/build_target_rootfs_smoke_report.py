#!/usr/bin/env python3
"""Run inert QEMU/rootfs smoke tests for ready TSDS canary targets.

This script validates the execution substrate only.  It runs BusyBox `echo`
inside each target rootfs and never starts firmware services, handlers, or
command sinks.
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
DEFAULT_OUT = Path("experiment_reports/target_rootfs_smoke_v9_20260626")


class Remote:
    def __init__(self, host: str, user: str, password: str, timeout: int = 30) -> None:
        try:
            import paramiko  # type: ignore
        except ImportError as exc:
            raise SystemExit("paramiko is required for SSH smoke checks") from exc
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
    required = str(row.get("qemu_required") or "")
    return required.split(";", 1)[0].strip()


def run_smoke(remote: Remote, row: Dict[str, Any]) -> Dict[str, Any]:
    rootfs = str(row.get("target_rootfs_path") or "")
    qemu = qemu_for_row(row)
    token = f"TSDS_ROOTFS_SMOKE_{row.get('candidate_id', 'unknown').replace('-', '_').upper()}"
    command = f"""
set -u
root={quote(rootfs)}
qemu={quote(qemu)}
token={quote(token)}
busybox=""
for candidate in "$root/bin/busybox" "$root/sbin/busybox" "$root/usr/bin/busybox"; do
  if [ -x "$candidate" ]; then busybox="$candidate"; break; fi
done
printf 'qemu_path='
command -v "$qemu" || true
printf 'rootfs='
printf '%s\\n' "$root"
printf 'busybox='
printf '%s\\n' "$busybox"
printf 'busybox_file='
if [ -n "$busybox" ]; then file "$busybox" 2>&1; else echo missing; fi
printf 'smoke='
if [ -n "$busybox" ]; then timeout 20s "$qemu" -L "$root" "$busybox" echo "$token" 2>&1; else echo missing_busybox; fi
printf 'smoke_rc=%s\\n' "$?"
"""
    result = remote.run(command, timeout=60)
    parsed: Dict[str, Any] = {
        "candidate_id": row.get("candidate_id"),
        "target": row.get("target"),
        "rootfs": rootfs,
        "qemu": qemu,
        "token": token,
        "boundary": "target-rootfs ABI smoke only; no firmware service execution; no command sink execution",
        "returncode": result["returncode"],
    }
    for line in result["stdout"].splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            parsed[key] = value
    parsed["pass"] = result["returncode"] == 0 and token in result["stdout"] and "smoke_rc=0" in result["stdout"]
    parsed["stdout"] = result["stdout"]
    parsed["stderr"] = result["stderr"]
    return parsed


def markdown(rows: List[Dict[str, Any]]) -> str:
    passed = sum(1 for row in rows if row.get("pass"))
    lines = [
        "# TSDS Target Rootfs Smoke Report",
        "",
        "This report validates only the QEMU/rootfs execution substrate for preflight-ready canary targets. It does not start firmware services, trigger handlers, or execute command sinks.",
        "",
        f"- Tasks checked: `{len(rows)}`",
        f"- PASS: `{passed}`",
        f"- FAIL: `{len(rows) - passed}`",
        "",
        "| ID | Target | QEMU | Rootfs | BusyBox | Verdict |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        verdict = "PASS" if row.get("pass") else "FAIL"
        lines.append(
            f"| `{row.get('candidate_id')}` | {row.get('target')} | `{row.get('qemu')}` | `{row.get('rootfs')}` | `{row.get('busybox', '')}` | `{verdict}` |"
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "A PASS row means that the target architecture emulator can run an inert BusyBox echo inside the extracted target rootfs. It is a prerequisite for sink-intercept canary validation, not evidence that a firmware service or command sink has been reached.",
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
    preflight_rows = load_json(root / args.preflight_json)
    selected = [row for row in preflight_rows if row.get("ready_for_isolated_run")]
    remote = Remote(args.host, args.user, args.password)
    try:
        rows = [run_smoke(remote, row) for row in selected]
    finally:
        remote.close()

    out_dir = root / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "target_rootfs_smoke.json", rows)
    write_csv(out_dir / "target_rootfs_smoke.csv", rows)
    (out_dir / "target_rootfs_smoke.md").write_text(markdown(rows), encoding="utf-8")
    summary = {
        "tasks": len(rows),
        "pass": sum(1 for row in rows if row.get("pass")),
        "fail": sum(1 for row in rows if not row.get("pass")),
        "boundary": "target-rootfs ABI smoke only; no firmware service execution; no command sink execution",
        "out_dir": str(out_dir),
    }
    write_json(out_dir / "target_rootfs_smoke_summary.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
