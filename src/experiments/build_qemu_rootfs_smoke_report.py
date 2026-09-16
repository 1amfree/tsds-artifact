#!/usr/bin/env python3
"""Build a safe QEMU/rootfs smoke report for TSDS dynamic validation.

The smoke test only executes an inert BusyBox echo inside an already extracted
rootfs.  It does not start firmware services, trigger handlers, or invoke
command sinks.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
from pathlib import Path
from typing import Any, Dict, List


DEFAULT_OUT = Path("experiment_reports/qemu_rootfs_smoke_v9_20260626")
DEFAULT_REMOTE_ROOTFS = (
    "/home/ubuntu/work/sanitizer/"
    "_RT-BE57_3.0.0.6_102_58491-g1262a8f_598-g65a76_Q7PB.trx.extracted/squashfs-root"
)


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


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def smoke(remote: Remote, rootfs: str) -> Dict[str, Any]:
    command = f"""
set -u
root={quote(rootfs)}
busybox="$root/bin/busybox"
printf 'qemu_arm='
command -v qemu-arm || true
printf 'qemu_mipsel='
command -v qemu-mipsel || true
printf 'busybox_file='
file "$busybox" 2>&1 || true
printf 'rootfs_interp='
find "$root" -maxdepth 4 \\( -name 'ld-uClibc.so.0' -o -name 'ld-musl-*.so*' -o -name 'ld-linux*.so*' \\) -type f 2>/dev/null | head -5 | tr '\\n' ';'
printf '\\nrootfs_libc='
find "$root" -maxdepth 4 \\( -name 'libc.so*' -o -name 'libuClibc*.so*' \\) -type f 2>/dev/null | head -5 | tr '\\n' ';'
printf '\\nsmoke='
timeout 20s qemu-arm -L "$root" "$busybox" echo TSDS_QEMU_SMOKE_OK 2>&1
printf 'smoke_rc=%s\\n' "$?"
"""
    result = remote.run(command, timeout=60)
    parsed: Dict[str, Any] = {"raw": result}
    for line in result["stdout"].splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            parsed[key] = value
    parsed["pass"] = result["returncode"] == 0 and "TSDS_QEMU_SMOKE_OK" in result["stdout"] and "smoke_rc=0" in result["stdout"]
    parsed["boundary"] = "QEMU/rootfs smoke only; no firmware service execution; no command sink execution"
    return parsed


def markdown(result: Dict[str, Any], rootfs: str) -> str:
    lines: List[str] = [
        "# TSDS QEMU/Rootfs Smoke Report",
        "",
        "This smoke test checks whether the VM can execute an inert BusyBox command inside an extracted ARM rootfs. It does not run firmware services or command sinks.",
        "",
        f"- Rootfs: `{rootfs}`",
        f"- Verdict: `{'PASS' if result.get('pass') else 'FAIL'}`",
        f"- Boundary: `{result.get('boundary')}`",
        "",
        "## Observations",
        "",
        f"- qemu-arm: `{result.get('qemu_arm', '').strip() or 'missing'}`",
        f"- qemu-mipsel: `{result.get('qemu_mipsel', '').strip() or 'missing'}`",
        f"- BusyBox file: `{result.get('busybox_file', '').strip()}`",
        f"- Interpreter: `{result.get('rootfs_interp', '').strip()}`",
        f"- Libc: `{result.get('rootfs_libc', '').strip()}`",
        f"- Smoke output: `{result.get('smoke', '').strip()}`",
        "",
        "## Interpretation",
        "",
        "A PASS proves that qemu-user and at least one extracted ARM rootfs can run an inert command in the VM. It does not make the first-wave Tenda/DIR-878 canary tasks ready, because those tasks still require their own target rootfs/uClibc resources.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--host", default=os.environ.get("TSDS_SSH_HOST", "192.168.206.137"))
    parser.add_argument("--user", default=os.environ.get("TSDS_SSH_USER", "ubuntu"))
    parser.add_argument("--password", default=os.environ.get("TSDS_SSH_PASSWORD", "ubuntu"))
    parser.add_argument("--remote-rootfs", default=os.environ.get("TSDS_SMOKE_ROOTFS", DEFAULT_REMOTE_ROOTFS))
    args = parser.parse_args()

    remote = Remote(args.host, args.user, args.password)
    try:
        result = smoke(remote, args.remote_rootfs)
    finally:
        remote.close()

    out_dir = Path(args.root).resolve() / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "qemu_rootfs_smoke.json", result)
    (out_dir / "qemu_rootfs_smoke.md").write_text(markdown(result, args.remote_rootfs), encoding="utf-8")
    summary = {
        "pass": bool(result.get("pass")),
        "rootfs": args.remote_rootfs,
        "boundary": result.get("boundary"),
        "out_dir": str(out_dir),
    }
    write_json(out_dir / "qemu_rootfs_smoke_summary.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
