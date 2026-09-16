#!/usr/bin/env python3
"""Launch or fetch the full TSDS firmware campaign on the Ubuntu VM.

Run from the Windows workspace root.  The script uploads the current evaluator
and campaign runner, starts the campaign in the Ubuntu workspace, and can fetch
the completed result directory back into the local ``experiment_reports`` tree.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import socket
import sys
import time
from pathlib import Path
from typing import Iterable, List

import paramiko


DEFAULT_HOSTS = [
    "192.168.206.137",
    "192.168.206.136",
    "192.168.206.138",
    "192.168.206.128",
    "192.168.206.129",
    "192.168.206.130",
    "192.168.206.131",
    "192.168.206.132",
    "192.168.206.133",
    "192.168.206.134",
    "192.168.206.135",
]


def can_connect(host: str, port: int, timeout: float = 0.4) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def iter_hosts(args: argparse.Namespace) -> Iterable[str]:
    if args.host:
        yield args.host
        return
    seen = set()
    for host in DEFAULT_HOSTS:
        if host not in seen:
            seen.add(host)
            yield host
    if args.scan_subnet:
        prefix = args.scan_subnet.rstrip(".")
        for i in range(2, 255):
            host = f"{prefix}.{i}"
            if host not in seen:
                yield host


def connect(args: argparse.Namespace) -> tuple[str, paramiko.SSHClient]:
    hosts = list(iter_hosts(args))
    reachable: List[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(96, max(1, len(hosts)))) as executor:
        future_to_host = {executor.submit(can_connect, host, args.port): host for host in hosts}
        for future in concurrent.futures.as_completed(future_to_host):
            if future.result():
                reachable.append(future_to_host[future])
    for host in reachable:
        if not can_connect(host, args.port):
            continue
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(host, args.port, args.user, args.password, timeout=8, banner_timeout=8, auth_timeout=8)
            return host, ssh
        except Exception:
            ssh.close()
    raise RuntimeError("No reachable Ubuntu SSH host was found.")


def sftp_mkdirs(sftp: paramiko.SFTPClient, path: str) -> None:
    parts = [part for part in path.split("/") if part]
    current = ""
    for part in parts:
        current += "/" + part
        try:
            sftp.stat(current)
        except IOError:
            sftp.mkdir(current)


def upload_file(sftp: paramiko.SFTPClient, local: Path, remote: str) -> None:
    sftp_mkdirs(sftp, str(Path(remote).parent).replace("\\", "/"))
    sftp.put(str(local), remote)


def download_tree(sftp: paramiko.SFTPClient, remote_dir: str, local_dir: Path) -> None:
    local_dir.mkdir(parents=True, exist_ok=True)
    for entry in sftp.listdir_attr(remote_dir):
        remote_path = f"{remote_dir.rstrip('/')}/{entry.filename}"
        local_path = local_dir / entry.filename
        if entry.st_mode & 0o040000:
            download_tree(sftp, remote_path, local_path)
        else:
            sftp.get(remote_path, str(local_path))


def run_command(ssh: paramiko.SSHClient, command: str) -> tuple[int, str, str]:
    stdin, stdout, stderr = ssh.exec_command(command)
    del stdin
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return int(stdout.channel.recv_exit_status()), out, err


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=None)
    parser.add_argument("--scan-subnet", default="192.168.206")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", default="ubuntu")
    parser.add_argument("--password", default="ubuntu")
    parser.add_argument("--remote-root", default="/home/ubuntu/work/sanitizer")
    parser.add_argument("--campaign-name", default="full_firmware_campaign_current_tsds_20260627")
    parser.add_argument("--wait", action="store_true", help="Run in foreground and wait for completion.")
    parser.add_argument("--download-only", action="store_true")
    parser.add_argument("--download", action="store_true", help="Fetch result directory after launching or checking.")
    args = parser.parse_args()

    workspace = Path.cwd()
    # Keep the remote destination aligned with the canonical implementation.
    # The repository-root entry point is only a compatibility wrapper; copying
    # it over the canonical path would make the remote source lock ambiguous.
    local_evaluator = workspace / "Taint_demo" / "sanitizer_demo" / "advanced_sanitizer_evaluator.py"
    local_runner = workspace / "experiments" / "run_full_firmware_campaign.py"
    local_lock_tool = workspace / "experiments" / "build_source_dependency_manifest.py"
    local_tsds = sorted((workspace / "tsds").glob("*.py"))
    if (
        not local_evaluator.exists()
        or not local_runner.exists()
        or not local_lock_tool.exists()
        or not local_tsds
    ):
        raise SystemExit("Run this script from the sanitizer workspace root.")

    host, ssh = connect(args)
    print(f"Connected to {args.user}@{host}")
    sftp = ssh.open_sftp()
    try:
        remote_root = args.remote_root.rstrip("/")
        remote_campaign = f"{remote_root}/experiment_reports/{args.campaign_name}"
        if not args.download_only:
            upload_file(
                sftp,
                local_evaluator,
                f"{remote_root}/Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py",
            )
            upload_file(
                sftp,
                local_runner,
                f"{remote_root}/experiments/run_full_firmware_campaign.py",
            )
            upload_file(
                sftp,
                local_lock_tool,
                f"{remote_root}/experiments/build_source_dependency_manifest.py",
            )
            for local_module in local_tsds:
                upload_file(
                    sftp,
                    local_module,
                    f"{remote_root}/tsds/{local_module.name}",
                )
            launch = (
                f"cd {remote_root} && "
                f"/home/ubuntu/work/sanitizer/operation-mango-public/.venv/bin/python "
                f"experiments/run_full_firmware_campaign.py "
                f"--out-dir experiment_reports/{args.campaign_name}"
            )
            if args.wait:
                code, out, err = run_command(ssh, launch)
                print(out)
                if err:
                    print(err, file=sys.stderr)
                if code != 0:
                    return code
            else:
                bg = (
                    # Keep launcher diagnostics outside the fresh campaign
                    # directory; the runner rejects any pre-existing files.
                    f"mkdir -p {remote_campaign} && "
                    f"nohup bash -lc {launch!r} "
                    f"> {remote_root}/experiment_reports/{args.campaign_name}.launcher.stdout.log "
                    f"2> {remote_root}/experiment_reports/{args.campaign_name}.launcher.stderr.log < /dev/null & echo $!"
                )
                code, out, err = run_command(ssh, bg)
                if err:
                    print(err, file=sys.stderr)
                if code != 0:
                    return code
                print(f"Started remote campaign pid={out.strip()} dir={remote_campaign}")
                print(f"Check progress: tail -f {remote_campaign}/campaign.log")

        if args.download or args.download_only:
            local_dir = workspace / "experiment_reports" / args.campaign_name
            for _ in range(3):
                try:
                    sftp.stat(remote_campaign)
                    break
                except IOError:
                    time.sleep(1)
            download_tree(sftp, remote_campaign, local_dir)
            print(f"Downloaded to {local_dir}")
    finally:
        sftp.close()
        ssh.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
