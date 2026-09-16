#!/usr/bin/env python3
"""Wait for and retrieve a completed TSDS v20 release without remote mutation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.build_v20_manuscript_binding import build_binding, write_outputs


RELEASE_PREFIXES = (
    "tsds_v20_full_{tag}",
    "tsds_v20_full_audits_{tag}",
    "tsds_v20_matrix_{tag}",
    "tsds_v20_matrix_analysis_{tag}",
    "tsds_v20_matrix_transitions_{tag}",
    "tsds_v20_confirmatory_{tag}",
    "tsds_v20_confirmatory_analysis_{tag}",
    "tsds_v20_confirmatory_transitions_{tag}",
    "tsds_v20_resource_calibration_{tag}",
    "tsds_v20_accepted_repeat_{tag}",
    "tsds_v20_runtime_repeatability_{tag}",
    "tsds_v20_runtime_validation_expansion_{tag}",
    "tsds_v20_shell_syntax_{tag}",
    "tsds_v20_boundary_suite_{tag}",
    "tsds_v20_evidence_extension_{tag}",
    "tsds_v20_evidence_extension_verification_{tag}",
    "tsds_v20_blinded_role_packages_{tag}",
    "tsds_v20_post_release_{tag}_{post_release_suffix}",
)
FETCH_STATUS_SCHEMA = "tsds-v20-release-fetch-status-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def release_names(tag: str, post_release_suffix: str) -> tuple[str, ...]:
    if not tag or any(char not in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-" for char in tag):
        raise ValueError("tag contains unsafe characters")
    if not post_release_suffix or any(
        char not in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-"
        for char in post_release_suffix
    ):
        raise ValueError("post-release suffix contains unsafe characters")
    return tuple(
        value.format(tag=tag, post_release_suffix=post_release_suffix)
        for value in RELEASE_PREFIXES
    )


def relative_remote_path(root: str, path: str) -> PurePosixPath:
    root_path = PurePosixPath(root)
    candidate = PurePosixPath(path)
    relative = candidate.relative_to(root_path)
    if not relative.parts or ".." in relative.parts:
        raise ValueError(f"unsafe remote path: {path}")
    return relative


def required_remote_paths(reports: str, tag: str, suffix: str) -> dict[str, str]:
    reports = reports.rstrip("/")
    names = release_names(tag, suffix)
    values = {name: posixpath.join(reports, name) for name in names}
    values["queue_marker"] = posixpath.join(
        reports, f"tsds_v20_experiment_queue_{tag}.complete"
    )
    values["post_release_root"] = values[f"tsds_v20_post_release_{tag}_{suffix}"]
    values["post_release_summary"] = posixpath.join(
        values["post_release_root"], "post_release_summary.json"
    )
    return values


def remote_exists(sftp: Any, path: str) -> bool:
    try:
        sftp.stat(path)
        return True
    except OSError:
        return False


def remote_ready(sftp: Any, paths: dict[str, str]) -> bool:
    return remote_exists(sftp, paths["queue_marker"]) and remote_exists(
        sftp, paths["post_release_summary"]
    )


def remote_tail(sftp: Any, path: str, maximum_bytes: int = 65536) -> str:
    """Read a bounded remote log tail for terminal-state detection."""

    metadata = sftp.stat(path)
    start = max(0, int(metadata.st_size) - maximum_bytes)
    with sftp.open(path, "rb") as stream:
        stream.seek(start)
        return stream.read().decode("utf-8", errors="replace")


def remote_terminal_failure(sftp: Any, paths: dict[str, str]) -> str | None:
    """Return a bounded failure reason emitted by the post-release worker."""

    error_log = posixpath.join(paths["post_release_root"], "orchestrator.stderr.log")
    if not remote_exists(sftp, error_log):
        return None
    text = remote_tail(sftp, error_log)
    failure_lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
        and (
            "POST_RELEASE_ABORT" in line
            or "post-release gates did not all pass" in line
            or "POST_RELEASE_ERROR" in line
        )
    ]
    return failure_lines[-1] if failure_lines else None


def write_fetch_status(
    path: Path | None,
    *,
    tag: str,
    post_release_suffix: str,
    state: str,
    phase: str,
    poll_count: int,
    queue_marker_observed: bool,
    post_release_summary_observed: bool,
    detail: str = "",
) -> None:
    """Atomically publish a local progress heartbeat outside the release root."""

    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schema": FETCH_STATUS_SCHEMA,
        "tag": tag,
        "post_release_suffix": post_release_suffix,
        "state": state,
        "phase": phase,
        "poll_count": poll_count,
        "queue_marker_observed": queue_marker_observed,
        "post_release_summary_observed": post_release_summary_observed,
        "detail": detail,
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


def walk_remote(sftp: Any, root: str) -> Iterable[tuple[str, Any]]:
    try:
        entries = sorted(sftp.listdir_attr(root), key=lambda entry: entry.filename)
    except OSError as exc:
        raise ValueError(f"cannot list remote directory: {root}") from exc
    for entry in entries:
        if entry.filename in {".", ".."} or "/" in entry.filename or "\\" in entry.filename:
            raise ValueError(f"unsafe remote member name: {entry.filename!r}")
        path = posixpath.join(root, entry.filename)
        mode = int(entry.st_mode or 0)
        if stat.S_ISLNK(mode):
            raise ValueError(f"refusing remote symbolic link: {path}")
        if stat.S_ISDIR(mode):
            yield from walk_remote(sftp, path)
        elif stat.S_ISREG(mode):
            yield path, entry
        else:
            raise ValueError(f"refusing non-regular remote member: {path}")


def download_tree(sftp: Any, remote_root: str, local_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for remote_path, entry in walk_remote(sftp, remote_root):
        relative = relative_remote_path(remote_root, remote_path)
        local_path = local_root.joinpath(*relative.parts)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        sftp.get(remote_path, str(local_path))
        size = local_path.stat().st_size
        if size != int(entry.st_size):
            raise ValueError(f"download size mismatch: {remote_path}")
        rows.append(
            {
                "path": relative.as_posix(),
                "size": size,
                "sha256": sha256_file(local_path),
            }
        )
    return rows


def wait_for_release(
    sftp: Any,
    paths: dict[str, str],
    *,
    timeout_seconds: int,
    poll_seconds: int,
    status_path: Path | None = None,
    tag: str = "",
    post_release_suffix: str = "",
) -> None:
    deadline = time.monotonic() + max(0, int(timeout_seconds))
    polls = 0
    while True:
        polls += 1
        marker_observed = remote_exists(sftp, paths["queue_marker"])
        summary_observed = remote_exists(sftp, paths["post_release_summary"])
        terminal_failure = remote_terminal_failure(sftp, paths)
        if marker_observed and summary_observed:
            write_fetch_status(
                status_path,
                tag=tag,
                post_release_suffix=post_release_suffix,
                state="ready",
                phase="remote_release_ready",
                poll_count=polls,
                queue_marker_observed=marker_observed,
                post_release_summary_observed=summary_observed,
            )
            return
        if terminal_failure:
            write_fetch_status(
                status_path,
                tag=tag,
                post_release_suffix=post_release_suffix,
                state="failed",
                phase="remote_post_release_failure",
                poll_count=polls,
                queue_marker_observed=marker_observed,
                post_release_summary_observed=summary_observed,
                detail=terminal_failure,
            )
            raise RuntimeError(f"remote post-release failed: {terminal_failure}")
        write_fetch_status(
            status_path,
            tag=tag,
            post_release_suffix=post_release_suffix,
            state="waiting",
            phase="waiting_for_remote_release",
            poll_count=polls,
            queue_marker_observed=marker_observed,
            post_release_summary_observed=summary_observed,
        )
        if time.monotonic() >= deadline:
            write_fetch_status(
                status_path,
                tag=tag,
                post_release_suffix=post_release_suffix,
                state="failed",
                phase="timeout",
                poll_count=polls,
                queue_marker_observed=marker_observed,
                post_release_summary_observed=summary_observed,
                detail="v20 queue or post-release summary did not complete before timeout",
            )
            raise TimeoutError("v20 queue or post-release summary did not complete before timeout")
        time.sleep(max(1, int(poll_seconds)))


def build_downloaded_manuscript_binding(
    out_dir: Path, tag: str, post_release_suffix: str
) -> dict[str, Any]:
    post_root = out_dir / f"tsds_v20_post_release_{tag}_{post_release_suffix}"
    candidates = sorted(post_root.rglob("claim_evidence_matrix.json"))
    if len(candidates) != 1:
        raise ValueError(
            "expected exactly one downloaded claim_evidence_matrix.json, "
            f"found {len(candidates)}"
        )
    accepted_run = out_dir / f"tsds_v20_accepted_repeat_{tag}"
    binding = build_binding(candidates[0], accepted_run)
    binding_dir = out_dir / "manuscript_binding"
    write_outputs(binding_dir, binding)
    return {
        "path": str(binding_dir),
        "binding": {
            "path": "manuscript_binding/manuscript_binding.json",
            "size": (binding_dir / "manuscript_binding.json").stat().st_size,
            "sha256": sha256_file(binding_dir / "manuscript_binding.json"),
        },
        "counts_tex": {
            "path": "manuscript_binding/manuscript_counts.tex",
            "size": (binding_dir / "manuscript_counts.tex").stat().st_size,
            "sha256": sha256_file(binding_dir / "manuscript_counts.tex"),
        },
    }


def retrieve_release(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    reports: str,
    tag: str,
    post_release_suffix: str,
    out_dir: Path,
    timeout_seconds: int,
    poll_seconds: int,
    status_path: Path | None = None,
) -> dict[str, Any]:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        import paramiko
    except ImportError as exc:
        raise ValueError("paramiko is required to retrieve a remote release") from exc

    paths = required_remote_paths(reports, tag, post_release_suffix)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=int(port),
            username=user,
            password=password,
            timeout=20,
            banner_timeout=20,
            auth_timeout=20,
        )
        sftp = client.open_sftp()
        try:
            wait_for_release(
                sftp,
                paths,
                timeout_seconds=timeout_seconds,
                poll_seconds=poll_seconds,
                status_path=status_path,
                tag=tag,
                post_release_suffix=post_release_suffix,
            )
            write_fetch_status(
                status_path,
                tag=tag,
                post_release_suffix=post_release_suffix,
                state="running",
                phase="downloading_release",
                poll_count=0,
                queue_marker_observed=True,
                post_release_summary_observed=True,
            )
            downloads: dict[str, list[dict[str, Any]]] = {}
            for name in release_names(tag, post_release_suffix):
                remote_root = paths[name]
                if not remote_exists(sftp, remote_root):
                    raise ValueError(f"missing required release directory: {remote_root}")
                downloads[name] = download_tree(sftp, remote_root, out_dir / name)
            marker = out_dir / Path(paths["queue_marker"]).name
            sftp.get(paths["queue_marker"], str(marker))
            marker_row = {
                "path": marker.name,
                "size": marker.stat().st_size,
                "sha256": sha256_file(marker),
            }
        finally:
            sftp.close()
    finally:
        client.close()

    manuscript_binding = build_downloaded_manuscript_binding(
        out_dir, tag, post_release_suffix
    )
    summary = {
        "schema": "tsds-v20-release-fetch-v1",
        "tag": tag,
        "remote_reports": reports,
        "post_release_suffix": post_release_suffix,
        "queue_marker": marker_row,
        "downloads": downloads,
        "files": sum(len(rows) for rows in downloads.values()),
        "manuscript_binding": manuscript_binding,
    }
    (out_dir / "fetch_manifest.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_fetch_status(
        status_path,
        tag=tag,
        post_release_suffix=post_release_suffix,
        state="complete",
        phase="fetch_complete",
        poll_count=0,
        queue_marker_observed=True,
        post_release_summary_observed=True,
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--host", default=os.environ.get("TSDS_SSH_HOST", "192.168.206.137"))
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", default=os.environ.get("TSDS_SSH_USER", "ubuntu"))
    parser.add_argument("--password-env", default="TSDS_VM_PASSWORD")
    parser.add_argument(
        "--reports",
        default="/home/ubuntu/work/sanitizer/experiment_reports",
    )
    parser.add_argument("--post-release-suffix", default="v2")
    parser.add_argument("--timeout-seconds", type=int, default=259200)
    parser.add_argument("--poll-seconds", type=int, default=60)
    parser.add_argument(
        "--status-path",
        type=Path,
        help="Local heartbeat JSON path; defaults beside --out-dir.",
    )
    args = parser.parse_args()
    password = os.environ.get(args.password_env)
    if not password:
        parser.error(f"missing password environment variable: {args.password_env}")
    status_path = (
        args.status_path.resolve()
        if args.status_path is not None
        else args.out_dir.resolve().with_name(args.out_dir.name + ".status.json")
    )
    try:
        summary = retrieve_release(
            host=args.host,
            port=args.port,
            user=args.user,
            password=password,
            reports=args.reports,
            tag=args.tag,
            post_release_suffix=args.post_release_suffix,
            out_dir=args.out_dir.resolve(),
            timeout_seconds=args.timeout_seconds,
            poll_seconds=args.poll_seconds,
            status_path=status_path,
        )
    except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as exc:
        write_fetch_status(
            status_path,
            tag=args.tag,
            post_release_suffix=args.post_release_suffix,
            state="failed",
            phase="fetch_error",
            poll_count=0,
            queue_marker_observed=False,
            post_release_summary_observed=False,
            detail=str(exc),
        )
        print(f"V20_RELEASE_FETCH_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
