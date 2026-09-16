#!/usr/bin/env python3
"""Wait for a local v20 fetch to finish, then run the independent final audit."""

from __future__ import annotations

import argparse
import json
import sys
import tarfile
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.audit_v20_downloaded_release import audit_release, write_outputs


def wait_for_fetch(
    root: Path,
    timeout_seconds: int,
    poll_seconds: int,
    fetch_status_path: Path | None = None,
) -> Path:
    manifest = root / "fetch_manifest.json"
    deadline = time.monotonic() + max(0, int(timeout_seconds))
    while not manifest.is_file():
        if fetch_status_path is not None and fetch_status_path.is_file():
            status = json.loads(fetch_status_path.read_text(encoding="utf-8"))
            if status.get("state") == "failed":
                detail = str(status.get("detail") or "unknown fetch failure")
                raise RuntimeError(f"release fetch failed before audit: {detail}")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"fetch manifest did not appear before timeout: {manifest}")
        time.sleep(max(1, int(poll_seconds)))
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-root", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--post-release-suffix", default="v2")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=266400)
    parser.add_argument("--poll-seconds", type=int, default=60)
    parser.add_argument(
        "--fetch-status-path",
        type=Path,
        help="Optional fetch heartbeat JSON; a terminal fetch failure stops this waiter.",
    )
    args = parser.parse_args()
    try:
        root = args.release_root.resolve()
        wait_for_fetch(
            root,
            args.timeout_seconds,
            args.poll_seconds,
            args.fetch_status_path.resolve() if args.fetch_status_path else None,
        )
        document = audit_release(root, args.tag, args.post_release_suffix)
        write_outputs(args.out_dir.resolve(), document)
    except (
        OSError,
        RuntimeError,
        TimeoutError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        tarfile.TarError,
    ) as exc:
        print(f"V20_FINAL_AUDIT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0 if document["valid"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
