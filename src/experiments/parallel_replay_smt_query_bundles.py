#!/usr/bin/env python3
"""Replay exported SMT bundles in independent worker processes.

This is an evidence-production companion to ``replay_smt_query_bundles.py``.
It preserves the latter's manifest validation and solver invocation, but
partitions manifests across worker processes so large target bundles do not
have to be replayed serially.  A partial run is never published as the final
receipt file.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import shlex
from collections import Counter
from pathlib import Path
from typing import Any

try:  # Works both as ``python experiments/...py`` and as a package import.
    from .replay_smt_query_bundles import SolverCommand, replay_manifest
except ImportError:  # pragma: no cover - exercised by the script entrypoint
    from replay_smt_query_bundles import SolverCommand, replay_manifest


def _replay_one(
    item: tuple[str, list[SolverCommand], int, str],
) -> dict[str, Any]:
    manifest, solvers, timeout, root = item
    return replay_manifest(
        Path(manifest),
        solvers,
        timeout=timeout,
        root=Path(root),
    )


def _parse_solvers(args: argparse.Namespace) -> list[SolverCommand]:
    if args.solver and args.solver_argv:
        raise SystemExit("--solver and --solver-argv are mutually exclusive")
    if args.solver_argv:
        solvers: list[SolverCommand] = []
        for command in args.solver_argv:
            try:
                if os.name == "nt":
                    # POSIX shlex treats the backslash in a Windows path as
                    # an escape.  Keep quoted Windows paths intact while
                    # retaining the shell-free argv contract.
                    argv = [
                        part[1:-1]
                        if len(part) >= 2 and part[0] == part[-1] == '"'
                        else part
                        for part in shlex.split(command, posix=False)
                    ]
                else:
                    argv = shlex.split(command, posix=True)
            except ValueError as exc:
                raise SystemExit(f"invalid --solver-argv: {exc}") from exc
            if not argv:
                raise SystemExit("--solver-argv must not be empty")
            solvers.append(argv)
        return solvers
    return list(args.solver or ["z3"])


def _write_summary(
    path: Path,
    *,
    bundle_dir: Path,
    manifest_count: int,
    invalid_manifest_count: int,
    replay_count: int,
    comparison_counts: Counter[str],
    model_comparison_counts: Counter[str],
    status_counts: Counter[str],
    solvers: list[SolverCommand],
) -> None:
    summary = {
        "schema": "tsds-smt-query-replay-v1",
        "bundle_dir": str(bundle_dir),
        "manifest_count": manifest_count,
        "invalid_manifest_count": invalid_manifest_count,
        "replay_count": replay_count,
        "comparison_counts": {
            value: comparison_counts[value]
            for value in ("MATCH", "MISMATCH", "UNKNOWN", "NOT_APPLICABLE")
        },
        "model_comparison_counts": {
            value: model_comparison_counts[value]
            for value in ("MATCH", "MISMATCH", "UNKNOWN", "NOT_APPLICABLE")
        },
        "status_counts": {
            value: status_counts[value]
            for value in ("OK", "UNKNOWN", "UNAVAILABLE")
        },
        "solvers": solvers,
        "claim_boundary": (
            "Replay receipts compare externally executed SMT results with producer metadata. "
            "Unavailable or unknown runs remain abstentions; a matching query result is not "
            "a device-level exploitability result."
        ),
    }
    path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--solver", action="append", default=None)
    parser.add_argument(
        "--solver-argv",
        action="append",
        default=None,
        help="Shell-free solver command line; repeat once per solver.",
    )
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument(
        "--start-method",
        choices=("fork", "spawn", "forkserver"),
        default=None,
    )
    parser.add_argument("--fail-on-mismatch", action="store_true")
    parser.add_argument("--fail-on-model-mismatch", action="store_true")
    parser.add_argument("--fail-if-unavailable", action="store_true")
    args = parser.parse_args()

    bundle_dir = args.bundle_dir.resolve()
    out_dir = args.out_dir.resolve()
    if not bundle_dir.is_dir():
        raise SystemExit(f"bundle directory not found: {bundle_dir}")
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to overwrite non-empty output: {out_dir}")
        return 2
    manifests = sorted(bundle_dir.rglob("*.manifest.json"))
    if not manifests:
        print(f"no query manifests found under {bundle_dir}")
        return 2
    if args.workers < 1:
        raise SystemExit("--workers must be positive")

    solvers = _parse_solvers(args)
    workers = min(args.workers, len(manifests))
    items = [
        (str(path), solvers, max(1, args.timeout), str(bundle_dir))
        for path in manifests
    ]
    out_dir.mkdir(parents=True, exist_ok=True)
    partial_receipts = out_dir / "replay_receipts.jsonl.partial"
    final_receipts = out_dir / "replay_receipts.jsonl"
    summary_path = out_dir / "summary.json"

    comparison_counts: Counter[str] = Counter()
    model_comparison_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    invalid_manifest_count = 0
    replay_count = 0

    context = mp.get_context(args.start_method)
    with partial_receipts.open("w", encoding="utf-8", newline="\n") as stream:
        with context.Pool(processes=workers) as pool:
            for receipt in pool.imap(_replay_one, items, chunksize=1):
                if receipt.get("status") != "OK":
                    invalid_manifest_count += 1
                stream.write(json.dumps(receipt, ensure_ascii=False, sort_keys=True) + "\n")
                for row in receipt.get("replays", []):
                    replay_count += 1
                    comparison_counts[str(row.get("comparison"))] += 1
                    model = row.get("model_check") or {}
                    model_comparison_counts[str(model.get("comparison"))] += 1
                    status_counts[str(row.get("status"))] += 1

    partial_receipts.replace(final_receipts)
    _write_summary(
        summary_path,
        bundle_dir=bundle_dir,
        manifest_count=len(manifests),
        invalid_manifest_count=invalid_manifest_count,
        replay_count=replay_count,
        comparison_counts=comparison_counts,
        model_comparison_counts=model_comparison_counts,
        status_counts=status_counts,
        solvers=solvers,
    )
    result = json.loads(summary_path.read_text(encoding="utf-8"))
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    if args.fail_on_mismatch and result["comparison_counts"]["MISMATCH"]:
        return 1
    if args.fail_on_model_mismatch and result["model_comparison_counts"]["MISMATCH"]:
        return 1
    if args.fail_if_unavailable and (
        result["status_counts"]["UNAVAILABLE"]
        or result["comparison_counts"]["UNKNOWN"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
