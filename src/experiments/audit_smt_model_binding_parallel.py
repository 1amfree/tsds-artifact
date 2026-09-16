#!/usr/bin/env python3
"""Run the SMT model-binding audit with bounded parallelism.

This wrapper preserves the single-manifest audit logic from
``audit_smt_model_binding.py`` while parallelizing independent bundles.  It
keeps result ordering deterministic and retains the same finite claim
boundary; parallel execution is a throughput option, not a semantic change.
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.audit_smt_model_binding import (
    SCHEMA,
    _manifest_paths,
    _solver_argv,
    audit_manifest,
    select_manifests,
    write_outputs,
)


def collect_campaign(
    campaign_dir: Path,
    *,
    solver: str | Sequence[str],
    timeout: int,
    limit: int | None,
    workers: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    paths = _manifest_paths(campaign_dir)
    if not paths:
        raise ValueError(f"no SMT manifests found under {campaign_dir}")
    selected = select_manifests(paths, campaign_dir, limit)
    ordered_rows: list[list[dict[str, Any]] | None] = [None] * len(selected)
    manifest_errors: list[dict[str, str]] = []

    def run_one(path: Path) -> list[dict[str, Any]]:
        return audit_manifest(
            path,
            campaign_dir=campaign_dir,
            solver=solver,
            timeout=timeout,
            root=campaign_dir,
        )

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {
            executor.submit(run_one, path): index
            for index, path in enumerate(selected)
        }
        for future in as_completed(futures):
            index = futures[future]
            path = selected[index]
            try:
                ordered_rows[index] = future.result()
            except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
                manifest_errors.append(
                    {
                        "manifest": str(path),
                        "error": f"{type(exc).__name__}:{exc}",
                    }
                )

    rows: list[dict[str, Any]] = []
    for result in ordered_rows:
        if result:
            rows.extend(result)

    from collections import Counter

    status_counts = Counter(str(row.get("observed") or "UNKNOWN") for row in rows)
    declared_counts = Counter(str(row.get("declared") or "UNKNOWN") for row in rows)
    model_rows = [row for row in rows if row.get("model", {}).get("requested")]
    model_checks = Counter(
        str(row.get("model_check", {}).get("comparison")) for row in model_rows
    )
    issues = [
        {
            "manifest": row.get("manifest"),
            "kind": row.get("kind"),
            "issues": row.get("issues"),
        }
        for row in rows
        if row.get("issues")
    ]
    issues.extend(
        {
            "manifest": item["manifest"],
            "kind": "manifest",
            "issues": [item["error"]],
        }
        for item in manifest_errors
    )
    summary = {
        "schema": SCHEMA,
        "campaign_dir": str(campaign_dir),
        "solver": _solver_argv(solver),
        "workers": max(1, workers),
        "available_manifest_count": len(paths),
        "selected_manifest_count": len(selected),
        "query_count": len(rows),
        "selection_policy": "deterministic target/outcome-stratified sample; limit<=0 means all",
        "status_counts": dict(sorted(status_counts.items())),
        "declared_counts": dict(sorted(declared_counts.items())),
        "model_requested_queries": len(model_rows),
        "model_check_comparisons": dict(sorted(model_checks.items())),
        "valid_query_rows": sum(bool(row.get("valid")) for row in rows),
        "invalid_query_rows": sum(not bool(row.get("valid")) for row in rows),
        "manifest_errors": manifest_errors,
        "issues": issues,
        "claim_boundary": (
            "Finite audit of the selected current exported SMT bundles. It checks query-file "
            "hashes, external Z3 status replay, and primitive SAT-model binding to the same "
            "query. It does not prove solver soundness, historical exhaustive state coverage, "
            "source realizability, firmware-wide precision/recall, or device exploitability."
        ),
        "valid": not issues and bool(rows),
    }
    return summary, rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--solver", default="z3")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument(
        "--limit",
        type=int,
        default=512,
        help="number of manifests to sample; <=0 audits all available manifests",
    )
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    try:
        summary, rows = collect_campaign(
            args.campaign_dir,
            solver=args.solver,
            timeout=max(1, args.timeout),
            limit=args.limit,
            workers=max(1, args.workers),
        )
        write_outputs(args.out_dir.resolve(), summary, rows)
    except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"SMT_MODEL_BINDING_PARALLEL_AUDIT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
