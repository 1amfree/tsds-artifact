#!/usr/bin/env python3
"""Replay the closed matrix calibration with a fresh Z3 process boundary.

This script is intentionally separate from the TSDS evaluator.  It consumes
the exported SMT-LIB files and the immutable calibration rows, then records
Z3's result, model digest, and any parse/solver error.  Missing or malformed
rows are reported as failures rather than being converted to UNSAT.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-file", type=Path, required=True)
    parser.add_argument("--query-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()

    # Import here so the script can still report a useful dependency error.
    try:
        import z3
    except ImportError as exc:  # pragma: no cover - exercised by environment
        raise SystemExit(f"z3-solver is required: {exc}")

    rows = json.loads(args.case_file.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise SystemExit("case file must contain a JSON array")

    query_paths = sorted(args.query_dir.glob("*.smt2"))
    by_digest = {sha256_file(path): path for path in query_paths}
    receipts: list[dict[str, Any]] = []
    issues: list[str] = []

    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            issues.append(f"row_{index}_not_object")
            continue
        expected = row.get("solver_replay")
        query_digest = row.get("query_sha256")
        if expected not in {"SAT", "UNSAT"} or not query_digest:
            # Boundary cases intentionally have no SMT query.  They are
            # preserved in the source calibration but are not solver rows.
            continue
        query_path = by_digest.get(str(query_digest))
        receipt: dict[str, Any] = {
            "case_id": row.get("case_id"),
            "vector_id": row.get("vector_id"),
            "kind": row.get("kind"),
            "expected": expected,
            "query_sha256": query_digest,
            "query_file": query_path.name if query_path else None,
            "status": "ERROR",
            "observed": None,
            "comparison": "ERROR",
        }
        if query_path is None:
            receipt["error"] = "query_digest_not_found"
            receipts.append(receipt)
            issues.append(f"row_{index}_query_digest_not_found")
            continue
        try:
            assertions = z3.parse_smt2_file(str(query_path))
            solver = z3.Solver()
            solver.add(assertions)
            outcome = solver.check()
            observed = str(outcome).upper()
            receipt["status"] = "OK"
            receipt["observed"] = observed
            receipt["comparison"] = "MATCH" if observed == expected else "MISMATCH"
            if outcome == z3.sat:
                model_text = str(solver.model())
                receipt["model_sha256"] = hashlib.sha256(
                    model_text.encode("utf-8")
                ).hexdigest()
                receipt["model_assignment_count"] = len(solver.model().decls())
            if receipt["comparison"] == "MISMATCH":
                issues.append(f"row_{index}_result_mismatch")
        except Exception as exc:  # keep each query independently auditable
            receipt["error"] = f"{type(exc).__name__}: {exc}"
            issues.append(f"row_{index}_replay_error")
        receipts.append(receipt)

    comparisons = {key: sum(r["comparison"] == key for r in receipts) for key in (
        "MATCH", "MISMATCH", "ERROR"
    )}
    observed = {
        key: sum(r.get("observed") == key for r in receipts)
        for key in ("SAT", "UNSAT", "UNKNOWN")
    }
    summary = {
        "schema": "tsds-smt-matrix-z3-replay-v1",
        "case_file": str(args.case_file),
        "query_dir": str(args.query_dir),
        "case_rows": len(rows),
        "query_files": len(query_paths),
        "applicable_rows": len(receipts),
        "comparison_counts": comparisons,
        "observed_counts": observed,
        "z3_version": z3.get_version_string(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "issues": sorted(set(issues)),
        "valid": not issues and bool(receipts),
        "claim_boundary": (
            "Independent Z3 replay of a closed synthetic SMT-LIB calibration. "
            "This validates the exported query semantics for the declared cases; "
            "it does not validate historical firmware records, source realizability, "
            "candidate-wide accuracy, or device exploitability."
        ),
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    with (args.out_dir / "replay_receipts.jsonl").open(
        "w", encoding="utf-8", newline="\n"
    ) as stream:
        for receipt in receipts:
            stream.write(json.dumps(receipt, sort_keys=True) + "\n")
    write_json(args.out_dir / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
