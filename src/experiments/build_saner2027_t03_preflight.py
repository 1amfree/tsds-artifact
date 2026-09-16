#!/usr/bin/env python3
"""Build a synthetic preflight bundle for isolated SMT replay.

The generated process is a deliberately tiny restricted checker, not an SMT
solver.  It is used only to exercise the external-process boundary, exact
file hashing, and model-mismatch handling on this machine.  A real Z3 or
cvc5 binary must be used before making any solver-replay claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.replay_smt_query_bundles import replay_manifest


SCHEMA = "tsds-saner2027-smt-replay-preflight-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_bundle(
    query_dir: Path,
    query_id: str,
    query: str,
    producer: dict[str, Any],
) -> Path:
    query_path = query_dir / f"{query_id}.full.smt2"
    manifest_path = query_dir / f"{query_id}.manifest.json"
    query_path.write_text(query, encoding="utf-8", newline="\n")
    manifest = {
        "schema": "tsds-solver-query-bundle-v1",
        "query_id": query_id,
        "files": {"full": query_path.name, "projected": None},
        "sha256": {
            "full_smt2": sha256_file(query_path),
            "projected_smt2": None,
        },
        "producer": producer,
        "claim_boundary": (
            "Synthetic preflight only. The bundle tests serialization and an "
            "external replay boundary; it is not firmware evidence."
        ),
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest_path


def write_restricted_checker(path: Path) -> None:
    path.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "payload = Path(sys.argv[1]).read_text(encoding='utf-8')\n"
        "# This recognizes only the fixed fixture relation x=7.\n"
        "if '(get-model)' in payload and '(assert (= x 7))' in payload:\n"
        "    print('sat')\n"
        "    print('(model\\n  (define-fun x () Int 7)\\n)')\n"
        "    raise SystemExit(0)\n"
        "if '(assert (= x 8))' in payload:\n"
        "    print('unsat')\n"
        "elif '(assert (= x 7))' in payload:\n"
        "    print('sat')\n"
        "else:\n"
        "    print('unknown')\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to overwrite non-empty output: {out_dir}", file=sys.stderr)
        return 2
    query_dir = out_dir / "queries"
    query_dir.mkdir(parents=True, exist_ok=True)

    checker = out_dir / "restricted_reference_checker.py"
    write_restricted_checker(checker)
    base = (
        "(set-logic QF_LIA)\n"
        "(declare-const x Int)\n"
        "(assert (= x 7))\n"
        "(check-sat)\n"
    )
    contradiction = (
        "(set-logic QF_LIA)\n"
        "(declare-const x Int)\n"
        "(assert (= x 7))\n"
        "(assert (= x 8))\n"
        "(check-sat)\n"
    )
    model_request = base.replace("(check-sat)\n", "(check-sat)\n(get-model)\n")
    manifests = [
        write_bundle(
            query_dir,
            "known_sat",
            base,
            {
                "decision": "SAT",
                "full_result": "SAT",
                "projected_result": "NOT_RUN",
                "full_validation": "performed",
                "model": {
                    "status": "provided",
                    "scope": "full_model",
                    "assignments": [{"name": "x", "sort": "Int", "value": 7}],
                },
            },
        ),
        write_bundle(
            query_dir,
            "known_unsat",
            contradiction,
            {
                "decision": "UNSAT",
                "full_result": "UNSAT",
                "projected_result": "NOT_RUN",
                "full_validation": "performed",
                "model": {
                    "status": "not_exported",
                    "scope": "query_result_only",
                },
            },
        ),
        write_bundle(
            query_dir,
            "model_violation",
            base,
            {
                "decision": "SAT",
                "full_result": "SAT",
                "projected_result": "NOT_RUN",
                "full_validation": "performed",
                "model": {
                    "status": "provided",
                    "scope": "full_model",
                    "assignments": [{"name": "x", "sort": "Int", "value": 8}],
                },
            },
        ),
        write_bundle(
            query_dir,
            "model_request",
            model_request,
            {
                "decision": "SAT",
                "full_result": "SAT",
                "projected_result": "NOT_RUN",
                "full_validation": "performed",
                "model": {
                    "status": "embedded_get_model_request",
                    "scope": "external_solver_model_output",
                },
            },
        ),
    ]

    receipts = [
        replay_manifest(
            manifest,
            [[sys.executable, str(checker)]],
            timeout=5,
            root=out_dir,
        )
        for manifest in manifests
    ]
    replay_rows = [row for receipt in receipts for row in receipt.get("replays", [])]
    model_mismatch = sum(
        (row.get("model_check") or {}).get("comparison") == "MISMATCH"
        for row in replay_rows
    )
    external_model_counts = {
        value: sum((row.get("external_model") or {}).get("status") == value for row in replay_rows)
        for value in ("CAPTURED", "NOT_RETURNED", "NOT_REQUESTED")
    }
    summary = {
        "schema": SCHEMA,
        "bundle_count": len(manifests),
        "replay_count": len(replay_rows),
        "base_comparison_counts": {
            value: sum(row.get("comparison") == value for row in replay_rows)
            for value in ("MATCH", "MISMATCH", "UNKNOWN", "NOT_APPLICABLE")
        },
        "model_comparison_counts": {
            value: sum(
                (row.get("model_check") or {}).get("comparison") == value
                for row in replay_rows
            )
            for value in ("MATCH", "MISMATCH", "UNKNOWN", "NOT_APPLICABLE")
        },
        "model_violation_detected": model_mismatch == 1,
        "external_model_status_counts": external_model_counts,
        "external_model_capture_detected": external_model_counts["CAPTURED"] == 1,
        "external_process": "restricted_reference_checker.py",
        "real_solver_used": False,
        "claim_boundary": (
            "Synthetic protocol receipt only. The restricted checker is not a "
            "solver and these rows are excluded from firmware replay counts. "
            "Run the exact manifests with an installed Z3 or cvc5 binary for "
            "actual solver evidence."
        ),
    }
    (out_dir / "replay_receipts.jsonl").write_text(
        "".join(json.dumps(receipt, sort_keys=True) + "\n" for receipt in receipts),
        encoding="utf-8",
        newline="\n",
    )
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (out_dir / "README.md").write_text(
        "# T03 SMT replay preflight\n\n"
        "This directory is a synthetic protocol check. The external process "
        "`restricted_reference_checker.py` recognizes only the fixture relation "
        "`x = 7`; it is not Z3, cvc5, or a firmware analysis result. The "
        "`model_violation` receipt demonstrates that a SAT base query does not "
        "authorize a producer model that violates the full query. The "
        "`model_request` receipt demonstrates capture of an external model "
        "response from an embedded `(get-model)` request.\n\n"
        "To perform real replay after installing a solver, run the exact query "
        "manifests with `experiments/replay_smt_query_bundles.py` and record the "
        "new output separately.\n",
        encoding="utf-8",
        newline="\n",
    )
    files = sorted(
        path
        for path in out_dir.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    (out_dir / "SHA256SUMS").write_text(
        "".join(
            f"{sha256_file(path)}  {path.relative_to(out_dir).as_posix()}\n"
            for path in files
        ),
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["model_violation_detected"] and summary["external_model_capture_detected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
