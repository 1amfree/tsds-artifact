#!/usr/bin/env python3
"""Replay exported SMT query bundles without importing the TSDS evaluator.

The runner is intentionally an external process boundary.  It checks the
producer's exact SMT files and reports solver agreement, disagreement, or
unavailability; it never converts an unavailable replay into UNSAT.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence


SolverCommand = str | Sequence[str]
MODEL_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$-]*$")
INTEGER_LITERAL = re.compile(r"^-?[0-9]+$")
BITVECTOR_LITERAL = re.compile(r"^\(_ bv[0-9]+ [1-9][0-9]*\)$")
GET_MODEL_REQUEST = re.compile(r"^\s*\(get-model\)\s*$", re.IGNORECASE | re.MULTILINE)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_solver_result(stdout: str) -> str:
    """Extract the first SMT-LIB status token from solver stdout."""

    for token in stdout.split():
        normalized = token.strip().lower()
        if normalized in {"sat", "unsat", "unknown"}:
            return normalized.upper()
    return "UNKNOWN"


def extract_model_text(stdout: str) -> str | None:
    """Return an SMT-LIB model block when a solver emitted one."""

    marker = "(model"
    start = stdout.find(marker)
    return stdout[start:].strip() if start >= 0 else None


def safe_member(root: Path, name: Any) -> Path | None:
    if not isinstance(name, str) or not name or "\x00" in name:
        return None
    candidate = (root / Path(name)).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        return None
    return candidate


def _solver_argv(executable: SolverCommand) -> list[str]:
    if isinstance(executable, str):
        return [executable]
    return [str(part) for part in executable]


def _solver_label(executable: SolverCommand) -> str:
    return " ".join(_solver_argv(executable))


def solver_command(executable: SolverCommand, query: Path) -> list[str]:
    argv = _solver_argv(executable)
    if not argv:
        return []
    name = Path(argv[0]).name.lower()
    if "cvc5" in name:
        return [*argv, "--lang=smt2", str(query)]
    if "z3" in name:
        return [*argv, "-smt2", str(query)]
    return [*argv, str(query)]


def replay_file(
    executable: SolverCommand,
    query: Path,
    *,
    timeout: int,
    root: Path,
) -> dict[str, Any]:
    argv = _solver_argv(executable)
    program = argv[0] if argv else ""
    if not program or (not Path(program).is_file() and shutil.which(program) is None):
        return {
            "solver": _solver_label(executable),
            "query": str(query),
            "status": "UNAVAILABLE",
            "observed": None,
            "returncode": None,
            "stderr": "solver_not_found",
        }
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "SystemRoot": os.environ.get("SystemRoot", ""),
        "LANG": "C",
        "LC_ALL": "C",
    }
    try:
        completed = subprocess.run(
            solver_command(executable, query),
            cwd=str(root),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "solver": _solver_label(executable),
            "query": str(query),
            "status": "UNKNOWN",
            "observed": "UNKNOWN",
            "returncode": 124,
            "stderr": f"timeout:{exc}",
        }
    observed = parse_solver_result(completed.stdout) if completed.returncode == 0 else "UNKNOWN"
    return {
        "solver": _solver_label(executable),
        "query": str(query),
        "status": "OK" if completed.returncode == 0 and observed != "UNKNOWN" else "UNKNOWN",
        "observed": observed,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
    }


def compare(observed: str | None, expected: Any) -> str:
    if observed is None or observed == "UNKNOWN":
        return "UNKNOWN"
    if expected not in {"SAT", "UNSAT"}:
        return "NOT_APPLICABLE"
    return "MATCH" if observed == expected else "MISMATCH"


def _model_assertions(model: Any) -> tuple[list[str], list[str]]:
    """Render a restricted, injection-safe model assignment list.

    The bundle format intentionally supports only primitive values that can be
    checked without importing a solver library.  A partial assignment is
    still useful, but its scope must be declared by the producer.
    """

    if not isinstance(model, dict) or model.get("status") != "provided":
        return [], []
    assignments = model.get("assignments")
    if not isinstance(assignments, list) or not assignments:
        return [], ["model_assignments_missing_or_empty"]
    assertions: list[str] = []
    issues: list[str] = []
    seen: set[str] = set()
    for index, assignment in enumerate(assignments):
        if not isinstance(assignment, dict):
            issues.append(f"model_assignment_{index}_not_an_object")
            continue
        issue_count = len(issues)
        name = str(assignment.get("name") or "")
        sort = str(assignment.get("sort") or "")
        raw_value = assignment.get("value")
        value = (
            "true"
            if raw_value is True
            else "false"
            if raw_value is False
            else str(raw_value)
            if raw_value is not None
            else ""
        )
        if not MODEL_SYMBOL.fullmatch(name):
            issues.append(f"model_assignment_{index}_invalid_symbol")
        if name in seen:
            issues.append(f"model_assignment_{index}_duplicate_symbol")
        seen.add(name)
        if sort == "Int" and not INTEGER_LITERAL.fullmatch(value):
            issues.append(f"model_assignment_{index}_invalid_int")
        elif sort == "Bool" and value not in {"true", "false"}:
            issues.append(f"model_assignment_{index}_invalid_bool")
        elif sort == "BitVec" and not BITVECTOR_LITERAL.fullmatch(value):
            issues.append(f"model_assignment_{index}_invalid_bitvector")
        elif sort not in {"Int", "Bool", "BitVec"}:
            issues.append(f"model_assignment_{index}_unsupported_sort")
        if len(issues) == issue_count:
            assertions.append(f"(assert (= {name} {value}))")
    return assertions, issues


def _model_check_query(query_text: str, assertions: Sequence[str]) -> str:
    """Append assignment assertions before the exact query's check-sat."""

    lines = query_text.splitlines()
    check_sat = re.compile(r"^\s*\(check-sat\)\s*$", re.IGNORECASE)
    get_model = re.compile(r"^\s*\(get-model\)\s*$", re.IGNORECASE)
    kept = [line for line in lines if not check_sat.match(line) and not get_model.match(line)]
    return "\n".join([*kept, *assertions, "(check-sat)", ""])


def _run_model_check(
    executable: SolverCommand,
    query_text: str,
    model: Any,
    *,
    timeout: int,
    root: Path,
) -> dict[str, Any]:
    assertions, issues = _model_assertions(model)
    if issues:
        return {
            "status": "INVALID",
            "observed": None,
            "comparison": "NOT_APPLICABLE",
            "issues": issues,
        }
    if not assertions:
        return {
            "status": "NOT_RUN",
            "observed": None,
            "comparison": "NOT_APPLICABLE",
            "reason": "model_not_exported",
        }
    rendered = _model_check_query(query_text, assertions)
    with tempfile.TemporaryDirectory(prefix="tsds-model-check-", dir=str(root)) as directory:
        check_path = Path(directory) / "model_check.smt2"
        check_path.write_text(rendered, encoding="utf-8", newline="\n")
        replay = replay_file(executable, check_path, timeout=timeout, root=root)
    observed = replay.get("observed")
    if observed is None or observed == "UNKNOWN":
        comparison = "UNKNOWN"
    else:
        comparison = "MATCH" if observed == "SAT" else "MISMATCH"
    return {
        "status": replay.get("status"),
        "observed": observed,
        "comparison": comparison,
        "query_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        "assignments": len(assertions),
        "scope": model.get("scope"),
        "solver_stderr": replay.get("stderr"),
    }


def replay_manifest(
    manifest_path: Path,
    solvers: list[SolverCommand],
    *,
    timeout: int,
    root: Path,
) -> dict[str, Any]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "manifest": str(manifest_path),
            "status": "INVALID",
            "issues": [f"manifest_read:{type(exc).__name__}"],
        }
    if not isinstance(manifest, dict) or manifest.get("schema") != "tsds-solver-query-bundle-v1":
        return {"manifest": str(manifest_path), "status": "INVALID", "issues": ["unsupported_schema"]}

    bundle_root = manifest_path.parent
    files = manifest.get("files") or {}
    hashes = manifest.get("sha256") or {}
    issues: list[str] = []
    queries: dict[str, Path] = {}
    for kind in ("full", "projected"):
        member = files.get(kind)
        if member is None:
            continue
        path = safe_member(bundle_root, member)
        if path is None or not path.is_file():
            issues.append(f"missing_or_unsafe_{kind}_query")
            continue
        expected_hash = hashes.get(f"{kind}_smt2")
        if expected_hash and sha256_file(path) != expected_hash:
            issues.append(f"{kind}_query_hash_mismatch")
            continue
        queries[kind] = path

    producer = manifest.get("producer") or {}
    model = producer.get("model")
    model_status = model.get("status") if isinstance(model, dict) else None
    model_requests = producer.get("model_requests")
    if not isinstance(model_requests, dict):
        model_requests = {}
    rows: list[dict[str, Any]] = []
    for kind, path in queries.items():
        expected = producer.get(f"{kind}_result")
        query_text = path.read_text(encoding="utf-8")
        replay_rows = [
            replay_file(solver, path, timeout=timeout, root=root) for solver in solvers
        ]
        for solver, replay in zip(solvers, replay_rows):
            replay["kind"] = kind
            replay["expected"] = expected
            replay["comparison"] = compare(replay.get("observed"), expected)
            replay["manifest"] = str(manifest_path)
            model_requested = bool(model_requests.get(kind)) or (
                kind == "full" and model_status == "embedded_get_model_request"
            )
            if model_requested and not GET_MODEL_REQUEST.search(query_text):
                issues.append(f"{kind}_model_request_missing")
                replay["external_model"] = {
                    "status": "REQUEST_MISSING",
                    "text": None,
                    "claim_boundary": "The manifest requested a model, but the query did not contain an SMT-LIB get-model command.",
                }
            elif model_requested and expected == "SAT":
                model_text = extract_model_text(str(replay.get("stdout") or ""))
                replay["external_model"] = {
                    "status": "CAPTURED" if model_text else "NOT_RETURNED",
                    "text": model_text,
                    "claim_boundary": (
                        "The model is raw output from the external solver. This "
                        "receipt does not independently bind it to a producer-side "
                        "witness unless a separate model comparison is supplied."
                    ),
                }
            elif model_requested:
                replay["external_model"] = {
                    "status": "NOT_APPLICABLE",
                    "text": None,
                    "claim_boundary": "A model request is not interpreted as a SAT model when the declared query result is not SAT.",
                }
            else:
                replay["external_model"] = {
                    "status": "NOT_REQUESTED",
                    "text": None,
                }
            if kind == "full" and expected == "SAT" and model_status == "provided":
                replay["model_check"] = _run_model_check(
                    solver,
                    query_text,
                    model,
                    timeout=timeout,
                    root=root,
                )
            else:
                replay["model_check"] = {
                    "status": "NOT_RUN",
                    "observed": None,
                    "comparison": "NOT_APPLICABLE",
                    "reason": (
                        "model_not_provided"
                        if model_status != "provided"
                        else "model_check_requires_full_expected_sat"
                    ),
                }
            rows.append(replay)
    if not queries:
        issues.append("no_replayable_query")
    return {
        "manifest": str(manifest_path),
        "query_id": manifest.get("query_id"),
        "status": "INVALID" if issues else "OK",
        "issues": sorted(set(issues)),
        "producer_decision": producer.get("decision"),
        "producer_full_validation": producer.get("full_validation"),
        "replays": rows,
        "claim_boundary": manifest.get("claim_boundary"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--solver", action="append", default=None)
    parser.add_argument(
        "--solver-argv",
        action="append",
        default=None,
        help=(
            "Shell-free solver command line, parsed with POSIX shlex and "
            "repeated once per solver; useful when a solver needs a Python "
            "wrapper or interpreter."
        ),
    )
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--fail-on-mismatch", action="store_true")
    parser.add_argument("--fail-on-model-mismatch", action="store_true")
    parser.add_argument("--fail-if-unavailable", action="store_true")
    args = parser.parse_args()
    bundle_dir = args.bundle_dir.resolve()
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to overwrite non-empty output: {out_dir}", file=sys.stderr)
        return 2
    manifests = sorted(bundle_dir.rglob("*.manifest.json")) if bundle_dir.is_dir() else []
    if not manifests:
        print(f"no query manifests found under {bundle_dir}", file=sys.stderr)
        return 2

    if args.solver and args.solver_argv:
        parser.error("--solver and --solver-argv are mutually exclusive")
    if args.solver_argv:
        solvers = []
        for command in args.solver_argv:
            try:
                argv = shlex.split(command, posix=True)
            except ValueError as exc:
                parser.error(f"invalid --solver-argv: {exc}")
            if not argv:
                parser.error("--solver-argv must not be empty")
            solvers.append(argv)
    else:
        solvers = list(args.solver or ["z3"])
    receipts = [
        replay_manifest(path, solvers, timeout=max(1, args.timeout), root=bundle_dir)
        for path in manifests
    ]
    replays = [row for receipt in receipts for row in receipt.get("replays", [])]
    summary = {
        "schema": "tsds-smt-query-replay-v1",
        "bundle_dir": str(bundle_dir),
        "manifest_count": len(manifests),
        "invalid_manifest_count": sum(receipt.get("status") != "OK" for receipt in receipts),
        "replay_count": len(replays),
        "comparison_counts": {
            value: sum(row.get("comparison") == value for row in replays)
            for value in ("MATCH", "MISMATCH", "UNKNOWN", "NOT_APPLICABLE")
        },
        "model_comparison_counts": {
            value: sum(
                (row.get("model_check") or {}).get("comparison") == value
                for row in replays
            )
            for value in ("MATCH", "MISMATCH", "UNKNOWN", "NOT_APPLICABLE")
        },
        "status_counts": {
            value: sum(row.get("status") == value for row in replays)
            for value in ("OK", "UNKNOWN", "UNAVAILABLE")
        },
        "solvers": solvers,
        "claim_boundary": (
            "Replay receipts compare externally executed SMT results with producer metadata. "
            "Unavailable or unknown runs remain abstentions; a matching query result is not "
            "a device-level exploitability result."
        ),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "replay_receipts.jsonl").open("w", encoding="utf-8", newline="\n") as stream:
        for receipt in receipts:
            stream.write(json.dumps(receipt, ensure_ascii=False, sort_keys=True) + "\n")
    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    mismatches = summary["comparison_counts"]["MISMATCH"]
    model_mismatches = summary["model_comparison_counts"]["MISMATCH"]
    unavailable = summary["status_counts"]["UNAVAILABLE"]
    if args.fail_on_mismatch and mismatches:
        return 1
    if args.fail_on_model_mismatch and model_mismatches:
        return 1
    if args.fail_if_unavailable and unavailable:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
