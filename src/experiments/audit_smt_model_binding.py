#!/usr/bin/env python3
"""Audit exported SMT queries and bind SAT models to the same full query.

The audit runs outside the TSDS evaluator.  It is deliberately narrower than
an independent solver proof: it checks query-file integrity, obtains a model
from an external Z3 process for SAT queries, and rechecks that model by adding
its primitive assignments to the original query.  The result is a finite,
target-local audit of exported queries; it is not firmware ground truth,
source-realizability evidence, or device-level validation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA = "tsds-smt-model-binding-audit-v1"
STATUS = {"SAT", "UNSAT", "UNKNOWN"}
SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$-]*$")
INTEGER = re.compile(r"^-?[0-9]+$")
BOOL = {"true", "false"}
BITVECTOR = re.compile(r"^#(?:x[0-9A-Fa-f]+|b[01]+)$")
BITVECTOR_CONSTRUCTOR = re.compile(r"^bv[0-9]+$")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_status(stdout: str) -> str:
    """Extract the first SMT-LIB status token from solver output."""

    for token in stdout.split():
        value = token.strip().lower()
        if value in {"sat", "unsat", "unknown"}:
            return value.upper()
    return "UNKNOWN"


def remove_terminal_commands(query: str) -> str:
    """Remove terminal check/model commands before appending a new request."""

    lines = []
    for line in query.splitlines():
        if re.fullmatch(r"\s*\(check-sat\)\s*", line, flags=re.IGNORECASE):
            continue
        if re.fullmatch(r"\s*\(get-model\)\s*", line, flags=re.IGNORECASE):
            continue
        lines.append(line)
    return "\n".join(lines).rstrip() + "\n"


def extract_model_text(stdout: str) -> str | None:
    """Extract one balanced SMT-LIB model block from solver stdout.

    Z3's command-line interface emits a model as ``( ... )`` without the
    optional ``model`` atom, while other SMT-LIB front ends may emit
    ``(model ... )``.  Both forms are accepted at this evidence boundary.
    """

    status_match = re.search(r"\b(?:sat|unsat|unknown)\b", stdout, flags=re.IGNORECASE)
    start = stdout.find("(", status_match.end() if status_match else 0)
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(stdout)):
        char = stdout[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return stdout[start : index + 1]
    return None


def _tokens(text: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", text)


def _parse_sexpr(text: str) -> Any:
    tokens = _tokens(text)
    position = 0

    def parse_one() -> Any:
        nonlocal position
        if position >= len(tokens):
            raise ValueError("unexpected end of S-expression")
        token = tokens[position]
        position += 1
        if token != "(":
            if token == ")":
                raise ValueError("unexpected closing parenthesis")
            return token
        values: list[Any] = []
        while position < len(tokens) and tokens[position] != ")":
            values.append(parse_one())
        if position >= len(tokens):
            raise ValueError("unclosed S-expression")
        position += 1
        return values

    result = parse_one()
    if position != len(tokens):
        raise ValueError("trailing S-expression tokens")
    return result


def _render_sort(value: Any) -> str | None:
    if isinstance(value, str) and value in {"Int", "Bool"}:
        return value
    if (
        isinstance(value, list)
        and len(value) == 3
        and value[0] == "_"
        and value[1] == "BitVec"
        and isinstance(value[2], str)
        and value[2].isdigit()
        and int(value[2]) > 0
    ):
        return f"(_ BitVec {value[2]})"
    return None


def _render_value(value: Any) -> str | None:
    if isinstance(value, str):
        if INTEGER.fullmatch(value) or value in BOOL or BITVECTOR.fullmatch(value):
            return value
        return None
    if (
        isinstance(value, list)
        and len(value) == 2
        and value[0] == "-"
        and isinstance(value[1], str)
        and value[1].isdigit()
    ):
        return f"(- {value[1]})"
    if (
        isinstance(value, list)
        and len(value) == 3
        and value[0] == "_"
        and isinstance(value[1], str)
        and BITVECTOR_CONSTRUCTOR.fullmatch(value[1])
        and isinstance(value[2], str)
        and value[2].isdigit()
        and int(value[2]) > 0
    ):
        return f"(_ {value[1]} {value[2]})"
    return None


def model_assertions(model_text: str) -> tuple[list[str], dict[str, Any]]:
    """Render safe primitive equalities from an SMT-LIB model."""

    tree = _parse_sexpr(model_text)
    if not isinstance(tree, list) or not tree:
        raise ValueError("model root is not an SMT-LIB list")
    if tree[0] == "model":
        entries = tree[1:]
    else:
        entries = tree
    assertions: list[str] = []
    issues: list[str] = []
    names: set[str] = set()
    definitions = 0
    skipped = 0
    for item in entries:
        if not isinstance(item, list) or not item or item[0] != "define-fun":
            skipped += 1
            continue
        definitions += 1
        if len(item) != 5 or item[2] != []:
            skipped += 1
            issues.append("non_constant_model_definition")
            continue
        name = item[1]
        if not isinstance(name, str) or not SYMBOL.fullmatch(name):
            issues.append("invalid_model_symbol")
            continue
        if name in names:
            issues.append("duplicate_model_symbol")
            continue
        names.add(name)
        sort = _render_sort(item[3])
        value = _render_value(item[4])
        if sort is None or value is None:
            skipped += 1
            issues.append("unsupported_primitive_model_definition")
            continue
        assertions.append(f"(assert (= {name} {value}))")
    if not assertions:
        issues.append("no_primitive_model_assertions")
    return assertions, {
        "definitions": definitions,
        "primitive_definitions": len(assertions),
        "skipped_definitions": skipped,
        "issues": sorted(set(issues)),
        "model_sha256": sha256_bytes(model_text.encode("utf-8")),
    }


def _solver_argv(solver: str | Sequence[str]) -> list[str]:
    if isinstance(solver, str):
        return [solver]
    return [str(item) for item in solver]


def _run_solver(
    solver: str | Sequence[str],
    query_text: str,
    *,
    timeout: int,
    root: Path,
    request_model: bool = False,
) -> dict[str, Any]:
    root = root.resolve()
    argv = _solver_argv(solver)
    if not argv:
        return {"status": "UNAVAILABLE", "observed": None, "stderr": "empty_solver"}
    program = argv[0]
    program_path = Path(program)
    if program_path.is_file():
        argv[0] = str(program_path.resolve())
    else:
        resolved = shutil.which(program)
        if resolved is None:
            return {"status": "UNAVAILABLE", "observed": None, "stderr": "solver_not_found"}
        argv[0] = resolved
    rendered = remove_terminal_commands(query_text)
    rendered += "(check-sat)\n"
    if request_model:
        rendered += "(get-model)\n"
    with tempfile.TemporaryDirectory(prefix="tsds-model-binding-", dir=str(root)) as directory:
        query_path = Path(directory) / "query.smt2"
        query_path.write_text(rendered, encoding="utf-8", newline="\n")
        try:
            completed = subprocess.run(
                [*argv, "-smt2", str(query_path)],
                cwd=str(root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=max(1, timeout),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "status": "UNKNOWN",
                "observed": "UNKNOWN",
                "returncode": 124,
                "stdout": str(exc.stdout or "")[-4000:],
                "stderr": f"timeout:{exc}",
                "rendered_query_sha256": sha256_bytes(rendered.encode("utf-8")),
            }
    observed = parse_status(completed.stdout) if completed.returncode == 0 else "UNKNOWN"
    return {
        "status": "OK" if completed.returncode == 0 and observed != "UNKNOWN" else "UNKNOWN",
        "observed": observed,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-12000:],
        "stderr": completed.stderr[-4000:],
        "rendered_query_sha256": sha256_bytes(rendered.encode("utf-8")),
    }


def _model_check(
    solver: str | Sequence[str],
    query_text: str,
    assertions: Sequence[str],
    *,
    timeout: int,
    root: Path,
) -> dict[str, Any]:
    rendered = remove_terminal_commands(query_text)
    rendered += "\n".join(assertions) + "\n(check-sat)\n"
    result = _run_solver(
        solver,
        rendered,
        timeout=timeout,
        root=root,
        request_model=False,
    )
    observed = result.get("observed")
    return {
        "observed": observed,
        "comparison": "MATCH" if observed == "SAT" else "MISMATCH" if observed else "UNKNOWN",
        "status": result.get("status"),
        "assertion_count": len(assertions),
        "query_sha256": sha256_bytes(rendered.encode("utf-8")),
        "stderr": result.get("stderr", ""),
    }


def _manifest_expected(manifest: dict[str, Any], kind: str) -> str | None:
    producer = manifest.get("producer")
    if not isinstance(producer, dict):
        return None
    value = producer.get(f"{kind}_result")
    if value in STATUS:
        return value
    decision = producer.get("decision")
    return decision if decision in {"SAT", "UNSAT"} else None


def _load_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != "tsds-solver-query-bundle-v1":
        raise ValueError(f"unsupported manifest: {path}")
    return value


def _manifest_paths(campaign_dir: Path) -> list[Path]:
    return sorted(campaign_dir.rglob("*.manifest.json"))


def _target_for(path: Path, campaign_dir: Path) -> str:
    relative = path.relative_to(campaign_dir)
    return relative.parts[0] if relative.parts else "."


def select_manifests(paths: Sequence[Path], campaign_dir: Path, limit: int | None) -> list[Path]:
    """Select a deterministic target/outcome-stratified finite sample."""

    if limit is None or limit <= 0 or limit >= len(paths):
        return list(paths)
    groups: dict[tuple[str, str], list[Path]] = defaultdict(list)
    for path in paths:
        try:
            manifest = _load_manifest(path)
            outcome = str((manifest.get("producer") or {}).get("decision") or "UNKNOWN")
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            outcome = "INVALID"
        groups[(_target_for(path, campaign_dir), outcome)].append(path)
    ordered_groups = [groups[key] for key in sorted(groups)]
    selected: list[Path] = []
    cursor = 0
    while len(selected) < limit and ordered_groups:
        progressed = False
        for group in ordered_groups:
            if cursor < len(group) and len(selected) < limit:
                selected.append(group[cursor])
                progressed = True
        if not progressed:
            break
        cursor += 1
    return selected


def audit_manifest(
    manifest_path: Path,
    *,
    campaign_dir: Path,
    solver: str | Sequence[str],
    timeout: int,
    root: Path,
) -> list[dict[str, Any]]:
    manifest = _load_manifest(manifest_path)
    bundle_root = manifest_path.parent
    files = manifest.get("files")
    hashes = manifest.get("sha256")
    if not isinstance(files, dict):
        raise ValueError(f"manifest has no files map: {manifest_path}")
    if not isinstance(hashes, dict):
        hashes = {}
    rows: list[dict[str, Any]] = []
    for kind in ("full", "projected"):
        member = files.get(kind)
        if not isinstance(member, str):
            continue
        query_path = (bundle_root / member).resolve()
        if bundle_root.resolve() not in query_path.parents or not query_path.is_file():
            rows.append({
                "manifest": str(manifest_path),
                "kind": kind,
                "status": "INVALID",
                "issues": ["query_missing_or_outside_bundle"],
            })
            continue
        query_bytes = query_path.read_bytes()
        query_text = query_bytes.decode("utf-8")
        issues: list[str] = []
        declared_hash = hashes.get(f"{kind}_smt2")
        if declared_hash and declared_hash != sha256_bytes(query_bytes):
            issues.append("query_hash_mismatch")
        expected = _manifest_expected(manifest, kind)
        replay = _run_solver(
            solver,
            query_text,
            timeout=timeout,
            root=root,
            request_model=expected == "SAT",
        )
        observed = replay.get("observed")
        if expected and observed not in {expected}:
            issues.append("producer_status_mismatch")
        model_info: dict[str, Any] = {
            "requested": expected == "SAT",
            "status": "NOT_REQUESTED" if expected != "SAT" else "NOT_RETURNED",
        }
        model_check: dict[str, Any] = {
            "status": "NOT_RUN",
            "comparison": "NOT_APPLICABLE",
        }
        if expected == "SAT" and observed == "SAT":
            model_text = extract_model_text(str(replay.get("stdout") or ""))
            if model_text is None:
                issues.append("sat_model_not_returned")
            else:
                assertions, model_info = model_assertions(model_text)
                model_info["requested"] = True
                model_info["status"] = "CAPTURED"
                model_check = _model_check(
                    solver,
                    query_text,
                    assertions,
                    timeout=timeout,
                    root=root,
                )
                if model_check.get("comparison") != "MATCH":
                    issues.append("sat_model_binding_failed")
                if model_info.get("issues"):
                    issues.extend(f"model:{item}" for item in model_info["issues"])
        elif expected == "SAT":
            model_info["status"] = "NOT_APPLICABLE_AFTER_NON_SAT_REPLAY"
        rows.append({
            "manifest": str(manifest_path),
            "manifest_relative": str(manifest_path.relative_to(campaign_dir)),
            "query_id": manifest.get("query_id"),
            "kind": kind,
            "query": str(query_path),
            "query_sha256": sha256_bytes(query_bytes),
            "declared": expected,
            "observed": observed,
            "replay_status": replay.get("status"),
            "returncode": replay.get("returncode"),
            "model": model_info,
            "model_check": model_check,
            "issues": sorted(set(issues)),
            "valid": not issues,
        })
    return rows


def _collect_campaign(
    campaign_dir: Path,
    *,
    solver: str | Sequence[str],
    timeout: int,
    limit: int | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    paths = _manifest_paths(campaign_dir)
    if not paths:
        raise ValueError(f"no SMT manifests found under {campaign_dir}")
    selected = select_manifests(paths, campaign_dir, limit)
    rows: list[dict[str, Any]] = []
    manifest_errors: list[dict[str, str]] = []
    for path in selected:
        try:
            rows.extend(
                audit_manifest(
                    path,
                    campaign_dir=campaign_dir,
                    solver=solver,
                    timeout=timeout,
                    root=campaign_dir,
                )
            )
        except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
            manifest_errors.append({
                "manifest": str(path),
                "error": f"{type(exc).__name__}:{exc}",
            })
    status_counts = Counter(str(row.get("observed") or "UNKNOWN") for row in rows)
    declared_counts = Counter(str(row.get("declared") or "UNKNOWN") for row in rows)
    model_rows = [row for row in rows if row.get("model", {}).get("requested")]
    model_checks = Counter(str(row.get("model_check", {}).get("comparison")) for row in model_rows)
    issues = [
        {
            "manifest": row.get("manifest"),
            "kind": row.get("kind"),
            "issues": row.get("issues"),
        }
        for row in rows
        if row.get("issues")
    ]
    issues.extend({"manifest": item["manifest"], "kind": "manifest", "issues": [item["error"]]} for item in manifest_errors)
    summary = {
        "schema": SCHEMA,
        "campaign_dir": str(campaign_dir),
        "solver": _solver_argv(solver),
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


def audit_campaign(
    campaign_dir: Path,
    *,
    solver: str | Sequence[str],
    timeout: int,
    limit: int | None,
) -> dict[str, Any]:
    """Return the summary while keeping row collection internal to the CLI."""

    summary, _ = _collect_campaign(
        campaign_dir,
        solver=solver,
        timeout=timeout,
        limit=limit,
    )
    return summary


def write_outputs(out_dir: Path, summary: dict[str, Any], rows: Iterable[dict[str, Any]]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "summary.json"
    rows_path = out_dir / "model_binding_receipts.jsonl"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with rows_path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    model_checks = summary.get("model_check_comparisons", {})
    lines = [
        "# SMT model-binding audit",
        "",
        f"Valid: **{summary['valid']}**",
        f"Available manifests: **{summary['available_manifest_count']}**",
        f"Selected manifests: **{summary['selected_manifest_count']}**",
        f"Audited query rows: **{summary['query_count']}**",
        f"SAT-model binding checks: **{summary['model_requested_queries']}**",
        f"Model-check outcomes: `{json.dumps(model_checks, sort_keys=True)}`",
        "",
        summary["claim_boundary"],
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    sums = {
        name: sha256_file(out_dir / name)
        for name in ("summary.json", "model_binding_receipts.jsonl", "README.md")
    }
    (out_dir / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())),
        encoding="utf-8",
        newline="\n",
    )


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
    args = parser.parse_args()
    try:
        summary, rows = _collect_campaign(
            args.campaign_dir,
            solver=args.solver,
            timeout=max(1, args.timeout),
            limit=args.limit,
        )
        write_outputs(args.out_dir, summary, rows)
    except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"SMT_MODEL_BINDING_AUDIT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
