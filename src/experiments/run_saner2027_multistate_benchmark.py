#!/usr/bin/env python3
"""Run bounded multi-state audits over the controlled 24-case ELF benchmark.

The ordinary benchmark remains immutable.  This driver reuses its binary and
closures, enables the evaluator's opt-in bounded sink-instance sidecar, and
records both the frozen-style primary result and the collected profiles.  A
sidecar is a coverage calibration, not a complete path-space enumeration.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.multi_state_aggregation import profile_is_direct_positive  # noqa: E402
from tsds.shell_matrix_spec import MATRIX_SPEC_VERSION, matrix_spec_sha256  # noqa: E402
from experiments.build_source_dependency_manifest import (  # noqa: E402
    build_manifest,
)


EVALUATOR = PROJECT_ROOT / "Taint_demo" / "sanitizer_demo" / "advanced_sanitizer_evaluator.py"
AGGREGATION_MODULE = PROJECT_ROOT / "tsds" / "multi_state_aggregation.py"
DEFAULT_INPUT = PROJECT_ROOT / "experiment_reports" / "saner2027_controlled_benchmark_20260913"
DEFAULT_OUTPUT = PROJECT_ROOT / "experiment_reports" / "saner2027_multistate_benchmark_20260913"
SOURCE_LOCK_ENTRYPOINTS = (
    "experiments/run_saner2027_multistate_benchmark.py",
    "Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py",
)
SOURCE_LOCK_TOOL = "experiments/build_source_dependency_manifest.py"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_jsonl(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    rows = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        return None
    value = json.loads(rows[-1])
    return value if isinstance(value, dict) else None


def selected_profile(record: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return the profile selected by the evaluator, if it is well formed."""

    if not isinstance(record, dict):
        return None
    audit = record.get("multi_state_audit")
    if not isinstance(audit, dict):
        return None
    profiles = audit.get("profiles")
    selection = record.get("multi_state_selection")
    if not isinstance(selection, dict):
        selection = audit.get("primary_selection")
    if not isinstance(profiles, list) or not isinstance(selection, dict):
        return None
    index = selection.get("selected_state_index")
    if not isinstance(index, int) or not (0 <= index < len(profiles)):
        return None
    profile = profiles[index]
    return profile if isinstance(profile, dict) else None


def classify(record: dict[str, Any] | None) -> tuple[str, bool]:
    """Classify only from the evaluator's admission-aware selected profile."""

    if not record:
        return "UNRESOLVED", False
    profile = selected_profile(record)
    if profile_is_direct_positive(profile or {}):
        return "POSITIVE", True
    status = str(record.get("status") or record.get("verdict") or "").lower()
    if status in {
        "filtered",
        "matrix_unsat",
        "no_taint_sink",
        "no_modeled_source",
        "static_warning_reduction",
        "static_candidate",
    }:
        return "LOCAL_PROFILE", False
    return "UNRESOLVED", False


def profile_positive(profile: dict[str, Any]) -> bool:
    return profile_is_direct_positive(profile)


def label_contract(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare primary admissions with the frozen external case labels."""

    expected_positive = {
        int(row["index"])
        for row in rows
        if row.get("expected") == "POSITIVE"
    }
    observed_positive = {
        int(row["index"])
        for row in rows
        if row.get("primary_positive") is True
    }
    missing = sorted(expected_positive - observed_positive)
    unexpected = sorted(observed_positive - expected_positive)
    return {
        "expected_positive_count": len(expected_positive),
        "observed_primary_positive_count": len(observed_positive),
        "missing_expected_positive_indices": missing,
        "unexpected_primary_positive_indices": unexpected,
        "matches": not missing and not unexpected,
    }


def run_one(
    *,
    binary: Path,
    closure: Path,
    case_dir: Path,
    evaluator_python: str,
    settle_steps: int,
    engine_timeout: int,
    max_steps: int,
    closure_timeout: int,
    process_timeout: int,
) -> dict[str, Any]:
    case_dir.mkdir(parents=True, exist_ok=True)
    result_path = case_dir / "result.jsonl"
    summary_path = case_dir / "summary.json"
    stdout_path = case_dir / "stdout.log"
    stderr_path = case_dir / "stderr.log"
    command = [
        evaluator_python,
        str(EVALUATOR),
        str(binary),
        str(closure),
        "--closure-idx",
        "0",
        "--multi-state-audit",
        "--multi-state-settle-steps",
        str(settle_steps),
        "--engine-timeout",
        str(engine_timeout),
        "--max-steps",
        str(max_steps),
        "--closure-timeout",
        str(closure_timeout),
        "--no-evidence-cache",
        "--summary-json",
        str(summary_path),
        "--results-jsonl",
        str(result_path),
    ]
    environment = {
        **os.environ,
        "LC_ALL": "C",
        "LANG": "C",
        "PYTHONHASHSEED": "0",
        "PYTHONPATH": str(PROJECT_ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""),
    }
    started = time.monotonic()
    try:
        with (
            stdout_path.open("w", encoding="utf-8") as stdout_stream,
            stderr_path.open("w", encoding="utf-8") as stderr_stream,
        ):
            completed = subprocess.run(
                command,
                cwd=str(PROJECT_ROOT),
                env=environment,
                stdout=stdout_stream,
                stderr=stderr_stream,
                timeout=process_timeout,
                check=False,
            )
        returncode = completed.returncode
        timed_out = False
    except subprocess.TimeoutExpired:
        returncode = 124
        timed_out = True
    record = load_jsonl(result_path)
    primary_class, primary_positive = classify(record)
    audit = (record or {}).get("multi_state_audit") or {}
    profiles = [profile for profile in audit.get("profiles") or [] if isinstance(profile, dict)]
    positive_profiles = [profile for profile in profiles if profile_positive(profile)]
    later_positive = any(
        profile_positive(profile) and int(profile.get("state_index") or 0) > 0
        for profile in profiles
    )
    fingerprints = {
        str(profile.get("profile_fingerprint"))
        for profile in profiles
        if profile.get("profile_fingerprint")
    }
    return {
        "returncode": returncode,
        "timed_out": timed_out,
        "elapsed_sec": round(time.monotonic() - started, 6),
        "command": command,
        "result_path": str(result_path),
        "summary_path": str(summary_path),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "primary_class": primary_class,
        "primary_positive": primary_positive,
        "primary_status": (record or {}).get("status"),
        "primary_verdict": (record or {}).get("verdict"),
        "profile_count": len(profiles),
        "distinct_profile_count": len(fingerprints),
        "positive_profile_count": len(positive_profiles),
        "later_positive_after_first": later_positive,
        "collection_complete": bool(audit.get("collection_complete")),
        "collection_blockers": list(
            (audit.get("collection_accounting") or {}).get("blockers") or []
        ),
        "aggregate_profile_count": int(
            (audit.get("aggregate") or {}).get("unique_profile_count") or 0
        ),
        "aggregate_class": (audit.get("aggregate") or {}).get("aggregate_class"),
        "aggregate_quantifier": (audit.get("aggregate") or {}).get("quantifier"),
        "candidate_wide_negative": (audit.get("aggregate") or {}).get("candidate_wide_negative"),
        "profile_statuses": sorted({str(profile.get("status")) for profile in profiles}),
        "profiles": profiles,
    }


def write_sha256sums(root: Path) -> None:
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            rows.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")


def main() -> int:
    if os.name != "posix":
        print("This benchmark must run on the Ubuntu VM, not on the Windows host.", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--settle-steps", type=int, default=8)
    parser.add_argument("--engine-timeout", type=int, default=25)
    parser.add_argument("--max-steps", type=int, default=260)
    parser.add_argument("--closure-timeout", type=int, default=60)
    parser.add_argument("--process-timeout", type=int, default=95)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    input_root = args.input_dir.resolve()
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to overwrite non-empty output: {out_dir}", file=sys.stderr)
        return 2
    summary_path = input_root / "summary.json"
    binary = input_root / "build" / "controlled_benchmark"
    if not summary_path.is_file() or not binary.is_file() or not EVALUATOR.is_file():
        print("controlled benchmark summary, binary, or evaluator is missing", file=sys.stderr)
        return 2
    source_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    cases = list(source_summary.get("cases") or [])
    if args.limit is not None:
        cases = cases[: max(0, args.limit)]
    out_dir.mkdir(parents=True, exist_ok=True)
    source_manifest = build_manifest(
        PROJECT_ROOT,
        SOURCE_LOCK_ENTRYPOINTS,
        SOURCE_LOCK_TOOL,
    )
    source_manifest_path = out_dir / "source_dependency_manifest.json"
    write_json(source_manifest_path, source_manifest)
    write_json(
        out_dir / "input_manifest.json",
        {
            "schema": "tsds-saner2027-multistate-input-manifest-v2",
            "input_root": str(input_root),
            "summary_sha256": sha256_file(summary_path),
            "binary_sha256": sha256_file(binary),
            "evaluator_sha256": sha256_file(EVALUATOR),
            "aggregation_module_sha256": sha256_file(AGGREGATION_MODULE),
            "driver_sha256": sha256_file(Path(__file__).resolve()),
            "matrix_spec_version": MATRIX_SPEC_VERSION,
            "matrix_spec_sha256": matrix_spec_sha256(),
            "source_dependency_manifest_schema": source_manifest["schema"],
            "source_dependency_manifest_sha256": sha256_file(source_manifest_path),
            "cases": cases,
            "configuration": {
                "settle_steps": args.settle_steps,
                "engine_timeout": args.engine_timeout,
                "max_steps": args.max_steps,
                "closure_timeout": args.closure_timeout,
                "process_timeout": args.process_timeout,
            },
        },
    )
    rows: list[dict[str, Any]] = []
    all_profile_fingerprints: set[str] = set()
    for case in cases:
        index = int(case["index"])
        case_id = str(case["id"])
        source_case_dir = input_root / "tsds" / f"{index:02d}_{case_id}"
        closure = source_case_dir / "closure.json"
        if not closure.is_file():
            rows.append({
                "index": index,
                "case_id": case_id,
                "expected": case.get("expected"),
                "input_closure": str(closure),
                "input_missing": True,
                "primary_class": "UNRESOLVED",
                "primary_positive": False,
                "returncode": 2,
                "timed_out": False,
                "error": "closure_missing",
            })
            continue
        result = run_one(
            binary=binary,
            closure=closure,
            case_dir=out_dir / "tsds" / f"{index:02d}_{case_id}",
            evaluator_python=args.python,
            settle_steps=args.settle_steps,
            engine_timeout=args.engine_timeout,
            max_steps=args.max_steps,
            closure_timeout=args.closure_timeout,
            process_timeout=args.process_timeout,
        )
        all_profile_fingerprints.update(
            str(profile["profile_fingerprint"])
            for profile in result.get("profiles") or []
            if profile.get("profile_fingerprint")
        )
        rows.append({
            "index": index,
            "case_id": case_id,
            "expected": case.get("expected"),
            "input_closure": str(closure),
            "input_missing": False,
            **{key: value for key, value in result.items() if key != "profiles"},
        })
        write_json(out_dir / "tsds" / f"{index:02d}_{case_id}" / "profiles.json", result.get("profiles") or [])
    write_json(out_dir / "results.json", rows)
    if rows:
        fields = sorted({key for row in rows for key in row})
        with (out_dir / "results.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
    processed = [
        row
        for row in rows
        if not row.get("input_missing") and int(row.get("returncode") or 0) == 0
    ]
    completed = [row for row in rows if not row.get("input_missing")]
    aggregate_classes = Counter(str(row.get("aggregate_class") or "MISSING") for row in completed)
    expected_positive = {
        int(case["index"])
        for case in cases
        if case.get("expected") == "POSITIVE"
    }
    primary_positive = {int(row["index"]) for row in completed if row.get("primary_positive")}
    sidecar_positive = {int(row["index"]) for row in completed if int(row.get("positive_profile_count") or 0) > 0}
    primary_nonpositive_later_positive = [
        row["case_id"]
        for row in completed
        if not row.get("primary_positive") and row.get("later_positive_after_first")
    ]
    labels = label_contract(rows)
    summary = {
        "schema": "tsds-saner2027-multistate-benchmark-v2",
        "input_root": str(input_root),
        "out_dir": str(out_dir),
        "case_count": len(cases),
        "completed_case_count": len(completed),
        "process_success_case_count": len(processed),
        "returncode_counts": dict(sorted(Counter(str(row.get("returncode")) for row in rows).items())),
        "timeout_count": sum(bool(row.get("timed_out")) for row in rows),
        "profile_case_count": sum(int(row.get("profile_count") or 0) > 0 for row in completed),
        "profile_count": sum(int(row.get("profile_count") or 0) for row in completed),
        "distinct_profile_count": len(all_profile_fingerprints),
        "distinct_profile_count_sum": sum(
            int(row.get("distinct_profile_count") or 0) for row in completed
        ),
        "sidecar_positive_case_count": len(sidecar_positive),
        "primary_positive_case_count": len(primary_positive),
        "expected_positive_case_count": len(expected_positive),
        "primary_positive_expected_overlap": len(primary_positive & expected_positive),
        "sidecar_positive_expected_overlap": len(sidecar_positive & expected_positive),
        "label_contract": labels,
        "primary_nonpositive_later_positive_cases": primary_nonpositive_later_positive,
        "aggregate_classes": dict(sorted(aggregate_classes.items())),
        "collection_complete_count": sum(bool(row.get("collection_complete")) for row in completed),
        "collection_incomplete_count": sum(
            not bool(row.get("collection_complete")) for row in completed
        ),
        "collection_blocker_counts": dict(
            sorted(
                Counter(
                    str(blocker)
                    for row in completed
                    for blocker in row.get("collection_blockers") or []
                ).items()
            )
        ),
        "candidate_wide_negative_count": sum(row.get("candidate_wide_negative") is True for row in completed),
        "claim_boundary": (
            "Bounded multi-state audit over the controlled 24-case ELF using the "
            "evaluator's opt-in settle window. Primary records preserve the ordinary "
            "selected-instance result; sidecar profiles use existential positive and "
            "non-escalating aggregation. This is not complete path-space coverage, "
            "firmware ground truth, or device-level exploitability."
        ),
    }
    write_json(out_dir / "summary.json", summary)
    lines = [
        "# SANER 2027 bounded multi-state benchmark",
        "",
        summary["claim_boundary"],
        "",
        f"- Cases: `{summary['case_count']}`; completed: `{summary['completed_case_count']}`.",
        f"- Cases with collected profiles: `{summary['profile_case_count']}`; profiles: `{summary['profile_count']}`.",
        f"- Bounded-complete cases: `{summary['collection_complete_count']}`; globally distinct profiles: `{summary['distinct_profile_count']}`.",
        f"- Primary positive cases: `{summary['primary_positive_case_count']}`; sidecar positive cases: `{summary['sidecar_positive_case_count']}`.",
        f"- Primary label contract: `{'PASS' if labels['matches'] else 'FAIL'}`; missing expected positives: `{labels['missing_expected_positive_indices']}`; unexpected positives: `{labels['unexpected_primary_positive_indices']}`.",
        f"- Primary non-positive cases with a later collected positive: `{len(primary_nonpositive_later_positive)}`.",
        f"- Candidate-wide-negative flags: `{summary['candidate_wide_negative_count']}`.",
        "",
        "The sidecar does not rewrite the original benchmark or upgrade a bounded collection to universal coverage.",
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_sha256sums(out_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if (
        len(processed) == len(cases)
        and not summary["candidate_wide_negative_count"]
        and labels["matches"]
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
