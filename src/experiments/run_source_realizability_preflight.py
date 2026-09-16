#!/usr/bin/env python3
"""Run a small preflight for the conditioned source-realizability contract.

The cases use declarative byte traces and do not execute a firmware binary or a
shell.  They validate the independent replay implementation and its link
admission boundary; they are not a production CT-SAT validation result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tsds.reconciliation_link import build_verified_link  # noqa: E402
from tsds.source_realizability import (  # noqa: E402
    SOURCE_REPLAY_SCHEMA,
    replay_reconciliation_link,
    replay_source_trace,
)


SCHEMA = "tsds-source-realizability-preflight-v1"


def _copy_trace(source: bytes, expected_sink: bytes, mapping: list[dict[str, int]]) -> dict[str, Any]:
    return {
        "schema": SOURCE_REPLAY_SCHEMA,
        "source_variable": "x",
        "source_bytes_hex": source.hex(),
        "steps": [
            {"step_id": "src", "operation": "source", "source_variable": "x"},
            {"step_id": "copy0", "operation": "copy", "input_step": "src"},
            {
                "step_id": "cmd",
                "operation": "concat",
                "parts": [
                    {"kind": "literal", "bytes_hex": b"echo ".hex()},
                    {"kind": "step", "step_id": "copy0"},
                ],
            },
        ],
        "sink_step": "cmd",
        "expected_sink_bytes_hex": expected_sink.hex(),
        "expected_mapping": mapping,
    }


def _link() -> dict[str, Any]:
    digest = "b" * 64
    return build_verified_link(
        program_sha256="a" * 64,
        sink_snapshot_sha256=hashlib.sha256(b"6563686f204142433b").hexdigest(),
        source_variables=["x"],
        transform_chain=[
            {
                "step_id": "copy0",
                "operation": "copy",
                "input_variables": ["x"],
                "output_offsets": [5, 6, 7, 8],
                "constraint_sha256": digest,
            }
        ],
        source_to_sink=[
            {
                "sink_offset": offset,
                "source_offset": offset - 5,
                "source_variable": "x",
                "transform_step": "copy0",
                "relation": "copy",
                "constraint_sha256": digest,
            }
            for offset in range(5, 9)
        ],
        max_input_length=16,
        terminator_offset=9,
    )


def _cases() -> list[dict[str, Any]]:
    return [
        {
            "id": "copy_concat_exact",
            "expected": "PASS",
            "trace": _copy_trace(
                b"ABC;",
                b"echo ABC;",
                [{"sink_offset": index, "source_offset": index - 5} for index in range(5, 9)],
            ),
        },
        {
            "id": "first_nul_terminates",
            "expected": "PASS",
            "trace": _copy_trace(
                b"AB\x00;",
                b"echo AB",
                [{"sink_offset": 5, "source_offset": 0}, {"sink_offset": 6, "source_offset": 1}],
            ),
        },
        {
            "id": "declared_sink_mismatch",
            "expected": "MISMATCH",
            "trace": _copy_trace(b"ABC", b"echo WRONG", []),
        },
        {
            "id": "unsupported_wrapper",
            "expected": "UNSUPPORTED",
            "trace": {
                "schema": SOURCE_REPLAY_SCHEMA,
                "source_variable": "x",
                "source_bytes_hex": b"A".hex(),
                "steps": [
                    {"step_id": "src", "operation": "source", "source_variable": "x"},
                    {"step_id": "cmd", "operation": "opaque_wrapper", "input_step": "src"},
                ],
                "sink_step": "cmd",
                "expected_sink_bytes_hex": b"A".hex(),
                "expected_mapping": [{"sink_offset": 0, "source_offset": 0}],
            },
        },
        {
            "id": "unbound_trace",
            "expected": "TRACE_ONLY",
            "trace": {
                "schema": SOURCE_REPLAY_SCHEMA,
                "source_variable": "x",
                "source_bytes_hex": b"A".hex(),
                "steps": [{"step_id": "src", "operation": "source", "source_variable": "x"}],
                "sink_step": "src",
            },
        },
        {
            "id": "link_and_trace_agree",
            "expected": "PASS",
            "trace": _copy_trace(
                b"ABC;",
                b"echo ABC;",
                [{"sink_offset": index, "source_offset": index - 5} for index in range(5, 9)],
            ),
            "link": _link(),
        },
    ]


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def run(out_dir: Path) -> dict[str, Any]:
    cases = _cases()
    rows: list[dict[str, Any]] = []
    for case in cases:
        if case.get("link") is not None:
            result = replay_reconciliation_link(case["link"], case["trace"])
            observed = "PASS" if result["admitted"] else "REJECTED"
        else:
            result = replay_source_trace(case["trace"])
            observed = str(result.get("status"))
        rows.append({
            "case_id": case["id"],
            "expected_status": case["expected"],
            "observed_status": observed,
            "matches_expectation": observed == case["expected"],
            "result": result,
            "trace_sha256": _sha256(_canonical(case["trace"])),
        })
    summary = {
        "schema": SCHEMA,
        "case_count": len(rows),
        "observed_status_counts": dict(sorted(Counter(row["observed_status"] for row in rows).items())),
        "expectation_matches": sum(bool(row["matches_expectation"]) for row in rows),
        "all_expectations_match": all(bool(row["matches_expectation"]) for row in rows),
        "firmware_execution": False,
        "shell_execution": False,
        "ground_truth": False,
        "claim_boundary": (
            "This preflight checks an independent declarative byte-trace replay "
            "and link-admission contract only. It does not establish binary "
            "execution, source reachability, solver correctness, firmware ground "
            "truth, or exploitability."
        ),
    }
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "case_results.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "README.md").write_text(
        "# Source-realizability replay preflight\n\n"
        + summary["claim_boundary"]
        + "\n\n"
        + f"- Cases: `{summary['case_count']}`\n"
        + f"- Statuses: `{summary['observed_status_counts']}`\n"
        + f"- Expectations matched: `{summary['expectation_matches']}/{summary['case_count']}`\n"
        + "- No firmware or shell was executed.\n",
        encoding="utf-8",
    )
    sums = []
    for path in sorted(out_dir.iterdir()):
        if path.name == "SHA256SUMS":
            continue
        sums.append(f"{_sha256(path.read_bytes())}  {path.name}")
    (out_dir / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("experiment_reports/saner2027_remediation_20260913_t00_t01/T04_source_realizability_preflight_v1"),
    )
    args = parser.parse_args()
    summary = run(args.out_dir.resolve())
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["all_expectations_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
