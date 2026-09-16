#!/usr/bin/env python3
"""Stress the conditioned source-link admission boundary.

This calibration exercises the bounded source-to-sink replay contract with
native transformation cases and adversarial mutations.  It is deliberately
separate from the historical firmware campaign: a passing case demonstrates
only that a complete serialized link is accepted when its byte trace agrees;
it does not establish historical source linkage or exploitability.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tsds.reconciliation_link import (  # noqa: E402
    build_verified_link,
    sha256_json,
    unverified_link,
)
from tsds.source_realizability import (  # noqa: E402
    SOURCE_REPLAY_SCHEMA,
    replay_reconciliation_link,
    replay_source_trace,
)


SOURCE = ROOT / "experiments" / "fixtures" / "tsds_source_link_fixture.c"
SCHEMA = "tsds-conditioned-link-adversarial-calibration-v1"

# The six operations are the complete bounded transform vocabulary exercised by
# the native source-link calibration fixture.
CASES: tuple[tuple[int, str, tuple[bytes, ...]], ...] = (
    (0, "copy", (b"ABC;", b"SAFE", bytes.fromhex("410042"))),
    (1, "replace_byte", (b"ABC;", b"SAFE", b";;&")),
    (2, "hex_encode", (b"AZ", bytes.fromhex("01ff"), b"safe")),
    (3, "reverse", (b"ABCD", b"SAFE", b"x;y")),
    (4, "percent_decode", (b"%41%42", b"SAFE", b"%3bX")),
    (5, "truncate", (b"ABCDEFG", b"AB", b"1234;")),
)


def build_trace(mode: int, operation: str, source: bytes) -> dict[str, Any]:
    transform: dict[str, Any] = {
        "step_id": "transform",
        "operation": operation,
        "input_step": "src",
    }
    if operation == "replace_byte":
        transform.update({"from": ord(";"), "to": ord("_")})
    if operation == "truncate":
        transform.update({"start": 0, "length": 4})
    return {
        "schema": SOURCE_REPLAY_SCHEMA,
        "source_variable": "x",
        "source_bytes_hex": source.hex(),
        "steps": [
            {"step_id": "src", "operation": "source", "source_variable": "x"},
            transform,
            {
                "step_id": "cmd",
                "operation": "concat",
                "parts": [
                    {"kind": "literal", "bytes_hex": b"echo ".hex()},
                    {"kind": "step", "step_id": "transform"},
                ],
            },
        ],
        "sink_step": "cmd",
        "mode": mode,
    }


def bind_trace(trace: dict[str, Any]) -> dict[str, Any]:
    unbound = replay_source_trace(trace)
    if not isinstance(unbound.get("sink_bytes_hex"), str):
        raise ValueError("cannot bind a trace without sink bytes")
    bound = copy.deepcopy(trace)
    bound["expected_sink_bytes_hex"] = unbound["sink_bytes_hex"]
    bound["expected_mapping"] = unbound["mapping"]
    return bound


def build_link(trace_result: dict[str, Any], binary_digest: str, operation: str) -> dict[str, Any]:
    mapping = trace_result["mapping"]
    constraint_digest = hashlib.sha256(
        f"conditioned-link-{operation}".encode("ascii")
    ).hexdigest()
    transform_step = {
        "step_id": "transform",
        "operation": operation,
        "input_variables": ["x"],
        "output_offsets": [row["sink_offset"] for row in mapping],
        "constraint_sha256": constraint_digest,
    }
    rows = [
        {
            **row,
            "source_variable": "x",
            "transform_step": "transform",
            "relation": "copy" if operation == "copy" else "derived",
            "constraint_sha256": constraint_digest,
        }
        for row in mapping
    ]
    return build_verified_link(
        program_sha256=binary_digest,
        sink_snapshot_sha256=hashlib.sha256(
            trace_result["sink_bytes_hex"].encode("ascii")
        ).hexdigest(),
        source_variables=["x"],
        transform_chain=[transform_step],
        source_to_sink=rows,
        max_input_length=256,
        terminator_offset=trace_result["sink_length"],
    )


def make_bound_fixture(operation: str, source: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    mode = next(mode for mode, name, _ in CASES if name == operation)
    trace = bind_trace(build_trace(mode, operation, source))
    replay = replay_source_trace(trace)
    return trace, build_link(replay, "a" * 64, operation)


def _resign_link(link: dict[str, Any]) -> dict[str, Any]:
    body = dict(link)
    body.pop("link_sha256", None)
    link["link_sha256"] = sha256_json(body)
    return link


def adversarial_mutations(
    trace: dict[str, Any], link: dict[str, Any]
) -> Iterable[tuple[str, dict[str, Any], dict[str, Any] | None]]:
    """Yield mutations that must not be admitted by the replay boundary."""

    yield "missing_link", copy.deepcopy(trace), None

    unverified = unverified_link(
        "reconstructed_symbolic_slot_is_not_linked_to_original_source_variables"
    )
    yield "unverified_link", copy.deepcopy(trace), unverified

    ambiguous = copy.deepcopy(link)
    ambiguous["status"] = "ambiguous"
    yield "ambiguous_link_status", copy.deepcopy(trace), _resign_link(ambiguous)

    wrong_sink = copy.deepcopy(trace)
    wrong_sink["expected_sink_bytes_hex"] = b"echo WRONG".hex()
    yield "expected_sink_mismatch", wrong_sink, copy.deepcopy(link)

    wrong_mapping = copy.deepcopy(trace)
    wrong_mapping["expected_mapping"][0]["source_offset"] += 1
    yield "expected_mapping_mismatch", wrong_mapping, copy.deepcopy(link)

    unsupported = copy.deepcopy(trace)
    unsupported["steps"][1]["operation"] = "opaque_wrapper"
    yield "unsupported_transform", unsupported, copy.deepcopy(link)

    wrong_source = copy.deepcopy(trace)
    wrong_source["source_variable"] = "other_source"
    wrong_source["steps"][0]["source_variable"] = "other_source"
    yield "source_variable_not_bound", wrong_source, copy.deepcopy(link)

    wrong_digest = copy.deepcopy(link)
    wrong_digest["sink_snapshot_sha256"] = "d" * 64
    yield "sink_digest_not_bound", copy.deepcopy(trace), _resign_link(wrong_digest)

    outside_input = copy.deepcopy(link)
    outside_input["source_to_sink"][0]["source_offset"] = 999
    outside_input["source_to_sink_sha256"] = sha256_json(outside_input["source_to_sink"])
    yield "source_offset_outside_input", copy.deepcopy(trace), _resign_link(outside_input)

    outside_cstring = copy.deepcopy(link)
    outside_cstring["source_to_sink"][0]["sink_offset"] = link["sink_cstring"]["terminator_offset"]
    outside_cstring["source_to_sink_sha256"] = sha256_json(outside_cstring["source_to_sink"])
    yield "sink_offset_outside_cstring", copy.deepcopy(trace), _resign_link(outside_cstring)

    duplicate_sink = copy.deepcopy(link)
    duplicate_sink["source_to_sink"][1]["sink_offset"] = duplicate_sink["source_to_sink"][0]["sink_offset"]
    duplicate_sink["source_to_sink_sha256"] = sha256_json(duplicate_sink["source_to_sink"])
    yield "duplicate_sink_offset", copy.deepcopy(trace), _resign_link(duplicate_sink)

    missing_constraint = copy.deepcopy(link)
    missing_constraint["source_to_sink"][0]["constraint_sha256"] = ""
    missing_constraint["source_to_sink_sha256"] = sha256_json(missing_constraint["source_to_sink"])
    yield "missing_mapping_constraint", copy.deepcopy(trace), _resign_link(missing_constraint)

    incomplete_snapshot = copy.deepcopy(link)
    incomplete_snapshot["sink_cstring"]["complete"] = False
    yield "incomplete_cstring_contract", copy.deepcopy(trace), _resign_link(incomplete_snapshot)


def assess(trace: dict[str, Any], link: dict[str, Any] | None) -> dict[str, Any]:
    result = replay_reconciliation_link(link, trace)
    return {
        "admitted": bool(result.get("admitted")),
        "issues": list(result.get("issues") or []),
        "replay_status": (result.get("replay") or {}).get("status"),
    }


def _native_sink_hex(binary: Path, mode: int, payload: bytes) -> tuple[int, str | None]:
    native = subprocess.run(
        [str(binary), str(mode), payload.hex()],
        capture_output=True,
        text=True,
        check=False,
    )
    fields = native.stdout.strip().split()
    sink_hex = fields[2] if len(fields) == 3 and fields[0] == "SINK_HEX" else None
    return native.returncode, sink_hex


def run(out_dir: Path) -> dict[str, Any]:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / (
        "tsds_source_link_fixture.exe"
        if os.name == "nt"
        else "tsds_source_link_fixture"
    )
    subprocess.run(
        [
            "gcc",
            "-O0",
            "-fno-inline",
            "-fno-builtin",
            "-fno-omit-frame-pointer",
            "-no-pie",
            str(SOURCE),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    rows: list[dict[str, Any]] = []

    for mode, operation, payloads in CASES:
        for index, payload in enumerate(payloads):
            trace = bind_trace(build_trace(mode, operation, payload))
            replay = replay_source_trace(trace)
            link = build_link(replay, binary_digest, operation)
            admission = assess(trace, link)
            native_returncode, native_hex = _native_sink_hex(binary, mode, payload)
            rows.append(
                {
                    "case_id": f"positive_{operation}_{index}",
                    "kind": "positive",
                    "operation": operation,
                    "source_bytes_hex": payload.hex(),
                    "expected_admitted": True,
                    "observed_admitted": admission["admitted"],
                    "replay_status": admission["replay_status"],
                    "issues": admission["issues"],
                    "native_returncode": native_returncode,
                    "native_sink_bytes_hex": native_hex,
                    "native_matches_replay": native_hex == replay.get("sink_bytes_hex"),
                }
            )

    base_trace, base_link = make_bound_fixture("copy", b"ABC;")
    for name, trace, link in adversarial_mutations(base_trace, base_link):
        admission = assess(trace, link)
        rows.append(
            {
                "case_id": f"negative_{name}",
                "kind": "negative",
                "operation": "copy",
                "expected_admitted": False,
                "observed_admitted": admission["admitted"],
                "replay_status": admission["replay_status"],
                "issues": admission["issues"],
                "native_returncode": None,
                "native_sink_bytes_hex": None,
                "native_matches_replay": None,
            }
        )

    positives = [row for row in rows if row["kind"] == "positive"]
    negatives = [row for row in rows if row["kind"] == "negative"]
    false_rejections = sum(not row["observed_admitted"] for row in positives)
    false_accepts = sum(row["observed_admitted"] for row in negatives)
    native_failures = sum(row["native_returncode"] != 0 for row in positives)
    native_mismatches = sum(not row["native_matches_replay"] for row in positives)
    summary = {
        "schema": SCHEMA,
        "case_count": len(rows),
        "positive_cases": len(positives),
        "negative_cases": len(negatives),
        "operation_count": len(CASES),
        "operations": [operation for _, operation, _ in CASES],
        "positive_admissions": sum(row["observed_admitted"] for row in positives),
        "negative_rejections": sum(not row["observed_admitted"] for row in negatives),
        "false_rejections": false_rejections,
        "false_accepts": false_accepts,
        "native_execution_failures": native_failures,
        "native_trace_mismatches": native_mismatches,
        "issue_counts": dict(
            sorted(
                Counter(
                    issue
                    for row in negatives
                    for issue in row["issues"]
                ).items()
            )
        ),
        "all_checks_pass": bool(
            not false_rejections
            and not false_accepts
            and not native_failures
            and not native_mismatches
        ),
        "claim_boundary": (
            "This finite calibration checks a bounded serialized source-to-sink "
            "replay and its fail-closed admission boundary. Positive cases also "
            "compare the replay with a native synthetic C fixture. It does not "
            "establish historical CT-SAT source linkage, firmware ground truth, "
            "solver completeness, or device-level exploitability."
        ),
    }
    (out_dir / "case_results.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "README.md").write_text(
        "# Conditioned-link adversarial calibration\n\n"
        + summary["claim_boundary"]
        + "\n\n"
        + f"- Cases: `{summary['case_count']}` (`{summary['positive_cases']}` positive, `{summary['negative_cases']}` adversarial).\n"
        + f"- Native positive cases: `{summary['positive_admissions']}/{summary['positive_cases']}` admitted; native/replay byte mismatches: `{summary['native_trace_mismatches']}`.\n"
        + f"- Adversarial cases rejected: `{summary['negative_rejections']}/{summary['negative_cases']}`; false accepts: `{summary['false_accepts']}`.\n"
        + "- No shell command was executed.\n",
        encoding="utf-8",
    )
    digest_lines = []
    for path in sorted(out_dir.iterdir()):
        if path.name == "SHA256SUMS":
            continue
        digest_lines.append(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
        )
    (out_dir / "SHA256SUMS").write_text("\n".join(digest_lines) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    summary = run(args.out_dir.resolve())
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["all_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
