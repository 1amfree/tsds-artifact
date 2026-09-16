#!/usr/bin/env python3
"""Execute a bounded source-link fixture and compare it with trace replay."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
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

SOURCE = ROOT / "experiments" / "fixtures" / "tsds_source_link_fixture.c"

CASES = (
    (0, "copy", [b"ABC;", b"SAFE", bytes.fromhex("410042")]),
    (1, "replace_byte", [b"ABC;", b"SAFE", b";;&"]),
    (2, "hex_encode", [b"AZ", bytes.fromhex("01ff"), b"safe"]),
    (3, "reverse", [b"ABCD", b"SAFE", b"x;y"]),
    (4, "percent_decode", [b"%41%42", b"SAFE", b"%3bX"]),
    (5, "truncate", [b"ABCDEFG", b"AB", b"1234;"]),
)


def _trace(mode: int, operation: str, source: bytes) -> dict[str, Any]:
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
    }


def _link(trace_result: dict[str, Any], binary_digest: str, mode: int) -> dict[str, Any]:
    mapping = trace_result["mapping"]
    constraint_digest = hashlib.sha256(f"fixture-transform-{mode}".encode()).hexdigest()
    transform_step = {
        "step_id": "transform",
        "operation": CASES[mode][1],
        "input_variables": ["x"],
        "output_offsets": [row["sink_offset"] for row in mapping],
        "constraint_sha256": constraint_digest,
    }
    rows = [
        {
            **row,
            "source_variable": "x",
            "transform_step": "transform",
            "relation": "copy" if mode == 0 else "derived",
            "constraint_sha256": constraint_digest,
        }
        for row in mapping
    ]
    return build_verified_link(
        program_sha256=binary_digest,
        sink_snapshot_sha256=hashlib.sha256(trace_result["sink_bytes_hex"].encode()).hexdigest(),
        source_variables=["x"],
        transform_chain=[transform_step],
        source_to_sink=rows,
        max_input_length=256,
        terminator_offset=trace_result["sink_length"],
    )


def run(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / "tsds_source_link_fixture"
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
            trace = _trace(mode, operation, payload)
            unbound = replay_source_trace(trace)
            bound_trace = dict(trace)
            bound_trace["expected_sink_bytes_hex"] = unbound["sink_bytes_hex"]
            bound_trace["expected_mapping"] = unbound["mapping"]
            replay = replay_source_trace(bound_trace)
            link = _link(replay, binary_digest, mode)
            admission = replay_reconciliation_link(link, bound_trace)
            native = subprocess.run(
                [str(binary), str(mode), payload.hex()],
                capture_output=True,
                text=True,
                check=False,
            )
            native_hex = None
            fields = native.stdout.strip().split()
            if len(fields) == 3 and fields[0] == "SINK_HEX":
                native_hex = fields[2]
            rows.append(
                {
                    "case_id": f"{operation}_{index}",
                    "mode": mode,
                    "operation": operation,
                    "source_bytes_hex": payload.hex(),
                    "trace_status": replay.get("status"),
                    "link_admitted": bool(admission.get("admitted")),
                    "native_returncode": native.returncode,
                    "native_sink_bytes_hex": native_hex,
                    "native_matches_trace": native_hex == replay.get("sink_bytes_hex"),
                    "mapping_count": len(replay.get("mapping") or []),
                    "admission_issues": admission.get("issues", []),
                }
            )
    summary = {
        "schema": "tsds-native-source-link-calibration-v1",
        "case_count": len(rows),
        "operation_count": len(CASES),
        "native_execution_pass": sum(row["native_returncode"] == 0 for row in rows),
        "native_trace_byte_matches": sum(row["native_matches_trace"] for row in rows),
        "trace_replay_pass": sum(row["trace_status"] == "PASS" for row in rows),
        "link_admission_pass": sum(row["link_admitted"] for row in rows),
        "native_trace_byte_mismatches": sum(not row["native_matches_trace"] for row in rows),
        "link_rejections": sum(not row["link_admitted"] for row in rows),
        "claim_boundary": (
            "Finite native execution of an original synthetic C fixture plus "
            "independent byte-trace and Link_c replay. It does not establish "
            "historical CT-SAT source linkage, firmware ground truth, or exploitability."
        ),
    }
    summary["all_checks_pass"] = bool(
        summary["native_execution_pass"] == len(rows)
        and summary["native_trace_byte_matches"] == len(rows)
        and summary["trace_replay_pass"] == len(rows)
        and summary["link_admission_pass"] == len(rows)
    )
    (out_dir / "case_results.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.out_dir.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["all_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
