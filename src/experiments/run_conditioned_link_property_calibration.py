#!/usr/bin/env python3
"""Run a deterministic property calibration for conditioned source links.

The calibration is deliberately separate from the firmware ledger.  It combines
randomized byte payloads, a small native C oracle, and adversarial link/trace
mutations.  A passing result is evidence for the bounded replay and admission
contract only; it is not evidence that a historical firmware path executed the
declared transform.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import random
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tsds.reconciliation_link import sha256_json  # noqa: E402
from tsds.source_realizability import replay_source_trace  # noqa: E402
from run_conditioned_link_adversarial_calibration import (  # noqa: E402
    CASES,
    assess,
    bind_trace,
    build_link,
    build_trace,
)


SCHEMA = "tsds-conditioned-link-property-calibration-v1"
SEED = 20260916
PAYLOADS_PER_OPERATION = 60
MUTATIONS_PER_OPERATION = 8
SOURCE = ROOT / "experiments" / "fixtures" / "tsds_source_link_fixture.c"


def _payloads(rng: random.Random) -> list[bytes]:
    """Return deterministic edge cases plus arbitrary byte payloads."""

    fixed = [
        b"A",
        b";",
        b"%41",
        b"%zz",
        b"%3bX",
        b"A\x00B",
        bytes(range(1, 17)),
        bytes([1, 0, 2, 255]),
        b"percent%41decode%3B",
    ]
    values = list(fixed)
    while len(values) < PAYLOADS_PER_OPERATION:
        length = rng.randrange(0, 65)
        if length == 0:
            length = 1
        first = rng.randrange(1, 256)
        values.append(bytes([first] + [rng.getrandbits(8) for _ in range(length - 1)]))
    return values[:PAYLOADS_PER_OPERATION]


def _native_sink_hex(binary: Path, mode: int, payload: bytes) -> tuple[int, str | None]:
    result = subprocess.run(
        [str(binary), str(mode), payload.hex()],
        capture_output=True,
        text=True,
        check=False,
    )
    fields = result.stdout.strip().split()
    sink_hex = fields[2] if len(fields) == 3 and fields[0] == "SINK_HEX" else None
    return result.returncode, sink_hex


def _resign(link: dict[str, Any]) -> dict[str, Any]:
    body = dict(link)
    body.pop("link_sha256", None)
    link["link_sha256"] = sha256_json(body)
    return link


def _mutations(
    trace: dict[str, Any],
    link: dict[str, Any],
) -> Iterable[tuple[str, dict[str, Any], dict[str, Any] | None]]:
    """Generate mutations that must be rejected by the admission boundary."""

    yield "missing_link", copy.deepcopy(trace), None

    missing_expected = copy.deepcopy(trace)
    missing_expected.pop("expected_mapping", None)
    yield "missing_expected_mapping", missing_expected, copy.deepcopy(link)

    wrong_sink = copy.deepcopy(trace)
    sink = bytes.fromhex(str(wrong_sink.get("expected_sink_bytes_hex") or ""))
    wrong_sink["expected_sink_bytes_hex"] = bytes(
        ([sink[0] ^ 1] if sink else [0]) + list(sink[1:])
    ).hex()
    yield "expected_sink_mismatch", wrong_sink, copy.deepcopy(link)

    wrong_mapping = copy.deepcopy(trace)
    mapping = wrong_mapping.get("expected_mapping") or []
    if mapping:
        mapping[0]["source_offset"] = int(mapping[0]["source_offset"]) + 1
    else:
        mapping.append({"sink_offset": 0, "source_offset": 0})
    wrong_mapping["expected_mapping"] = mapping
    yield "expected_mapping_mismatch", wrong_mapping, copy.deepcopy(link)

    wrong_variable = copy.deepcopy(trace)
    wrong_variable["source_variable"] = "unbound_source"
    for step in wrong_variable.get("steps", []):
        if step.get("operation") == "source":
            step["source_variable"] = "unbound_source"
    yield "source_variable_not_bound", wrong_variable, copy.deepcopy(link)

    wrong_digest = copy.deepcopy(link)
    wrong_digest["sink_snapshot_sha256"] = "d" * 64
    yield "sink_digest_not_bound", copy.deepcopy(trace), _resign(wrong_digest)

    outside_input = copy.deepcopy(link)
    if outside_input.get("source_to_sink"):
        outside_input["source_to_sink"][0]["source_offset"] = 1000000
    outside_input["source_to_sink_sha256"] = sha256_json(
        outside_input.get("source_to_sink")
    )
    yield "source_offset_outside_input", copy.deepcopy(trace), _resign(outside_input)

    outside_cstring = copy.deepcopy(link)
    cstring = outside_cstring.get("sink_cstring") or {}
    if outside_cstring.get("source_to_sink"):
        outside_cstring["source_to_sink"][0]["sink_offset"] = int(
            cstring.get("terminator_offset", 0)
        )
    outside_cstring["source_to_sink_sha256"] = sha256_json(
        outside_cstring.get("source_to_sink")
    )
    yield "sink_offset_outside_cstring", copy.deepcopy(trace), _resign(outside_cstring)


def run(out_dir: Path) -> dict[str, Any]:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / ("tsds_source_link_fixture.exe" if os.name == "nt" else "tsds_source_link_fixture")
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
    rng = random.Random(SEED)
    rows: list[dict[str, Any]] = []

    for mode, operation, _ in CASES:
        for index, payload in enumerate(_payloads(rng)):
            trace = bind_trace(build_trace(mode, operation, payload))
            replay = replay_source_trace(trace)
            link = build_link(replay, binary_digest, operation)
            admission = assess(trace, link)
            native_returncode, native_hex = _native_sink_hex(binary, mode, payload)
            rows.append(
                {
                    "case_id": f"property_positive_{operation}_{index:03d}",
                    "kind": "positive",
                    "operation": operation,
                    "source_length": len(payload),
                    "source_bytes_sha256": hashlib.sha256(payload).hexdigest(),
                    "expected_admitted": True,
                    "observed_admitted": admission["admitted"],
                    "replay_status": admission["replay_status"],
                    "issues": admission["issues"],
                    "native_returncode": native_returncode,
                    "native_matches_replay": native_hex == replay.get("sink_bytes_hex"),
                }
            )

            if index < MUTATIONS_PER_OPERATION:
                for mutation, mutated_trace, mutated_link in _mutations(trace, link):
                    mutated = assess(mutated_trace, mutated_link)
                    rows.append(
                        {
                            "case_id": f"property_negative_{operation}_{index:03d}_{mutation}",
                            "kind": "negative",
                            "operation": operation,
                            "mutation": mutation,
                            "expected_admitted": False,
                            "observed_admitted": mutated["admitted"],
                            "replay_status": mutated["replay_status"],
                            "issues": mutated["issues"],
                            "native_returncode": None,
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
        "seed": SEED,
        "payloads_per_operation": PAYLOADS_PER_OPERATION,
        "mutations_per_operation": MUTATIONS_PER_OPERATION,
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
            "This randomized finite calibration compares six bounded byte "
            "transforms against a native synthetic C fixture and checks that "
            "eight classes of serialized-link mutations are rejected. It does "
            "not establish historical firmware source linkage, solver "
            "completeness, firmware ground truth, or device exploitability."
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
        "# Conditioned-link property calibration\n\n"
        + summary["claim_boundary"]
        + "\n\n"
        + f"- Seed: `{summary['seed']}`; cases: `{summary['case_count']}` (`{summary['positive_cases']}` positive, `{summary['negative_cases']}` negative).\n"
        + f"- Native/replay byte mismatches: `{summary['native_trace_mismatches']}`; native execution failures: `{summary['native_execution_failures']}`.\n"
        + f"- Positive admissions: `{summary['positive_admissions']}/{summary['positive_cases']}`; adversarial rejections: `{summary['negative_rejections']}/{summary['negative_cases']}`; false accepts: `{summary['false_accepts']}`.\n"
        + "- No shell command was executed.\n",
        encoding="utf-8",
    )
    digest_lines = []
    for path in sorted(out_dir.iterdir()):
        if path.name == "SHA256SUMS":
            continue
        digest_lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
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
