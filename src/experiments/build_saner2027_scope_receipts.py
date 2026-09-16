#!/usr/bin/env python3
"""Materialize the T01 evidence-scope contract and historical receipts.

The receipts are deliberately separate from the paper tables.  They make the
scope of an evidence record machine-checkable while preserving unknown states
instead of coercing them into binary labels.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.evidence_scope import (  # noqa: E402
    CANDIDATE_STATUSES,
    EVIDENCE_MODES,
    EVIDENCE_SCOPE_SCHEMA,
    LOCAL_PROFILES,
    MATRIX_DECISIONS,
    TRI_FIELDS,
    TRI_STATES,
    conservation_summary,
    scoped_binary_metrics,
    validate_scope_record,
)


DEFAULT_MAP = (
    PROJECT_ROOT
    / "experiment_reports/saner2027_remediation_20260913_t00_t01/T00_T01/candidate_identity_map.jsonl"
)
DEFAULT_CORPUS = (
    PROJECT_ROOT
    / "experiment_reports/saner2027_remediation_20260913_t00_t01/T00_T01/corpus_manifest.json"
)
DEFAULT_VECTOR_PROFILE = (
    PROJECT_ROOT
    / "experiment_reports/tsds_v20_release_20260718_r7_v8/tsds_v20_evidence_extension_20260718_r7/paper_tables/paper_vector_profile.csv"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: expected a JSON object")
        rows.append(value)
    return rows


def write_new(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8", newline="\n")


def schema_document() -> dict[str, Any]:
    return {
        "schema": EVIDENCE_SCOPE_SCHEMA,
        "versioning": "A producer must change schema when admission semantics change.",
        "evidence_modes": sorted(EVIDENCE_MODES),
        "local_profiles": sorted(LOCAL_PROFILES),
        "candidate_statuses": sorted(CANDIDATE_STATUSES),
        "tri_state_values": sorted(TRI_STATES),
        "tri_state_fields": list(TRI_FIELDS),
        "matrix_decisions": sorted(MATRIX_DECISIONS),
        "admission_rules": {
            "direct": [
                "profile is sv_sat",
                "candidate_status is direct_evidence",
                "direct_provenance is true",
                "source_link_status is observed or linked",
            ],
            "conditioned": [
                "profile is ct_sat",
                "candidate_status is conditioned_feasibility",
                "primary_aggregate_eligible is false",
                "conditioned records cannot be promoted to direct without new evidence",
            ],
            "local": [
                "profile is selected-instance scoped",
                "m_filt requires exactly one complete decision for each expected vector",
                "local profiles cannot set candidate_vulnerability to CONTRADICTED",
            ],
            "static_and_residual": [
                "static observations and residual obligations retain unknown semantic fields",
                "neither mode is a candidate-wide negative verdict",
            ],
        },
        "claim_boundary": (
            "The schema validates record structure, evidence level and quantifier scope. "
            "It does not prove solver correctness, source realizability, or device-level exploitability."
        ),
    }


def label_scope_text() -> str:
    return """# T01 evidence scope and label contract

## Objects and quantifiers

TSDS keeps four scopes separate: a candidate identity, a selected sink-instance
identity, a local evidence profile, and an optional candidate-level status.  A
selected-instance profile describes only the instance represented by its record;
it is not a universal statement about every state reachable from the candidate.

`direct` evidence is admitted only when byte provenance is observed at the final
shell-facing argument and the sink binding is explicit.  `conditioned` evidence
records template feasibility under a declared conditioning contract.  It is not
observed provenance and cannot be promoted to `direct` by naming or formatting.

`local/m_filt` means that the complete configured matrix was UNSAT for the
selected instance.  `local/nms` means that no modeled source was present for the
selected instance.  Neither label is a candidate-wide negative conclusion.
`static` records preserve an upstream observation, and `residual` records preserve
an unresolved obligation.  Both remain actionable work items rather than binary
safe labels.

## Tri-valued obligations

The fields `input_effect`, `instance_source_realizable`, `matrix_feasible`,
`bounded_program_effect_exists`, and `candidate_vulnerability` use
`CONFIRMED`, `CONTRADICTED`, `UNKNOWN`, or `NOT_APPLICABLE`.  Missing evidence is
`UNKNOWN`; it is never silently coerced to `CONTRADICTED`.  `NOT_APPLICABLE` is
used only when a field is outside the declared evidence mode, not when a check
failed to run.

## Matrix completeness

An M-Filt record must list a nonempty expected vector set, exactly one decision
for each expected vector, `complete: true`, and `MATRIX_UNSAT` for every decision.
Missing, duplicate, or unsupported vectors invalidate the record.  A SAT or
inconclusive cell is not an M-Filt result.

## Reporting rule

Counts are reported with their denominator and source artifact.  Binary accuracy
is reported only on resolved pairs; when an abstention or invalid row remains,
full-coverage accuracy is `unknown`.  Historical counts are traceability receipts,
not independent ground truth.
"""


def _base_record(**overrides: Any) -> dict[str, Any]:
    record = {
        "schema": EVIDENCE_SCOPE_SCHEMA,
        "candidate_id": "candidate-test",
        "instance_id": "instance-test",
        "evidence_mode": "direct",
        "local_profile": "sv_sat",
        "candidate_status": "direct_evidence",
        "direct_provenance": True,
        "source_link_status": "observed",
        "primary_aggregate_eligible": True,
        "input_effect": "UNKNOWN",
        "instance_source_realizable": "UNKNOWN",
        "matrix_feasible": "CONFIRMED",
        "bounded_program_effect_exists": "UNKNOWN",
        "candidate_vulnerability": "UNKNOWN",
        "matrix": None,
    }
    record.update(overrides)
    return record


def _complete_matrix() -> dict[str, Any]:
    vector_ids = [f"v{index}" for index in range(11)]
    return {
        "expected_vector_ids": vector_ids,
        "decisions": [
            {"vector_id": vector_id, "decision": "MATRIX_UNSAT"}
            for vector_id in vector_ids
        ],
        "complete": True,
    }


def regression_receipts() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []

    def check(name: str, record: Mapping[str, Any], expected: bool) -> None:
        issues = validate_scope_record(record)
        passed = bool(issues) is (not expected)
        cases.append(
            {
                "name": name,
                "expected_valid": expected,
                "observed_valid": not issues,
                "issues": issues,
                "status": "PASS" if passed else "FAIL",
            }
        )

    check("direct_observed_admits", _base_record(), True)
    check(
        "conditioned_cannot_be_primary",
        _base_record(
            evidence_mode="conditioned",
            local_profile="ct_sat",
            candidate_status="conditioned_feasibility",
            direct_provenance=False,
            source_link_status="unknown",
            primary_aggregate_eligible=True,
            matrix_feasible="CONFIRMED",
        ),
        False,
    )
    check(
        "local_profile_cannot_claim_candidate_negative",
        _base_record(
            evidence_mode="local",
            local_profile="nms",
            candidate_status="selected_instance_profile",
            direct_provenance=False,
            source_link_status="not_applicable",
            primary_aggregate_eligible=False,
            matrix_feasible="NOT_APPLICABLE",
            candidate_vulnerability="CONTRADICTED",
        ),
        False,
    )
    check(
        "incomplete_matrix_rejected",
        _base_record(
            evidence_mode="local",
            local_profile="m_filt",
            candidate_status="selected_instance_profile",
            direct_provenance=False,
            source_link_status="not_applicable",
            primary_aggregate_eligible=False,
            matrix_feasible="CONTRADICTED",
            matrix={"expected_vector_ids": ["v0"], "decisions": [], "complete": False},
        ),
        False,
    )
    check(
        "complete_matrix_admits",
        _base_record(
            evidence_mode="local",
            local_profile="m_filt",
            candidate_status="selected_instance_profile",
            direct_provenance=False,
            source_link_status="not_applicable",
            primary_aggregate_eligible=False,
            matrix_feasible="CONTRADICTED",
            matrix=_complete_matrix(),
        ),
        True,
    )
    metrics = scoped_binary_metrics(
        [("CONFIRMED", "CONFIRMED"), ("UNKNOWN", "CONFIRMED")]
    )
    metrics_pass = (
        metrics["coverage"] == 0.5
        and metrics["resolved_accuracy"] == 1.0
        and metrics["full_accuracy"] is None
    )
    cases.append(
        {
            "name": "abstention_not_coerced_to_binary",
            "expected_valid": True,
            "observed_valid": metrics_pass,
            "issues": [] if metrics_pass else ["abstention_metric_regression"],
            "metrics": metrics,
            "status": "PASS" if metrics_pass else "FAIL",
        }
    )
    return {
        "schema": "tsds-saner2027-t01-regression-receipts-v1",
        "cases": cases,
        "passed": sum(case["status"] == "PASS" for case in cases),
        "failed": sum(case["status"] == "FAIL" for case in cases),
        "status": "PASS" if all(case["status"] == "PASS" for case in cases) else "FAIL",
        "claim_boundary": (
            "These are contract and accounting regressions. They do not validate "
            "the semantic correctness of historical solver results."
        ),
    }


def matrix_receipt(path: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            rows.append(row)
    required = {"vector_id", "SAT", "UNSAT", "INCONCLUSIVE"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError(f"matrix profile is missing required columns: {path}")
    totals: dict[str, int] = {}
    decisions = {"SAT": 0, "UNSAT": 0, "INCONCLUSIVE": 0}
    for row in rows:
        vector_id = str(row.get("vector_id") or "")
        if not vector_id or vector_id in totals:
            raise ValueError(f"matrix profile has missing or duplicate vector: {vector_id!r}")
        values: dict[str, int] = {}
        for key in decisions:
            try:
                value = int(row.get(key) or "")
            except (TypeError, ValueError) as exc:
                raise ValueError(f"matrix profile has non-integer {key}: {vector_id}") from exc
            if value < 0:
                raise ValueError(f"matrix profile has negative {key}: {vector_id}")
            values[key] = value
            decisions[key] += value
        total = sum(values.values())
        totals[vector_id] = total
    unique_totals = sorted(set(totals.values()))
    profile_count = unique_totals[0] if len(unique_totals) == 1 else None
    return {
        "source": str(path.relative_to(PROJECT_ROOT)).replace("\\", "/"),
        "sha256": sha256_file(path),
        "vector_count": len(rows),
        "per_vector_totals": totals,
        "profiled_records": profile_count,
        "decision_counts": decisions,
        "cells": sum(decisions.values()),
        "expected_vector_count": 11,
        "expected_profiled_records": 102,
        "expected_cells": 1122,
        "expected_decision_counts": {"SAT": 679, "UNSAT": 292, "INCONCLUSIVE": 151},
        "valid": (
            len(rows) == 11
            and profile_count == 102
            and sum(decisions.values()) == 1122
            and decisions == {"SAT": 679, "UNSAT": 292, "INCONCLUSIVE": 151}
        ),
        "claim_boundary": (
            "The matrix receipt checks the historical table export and its denominator. "
            "It does not independently rerun any matrix query."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity-map", type=Path, default=DEFAULT_MAP)
    parser.add_argument("--corpus-manifest", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--vector-profile", type=Path, default=DEFAULT_VECTOR_PROFILE)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--expected-total", type=int, default=518)
    parser.add_argument("--expected-raw", type=int, default=546)
    args = parser.parse_args()

    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(f"refusing to overwrite non-empty output: {out_dir}")

    try:
        identity_map = load_jsonl(args.identity_map.resolve())
        corpus = load_json(args.corpus_manifest.resolve())
        scope_counts = conservation_summary(identity_map, expected_total=args.expected_total)
        regressions = regression_receipts()
        matrix = matrix_receipt(args.vector_profile.resolve())
        raw_closures = int(corpus.get("raw_closures") or 0)
        historical = {
            "raw_closures": raw_closures,
            "normalized_records": len(identity_map),
            "expected_raw_closures": args.expected_raw,
            "expected_normalized_records": args.expected_total,
            "raw_normalized_conservation": raw_closures == args.expected_raw and len(identity_map) == args.expected_total,
            "matrix": matrix,
        }
        output = {
            "schema": "tsds-saner2027-t01-counts-v1",
            "scope_summary": scope_counts,
            "historical": historical,
            "inputs": {
                "identity_map": {
                    "path": str(args.identity_map.resolve().relative_to(PROJECT_ROOT)).replace("\\", "/"),
                    "sha256": sha256_file(args.identity_map.resolve()),
                },
                "corpus_manifest": {
                    "path": str(args.corpus_manifest.resolve().relative_to(PROJECT_ROOT)).replace("\\", "/"),
                    "sha256": sha256_file(args.corpus_manifest.resolve()),
                },
                "vector_profile": {
                    "path": str(args.vector_profile.resolve().relative_to(PROJECT_ROOT)).replace("\\", "/"),
                    "sha256": sha256_file(args.vector_profile.resolve()),
                },
            },
            "valid": bool(
                scope_counts["valid"]
                and historical["raw_normalized_conservation"]
                and matrix["valid"]
                and regressions["status"] == "PASS"
            ),
            "claim_boundary": (
                "T01 receipts enforce evidence scope and historical accounting. They do "
                "not turn analyzer-level records into solver proofs or ground truth."
            ),
        }
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"T01_SCOPE_RECEIPT_ERROR: {exc}")
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)
    write_new(out_dir / "evidence_schema.json", json.dumps(schema_document(), indent=2, sort_keys=True) + "\n")
    write_new(out_dir / "label_scope.md", label_scope_text())
    write_new(out_dir / "regression_receipts.json", json.dumps(regressions, indent=2, sort_keys=True) + "\n")
    write_new(out_dir / "counts.json", json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"valid": output["valid"], "counts": output}, indent=2, sort_keys=True))
    return 0 if output["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
