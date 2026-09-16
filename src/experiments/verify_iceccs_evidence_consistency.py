#!/usr/bin/env python3
"""Cross-check independent ICECCS evidence ledgers without changing claims."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCHEMA = "tsds-iceccs-evidence-consistency-v1"
CLAIM_BOUNDARY = (
    "This gate checks cross-artifact accounting consistency only.  It does not "
    "replay SMT queries, establish source realizability, prove exhaustive path "
    "coverage, provide human ground truth, or establish device exploitability."
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def check_equal(issues: list[str], label: str, left: Any, right: Any) -> None:
    if left != right:
        issues.append(f"{label}:{left!r}!={right!r}")


def build_report(
    campaign_audit: dict[str, Any],
    performance: dict[str, Any],
    cross_solver: dict[str, Any],
    source_manifest: dict[str, Any],
    manuscript_guard: dict[str, Any],
) -> dict[str, Any]:
    issues: list[str] = []
    campaign = performance.get("campaign") or {}
    check_equal(issues, "campaign_target_count", campaign_audit.get("target_count"), campaign.get("target_count"))
    check_equal(issues, "campaign_record_count", campaign_audit.get("record_count"), campaign.get("records"))
    check_equal(issues, "campaign_matrix_profile_count", campaign_audit.get("matrix_profile_count"), campaign.get("matrix_profile_records"))
    check_equal(issues, "campaign_status_counts", campaign_audit.get("status_counts"), campaign.get("status_counts"))
    check_equal(issues, "campaign_valid", campaign_audit.get("valid"), True)
    check_equal(issues, "performance_valid", performance.get("valid"), True)

    audit_targets = campaign_audit.get("target_record_counts") or {}
    performance_targets = {
        str(row.get("target")): int(row.get("records") or 0)
        for row in performance.get("targets") or []
    }
    check_equal(issues, "target_record_counts", audit_targets, performance_targets)

    cross_totals = cross_solver.get("totals") or {}
    check_equal(issues, "cross_solver_valid", cross_solver.get("valid"), True)
    for key in (
        "observed_disagreement_count",
        "missing_left_count",
        "missing_right_count",
        "expected_disagreement_count",
    ):
        check_equal(issues, f"cross_solver_{key}", cross_totals.get(key), 0)
    query_targets = sum(
        1
        for row in performance.get("targets") or []
        if int(row.get("matrix_query_manifest_count") or 0) > 0
    )
    check_equal(issues, "query_target_count", cross_solver.get("target_count"), query_targets)

    check_equal(issues, "source_manifest_schema", source_manifest.get("schema"), "tsds-local-python-source-lock-v1")
    check_equal(issues, "source_manifest_unresolved_imports", source_manifest.get("unresolved_local_imports"), [])
    check_equal(issues, "manuscript_guard_pass", manuscript_guard.get("pass"), True)

    return {
        "schema": SCHEMA,
        "claim_boundary": CLAIM_BOUNDARY,
        "inputs": {
            "campaign_audit_schema": campaign_audit.get("schema"),
            "performance_schema": performance.get("schema"),
            "cross_solver_schema": cross_solver.get("schema"),
            "source_manifest_schema": source_manifest.get("schema"),
            "manuscript_guard_schema": manuscript_guard.get("schema"),
        },
        "observations": {
            "targets": campaign_audit.get("target_count"),
            "records": campaign_audit.get("record_count"),
            "matrix_profiles": campaign_audit.get("matrix_profile_count"),
            "query_targets": query_targets,
            "cross_solver_paired_replays": cross_totals.get("paired_replay_count"),
            "cross_solver_observed_agreement": cross_totals.get("observed_agreement_count"),
        },
        "issues": sorted(issues),
        "valid": not issues,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-audit", type=Path, required=True)
    parser.add_argument("--performance", type=Path, required=True)
    parser.add_argument("--cross-solver", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--manuscript-guard", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = build_report(
        load_json(args.campaign_audit.resolve()),
        load_json(args.performance.resolve()),
        load_json(args.cross_solver.resolve()),
        load_json(args.source_manifest.resolve()),
        load_json(args.manuscript_guard.resolve()),
    )
    args.out.resolve().write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
