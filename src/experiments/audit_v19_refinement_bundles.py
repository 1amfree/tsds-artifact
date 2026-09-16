#!/usr/bin/env python3
"""Verify target-specific TSDS residual-CEGAR bundles against source ledgers."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.model_refinement import (  # noqa: E402
    SummaryCandidate,
    candidate_admission,
    load_refinement_bundle,
)


SCHEMA = "tsds-v19-refinement-bundle-audit-v1"


def load_ledger(path: Path) -> dict[int, dict[str, Any]]:
    records = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"record is not an object: {path}:{line_number}")
        index = int(value.get("closure_idx"))
        if index in records:
            raise ValueError(f"duplicate closure index: {path}:{index}")
        records[index] = value
    return records


def candidate_object(value: dict[str, Any]) -> SummaryCandidate:
    return SummaryCandidate(
        kind=str(value.get("kind") or ""),
        target=str(value.get("target") or ""),
        source_kind=str(value.get("source_kind") or "source"),
        preconditions=tuple(str(item) for item in value.get("preconditions", [])),
        effects=tuple(str(item) for item in value.get("effects", [])),
        reason=str(value.get("reason") or ""),
        confidence=str(value.get("confidence") or "low"),
        evidence=str(value.get("evidence") or ""),
        command_template=str(value.get("command_template") or ""),
        source_slot=value.get("source_slot"),
        candidate_id=str(value.get("candidate_id") or ""),
    )


def audit_bundles(
    campaign: Path, bundle_dir: Path | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    bundle_dir = bundle_dir or campaign
    rows = []
    issues: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    violations: Counter[str] = Counter()
    source_verdicts: Counter[str] = Counter()
    per_target: dict[str, Counter[str]] = {}
    bundle_paths = sorted(bundle_dir.glob("*.refinement.json"))
    if not bundle_paths:
        raise ValueError(f"no refinement bundles found: {bundle_dir}")
    for bundle_path in bundle_paths:
        target = bundle_path.name.removesuffix(".refinement.json")
        ledger_path = campaign / f"{target}.results.jsonl"
        if not ledger_path.is_file():
            raise ValueError(f"source ledger missing for {bundle_path}")
        ledger = load_ledger(ledger_path)
        bundle = load_refinement_bundle(bundle_path)
        target_counts: Counter[str] = Counter()
        for bundle_record in bundle.get("records", []) or []:
            closure_idx = int(bundle_record.get("closure_idx", -1))
            source = ledger.get(closure_idx)
            if source is None:
                issues["candidate_closure_missing_from_source_ledger"] += len(
                    bundle_record.get("candidates") or []
                )
                continue
            source_verdict = str(source.get("verdict") or "UNKNOWN")
            source_verdicts[source_verdict] += len(bundle_record.get("candidates") or [])
            for value in bundle_record.get("candidates", []) or []:
                candidate = candidate_object(value)
                recorded = value.get("admission") or {}
                recomputed = candidate_admission(candidate, source).to_dict()
                candidate_issues = []
                if bool(recorded.get("admitted")) != bool(recomputed.get("admitted")):
                    candidate_issues.append("admission_decision_mismatch")
                if sorted(recorded.get("violations") or []) != sorted(
                    recomputed.get("violations") or []
                ):
                    candidate_issues.append("admission_violations_mismatch")
                if source_verdict != "RESIDUAL":
                    candidate_issues.append("candidate_source_not_residual")
                if not candidate.candidate_id:
                    candidate_issues.append("candidate_id_missing")
                issues.update(candidate_issues)
                kinds[candidate.kind] += 1
                admission = "admitted" if recorded.get("admitted") else "rejected"
                target_counts[admission] += 1
                target_counts["candidates"] += 1
                violations.update(str(item) for item in recorded.get("violations", []))
                rows.append(
                    {
                        "target": target,
                        "closure_idx": closure_idx,
                        "source_verdict": source_verdict,
                        "source_status": source.get("status"),
                        "candidate_id": candidate.candidate_id,
                        "kind": candidate.kind,
                        "summary_target": candidate.target,
                        "confidence": candidate.confidence,
                        "admitted": bool(recorded.get("admitted")),
                        "violations": ";".join(recorded.get("violations") or []),
                        "issues": ";".join(sorted(set(candidate_issues))),
                    }
                )
        target_counts["bundle_records"] = len(bundle.get("records") or [])
        target_counts["declared_candidates"] = int(bundle.get("candidate_count") or 0)
        if target_counts["candidates"] != target_counts["declared_candidates"]:
            issues["bundle_candidate_count_mismatch"] += 1
        per_target[target] = target_counts
    summary = {
        "schema": SCHEMA,
        "campaign": str(campaign),
        "bundle_dir": str(bundle_dir),
        "bundles": len(bundle_paths),
        "candidates": len(rows),
        "admitted": sum(bool(row["admitted"]) for row in rows),
        "rejected": sum(not bool(row["admitted"]) for row in rows),
        "candidate_kinds": dict(sorted(kinds.items())),
        "recorded_violations": dict(sorted(violations.items())),
        "source_verdicts": dict(sorted(source_verdicts.items())),
        "per_target": {
            target: dict(sorted(counts.items()))
            for target, counts in sorted(per_target.items())
        },
        "issue_counts": dict(sorted(issues.items())),
        "records_with_issues": sum(bool(row["issues"]) for row in rows),
        "valid": bool(bundle_paths) and not issues,
        "claim_boundary": (
            "Admitted candidates remain model hypotheses. Their bundle admission does "
            "not change a verdict without a separate sink-reaching replay and the normal "
            "shell-vector evidence contract."
        ),
    }
    return rows, summary


def write_outputs(out_dir: Path, rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "refinement_bundle_audit.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    fields = list(rows[0]) if rows else ["target", "closure_idx", "issues"]
    with (out_dir / "refinement_candidates.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "README.md").write_text(
        "# TSDS residual-CEGAR bundle audit\n\n"
        f"Bundles: **{summary['bundles']}**; candidates: **{summary['candidates']}**; "
        f"admitted: **{summary['admitted']}**; rejected: **{summary['rejected']}**.\n\n"
        + summary["claim_boundary"]
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument(
        "--bundle-dir",
        type=Path,
        default=None,
        help="Directory containing target-specific bundles; defaults to --campaign.",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--fail-on-issues", action="store_true")
    args = parser.parse_args()
    try:
        rows, summary = audit_bundles(
            args.campaign.resolve(),
            args.bundle_dir.resolve() if args.bundle_dir else None,
        )
        write_outputs(args.out_dir.resolve(), rows, summary)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"REFINEMENT_BUNDLE_AUDIT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.fail_on_issues and not summary["valid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
