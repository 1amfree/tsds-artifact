#!/usr/bin/env python3
"""Reconcile the raw V20 positive-result taxonomy.

This is an evidence-only accounting audit.  It separates direct sink-byte
provenance from the 34 historical reconciliation rows and reports the raw
``evidence_conditioning`` field exactly as serialized.  The latter is kept as
a metadata warning when it disagrees with the provenance/recovery fields; it
is never used to upgrade a conditioned result.  This audit does not establish
source realizability, solver soundness, firmware precision, or exploitability.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


EXPECTED = {
    "record_count": 518,
    "vector_sat": 85,
    "direct_provenance": 51,
    "reconciled_provenance": 34,
    "reconciled_recovery": 34,
    "direct_recovery_null": 51,
    "direct_sink_byte_claim": 37,
    "reconciled_sink_byte_claim": 34,
    "direct_observed_prefix_claim": 14,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_null(value: Any) -> bool:
    return value is None or value == ""


def audit_campaign(campaign_dir: Path, expected_targets: int | None = None) -> dict[str, Any]:
    paths = sorted(campaign_dir.glob("*.results.jsonl"))
    issues: list[str] = []
    warnings: list[str] = []
    if expected_targets is not None and len(paths) != expected_targets:
        issues.append("target_file_count_mismatch")
    if not paths:
        issues.append("no_result_files")

    rows: list[dict[str, Any]] = []
    inventory: list[dict[str, Any]] = []
    for path in paths:
        file_rows = 0
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            issues.append(f"file_unreadable:{path.name}")
            continue
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                issues.append(f"malformed_json:{path.name}:{line_number}")
                continue
            if not isinstance(value, dict):
                issues.append(f"row_not_object:{path.name}:{line_number}")
                continue
            row = dict(value)
            row["_audit_target"] = path.name[: -len(".results.jsonl")]
            row["_audit_line"] = line_number
            rows.append(row)
            file_rows += 1
        try:
            inventory.append(
                {
                    "name": path.name,
                    "rows": file_rows,
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
        except OSError:
            issues.append(f"file_stat_failed:{path.name}")

    vector_rows = [row for row in rows if row.get("verdict") == "VECTOR_SAT"]
    provenance = Counter(str(row.get("evidence_provenance")) for row in vector_rows)
    recovery = Counter(
        "null" if _is_null(row.get("analysis_recovery")) else str(row.get("analysis_recovery"))
        for row in vector_rows
    )
    claims = Counter(str(row.get("admissible_claim")) for row in vector_rows)
    conditioning = Counter(str(row.get("evidence_conditioning")) for row in vector_rows)
    paper_buckets = Counter(str(row.get("paper_claim_bucket")) for row in vector_rows)

    taxonomy_rows: list[dict[str, Any]] = []
    for row in vector_rows:
        reconciled = row.get("evidence_provenance") == "SINK_RECONCILED"
        conditioning_value = row.get("evidence_conditioning")
        metadata_mismatch = reconciled and conditioning_value != "conditioned"
        if metadata_mismatch:
            warnings.append("reconciled_rows_raw_conditioning_field_not_conditioned")
        taxonomy_rows.append(
            {
                "target": row["_audit_target"],
                "line": row["_audit_line"],
                "closure_idx": row.get("closure_idx"),
                "source_addr": row.get("source_addr"),
                "sink_addr": row.get("sink_addr"),
                "verdict": row.get("verdict"),
                "evidence_provenance": row.get("evidence_provenance"),
                "analysis_recovery": row.get("analysis_recovery"),
                "evidence_conditioning_raw": conditioning_value,
                "admissible_claim": row.get("admissible_claim"),
                "paper_claim_bucket": row.get("paper_claim_bucket"),
                "metadata_mismatch": metadata_mismatch,
            }
        )

    if len(rows) != EXPECTED["record_count"]:
        issues.append("record_count_not_518")
    if len(vector_rows) != EXPECTED["vector_sat"]:
        issues.append("vector_sat_count_not_85")
    if provenance.get("DIRECT_SINK_BYTE", 0) != EXPECTED["direct_provenance"]:
        issues.append("direct_provenance_count_not_51")
    if provenance.get("SINK_RECONCILED", 0) != EXPECTED["reconciled_provenance"]:
        issues.append("reconciled_provenance_count_not_34")
    if recovery.get("static_dynamic_taint_reconciliation", 0) != EXPECTED["reconciled_recovery"]:
        issues.append("reconciled_recovery_count_not_34")
    if recovery.get("null", 0) != EXPECTED["direct_recovery_null"]:
        issues.append("direct_recovery_null_count_not_51")
    if claims.get("direct_sink_byte_vector_sat", 0) != EXPECTED["direct_sink_byte_claim"]:
        issues.append("direct_sink_byte_claim_count_not_37")
    if claims.get("reconciled_sink_byte_vector_sat", 0) != EXPECTED["reconciled_sink_byte_claim"]:
        issues.append("reconciled_claim_count_not_34")
    if claims.get("direct_observed_prefix_vector_sat", 0) != EXPECTED["direct_observed_prefix_claim"]:
        issues.append("direct_observed_prefix_claim_count_not_14")
    if provenance.get("DIRECT_SINK_BYTE", 0) + provenance.get("SINK_RECONCILED", 0) != len(vector_rows):
        issues.append("provenance_partition_does_not_sum_to_vector_sat")

    conditioning_mismatch_count = sum(
        row["metadata_mismatch"] for row in taxonomy_rows
    )
    if conditioning_mismatch_count:
        warnings.append("raw_evidence_conditioning_metadata_requires_interpretation")

    result = {
        "schema": "tsds-historical-v20-taxonomy-audit-v1",
        "campaign_dir": str(campaign_dir),
        "target_count": len(paths),
        "record_count": len(rows),
        "vector_sat_count": len(vector_rows),
        "provenance_counts": dict(sorted(provenance.items())),
        "analysis_recovery_counts": dict(sorted(recovery.items())),
        "admissible_claim_counts": dict(sorted(claims.items())),
        "raw_evidence_conditioning_counts": dict(sorted(conditioning.items())),
        "paper_claim_bucket_counts": dict(sorted(paper_buckets.items())),
        "taxonomy_partition": {
            "direct_observed_provenance": provenance.get("DIRECT_SINK_BYTE", 0),
            "reconciled_provenance": provenance.get("SINK_RECONCILED", 0),
            "sum": provenance.get("DIRECT_SINK_BYTE", 0) + provenance.get("SINK_RECONCILED", 0),
            "equals_vector_sat": provenance.get("DIRECT_SINK_BYTE", 0)
            + provenance.get("SINK_RECONCILED", 0)
            == len(vector_rows),
        },
        "conditioning_metadata_mismatch_count": conditioning_mismatch_count,
        "metadata_warnings": sorted(set(warnings)),
        "file_inventory": inventory,
        "row_taxonomy": taxonomy_rows,
        "accounting_valid": not issues,
        "valid": not issues,
        "claim_boundary": (
            "This report reconciles serialized historical V20 accounting fields. "
            "DIRECT_SINK_BYTE is counted separately from SINK_RECONCILED, and the "
            "raw evidence_conditioning field is reported without reinterpretation. "
            "The 34 reconciled rows are not upgraded here: source-link admission, "
            "solver replay, exhaustive state coverage, firmware precision, and "
            "device exploitability require separate evidence."
        ),
        "issues": sorted(set(issues)),
    }
    return result


def write_outputs(out_dir: Path, result: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "taxonomy_audit.json"
    summary_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    fields = [
        "target",
        "line",
        "closure_idx",
        "source_addr",
        "sink_addr",
        "verdict",
        "evidence_provenance",
        "analysis_recovery",
        "evidence_conditioning_raw",
        "admissible_claim",
        "paper_claim_bucket",
        "metadata_mismatch",
    ]
    with (out_dir / "vector_sat_taxonomy.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(result["row_taxonomy"])
    lines = [
        "# Historical V20 taxonomy reconciliation audit",
        "",
        f"Valid for serialized accounting: **{result['valid']}**",
        f"Records: **{result['record_count']}**",
        f"VECTOR_SAT rows: **{result['vector_sat_count']}**",
        f"Direct observed provenance: **{result['provenance_counts'].get('DIRECT_SINK_BYTE', 0)}**",
        f"Reconciled provenance: **{result['provenance_counts'].get('SINK_RECONCILED', 0)}**",
        f"Raw conditioning metadata mismatches on reconciled rows: **{result['conditioning_metadata_mismatch_count']}**",
        "",
        "The raw field is reported verbatim.  A metadata mismatch is not treated as evidence that a conditioned row is direct, and no source link is synthesized by this audit.",
        "The report is accounting evidence only; it does not establish source realizability, solver semantics, exhaustive path coverage, firmware precision, or exploitability.",
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    digest_lines = []
    for path in sorted(out_dir.iterdir()):
        if path.name != "SHA256SUMS" and path.is_file():
            digest_lines.append(f"{sha256_file(path)}  {path.name}")
    (out_dir / "SHA256SUMS").write_text("\n".join(digest_lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--expected-targets", type=int, default=None)
    args = parser.parse_args()
    try:
        result = audit_campaign(args.campaign_dir.resolve(), args.expected_targets)
        write_outputs(args.out_dir.resolve(), result)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"HISTORICAL_V20_TAXONOMY_AUDIT_ERROR: {exc}")
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
