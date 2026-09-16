#!/usr/bin/env python3
"""Validate independent dual-auditor labels and emit a frozen ground truth."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.statistical_evidence import (  # noqa: E402
    agreement_statistics,
    cohen_kappa_components,
)


LABELS = ("POSITIVE", "NEGATIVE", "UNRESOLVED")
EVIDENCE_TYPES = ("DISASSEMBLY", "RUNTIME", "SOURCE_REVIEW", "OTHER")
BOUND_PROTOCOL_SCHEMA = "tsds-ground-truth-protocol-declaration-v3"
LABEL_DEFINITION_VERSION = "tsds-sink-evidence-labels-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_sha256(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def is_rfc3339_timestamp(value: Any) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def cohen_kappa(pairs: list[tuple[str, str]]) -> float | None:
    value, _, _ = cohen_kappa_components(pairs, LABELS)
    return round(value, 4) if value is not None else None


def _unique_rows(
    rows: list[dict[str, Any]], source: str
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    indexed: dict[str, dict[str, Any]] = {}
    issues = []
    for line_no, row in enumerate(rows, start=2):
        record_id = str(row.get("record_id") or "").strip()
        if not record_id:
            issues.append(f"{source}_line_{line_no}_missing_record_id")
            continue
        if record_id in indexed:
            issues.append(f"{source}_{record_id}_duplicate_record_id")
            continue
        indexed[record_id] = row
    return indexed, issues


def _validate_auditor_row(
    row: dict[str, Any], record_id: str, source: str
) -> tuple[str, str, list[str]]:
    issues = []
    auditor_id = str(row.get("auditor_id") or "").strip()
    label = str(row.get("label") or "").strip().upper()
    evidence_type = str(row.get("evidence_type") or "").strip().upper()
    evidence_locator = str(row.get("evidence_locator") or "").strip()
    rationale = str(row.get("rationale") or "").strip()
    if not auditor_id:
        issues.append(f"{source}_{record_id}_missing_auditor_id")
    if label not in LABELS:
        issues.append(f"{source}_{record_id}_invalid_label")
    if evidence_type not in EVIDENCE_TYPES:
        issues.append(f"{source}_{record_id}_invalid_evidence_type")
    if not evidence_locator:
        issues.append(f"{source}_{record_id}_missing_evidence_locator")
    if not rationale:
        issues.append(f"{source}_{record_id}_missing_rationale")
    return auditor_id, label, issues


def _expected_record_ids(path: Path | None) -> tuple[set[str] | None, list[str]]:
    if path is None:
        return None, []
    rows = read_csv(path)
    indexed, issues = _unique_rows(rows, "blinded_sample")
    if not indexed:
        issues.append("blinded_sample_has_no_records")
    return set(indexed), issues


def validate_independent_annotations(
    auditor_a_rows: list[dict[str, Any]],
    auditor_b_rows: list[dict[str, Any]],
    adjudication_rows: list[dict[str, Any]],
    protocol: dict[str, Any],
    expected_ids: set[str] | None = None,
    blinded_sample_sha256: str | None = None,
    label_definitions_sha256: str | None = None,
    corpus_commitment_sha256: str | None = None,
    require_bound_protocol: bool = False,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    left, issues = _unique_rows(auditor_a_rows, "auditor_a")
    right, right_issues = _unique_rows(auditor_b_rows, "auditor_b")
    adjudication, adjudication_issues = _unique_rows(
        adjudication_rows, "adjudication"
    )
    issues.extend(right_issues)
    issues.extend(adjudication_issues)
    observed_ids = set(left) | set(right)
    if expected_ids is not None:
        for record_id in sorted(expected_ids - set(left)):
            issues.append(f"auditor_a_{record_id}_missing_record")
        for record_id in sorted(expected_ids - set(right)):
            issues.append(f"auditor_b_{record_id}_missing_record")
        for record_id in sorted(observed_ids - expected_ids):
            issues.append(f"{record_id}_not_in_blinded_sample")
        for record_id in sorted(set(adjudication) - expected_ids):
            issues.append(f"adjudication_{record_id}_not_in_blinded_sample")
        record_ids = sorted(expected_ids)
    else:
        record_ids = sorted(observed_ids)

    pairs: list[tuple[str, str]] = []
    final_rows = []
    disagreements = 0
    auditor_a_ids: set[str] = set()
    auditor_b_ids: set[str] = set()
    adjudicator_ids: set[str] = set()
    for record_id in record_ids:
        left_row = left.get(record_id)
        right_row = right.get(record_id)
        if left_row is None or right_row is None:
            continue
        left_id, left_label, row_issues = _validate_auditor_row(
            left_row, record_id, "auditor_a"
        )
        issues.extend(row_issues)
        right_id, right_label, row_issues = _validate_auditor_row(
            right_row, record_id, "auditor_b"
        )
        issues.extend(row_issues)
        if left_id:
            auditor_a_ids.add(left_id)
        if right_id:
            auditor_b_ids.add(right_id)
        if left_label not in LABELS or right_label not in LABELS:
            continue
        pairs.append((left_label, right_label))
        if left_label == right_label:
            final_rows.append({"record_id": record_id, "ground_truth": left_label})
            continue
        disagreements += 1
        row = adjudication.get(record_id)
        if row is None:
            issues.append(f"{record_id}_missing_adjudication")
            continue
        adjudicator_id = str(row.get("adjudicator_id") or "").strip()
        label = str(row.get("label") or "").strip().upper()
        locator = str(row.get("evidence_locator") or "").strip()
        rationale = str(row.get("rationale") or "").strip()
        if not adjudicator_id:
            issues.append(f"{record_id}_missing_adjudicator_id")
        else:
            adjudicator_ids.add(adjudicator_id)
        if label not in LABELS:
            issues.append(f"{record_id}_invalid_adjudication_label")
        if not locator:
            issues.append(f"{record_id}_missing_adjudication_evidence_locator")
        if not rationale:
            issues.append(f"{record_id}_missing_adjudication_rationale")
        if adjudicator_id and adjudicator_id in {left_id, right_id}:
            issues.append(f"{record_id}_adjudicator_not_independent")
        if label in LABELS:
            final_rows.append({"record_id": record_id, "ground_truth": label})

    if len(auditor_a_ids) != 1:
        issues.append("auditor_a_identity_not_unique")
    if len(auditor_b_ids) != 1:
        issues.append("auditor_b_identity_not_unique")
    if auditor_a_ids & auditor_b_ids:
        issues.append("auditors_not_distinct")

    declared_a = str(protocol.get("auditor_a_id") or "").strip()
    declared_b = str(protocol.get("auditor_b_id") or "").strip()
    declared_adjudicator = str(protocol.get("adjudicator_id") or "").strip()
    if auditor_a_ids and declared_a not in auditor_a_ids:
        issues.append("protocol_auditor_a_mismatch")
    if auditor_b_ids and declared_b not in auditor_b_ids:
        issues.append("protocol_auditor_b_mismatch")
    if disagreements and adjudicator_ids and declared_adjudicator not in adjudicator_ids:
        issues.append("protocol_adjudicator_mismatch")
    if protocol.get("independent_of_tools") is not True:
        issues.append("protocol_independence_not_declared")
    if protocol.get("labels_frozen_before_unblinding") is not True:
        issues.append("protocol_labels_not_frozen")
    if protocol.get("audit_key_withheld_until_freeze") is not True:
        issues.append("protocol_key_withholding_not_declared")
    if require_bound_protocol:
        if protocol.get("schema") != BOUND_PROTOCOL_SCHEMA:
            issues.append("protocol_schema_not_bound_v3")
        if protocol.get("label_definition_version") != LABEL_DEFINITION_VERSION:
            issues.append("protocol_label_definition_mismatch")
        declared_sample_hash = str(
            protocol.get("blinded_sample_sha256") or ""
        ).strip().lower()
        if not is_sha256(declared_sample_hash):
            issues.append("protocol_blinded_sample_sha256_invalid")
        elif blinded_sample_sha256 and declared_sample_hash != blinded_sample_sha256:
            issues.append("protocol_blinded_sample_sha256_mismatch")
        if not is_sha256(protocol.get("audit_key_commitment_sha256")):
            issues.append("protocol_audit_key_commitment_invalid")
        if not is_sha256(protocol.get("campaign_results_sha256")):
            issues.append("protocol_campaign_results_sha256_invalid")
        declared_label_hash = str(
            protocol.get("label_definitions_sha256") or ""
        ).strip().lower()
        if not is_sha256(declared_label_hash):
            issues.append("protocol_label_definitions_sha256_invalid")
        elif (
            label_definitions_sha256
            and declared_label_hash != label_definitions_sha256
        ):
            issues.append("protocol_label_definitions_sha256_mismatch")
        declared_corpus_hash = str(
            protocol.get("corpus_commitment_sha256") or ""
        ).strip().lower()
        if not is_sha256(declared_corpus_hash):
            issues.append("protocol_corpus_commitment_sha256_invalid")
        elif (
            corpus_commitment_sha256
            and declared_corpus_hash != corpus_commitment_sha256
        ):
            issues.append("protocol_corpus_commitment_sha256_mismatch")
        repeatability_hash = protocol.get("repeatability_records_sha256")
        if repeatability_hash not in (None, "") and not is_sha256(
            repeatability_hash
        ):
            issues.append("protocol_repeatability_records_sha256_invalid")
        frozen_at = str(protocol.get("labels_frozen_at_utc") or "").strip()
        if not is_rfc3339_timestamp(frozen_at):
            issues.append("protocol_labels_frozen_at_utc_invalid")
        try:
            declared_records = int(protocol.get("sample_records"))
        except (TypeError, ValueError):
            declared_records = -1
        if declared_records != len(record_ids):
            issues.append("protocol_sample_record_count_mismatch")

    agreements = sum(left_label == right_label for left_label, right_label in pairs)
    agreement = agreement_statistics(pairs, LABELS)
    valid = not issues and len(final_rows) == len(record_ids) and bool(record_ids)
    summary = {
        "schema": "tsds-ground-truth-annotation-audit-v3",
        "mode": "independent_dual_auditor",
        "protocol_declaration_schema": protocol.get("schema"),
        "label_definition_version": protocol.get("label_definition_version"),
        "auditor_a_id": declared_a,
        "auditor_b_id": declared_b,
        "adjudicator_id": declared_adjudicator,
        "labels_frozen_at_utc": protocol.get("labels_frozen_at_utc"),
        "audit_key_commitment_sha256": protocol.get(
            "audit_key_commitment_sha256"
        ),
        "label_definitions_sha256": protocol.get("label_definitions_sha256"),
        "corpus_commitment_sha256": protocol.get("corpus_commitment_sha256"),
        "campaign_results_sha256": protocol.get("campaign_results_sha256"),
        "repeatability_records_sha256": protocol.get(
            "repeatability_records_sha256"
        ),
        "records": len(record_ids),
        "complete_pairs": len(pairs),
        "agreements": agreements,
        "disagreements": disagreements,
        "percent_agreement": round(100.0 * agreements / len(pairs), 2) if pairs else 0.0,
        "cohen_kappa": cohen_kappa(pairs),
        "cohen_kappa_bootstrap_95": agreement["cohen_kappa_bootstrap_95"],
        "agreement_statistics": agreement,
        "final_labels": len(final_rows),
        "label_distribution": dict(Counter(row["ground_truth"] for row in final_rows)),
        "issues": sorted(set(issues)),
        "valid": valid,
        "independent_protocol_ready": valid,
    }
    return final_rows, summary


def validate_rows(
    rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Validate the legacy combined sheet without asserting independence."""
    issues = []
    indexed, duplicate_issues = _unique_rows(rows, "combined")
    issues.extend(duplicate_issues)
    pairs = []
    final_rows = []
    disagreements = 0
    for record_id, row in indexed.items():
        left = str(row.get("auditor_a_label") or "").upper()
        right = str(row.get("auditor_b_label") or "").upper()
        adjudicated = str(row.get("adjudicated_label") or "").upper()
        if left not in LABELS:
            issues.append(f"{record_id}_invalid_a_label")
        if right not in LABELS:
            issues.append(f"{record_id}_invalid_b_label")
        if left in LABELS and right in LABELS:
            pairs.append((left, right))
            if left != right:
                disagreements += 1
                if adjudicated not in LABELS:
                    issues.append(f"{record_id}_missing_adjudication")
            final = left if left == right else adjudicated
            if final in LABELS:
                final_rows.append({"record_id": record_id, "ground_truth": final})
    agreements = sum(left == right for left, right in pairs)
    agreement = agreement_statistics(pairs, LABELS)
    summary = {
        "schema": "tsds-ground-truth-annotation-audit-v3",
        "mode": "legacy_combined_non_independent",
        "records": len(rows),
        "complete_pairs": len(pairs),
        "agreements": agreements,
        "disagreements": disagreements,
        "percent_agreement": round(100.0 * agreements / len(pairs), 2) if pairs else 0.0,
        "cohen_kappa": cohen_kappa(pairs),
        "cohen_kappa_bootstrap_95": agreement["cohen_kappa_bootstrap_95"],
        "agreement_statistics": agreement,
        "final_labels": len(final_rows),
        "issues": sorted(set(issues)),
        "valid": not issues and len(final_rows) == len(rows),
        "independent_protocol_ready": False,
    }
    return final_rows, summary


def write_outputs(
    out_dir: Path,
    final_rows: list[dict[str, str]],
    summary: dict[str, Any],
    input_hashes: dict[str, str],
) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty audit directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary.setdefault(
        "implementation",
        {
            "path": str(Path(__file__).resolve()),
            "sha256": sha256_file(Path(__file__).resolve()),
        },
    )
    labels_path = out_dir / "ground_truth_labels.csv"
    with labels_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["record_id", "ground_truth"], lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(final_rows)
    summary["input_sha256"] = input_hashes
    summary["annotation_sha256"] = sha256_file(labels_path)
    (out_dir / "annotation_audit.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    protocol = {
        "schema": "tsds-ground-truth-protocol-v3",
        "independent_of_tools": bool(summary.get("independent_protocol_ready")),
        "labels_frozen_before_unblinding": bool(summary.get("independent_protocol_ready")),
        "auditor_count": 2 if summary.get("independent_protocol_ready") else 0,
        "adjudication_complete": bool(summary.get("valid")),
        "annotation_sha256": summary["annotation_sha256"],
        "blinded_sample_sha256": input_hashes.get("blinded_sample"),
        "protocol_declaration_sha256": input_hashes.get("protocol_declaration"),
        "audit_key_commitment_sha256": summary.get(
            "audit_key_commitment_sha256"
        ),
        "label_definition_version": summary.get("label_definition_version"),
        "label_definitions_sha256": summary.get("label_definitions_sha256"),
        "corpus_commitment_sha256": summary.get("corpus_commitment_sha256"),
        "campaign_results_sha256": summary.get("campaign_results_sha256"),
        "repeatability_records_sha256": summary.get(
            "repeatability_records_sha256"
        ),
        "auditor_a_id": summary.get("auditor_a_id"),
        "auditor_b_id": summary.get("auditor_b_id"),
        "adjudicator_id": summary.get("adjudicator_id"),
        "labels_frozen_at_utc": summary.get("labels_frozen_at_utc"),
    }
    (out_dir / "ground_truth_protocol.json").write_text(
        json.dumps(protocol, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--annotations", type=Path, help="Legacy combined sheet")
    mode.add_argument("--auditor-a", type=Path, help="First private annotation file")
    parser.add_argument("--auditor-b", type=Path)
    parser.add_argument("--adjudication", type=Path)
    parser.add_argument("--blinded-sample", type=Path)
    parser.add_argument("--protocol-declaration", type=Path)
    parser.add_argument("--label-definitions", type=Path)
    parser.add_argument("--corpus-commitment", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()

    input_hashes: dict[str, str] = {}
    if args.annotations:
        rows = read_csv(args.annotations)
        final_rows, summary = validate_rows(rows)
        input_hashes["annotations"] = sha256_file(args.annotations)
    else:
        required = {
            "auditor_b": args.auditor_b,
            "adjudication": args.adjudication,
            "blinded_sample": args.blinded_sample,
            "protocol_declaration": args.protocol_declaration,
            "label_definitions": args.label_definitions,
            "corpus_commitment": args.corpus_commitment,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            parser.error("independent mode requires: " + ", ".join(missing))
        expected_ids, sample_issues = _expected_record_ids(args.blinded_sample)
        protocol = json.loads(args.protocol_declaration.read_text(encoding="utf-8"))
        blinded_sample_sha256 = sha256_file(args.blinded_sample)
        label_definitions_sha256 = sha256_file(args.label_definitions)
        corpus_commitment_sha256 = sha256_file(args.corpus_commitment)
        final_rows, summary = validate_independent_annotations(
            read_csv(args.auditor_a),
            read_csv(args.auditor_b),
            read_csv(args.adjudication),
            protocol,
            expected_ids,
            blinded_sample_sha256=blinded_sample_sha256,
            label_definitions_sha256=label_definitions_sha256,
            corpus_commitment_sha256=corpus_commitment_sha256,
            require_bound_protocol=True,
        )
        summary["audit_key_commitment_sha256"] = protocol.get(
            "audit_key_commitment_sha256"
        )
        summary["label_definition_version"] = protocol.get(
            "label_definition_version"
        )
        summary["label_definitions_sha256"] = protocol.get(
            "label_definitions_sha256"
        )
        summary["campaign_results_sha256"] = protocol.get(
            "campaign_results_sha256"
        )
        summary["repeatability_records_sha256"] = protocol.get(
            "repeatability_records_sha256"
        )
        summary["corpus_commitment_sha256"] = protocol.get(
            "corpus_commitment_sha256"
        )
        if sample_issues:
            summary["issues"] = sorted(set(summary["issues"] + sample_issues))
            summary["valid"] = False
            summary["independent_protocol_ready"] = False
        for name, path in {
            "auditor_a": args.auditor_a,
            "auditor_b": args.auditor_b,
            "adjudication": args.adjudication,
            "blinded_sample": args.blinded_sample,
            "protocol_declaration": args.protocol_declaration,
            "label_definitions": args.label_definitions,
            "corpus_commitment": args.corpus_commitment,
        }.items():
            input_hashes[name] = sha256_file(path)

    write_outputs(args.out_dir, final_rows, summary, input_hashes)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.require_complete and not summary["valid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
