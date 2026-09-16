#!/usr/bin/env python3
"""Unblind a frozen TSDS audit and compute claim-bounded calibration metrics."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


BINARY_LABELS = {"POSITIVE", "NEGATIVE"}
KNOWN_VERDICTS = {
    "VECTOR_SAT",
    "MATRIX_UNSAT",
    "NO_MODELED_SOURCE",
    "STATIC_SOURCE_INFERENCE",
    "STATIC_WARNING_REDUCTION",
    "RESIDUAL",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def unique_rows(
    rows: list[dict[str, str]], source: str
) -> tuple[dict[str, dict[str, str]], list[str]]:
    indexed: dict[str, dict[str, str]] = {}
    issues = []
    for line_no, row in enumerate(rows, start=2):
        record_id = str(row.get("record_id") or "").strip()
        if not record_id:
            issues.append(f"{source}_line_{line_no}_missing_record_id")
        elif record_id in indexed:
            issues.append(f"{source}_{record_id}_duplicate_record_id")
        else:
            indexed[record_id] = row
    return indexed, issues


def parse_bool(value: Any) -> bool | None:
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def project_verdict(verdict: str, contract_valid: bool, mode: str) -> str:
    if not contract_valid:
        return "UNRESOLVED"
    if verdict == "VECTOR_SAT":
        return "POSITIVE"
    if verdict == "MATRIX_UNSAT":
        return "NEGATIVE"
    if mode == "triage" and verdict in {
        "NO_MODELED_SOURCE",
        "STATIC_WARNING_REDUCTION",
    }:
        return "NEGATIVE"
    return "UNRESOLVED"


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total <= 0:
        return None
    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    radius = (
        z
        * math.sqrt(
            proportion * (1.0 - proportion) / total
            + z * z / (4.0 * total * total)
        )
        / denominator
    )
    return [round(max(0.0, center - radius), 4), round(min(1.0, center + radius), 4)]


def calibration_metrics(rows: list[dict[str, Any]], projection_field: str) -> dict[str, Any]:
    resolved_truth = [row for row in rows if row["ground_truth"] in BINARY_LABELS]
    comparable = [
        row for row in resolved_truth if row[projection_field] in BINARY_LABELS
    ]
    tp = sum(
        row[projection_field] == "POSITIVE" and row["ground_truth"] == "POSITIVE"
        for row in comparable
    )
    fp = sum(
        row[projection_field] == "POSITIVE" and row["ground_truth"] == "NEGATIVE"
        for row in comparable
    )
    tn = sum(
        row[projection_field] == "NEGATIVE" and row["ground_truth"] == "NEGATIVE"
        for row in comparable
    )
    fn = sum(
        row[projection_field] == "NEGATIVE" and row["ground_truth"] == "POSITIVE"
        for row in comparable
    )
    correct = tp + tn
    precision_n = tp + fp
    recall_n = tp + fn
    specificity_n = tn + fp
    precision = tp / precision_n if precision_n else None
    recall = tp / recall_n if recall_n else None
    specificity = tn / specificity_n if specificity_n else None
    accuracy = correct / len(comparable) if comparable else None
    f1 = (
        2.0 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "sample_records": len(rows),
        "resolved_ground_truth": len(resolved_truth),
        "comparable_records": len(comparable),
        "abstentions": len(resolved_truth) - len(comparable),
        "coverage": round(len(comparable) / len(resolved_truth), 4)
        if resolved_truth
        else None,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": round(accuracy, 4) if accuracy is not None else None,
        "accuracy_wilson_95": wilson_interval(correct, len(comparable)),
        "precision": round(precision, 4) if precision is not None else None,
        "precision_wilson_95": wilson_interval(tp, precision_n),
        "recall": round(recall, 4) if recall is not None else None,
        "recall_wilson_95": wilson_interval(tp, recall_n),
        "specificity": round(specificity, 4) if specificity is not None else None,
        "specificity_wilson_95": wilson_interval(tn, specificity_n),
        "f1": round(f1, 4) if f1 is not None else None,
    }


def unblind(
    annotation_dir: Path,
    audit_key_path: Path,
    sample_summary_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    annotation_summary = json.loads(
        (annotation_dir / "annotation_audit.json").read_text(encoding="utf-8")
    )
    protocol = json.loads(
        (annotation_dir / "ground_truth_protocol.json").read_text(encoding="utf-8")
    )
    sample_summary = json.loads(sample_summary_path.read_text(encoding="utf-8"))
    labels_path = annotation_dir / "ground_truth_labels.csv"
    labels, issues = unique_rows(read_csv(labels_path), "ground_truth_labels")
    key, key_issues = unique_rows(read_csv(audit_key_path), "audit_key")
    issues.extend(key_issues)

    if annotation_summary.get("valid") is not True:
        issues.append("annotation_audit_not_valid")
    if annotation_summary.get("independent_protocol_ready") is not True:
        issues.append("annotation_protocol_not_independent")
    if protocol.get("independent_of_tools") is not True:
        issues.append("ground_truth_protocol_not_independent")
    if protocol.get("labels_frozen_before_unblinding") is not True:
        issues.append("labels_not_frozen_before_unblinding")
    if sha256_file(labels_path) != protocol.get("annotation_sha256"):
        issues.append("annotation_sha256_mismatch")

    key_sha256 = sha256_file(audit_key_path)
    if key_sha256 != sample_summary.get("audit_key_sha256"):
        issues.append("sample_summary_audit_key_sha256_mismatch")
    if key_sha256 != protocol.get("audit_key_commitment_sha256"):
        issues.append("protocol_audit_key_commitment_mismatch")
    if protocol.get("blinded_sample_sha256") != sample_summary.get(
        "audit_blinded_sha256"
    ):
        issues.append("blinded_sample_commitment_mismatch")
    if protocol.get("repeatability_records_sha256") != sample_summary.get(
        "repeatability_records_sha256"
    ):
        issues.append("repeatability_consensus_commitment_mismatch")
    if protocol.get("label_definitions_sha256") != sample_summary.get(
        "label_definitions_sha256"
    ):
        issues.append("label_definitions_commitment_mismatch")
    if protocol.get("corpus_commitment_sha256") != sample_summary.get(
        "corpus_commitment_sha256"
    ):
        issues.append("corpus_commitment_mismatch")
    if protocol.get("campaign_results_sha256") != sample_summary.get(
        "campaign_results_sha256"
    ):
        issues.append("campaign_results_commitment_mismatch")
    if set(labels) != set(key):
        issues.append("ground_truth_and_audit_key_record_sets_differ")

    rows = []
    for record_id in sorted(set(labels) & set(key)):
        label = str(labels[record_id].get("ground_truth") or "").strip().upper()
        if label not in {"POSITIVE", "NEGATIVE", "UNRESOLVED"}:
            issues.append(f"{record_id}_invalid_ground_truth")
            continue
        key_row = key[record_id]
        verdict = str(key_row.get("tsds_verdict") or "").strip().upper()
        if verdict not in KNOWN_VERDICTS:
            issues.append(f"{record_id}_unknown_tsds_verdict")
        contract_valid = parse_bool(key_row.get("contract_valid"))
        if contract_valid is None:
            issues.append(f"{record_id}_invalid_contract_valid")
            contract_valid = False
        strict = project_verdict(verdict, contract_valid, "strict")
        triage = project_verdict(verdict, contract_valid, "triage")
        rows.append(
            {
                "record_id": record_id,
                "stratum": key_row.get("stratum"),
                "tsds_verdict": verdict,
                "evidence_provenance": key_row.get("evidence_provenance"),
                "contract_valid": contract_valid,
                "strict_projection": strict,
                "triage_projection": triage,
                "ground_truth": label,
                "strict_correct": strict == label if strict in BINARY_LABELS and label in BINARY_LABELS else None,
                "triage_correct": triage == label if triage in BINARY_LABELS and label in BINARY_LABELS else None,
            }
        )

    strata: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        stratum = str(row.get("stratum") or "unknown")
        strata[stratum][f"truth_{row['ground_truth']}"] += 1
        strata[stratum][f"strict_{row['strict_projection']}"] += 1
        strata[stratum][f"triage_{row['triage_projection']}"] += 1
    valid = not issues and bool(rows) and len(rows) == len(labels) == len(key)
    summary = {
        "schema": "tsds-ground-truth-unblinding-v1",
        "implementation": {
            "path": str(Path(__file__).resolve()),
            "sha256": sha256_file(Path(__file__).resolve()),
        },
        "valid": valid,
        "records": len(rows),
        "issues": sorted(set(issues)),
        "input_sha256": {
            "annotation_audit": sha256_file(annotation_dir / "annotation_audit.json"),
            "ground_truth_protocol": sha256_file(annotation_dir / "ground_truth_protocol.json"),
            "ground_truth_labels": sha256_file(labels_path),
            "audit_key": key_sha256,
            "sample_summary": sha256_file(sample_summary_path),
        },
        "strict_sink_semantic": calibration_metrics(rows, "strict_projection"),
        "triage_projection": calibration_metrics(rows, "triage_projection"),
        "by_stratum": {name: dict(counts) for name, counts in sorted(strata.items())},
        "claim_boundary": (
            "Strict metrics classify only contract-valid VECTOR_SAT and MATRIX_UNSAT "
            "records; all other TSDS outcomes abstain. Triage metrics additionally "
            "project NO_MODELED_SOURCE and STATIC_WARNING_REDUCTION as warning "
            "reductions. Neither projection establishes device-level exploitability."
        ),
    }
    return rows, summary


def write_outputs(
    out_dir: Path, rows: list[dict[str, Any]], summary: dict[str, Any]
) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty unblinding directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "unblinded_records.csv").open(
        "w", newline="", encoding="utf-8"
    ) as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "unblinding_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        "# TSDS ground-truth unblinding\n\n"
        f"Valid: **{summary['valid']}**; records: **{summary['records']}**.\n\n"
        + summary["claim_boundary"]
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--annotation-dir", type=Path, required=True)
    parser.add_argument("--audit-key", type=Path, required=True)
    parser.add_argument("--sample-summary", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--require-valid", action="store_true")
    args = parser.parse_args()
    rows, summary = unblind(
        args.annotation_dir, args.audit_key, args.sample_summary
    )
    if rows:
        write_outputs(args.out_dir, rows, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.require_valid and not summary["valid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
