#!/usr/bin/env python3
"""Compare TSDS with an external validator under an explicit evidence budget.

The comparator refuses a superiority claim unless the external result declares
its version, commit, command, budget, and input hashes. Precision/recall are
computed only for records carrying independent ground truth.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
import statistics
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.statistical_evidence import paired_bootstrap_differences  # noqa: E402


REQUIRED_TOOL_FIELDS = ("name", "version", "commit", "command")
REQUIRED_BUDGET_FIELDS = (
    "per_record_timeout_sec",
    "max_memory_mb",
    "host",
    "architecture",
    "cpu_count",
    "cache_policy",
)
BASELINE_VERDICTS = {"POSITIVE", "NEGATIVE", "UNRESOLVED", "REACHED"}
GROUND_TRUTH_LABELS = {"POSITIVE", "NEGATIVE", "UNRESOLVED"}
COMPARISON_MODES = {"same_candidate_validator", "native_frontend"}
SIGNIFICANCE_ALPHA = 0.05


def normalize_addr(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    try:
        return hex(int(text, 16 if text.startswith("0x") else 0))
    except ValueError:
        return text


def comparison_key(
    record: dict[str, Any], include_closure_idx: bool = True
) -> str:
    closure_idx = record.get("closure_idx")
    parts = [
        str(record.get("target") or ""),
        normalize_addr(record.get("source_addr")),
        normalize_addr(record.get("sink_addr")),
    ]
    if include_closure_idx and closure_idx is not None:
        parts.append(str(closure_idx))
    return "|".join(parts)


def target_from_path(path: Path) -> str:
    suffix = ".results.jsonl"
    return path.name[: -len(suffix)] if path.name.endswith(suffix) else path.stem


def collapsed_verdict(verdicts: list[str]) -> str:
    unique = sorted(set(str(value) for value in verdicts))
    return unique[0] if len(unique) == 1 else "MIXED"


def load_tsds_records(
    campaign_dir: Path, comparison_mode: str = "same_candidate_validator"
) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    include_closure_idx = comparison_mode == "same_candidate_validator"
    for path in sorted(campaign_dir.rglob("*.results.jsonl")):
        target = target_from_path(path)
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            raw = json.loads(line)
            row = {
                "target": target,
                "closure_idx": raw.get("closure_idx"),
                "source_addr": raw.get("source_addr"),
                "sink_addr": raw.get("sink_addr"),
                "verdict": raw.get("verdict"),
                "provenance": raw.get("evidence_provenance"),
                "contract_valid": raw.get("evidence_contract_valid"),
                "elapsed_sec": raw.get("elapsed_sec"),
                "path": str(path),
                "line": line_no,
            }
            key = comparison_key(row, include_closure_idx=include_closure_idx)
            if key in rows:
                if include_closure_idx:
                    raise ValueError(f"duplicate TSDS comparison key: {key}")
                rows[key]["collapsed_records"] += 1
                rows[key]["collapsed_verdicts"] = sorted(
                    set(rows[key]["collapsed_verdicts"]) | {str(row.get("verdict"))}
                )
                rows[key]["verdict"] = collapsed_verdict(
                    rows[key]["collapsed_verdicts"]
                )
                rows[key]["contract_valid"] = bool(
                    rows[key].get("contract_valid") is True
                    and row.get("contract_valid") is True
                )
                continue
            row["collapsed_records"] = 1
            row["collapsed_verdicts"] = [str(row.get("verdict"))]
            rows[key] = row
    if not rows:
        raise ValueError(f"no TSDS records in {campaign_dir}")
    return rows


def normalize_hash(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text.split(":", 1)[1] if text.startswith("sha256:") else text


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_runtime_manifest(path: Path | None, expected: Any) -> dict[str, Any]:
    expected_hash = normalize_hash(expected)
    row = {
        "path": str(path) if path is not None else None,
        "expected_sha256": expected_hash or None,
        "actual_sha256": None,
        "verified": False,
    }
    if path is None or not path.is_file() or not is_sha256(expected_hash):
        return row
    row["actual_sha256"] = sha256_file(path)
    row["verified"] = row["actual_sha256"] == expected_hash
    return row


def is_sha256(value: Any) -> bool:
    digest = normalize_hash(value)
    return len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)


def manifest_input_hashes(
    path: Path,
    targets: set[str],
    kinds: tuple[str, ...] = ("binary", "mango"),
) -> set[str]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    hashes = set()
    for row in (manifest.get("reproducibility") or {}).get("campaign_inputs") or []:
        if str(row.get("target")) not in targets:
            continue
        for kind in kinds:
            digest = normalize_hash((row.get(kind) or {}).get("sha256"))
            if digest:
                hashes.add(digest)
    return hashes


def validate_baseline_document(
    document: dict[str, Any], expected_input_hashes: set[str] | None = None
) -> list[str]:
    issues = []
    tool = document.get("tool") or {}
    budget = document.get("budget") or {}
    comparison_mode = str(document.get("comparison_mode") or "")
    if comparison_mode not in COMPARISON_MODES:
        issues.append("missing_or_invalid_comparison_mode")
    for field in REQUIRED_TOOL_FIELDS:
        if not tool.get(field):
            issues.append(f"missing_tool_{field}")
    for field in REQUIRED_BUDGET_FIELDS:
        if budget.get(field) in (None, ""):
            issues.append(f"missing_budget_{field}")
    if not document.get("input_hashes"):
        issues.append("missing_input_hashes")
    elif expected_input_hashes is not None:
        hash_field = (
            "shared_input_hashes"
            if comparison_mode == "native_frontend"
            else "input_hashes"
        )
        declared = {normalize_hash(value) for value in document.get(hash_field) or []}
        if comparison_mode == "native_frontend" and not declared:
            issues.append("missing_shared_input_hashes")
        if declared != expected_input_hashes:
            issues.append("input_hash_mismatch")
    if not isinstance(document.get("records"), list) or not document.get("records"):
        issues.append("missing_records")
    for index, record in enumerate(document.get("records") or []):
        verdict = str(record.get("verdict") or "").upper()
        if verdict not in BASELINE_VERDICTS:
            issues.append(f"record_{index}_invalid_verdict")
        if not record.get("target") or not record.get("source_addr") or not record.get("sink_addr"):
            issues.append(f"record_{index}_missing_identity")
        if comparison_mode == "same_candidate_validator" and record.get("closure_idx") is None:
            issues.append(f"record_{index}_missing_closure_idx")
        truth = record.get("ground_truth")
        if truth not in (None, "") and str(truth).upper() not in GROUND_TRUTH_LABELS:
            issues.append(f"record_{index}_invalid_ground_truth")
    return issues


def ground_truth_protocol_issues(document: dict[str, Any]) -> list[str]:
    labeled = [
        record
        for record in document.get("records") or []
        if str(record.get("ground_truth") or "").upper() in GROUND_TRUTH_LABELS
    ]
    if not labeled:
        return ["no_ground_truth_labels"]
    protocol = document.get("ground_truth_protocol") or {}
    issues = []
    if protocol.get("independent_of_tools") is not True:
        issues.append("ground_truth_not_independent")
    if protocol.get("labels_frozen_before_unblinding") is not True:
        issues.append("ground_truth_not_frozen_before_unblinding")
    if int(protocol.get("auditor_count") or 0) < 2:
        issues.append("ground_truth_fewer_than_two_auditors")
    if protocol.get("adjudication_complete") is not True:
        issues.append("ground_truth_adjudication_incomplete")
    for field in (
        "annotation_sha256",
        "blinded_sample_sha256",
        "protocol_declaration_sha256",
    ):
        if not is_sha256(protocol.get(field)):
            issues.append(f"ground_truth_{field}_missing_or_invalid")
    return issues


def truth_value(value: Any) -> bool | None:
    label = str(value or "").upper()
    if label == "POSITIVE":
        return True
    if label == "NEGATIVE":
        return False
    return None


def load_baseline(path: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any], list[str]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    issues = validate_baseline_document(document)
    rows = {}
    include_closure_idx = (
        str(document.get("comparison_mode") or "") == "same_candidate_validator"
    )
    for raw in document.get("records") or []:
        row = dict(raw)
        row["verdict"] = str(row.get("verdict") or "").upper()
        key = comparison_key(row, include_closure_idx=include_closure_idx)
        if key in rows:
            if include_closure_idx:
                raise ValueError(f"duplicate external comparison key: {key}")
            rows[key]["collapsed_records"] += 1
            rows[key]["collapsed_verdicts"] = sorted(
                set(rows[key]["collapsed_verdicts"]) | {row["verdict"]}
            )
            rows[key]["verdict"] = collapsed_verdict(
                rows[key]["collapsed_verdicts"]
            )
            continue
        row["collapsed_records"] = 1
        row["collapsed_verdicts"] = [row["verdict"]]
        rows[key] = row
    return rows, document, issues


def wilson_interval(
    successes: int, total: int, z: float = 1.959963984540054
) -> list[float] | None:
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


def binary_metrics(
    predictions: list[tuple[bool, bool]], eligible_records: int | None = None
) -> dict[str, Any]:
    tp = sum(predicted and truth for predicted, truth in predictions)
    fp = sum(predicted and not truth for predicted, truth in predictions)
    tn = sum(not predicted and not truth for predicted, truth in predictions)
    fn = sum(not predicted and truth for predicted, truth in predictions)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    accuracy = (tp + tn) / len(predictions) if predictions else None
    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    eligible = len(predictions) if eligible_records is None else eligible_records
    coverage = len(predictions) / eligible if eligible else None
    return {
        "records": len(predictions),
        "eligible_records": eligible,
        "abstentions": max(0, eligible - len(predictions)),
        "coverage": round(coverage, 4) if coverage is not None else None,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4) if precision is not None else None,
        "precision_wilson_95": wilson_interval(tp, tp + fp),
        "recall": round(recall, 4) if recall is not None else None,
        "recall_wilson_95": wilson_interval(tp, tp + fn),
        "specificity": round(specificity, 4) if specificity is not None else None,
        "specificity_wilson_95": wilson_interval(tn, tn + fp),
        "accuracy": round(accuracy, 4) if accuracy is not None else None,
        "accuracy_wilson_95": wilson_interval(tp + tn, len(predictions)),
        "f1": round(f1, 4) if f1 is not None else None,
    }


def exact_mcnemar_pvalue(external_only_correct: int, tsds_only_correct: int) -> float | None:
    discordant = external_only_correct + tsds_only_correct
    if not discordant:
        return None
    lower = min(external_only_correct, tsds_only_correct)
    probability = sum(math.comb(discordant, index) for index in range(lower + 1)) / (2 ** discordant)
    return round(min(1.0, 2.0 * probability), 6)


def cost_metrics(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"records": 0, "total_sec": None, "median_sec": None, "mean_sec": None}
    return {
        "records": len(values),
        "total_sec": round(sum(values), 4),
        "median_sec": round(statistics.median(values), 4),
        "mean_sec": round(statistics.mean(values), 4),
    }


def compare(
    tsds_records: dict[str, dict[str, Any]],
    baseline_records: dict[str, dict[str, Any]],
    metadata_issues: list[str],
    document: dict[str, Any] | None = None,
    runtime_manifest_verification: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    document = document or {}
    runtime_manifest_verification = runtime_manifest_verification or {}
    comparison_mode = str(document.get("comparison_mode") or "")
    keys = sorted(set(tsds_records) | set(baseline_records))
    aligned = []
    crosstab = Counter()
    tsds_predictions: list[tuple[bool, bool]] = []
    external_predictions: list[tuple[bool, bool]] = []
    paired_tsds_predictions: list[tuple[bool, bool]] = []
    paired_external_predictions: list[tuple[bool, bool]] = []
    paired_bootstrap_rows: list[tuple[bool, bool, bool]] = []
    paired_truth_classes: set[bool] = set()
    external_only_correct = 0
    tsds_only_correct = 0
    for key in keys:
        tsds = tsds_records.get(key)
        external = baseline_records.get(key)
        truth_raw = (external or {}).get("ground_truth")
        truth = truth_value(truth_raw)
        tsds_verdict = str((tsds or {}).get("verdict") or "MISSING")
        external_verdict = str((external or {}).get("verdict") or "MISSING")
        crosstab[(external_verdict, tsds_verdict)] += 1
        comparable_tsds = (
            tsds_verdict in {"VECTOR_SAT", "MATRIX_UNSAT"}
            and (tsds or {}).get("contract_valid") is True
        )
        comparable_external = external_verdict in {"POSITIVE", "NEGATIVE"}
        if truth is not None and comparable_tsds:
            tsds_predictions.append((tsds_verdict == "VECTOR_SAT", truth))
        if truth is not None and comparable_external:
            external_predictions.append((external_verdict == "POSITIVE", truth))
        if truth is not None and comparable_tsds and comparable_external:
            paired_truth_classes.add(truth)
            paired_tsds_predictions.append((tsds_verdict == "VECTOR_SAT", truth))
            paired_external_predictions.append((external_verdict == "POSITIVE", truth))
            paired_bootstrap_rows.append(
                (tsds_verdict == "VECTOR_SAT", external_verdict == "POSITIVE", truth)
            )
            tsds_correct = (tsds_verdict == "VECTOR_SAT") == truth
            external_correct = (external_verdict == "POSITIVE") == truth
            if external_correct and not tsds_correct:
                external_only_correct += 1
            elif tsds_correct and not external_correct:
                tsds_only_correct += 1
        exemplar = tsds or external or {}
        aligned.append({
            "record_id": key,
            "target": exemplar.get("target"),
            "closure_idx": exemplar.get("closure_idx"),
            "source_addr": exemplar.get("source_addr"),
            "sink_addr": exemplar.get("sink_addr"),
            "tsds_verdict": tsds_verdict,
            "tsds_provenance": (tsds or {}).get("provenance"),
            "external_verdict": external_verdict,
            "tsds_elapsed_sec": (tsds or {}).get("elapsed_sec"),
            "external_elapsed_sec": (external or {}).get("elapsed_sec"),
            "external_peak_rss_mb": (external or {}).get("peak_rss_mb"),
            "ground_truth": truth_raw,
            "tsds_collapsed_records": (tsds or {}).get("collapsed_records"),
            "external_collapsed_records": (external or {}).get("collapsed_records"),
            "alignment": "matched" if tsds and external else ("tsds_only" if tsds else "external_only"),
        })
    matched = sum(row["alignment"] == "matched" for row in aligned)
    tsds_only = sum(row["alignment"] == "tsds_only" for row in aligned)
    external_only = sum(row["alignment"] == "external_only" for row in aligned)
    truth_records = sum(truth_value(row["ground_truth"]) is not None for row in aligned)
    alignment_issues: list[str] = []
    if comparison_mode == "same_candidate_validator":
        if not baseline_records:
            alignment_issues.append("external_candidate_slice_empty")
        if external_only:
            alignment_issues.append("external_candidates_missing_from_tsds")
        if matched != len(baseline_records):
            alignment_issues.append("external_candidate_slice_not_fully_aligned")
        alignment_complete = bool(baseline_records) and not alignment_issues
    else:
        alignment_complete = bool(tsds_records) and bool(baseline_records)
    admissible = not metadata_issues and alignment_complete
    gt_protocol_issues = ground_truth_protocol_issues(document)
    if comparison_mode != "same_candidate_validator":
        gt_protocol_issues.append("native_frontend_not_paired_accuracy")
    paired_tsds_metrics = binary_metrics(
        paired_tsds_predictions, eligible_records=truth_records
    )
    paired_external_metrics = binary_metrics(
        paired_external_predictions, eligible_records=truth_records
    )
    mcnemar_pvalue = exact_mcnemar_pvalue(external_only_correct, tsds_only_correct)
    paired_effect_uncertainty = paired_bootstrap_differences(paired_bootstrap_rows)
    accuracy_admissible = (
        admissible
        and not gt_protocol_issues
        and bool(paired_tsds_predictions)
    )
    superiority_admissible = (
        accuracy_admissible
        and paired_truth_classes == {False, True}
        and paired_tsds_metrics["f1"] is not None
        and paired_external_metrics["f1"] is not None
        and paired_tsds_metrics["f1"] > paired_external_metrics["f1"]
        and mcnemar_pvalue is not None
        and mcnemar_pvalue <= SIGNIFICANCE_ALPHA
    )
    budget = document.get("budget") or {}
    external_repetitions = int(budget.get("external_runtime_repetitions") or 0)
    tsds_repetitions = int(budget.get("tsds_runtime_repetitions") or 0)
    performance_admissible = (
        admissible
        and comparison_mode == "same_candidate_validator"
        and external_repetitions >= 3
        and tsds_repetitions >= 3
        and (runtime_manifest_verification.get("external") or {}).get("verified")
        is True
        and (runtime_manifest_verification.get("tsds") or {}).get("verified")
        is True
    )
    matched_tsds_times = [
        float(row["tsds_elapsed_sec"])
        for row in aligned
        if row["alignment"] == "matched" and row.get("tsds_elapsed_sec") is not None
    ]
    matched_external_times = [
        float(row["external_elapsed_sec"])
        for row in aligned
        if row["alignment"] == "matched" and row.get("external_elapsed_sec") is not None
    ]
    external_rss = [
        float(row["external_peak_rss_mb"])
        for row in aligned
        if row["alignment"] == "matched" and row.get("external_peak_rss_mb") is not None
    ]
    summary = {
        "schema": "tsds-external-baseline-comparison-v3",
        "claim_boundary": (
            "Without independent ground truth this artifact compares coverage, "
            "verdict cross-tabs, and observed cost only. Accuracy requires a "
            "frozen dual-auditor protocol; superiority additionally requires "
            "paired class coverage and a significant exact McNemar result."
        ),
        "metadata_issues": metadata_issues,
        "alignment_issues": alignment_issues,
        "alignment_complete": alignment_complete,
        "comparison_mode": comparison_mode,
        "ground_truth_protocol_issues": gt_protocol_issues,
        "comparison_admissible": admissible,
        "accuracy_claim_admissible": accuracy_admissible,
        "performance_claim_admissible": performance_admissible,
        "superiority_claim_admissible": superiority_admissible,
        "tsds_records": len(tsds_records),
        "external_records": len(baseline_records),
        "matched_records": matched,
        "tsds_only": tsds_only,
        "external_only": external_only,
        "candidate_overlap": {
            "intersection": matched,
            "union": len(keys),
            "jaccard": round(matched / len(keys), 4) if keys else None,
        },
        "ground_truth_records": truth_records,
        "tsds_metrics": binary_metrics(
            tsds_predictions, eligible_records=truth_records
        ),
        "external_metrics": binary_metrics(
            external_predictions, eligible_records=truth_records
        ),
        "paired_ground_truth_records": len(paired_tsds_predictions),
        "paired_ground_truth_classes": sorted(
            "POSITIVE" if value else "NEGATIVE" for value in paired_truth_classes
        ),
        "paired_tsds_metrics": paired_tsds_metrics,
        "paired_external_metrics": paired_external_metrics,
        "paired_disagreement": {
            "external_only_correct": external_only_correct,
            "tsds_only_correct": tsds_only_correct,
            "exact_mcnemar_pvalue": mcnemar_pvalue,
            "alpha": SIGNIFICANCE_ALPHA,
        },
        "paired_effect_uncertainty": paired_effect_uncertainty,
        "cost": {
            "tsds_elapsed": cost_metrics(matched_tsds_times),
            "external_elapsed": cost_metrics(matched_external_times),
            "external_peak_rss_mb": max(external_rss) if external_rss else None,
            "external_runtime_repetitions": external_repetitions,
            "tsds_runtime_repetitions": tsds_repetitions,
            "runtime_manifest_verification": runtime_manifest_verification,
        },
        "crosstab": [
            {"external_verdict": left, "tsds_verdict": right, "count": count}
            for (left, right), count in sorted(crosstab.items())
        ],
    }
    return aligned, summary


def write_outputs(out_dir: Path, aligned: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty comparison directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "external_alignment.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(aligned[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(aligned)
    with (out_dir / "external_crosstab.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["external_verdict", "tsds_verdict", "count"],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(summary["crosstab"])
    (out_dir / "external_comparison.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        "# TSDS external baseline comparison\n\n"
        f"Matched records: **{summary['matched_records']}**. Comparison admissible: "
        f"**{summary['comparison_admissible']}**. Superiority claim admissible: "
        f"**{summary['superiority_claim_admissible']}**.\n\n"
        + summary["claim_boundary"] + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tsds-campaign", type=Path, required=True)
    parser.add_argument("--external-results", type=Path, required=True)
    parser.add_argument("--tsds-manifest", type=Path)
    parser.add_argument("--external-runtime-manifest", type=Path)
    parser.add_argument("--tsds-runtime-manifest", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--require-admissible", action="store_true")
    parser.add_argument("--require-superiority-ground-truth", action="store_true")
    args = parser.parse_args()
    external, document, issues = load_baseline(args.external_results)
    comparison_mode = str(document.get("comparison_mode") or "")
    tsds = load_tsds_records(args.tsds_campaign, comparison_mode)
    if args.tsds_manifest:
        targets = {str(row.get("target")) for row in document.get("records") or []}
        expected_hashes = manifest_input_hashes(
            args.tsds_manifest,
            targets,
            kinds=("binary",) if comparison_mode == "native_frontend" else ("binary", "mango"),
        )
        issues = validate_baseline_document(document, expected_hashes)
        if not expected_hashes:
            issues.append("manifest_has_no_matching_inputs")
    else:
        issues.append("missing_tsds_manifest")
    budget = document.get("budget") or {}
    runtime_manifest_verification = {
        "external": verify_runtime_manifest(
            args.external_runtime_manifest,
            budget.get("external_runtime_manifest_sha256"),
        ),
        "tsds": verify_runtime_manifest(
            args.tsds_runtime_manifest,
            budget.get("tsds_runtime_manifest_sha256"),
        ),
    }
    aligned, summary = compare(
        tsds,
        external,
        issues,
        document,
        runtime_manifest_verification=runtime_manifest_verification,
    )
    summary["external_tool"] = document.get("tool")
    summary["external_budget"] = document.get("budget")
    summary["tsds_manifest"] = str(args.tsds_manifest) if args.tsds_manifest else None
    write_outputs(args.out_dir, aligned, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    if args.require_admissible and not summary["comparison_admissible"]:
        return 2
    if args.require_superiority_ground_truth and not summary["superiority_claim_admissible"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
