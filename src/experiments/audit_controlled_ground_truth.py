#!/usr/bin/env python3
"""Audit the fixed-label original-program calibration benchmark.

The audit recomputes binary metrics from the benchmark's retained rows.  It is
deliberately separate from the firmware campaign and must not be interpreted
as firmware-wide precision, recall, or exploitability evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "tsds-controlled-ground-truth-audit-v1"
LABELS = {"POSITIVE", "NEGATIVE"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def parse_bool(value: Any) -> bool | None:
    text = str(value).strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total <= 0:
        return None
    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    radius = z * math.sqrt(
        proportion * (1.0 - proportion) / total
        + z * z / (4.0 * total * total)
    ) / denominator
    return [round(max(0.0, center - radius), 4), round(min(1.0, center + radius), 4)]


def binary_metrics(truth: Iterable[bool], prediction: Iterable[bool]) -> dict[str, Any]:
    pairs = list(zip(truth, prediction))
    tp = sum(actual and predicted for actual, predicted in pairs)
    fp = sum((not actual) and predicted for actual, predicted in pairs)
    tn = sum((not actual) and (not predicted) for actual, predicted in pairs)
    fn = sum(actual and (not predicted) for actual, predicted in pairs)
    total = len(pairs)
    precision_denominator = tp + fp
    recall_denominator = tp + fn
    specificity_denominator = tn + fp
    precision = tp / precision_denominator if precision_denominator else None
    recall = tp / recall_denominator if recall_denominator else None
    specificity = tn / specificity_denominator if specificity_denominator else None
    accuracy = (tp + tn) / total if total else None
    f1 = (
        2.0 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "n": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": round(accuracy, 4) if accuracy is not None else None,
        "accuracy_wilson_95": wilson_interval(tp + tn, total),
        "precision": round(precision, 4) if precision is not None else None,
        "precision_wilson_95": wilson_interval(tp, precision_denominator),
        "recall": round(recall, 4) if recall is not None else None,
        "recall_wilson_95": wilson_interval(tp, recall_denominator),
        "specificity": round(specificity, 4) if specificity is not None else None,
        "specificity_wilson_95": wilson_interval(tn, specificity_denominator),
        "f1": round(f1, 4) if f1 is not None else None,
    }


def _row_id(row: dict[str, Any]) -> str:
    return str(row.get("case_id") or "").strip()


def _audit_baseline(
    baseline_rows: list[dict[str, Any]],
    expected_by_id: dict[str, bool],
    native_by_id: dict[str, bool],
    tsds_by_id: dict[str, bool],
) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    indexed: dict[str, dict[str, Any]] = {}
    for row in baseline_rows:
        case_id = _row_id(row)
        if not case_id:
            issues.append("baseline_missing_case_id")
        elif case_id in indexed:
            issues.append(f"baseline_duplicate_case_id:{case_id}")
        else:
            indexed[case_id] = row
    if set(indexed) != set(expected_by_id):
        issues.append("baseline_case_set_differs")

    validators: dict[str, dict[str, Any]] = {}
    for name, field in (
        ("B0_original_source_to_sink", "B0_reached_sink"),
        ("B1_source_owned_meta", "B1_source_meta"),
        ("B2_full_string_meta", "B2_full_string_meta"),
        ("TSDS", "TSDS"),
    ):
        truth: list[bool] = []
        prediction: list[bool] = []
        for case_id in sorted(expected_by_id):
            row = indexed.get(case_id)
            if row is None:
                continue
            actual = parse_bool(row.get("truth"))
            predicted = parse_bool(row.get(field))
            if actual is None:
                issues.append(f"baseline_invalid_truth:{case_id}")
                continue
            if predicted is None:
                issues.append(f"baseline_invalid_prediction:{name}:{case_id}")
                continue
            if actual != expected_by_id[case_id]:
                issues.append(f"baseline_truth_mismatch:{case_id}")
            native = parse_bool(row.get("native_trigger"))
            if native is None or native != native_by_id[case_id]:
                issues.append(f"baseline_native_mismatch:{case_id}")
            if name == "TSDS" and predicted != tsds_by_id[case_id]:
                issues.append(f"baseline_tsds_mismatch:{case_id}")
            truth.append(actual)
            prediction.append(predicted)
        validators[name] = binary_metrics(truth, prediction)
    return validators, sorted(set(issues))


def audit(summary_path: Path, cases_path: Path, baseline_path: Path | None = None) -> dict[str, Any]:
    source_summary = read_json(summary_path)
    cases = read_csv(cases_path)
    issues: list[str] = []
    expected_by_id: dict[str, bool] = {}
    native_by_id: dict[str, bool] = {}
    tsds_by_id: dict[str, bool] = {}
    normalized_rows: list[dict[str, Any]] = []

    for row in cases:
        case_id = _row_id(row)
        if not case_id:
            issues.append("cases_missing_case_id")
            continue
        if case_id in expected_by_id:
            issues.append(f"cases_duplicate_case_id:{case_id}")
            continue
        expected = str(row.get("expected") or "").strip().upper()
        if expected not in LABELS:
            issues.append(f"invalid_expected_label:{case_id}")
            continue
        native = parse_bool(row.get("marker_observed"))
        tsds = parse_bool(row.get("tsds_positive"))
        if native is None:
            issues.append(f"invalid_native_marker:{case_id}")
            continue
        if tsds is None:
            issues.append(f"invalid_tsds_prediction:{case_id}")
            continue
        expected_bool = expected == "POSITIVE"
        if native != expected_bool:
            issues.append(f"native_label_mismatch:{case_id}")
        if str(row.get("comparison") or "").strip().upper() != "MATCH":
            issues.append(f"benchmark_comparison_not_match:{case_id}")
        expected_by_id[case_id] = expected_bool
        native_by_id[case_id] = native
        tsds_by_id[case_id] = tsds
        normalized_rows.append({
            "case_id": case_id,
            "truth": expected,
            "native_marker": native,
            "tsds_prediction": "POSITIVE" if tsds else "NEGATIVE",
            "comparison": str(row.get("comparison") or ""),
            "tsds_class": str(row.get("tsds_class") or ""),
        })

    expected_case_count = int(source_summary.get("case_count", -1))
    if expected_case_count != len(cases):
        issues.append("summary_case_count_differs")
    if expected_case_count != len(expected_by_id):
        issues.append("invalid_or_duplicate_rows_reduce_case_count")
    positive_count = sum(expected_by_id.values())
    if int(source_summary.get("expected_positive_cases", -1)) != positive_count:
        issues.append("summary_positive_count_differs")
    if int(source_summary.get("native_marker_observed", -1)) != sum(native_by_id.values()):
        issues.append("summary_native_count_differs")
    if int(source_summary.get("tsds_matches", -1)) != len(cases):
        issues.append("summary_tsds_match_count_differs")
    if int(source_summary.get("tsds_mismatches", -1)) != 0:
        issues.append("summary_reports_tsds_mismatch")

    tsds_metrics = binary_metrics(
        (expected_by_id[case_id] for case_id in sorted(expected_by_id)),
        (tsds_by_id[case_id] for case_id in sorted(expected_by_id)),
    )
    baseline_metrics: dict[str, Any] | None = None
    if baseline_path is not None:
        baseline_metrics, baseline_issues = _audit_baseline(
            read_json(baseline_path).get("rows") or [],
            expected_by_id,
            native_by_id,
            tsds_by_id,
        )
        issues.extend(baseline_issues)

    result = {
        "schema": SCHEMA,
        "valid": not issues and bool(expected_by_id),
        "issues": sorted(set(issues)),
        "inputs": {
            "summary": str(summary_path.resolve()),
            "summary_sha256": sha256_file(summary_path),
            "cases": str(cases_path.resolve()),
            "cases_sha256": sha256_file(cases_path),
            "baseline": str(baseline_path.resolve()) if baseline_path else None,
            "baseline_sha256": sha256_file(baseline_path) if baseline_path else None,
        },
        "cases": {
            "n": len(expected_by_id),
            "positive": positive_count,
            "negative": len(expected_by_id) - positive_count,
            "native_marker_matches": sum(
                native_by_id[case_id] == expected_by_id[case_id]
                for case_id in expected_by_id
            ),
            "tsds_comparisons_match": sum(
                row["comparison"].strip().upper() == "MATCH"
                for row in normalized_rows
            ),
        },
        "tsds": tsds_metrics,
        "validators": baseline_metrics,
        "claim_boundary": (
            "Fixed-label original-program calibration on one synthetic ELF. "
            "The labels and native marker checks cover only the retained cases; "
            "the result is not firmware-wide precision/recall, candidate-wide "
            "ground truth, or device-level exploitability. B0/B1/B2 are simple "
            "same-input validators rather than independent firmware baselines."
        ),
    }
    return result


def write_outputs(result: dict[str, Any], cases: list[dict[str, Any]], out_dir: Path) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (out_dir / "audited_cases.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = ["case_id", "truth", "native_marker", "tsds_prediction", "comparison", "tsds_class"]
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(cases)
    lines = [
        "# Controlled ground-truth audit",
        "",
        result["claim_boundary"],
        "",
        f"- Valid: `{result['valid']}`",
        f"- Cases: `{result['cases']['n']}` ({result['cases']['positive']} positive, {result['cases']['negative']} negative)",
        f"- Native marker agreement: `{result['cases']['native_marker_matches']}/{result['cases']['n']}`",
        f"- TSDS row agreement: `{result['cases']['tsds_comparisons_match']}/{result['cases']['n']}`",
        f"- TSDS confusion matrix: TP={result['tsds']['tp']}, FP={result['tsds']['fp']}, TN={result['tsds']['tn']}, FN={result['tsds']['fn']}",
        f"- TSDS precision/recall/F1: `{result['tsds']['precision']}/{result['tsds']['recall']}/{result['tsds']['f1']}`",
        "- Wilson intervals are retained in `summary.json`; the fixed benchmark is not a firmware prevalence estimate.",
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    digest_lines = []
    for path in sorted(out_dir.iterdir()):
        if path.name != "SHA256SUMS" and path.is_file():
            digest_lines.append(f"{sha256_file(path)}  {path.name}")
    (out_dir / "SHA256SUMS").write_text("\n".join(digest_lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.summary.resolve(), args.cases.resolve(), args.baseline.resolve() if args.baseline else None)
    cases = []
    for row in read_csv(args.cases.resolve()):
        expected = str(row.get("expected") or "").strip().upper()
        tsds = parse_bool(row.get("tsds_positive"))
        cases.append({
            "case_id": _row_id(row),
            "truth": expected,
            "native_marker": parse_bool(row.get("marker_observed")),
            "tsds_prediction": "POSITIVE" if tsds else "NEGATIVE",
            "comparison": str(row.get("comparison") or ""),
            "tsds_class": str(row.get("tsds_class") or ""),
        })
    write_outputs(result, cases, args.out_dir.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
