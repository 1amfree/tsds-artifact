#!/usr/bin/env python3
"""Audit runtime and memory repeatability across TSDS campaigns.

The audit aligns records by the same content-derived closure identity used by
the semantic repeatability gate.  Resource variability is summarized only for
records that are present in every run and retain an identical semantic
projection, while missing records, semantic drift, and unavailable metrics are
reported as explicit exclusions.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.audit_repeatability import (  # noqa: E402
    SINK_SEMANTIC_VERDICTS,
    campaign_results_identity,
    load_campaign_records,
    semantic_projection,
    semantic_signature,
)
from tsds.residual_root_causes import classify_residual  # noqa: E402


SCHEMA = "tsds-runtime-repeatability-v3"
METRICS = {
    "elapsed_sec": {"minimum": 0.0, "run_aggregation": "sum"},
    "process_peak_rss_mib": {"minimum": 0.0, "run_aggregation": "maximum"},
}


def _canonical_json(value: Any) -> str:
    """Serialize a projection fragment for deterministic equality checks."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _residual_diagnostic_transition(
    entries: dict[str, dict[str, Any]],
) -> list[dict[str, Any]] | None:
    """Return an accounted residual transition when only diagnostics differ.

    A residual is not evidence of a positive or negative outcome.  Its stop
    mechanism is nevertheless useful audit information.  Runtime metrics omit
    every semantic drift, but the release gate may distinguish a diagnostic-
    only residual transition from a change to evidence-bearing fields.  The
    transition remains admissible only when all records are residuals, their
    projections are identical after removing ``diagnostic_boundary``, and both
    endpoint diagnoses map to explicit root-cause obligations.
    """

    records = {label: entry["record"] for label, entry in entries.items()}
    if not records or any(str(record.get("verdict") or "") != "RESIDUAL" for record in records.values()):
        return None

    nondiagnostic = []
    transitions: list[dict[str, Any]] = []
    for label, record in sorted(records.items()):
        projection = dict(semantic_projection(record))
        projection.pop("diagnostic_boundary", None)
        nondiagnostic.append(_canonical_json(projection))
        diagnosis = classify_residual(record)
        if diagnosis["root_cause"] == "unclassified_residual":
            return None
        transitions.append(
            {
                "campaign": label,
                "engine_stop_reason": record.get("engine_stop_reason"),
                "path_control_class": record.get("path_control_class"),
                "root_cause": diagnosis["root_cause"],
                "root_cause_confidence": diagnosis["root_cause_confidence"],
                "follow_up_obligation": diagnosis["follow_up_obligation"],
            }
        )
    return transitions if len(set(nondiagnostic)) == 1 else None


def _drift_class(
    entries: dict[str, dict[str, Any]],
) -> tuple[str, list[dict[str, Any]] | None]:
    """Classify a common-record drift without weakening evidence gates."""

    records = [entry["record"] for entry in entries.values()]
    verdicts = {str(record.get("verdict") or "UNKNOWN") for record in records}
    if verdicts & SINK_SEMANTIC_VERDICTS:
        return "sink_semantic_drift", None
    if verdicts != {"RESIDUAL"}:
        return "non_residual_evidence_drift", None
    transition = _residual_diagnostic_transition(entries)
    if transition is not None:
        return "accounted_residual_diagnostic_drift", transition
    return "unaccounted_residual_evidence_drift", None


def percentile(values: Iterable[float], quantile: float) -> float | None:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return None
    if not 0.0 <= quantile <= 1.0:
        raise ValueError("quantile must be between zero and one")
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def finite_metric(record: dict[str, Any], field: str) -> float | None:
    value = record.get(field)
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < METRICS[field]["minimum"]:
        return None
    return number


def sample_variation(values: Iterable[float]) -> dict[str, float | int | None]:
    samples = [float(value) for value in values]
    if not samples:
        return {
            "observations": 0,
            "mean": None,
            "median": None,
            "minimum": None,
            "maximum": None,
            "sample_stdev": None,
            "cv": None,
            "max_min_ratio": None,
        }
    mean = statistics.fmean(samples)
    minimum = min(samples)
    maximum = max(samples)
    stdev = statistics.stdev(samples) if len(samples) >= 2 else 0.0
    cv = stdev / mean if mean > 0.0 else (0.0 if maximum == 0.0 else None)
    ratio = maximum / minimum if minimum > 0.0 else (1.0 if maximum == 0.0 else None)
    return {
        "observations": len(samples),
        "mean": mean,
        "median": statistics.median(samples),
        "minimum": minimum,
        "maximum": maximum,
        "sample_stdev": stdev,
        "cv": cv,
        "max_min_ratio": ratio,
    }


def distribution_summary(values: Iterable[float | None]) -> dict[str, float | int | None]:
    samples = [float(value) for value in values if value is not None]
    return {
        "records": len(samples),
        "median": percentile(samples, 0.5),
        "p95": percentile(samples, 0.95),
        "maximum": max(samples) if samples else None,
    }


def parse_campaign_specs(specs: list[str]) -> list[tuple[str, Path]]:
    campaigns: list[tuple[str, Path]] = []
    labels: set[str] = set()
    paths: set[Path] = set()
    for spec in specs:
        if "=" not in spec:
            raise ValueError(f"campaign must use LABEL=PATH syntax: {spec}")
        label, raw_path = spec.split("=", 1)
        label = label.strip()
        if not label or any(character in label for character in ",;\n\r"):
            raise ValueError(f"invalid campaign label: {label!r}")
        path = Path(raw_path).expanduser().resolve()
        if label in labels:
            raise ValueError(f"duplicate campaign label: {label}")
        if path in paths:
            raise ValueError(f"duplicate campaign path: {path}")
        if not path.is_dir():
            raise ValueError(f"campaign directory does not exist: {path}")
        labels.add(label)
        paths.add(path)
        campaigns.append((label, path))
    if len(campaigns) < 2:
        raise ValueError("at least two campaigns are required")
    return campaigns


def _rounded(value: float | int | None) -> float | int | None:
    return round(value, 8) if isinstance(value, float) else value


def _rounded_mapping(values: dict[str, Any]) -> dict[str, Any]:
    return {key: _rounded(value) for key, value in values.items()}


def _format_latex(value: float | int | None, digits: int = 3) -> str:
    return "--" if value is None else f"{float(value):.{digits}f}"


def audit_campaigns(
    campaign_specs: list[tuple[str, Path]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    loaded = {
        label: load_campaign_records(path)
        for label, path in campaign_specs
    }
    labels = [label for label, _path in campaign_specs]
    all_keys = sorted(set().union(*(set(records) for records in loaded.values())))
    common_keys = set.intersection(*(set(records) for records in loaded.values()))

    per_record_rows: list[dict[str, Any]] = []
    measurement_rows: list[dict[str, Any]] = []
    complete_metric_counts = {field: 0 for field in METRICS}
    semantic_stable_count = 0
    semantic_drift_count = 0
    sink_semantic_common_count = 0
    sink_semantic_drift_count = 0
    non_residual_evidence_common_count = 0
    non_residual_evidence_drift_count = 0
    accounted_residual_diagnostic_drift_count = 0
    unaccounted_residual_evidence_drift_count = 0
    drift_classes: Counter[str] = Counter()
    residual_diagnostic_transitions: list[dict[str, Any]] = []
    per_record_variation: dict[str, list[dict[str, Any]]] = {
        field: [] for field in METRICS
    }
    complete_metric_keys: dict[str, set[str]] = {field: set() for field in METRICS}

    for key in all_keys:
        entries = {label: loaded[label].get(key) for label in labels}
        present = [label for label, entry in entries.items() if entry is not None]
        exemplar_entry = next(entry for entry in entries.values() if entry is not None)
        exemplar = exemplar_entry["record"]
        signatures = {
            semantic_signature(entry["record"])
            for entry in entries.values()
            if entry is not None
        }
        semantic_stable = len(present) == len(labels) and len(signatures) == 1
        if len(present) == len(labels):
            complete_entries = {
                label: entry
                for label, entry in entries.items()
                if entry is not None
            }
            verdicts = {
                str(entry["record"].get("verdict") or "UNKNOWN")
                for entry in complete_entries.values()
            }
            if verdicts & SINK_SEMANTIC_VERDICTS:
                sink_semantic_common_count += 1
            if verdicts != {"RESIDUAL"}:
                non_residual_evidence_common_count += 1
            if semantic_stable:
                semantic_stable_count += 1
                drift_class = "stable"
            else:
                semantic_drift_count += 1
                drift_class, transition = _drift_class(complete_entries)
                drift_classes[drift_class] += 1
                if drift_class == "sink_semantic_drift":
                    sink_semantic_drift_count += 1
                elif drift_class == "non_residual_evidence_drift":
                    non_residual_evidence_drift_count += 1
                elif drift_class == "accounted_residual_diagnostic_drift":
                    accounted_residual_diagnostic_drift_count += 1
                    residual_diagnostic_transitions.append(
                        {
                            "record_id": key,
                            "record_id_sha256": hashlib.sha256(
                                key.encode("utf-8")
                            ).hexdigest(),
                            "target": exemplar_entry["target"],
                            "closure_idx": exemplar.get("closure_idx"),
                            "source_addr": exemplar.get("source_addr"),
                            "sink_addr": exemplar.get("sink_addr"),
                            "campaigns": transition,
                        }
                    )
                elif drift_class == "unaccounted_residual_evidence_drift":
                    unaccounted_residual_evidence_drift_count += 1
        else:
            drift_class = "missing_record"

        row: dict[str, Any] = {
            "record_id": key,
            "record_id_sha256": hashlib.sha256(key.encode("utf-8")).hexdigest(),
            "target": exemplar_entry["target"],
            "closure_idx": exemplar.get("closure_idx"),
            "source_addr": exemplar.get("source_addr"),
            "sink_addr": exemplar.get("sink_addr"),
            "baseline_verdict": exemplar.get("verdict"),
            "present_runs": len(present),
            "missing_runs": ";".join(label for label in labels if label not in present),
            "semantic_stable": semantic_stable,
            "drift_class": drift_class,
        }
        for field in METRICS:
            values = []
            for label in labels:
                entry = entries[label]
                value = finite_metric(entry["record"], field) if entry else None
                measurement_rows.append(
                    {
                        "record_id_sha256": row["record_id_sha256"],
                        "target": row["target"],
                        "closure_idx": row["closure_idx"],
                        "campaign": label,
                        "semantic_stable": semantic_stable,
                        "metric": field,
                        "value": value,
                        "available": value is not None,
                    }
                )
                if value is not None:
                    values.append(value)
            variation = sample_variation(values)
            complete = semantic_stable and len(values) == len(labels)
            if complete:
                complete_metric_counts[field] += 1
                complete_metric_keys[field].add(key)
                per_record_variation[field].append(variation)
            row[f"{field}_complete"] = complete
            for statistic, value in variation.items():
                row[f"{field}_{statistic}"] = _rounded(value)
        per_record_rows.append(row)

    per_run_rows: list[dict[str, Any]] = []
    for label in labels:
        records = loaded[label]
        row: dict[str, Any] = {
            "campaign": label,
            "records": len(records),
            "common_records": len(set(records) & common_keys),
        }
        for field in METRICS:
            values = [
                value
                for key in sorted(complete_metric_keys[field])
                for value in [finite_metric(records[key]["record"], field)]
                if value is not None
            ]
            row[f"{field}_records"] = len(values)
            aggregation = METRICS[field]["run_aggregation"]
            aggregate = (
                sum(values) if aggregation == "sum" else max(values)
            ) if values else None
            row[f"{field}_aggregation"] = aggregation
            row[f"{field}_aggregate"] = _rounded(aggregate)
            row[f"{field}_median"] = _rounded(percentile(values, 0.5))
            row[f"{field}_p95"] = _rounded(percentile(values, 0.95))
            row[f"{field}_maximum"] = _rounded(max(values) if values else None)
        per_run_rows.append(row)

    summary: dict[str, Any] = {
        "schema": SCHEMA,
        "claim_boundary": (
            "This audit quantifies analyzer resource repeatability for aligned, "
            "semantically stable closure records. It does not measure discovery "
            "accuracy, device-level exploitability, or superiority over another tool."
        ),
        "campaigns": [
            {
                "label": label,
                **campaign_results_identity(path),
            }
            for label, path in campaign_specs
        ],
        "campaign_count": len(labels),
        "union_records": len(all_keys),
        "common_records": len(common_keys),
        "semantic_stable_common_records": semantic_stable_count,
        "semantic_drift_common_records": semantic_drift_count,
        "sink_semantic_common_records": sink_semantic_common_count,
        "sink_semantic_drift_common_records": sink_semantic_drift_count,
        "non_residual_evidence_common_records": non_residual_evidence_common_count,
        "non_residual_evidence_drift_common_records": non_residual_evidence_drift_count,
        "accounted_residual_diagnostic_drift_common_records": (
            accounted_residual_diagnostic_drift_count
        ),
        "unaccounted_residual_evidence_drift_common_records": (
            unaccounted_residual_evidence_drift_count
        ),
        "semantic_drift_classes": dict(sorted(drift_classes.items())),
        "accounted_residual_diagnostic_transitions": residual_diagnostic_transitions,
        "records_missing_from_at_least_one_run": len(all_keys) - len(common_keys),
        "metrics": {},
        "implementation": {
            "path": str(Path(__file__).resolve()),
            "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
    }
    for field in METRICS:
        variations = per_record_variation[field]
        aggregates = [
            row[f"{field}_aggregate"]
            for row in per_run_rows
            if row[f"{field}_aggregate"] is not None
        ]
        summary["metrics"][field] = {
            "complete_semantically_stable_records": complete_metric_counts[field],
            "per_record_cv": _rounded_mapping(
                distribution_summary(item["cv"] for item in variations)
            ),
            "per_record_max_min_ratio": _rounded_mapping(
                distribution_summary(item["max_min_ratio"] for item in variations)
            ),
            "run_aggregation": METRICS[field]["run_aggregation"],
            "per_run_aggregate": _rounded_mapping(sample_variation(aggregates)),
        }
    return per_record_rows, measurement_rows, summary | {"per_run": per_run_rows}


def audit_issues(
    summary: dict[str, Any],
    *,
    require_complete_records: bool,
    require_semantic_stability: bool,
    require_sink_semantic_stability: bool = False,
    require_non_residual_evidence_stability: bool = False,
    require_residual_diagnostic_accounting: bool = False,
    require_sink_semantic_records: bool = False,
    require_complete_metrics: bool,
    max_elapsed_cv_p95: float | None,
    max_rss_cv_p95: float | None,
    max_total_elapsed_ratio: float | None,
) -> list[str]:
    issues: list[str] = []
    if not summary["semantic_stable_common_records"]:
        issues.append("no semantically stable common closure records are available")
    if require_complete_records and summary["records_missing_from_at_least_one_run"]:
        issues.append("one or more closure records are missing from a campaign")
    if require_semantic_stability and summary["semantic_drift_common_records"]:
        issues.append("one or more common closure records have semantic drift")
    if require_sink_semantic_records and not summary["sink_semantic_common_records"]:
        issues.append("no sink-semantic common closure records are available")
    if (
        require_sink_semantic_stability
        and summary["sink_semantic_drift_common_records"]
    ):
        issues.append("one or more sink-semantic closure records have semantic drift")
    if (
        require_non_residual_evidence_stability
        and summary["non_residual_evidence_drift_common_records"]
    ):
        issues.append("one or more non-residual evidence records have semantic drift")
    if (
        require_residual_diagnostic_accounting
        and summary["unaccounted_residual_evidence_drift_common_records"]
    ):
        issues.append("one or more residual drifts change evidence outside the diagnostic boundary")
    if require_complete_metrics:
        expected = summary["semantic_stable_common_records"]
        for field, metric in summary["metrics"].items():
            if metric["complete_semantically_stable_records"] != expected:
                issues.append(f"{field} is unavailable for one or more stable records")
    threshold_pairs = (
        ("elapsed_sec", "per_record_cv", "p95", max_elapsed_cv_p95),
        ("process_peak_rss_mib", "per_record_cv", "p95", max_rss_cv_p95),
        (
            "elapsed_sec",
            "per_run_aggregate",
            "max_min_ratio",
            max_total_elapsed_ratio,
        ),
    )
    for field, group, statistic, threshold in threshold_pairs:
        if threshold is None:
            continue
        observed = summary["metrics"][field][group][statistic]
        if observed is None:
            issues.append(f"cannot evaluate {field} {group} {statistic}")
        elif observed > threshold:
            issues.append(
                f"{field} {group} {statistic} {observed:.6f} exceeds {threshold:.6f}"
            )
    return issues


def write_outputs(
    out_dir: Path,
    per_record_rows: list[dict[str, Any]],
    measurement_rows: list[dict[str, Any]],
    summary: dict[str, Any],
) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "runtime_repeatability_records.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=list(per_record_rows[0]) if per_record_rows else ["record_id"],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(per_record_rows)
    with (out_dir / "runtime_measurements.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        fields = [
            "record_id_sha256", "target", "closure_idx", "campaign",
            "semantic_stable", "metric", "value", "available",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(measurement_rows)
    with (out_dir / "runtime_repeatability_by_run.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        rows = summary["per_run"]
        writer = csv.DictWriter(
            stream,
            fieldnames=list(rows[0]) if rows else ["campaign"],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "runtime_repeatability_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    elapsed = summary["metrics"]["elapsed_sec"]
    rss = summary["metrics"]["process_peak_rss_mib"]
    lines = [
        r"\begin{tabular}{lrrr}",
        r"\toprule",
        r"Metric & Complete records & Median CV & P95 CV \\",
        r"\midrule",
        "Elapsed time & "
        f"{elapsed['complete_semantically_stable_records']} & "
        f"{_format_latex(elapsed['per_record_cv']['median'])} & "
        f"{_format_latex(elapsed['per_record_cv']['p95'])} \\",
        "Peak RSS & "
        f"{rss['complete_semantically_stable_records']} & "
        f"{_format_latex(rss['per_record_cv']['median'])} & "
        f"{_format_latex(rss['per_record_cv']['p95'])} \\",
        r"\bottomrule",
        r"\end{tabular}",
        "",
    ]
    (out_dir / "runtime_repeatability_table.tex").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        "# TSDS runtime repeatability audit\n\n"
        f"Campaigns: **{summary['campaign_count']}**; common records: "
        f"**{summary['common_records']}**; semantically stable common records: "
        f"**{summary['semantic_stable_common_records']}**; accounted residual "
        f"diagnostic drifts: **{summary['accounted_residual_diagnostic_drift_common_records']}**; issues: "
        f"**{len(summary.get('issues', []))}**.\n\n"
        + summary["claim_boundary"]
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--campaign",
        action="append",
        required=True,
        metavar="LABEL=PATH",
        help="Repeat for each campaign; at least two are required.",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--require-complete-records", action="store_true")
    parser.add_argument("--require-semantic-stability", action="store_true")
    parser.add_argument(
        "--require-sink-semantic-stability",
        action="store_true",
        help="Fail when a VECTOR_SAT, MATRIX_UNSAT, or NO_MODELED_SOURCE record drifts.",
    )
    parser.add_argument(
        "--require-non-residual-evidence-stability",
        action="store_true",
        help="Fail when a static or other non-residual evidence record drifts.",
    )
    parser.add_argument(
        "--require-residual-diagnostic-accounting",
        action="store_true",
        help="Allow only residual drifts limited to classified diagnostic boundaries.",
    )
    parser.add_argument(
        "--require-sink-semantic-records",
        action="store_true",
        help="Reject a vacuous gate with no common sink-semantic records.",
    )
    parser.add_argument("--require-complete-metrics", action="store_true")
    parser.add_argument("--max-elapsed-cv-p95", type=float)
    parser.add_argument("--max-rss-cv-p95", type=float)
    parser.add_argument("--max-total-elapsed-ratio", type=float)
    parser.add_argument("--fail-on-issues", action="store_true")
    args = parser.parse_args()
    try:
        campaigns = parse_campaign_specs(args.campaign)
        records, measurements, summary = audit_campaigns(campaigns)
        issues = audit_issues(
            summary,
            require_complete_records=args.require_complete_records,
            require_semantic_stability=args.require_semantic_stability,
            require_sink_semantic_stability=args.require_sink_semantic_stability,
            require_non_residual_evidence_stability=(
                args.require_non_residual_evidence_stability
            ),
            require_residual_diagnostic_accounting=(
                args.require_residual_diagnostic_accounting
            ),
            require_sink_semantic_records=args.require_sink_semantic_records,
            require_complete_metrics=args.require_complete_metrics,
            max_elapsed_cv_p95=args.max_elapsed_cv_p95,
            max_rss_cv_p95=args.max_rss_cv_p95,
            max_total_elapsed_ratio=args.max_total_elapsed_ratio,
        )
        summary["issues"] = issues
        write_outputs(args.out_dir.resolve(), records, measurements, summary)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 3 if args.fail_on_issues and issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
