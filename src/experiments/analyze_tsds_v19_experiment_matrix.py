#!/usr/bin/env python3
"""Produce paired, paper-ready diagnostics for a TSDS v19 experiment matrix."""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.audit_repeatability import (  # noqa: E402
    SINK_SEMANTIC_VERDICTS,
    record_identity,
    semantic_signature,
)
from tsds.performance_diagnostics import distribution  # noqa: E402
from tsds.statistical_evidence import percentile_interval  # noqa: E402


SCHEMA = "tsds-v19-paired-ablation-analysis-v1"
BOOTSTRAP_SEED = 0x563139
NUMERIC_METRICS = (
    "elapsed_sec",
    "process_peak_rss_mib",
    "engine_steps_total",
    "matrix_solver_queries",
    "matrix_projection_full_constraints",
    "matrix_projection_selected_constraints",
    "matrix_projection_cache_hits",
    "matrix_projection_cache_misses",
    "matrix_projection_unsat_shortcuts",
    "matrix_projection_full_validations",
    "matrix_projection_fallbacks",
    "engine_scheduler_rounds",
    "engine_scheduler_pruned",
    "engine_scheduler_protected_peak",
    "byte_provenance_node_count",
    "byte_provenance_edge_count",
    "byte_provenance_source_node_count",
)


def _number(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def load_campaign_records(campaign: Path) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for path in sorted(campaign.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError(f"record is not an object: {path}:{line_number}")
            identity = record_identity(target, record)
            if identity in records:
                raise ValueError(f"duplicate record identity: {path}:{line_number}")
            record = dict(record)
            record["_target"] = target
            records[identity] = record
    if not records:
        raise ValueError(f"no campaign records found: {campaign}")
    return records


def campaign_fingerprint(campaign: Path) -> dict[str, Any]:
    path = campaign / "campaign_configuration.json"
    if not path.is_file():
        raise ValueError(f"campaign configuration missing: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    targets = {
        str(item.get("name")): {
            "binary_sha256": item.get("binary_sha256"),
            "mango_sha256": item.get("mango_sha256"),
            "refinement_bundle": item.get("refinement_bundle"),
            "refinement_bundle_sha256": item.get("refinement_bundle_sha256"),
        }
        for item in value.get("targets", [])
    }
    return {
        "evaluator_sha256": value.get("evaluator_sha256"),
        "targets": targets,
        "arguments": value.get("arguments") or {},
    }


def paired_bootstrap_delta(
    pairs: Iterable[tuple[float, float]],
    *,
    replicates: int = 10_000,
    seed: int = BOOTSTRAP_SEED,
) -> dict[str, Any]:
    """Estimate variant-minus-baseline mean change with paired resampling."""
    rows = [(float(left), float(right)) for left, right in pairs]
    if replicates < 0:
        raise ValueError("bootstrap replicates must be non-negative")
    deltas = [right - left for left, right in rows]
    samples: list[float] = []
    if deltas and replicates:
        rng = random.Random(seed)
        for _ in range(replicates):
            sample = [deltas[rng.randrange(len(deltas))] for _ in deltas]
            samples.append(statistics.mean(sample))
    baseline_sum = sum(left for left, _ in rows)
    variant_sum = sum(right for _, right in rows)
    return {
        "pairs": len(rows),
        "mean_variant_minus_baseline": (
            round(statistics.mean(deltas), 4) if deltas else None
        ),
        "median_variant_minus_baseline": (
            round(statistics.median(deltas), 4) if deltas else None
        ),
        "mean_delta_bootstrap_95": percentile_interval(samples),
        "paired_total_change_pct": (
            round(100.0 * (variant_sum - baseline_sum) / baseline_sum, 4)
            if baseline_sum
            else None
        ),
        "bootstrap": {
            "method": "paired_percentile",
            "seed": seed,
            "requested_replicates": replicates,
            "valid_replicates": len(samples),
        },
    }


def mechanism_summary(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = list(records)
    metrics: dict[str, Any] = {}
    for key in NUMERIC_METRICS:
        values = [number for row in rows if (number := _number(row.get(key))) is not None]
        metrics[key] = {
            "observed": len(values),
            "sum": round(sum(values), 4),
            "distribution": distribution(values),
        }
    scheduler_tiers: Counter[str] = Counter()
    semantic_plugins: Counter[str] = Counter()
    refinement_outcomes: Counter[str] = Counter()
    refinement_rounds = 0
    refinement_candidates = 0
    refinement_installed = 0
    summary_candidates = 0
    summary_installed = 0
    summary_rejected = 0
    summary_runtime_events = 0
    for row in rows:
        scheduler_tiers.update(row.get("engine_scheduler_tiers") or {})
        semantic_plugins[str(row.get("sink_semantic_plugin") or "none")] += 1
        refinement = row.get("online_refinement") or {}
        for round_record in refinement.get("rounds", []) or []:
            refinement_rounds += 1
            refinement_candidates += len(round_record.get("candidate_ids") or [])
            refinement_installed += len(round_record.get("installed_ids") or [])
            refinement_outcomes[str(round_record.get("outcome") or "unknown")] += 1
        installation = row.get("summary_installation") or {}
        summary_candidates += int(installation.get("summary_candidates") or 0)
        summary_installed += len(installation.get("installed") or [])
        summary_rejected += len(installation.get("rejected") or [])
        summary_runtime_events += len(row.get("summary_runtime_events") or [])
    return {
        "numeric_metrics": metrics,
        "scheduler_tiers": dict(sorted(scheduler_tiers.items())),
        "sink_semantic_plugins": dict(sorted(semantic_plugins.items())),
        "online_refinement": {
            "rounds": refinement_rounds,
            "candidates": refinement_candidates,
            "installed": refinement_installed,
            "outcomes": dict(sorted(refinement_outcomes.items())),
        },
        "summary_replay": {
            "candidates": summary_candidates,
            "installed": summary_installed,
            "rejected": summary_rejected,
            "runtime_events": summary_runtime_events,
        },
    }


def fingerprint_issues(
    baseline: Mapping[str, Any], variant: Mapping[str, Any]
) -> list[str]:
    issues = []
    if baseline.get("evaluator_sha256") != variant.get("evaluator_sha256"):
        issues.append("evaluator_sha256_mismatch")
    baseline_targets = baseline.get("targets") or {}
    variant_targets = variant.get("targets") or {}
    for target in sorted(set(baseline_targets) & set(variant_targets)):
        for key in ("binary_sha256", "mango_sha256"):
            if baseline_targets[target].get(key) != variant_targets[target].get(key):
                issues.append(f"{target}_{key}_mismatch")
    return issues


def compare_configuration(
    name: str,
    baseline: Mapping[str, dict[str, Any]],
    variant: Mapping[str, dict[str, Any]],
    *,
    bootstrap_replicates: int,
) -> dict[str, Any]:
    baseline_ids = set(baseline)
    variant_ids = set(variant)
    common = sorted(baseline_ids & variant_ids)
    transitions: Counter[str] = Counter()
    semantic_stable = 0
    sink_baseline = 0
    sink_stable = 0
    metric_pairs: dict[str, list[tuple[float, float]]] = {
        key: [] for key in ("elapsed_sec", "process_peak_rss_mib", "engine_steps_total")
    }
    for identity in common:
        left = baseline[identity]
        right = variant[identity]
        left_verdict = str(left.get("verdict") or "UNKNOWN")
        right_verdict = str(right.get("verdict") or "UNKNOWN")
        transitions[f"{left_verdict}->{right_verdict}"] += 1
        same = semantic_signature(left) == semantic_signature(right)
        semantic_stable += int(same)
        if left_verdict in SINK_SEMANTIC_VERDICTS:
            sink_baseline += 1
            sink_stable += int(same)
        for key in metric_pairs:
            left_value = _number(left.get(key))
            right_value = _number(right.get(key))
            if left_value is not None and right_value is not None:
                metric_pairs[key].append((left_value, right_value))
    verdicts = Counter(str(row.get("verdict") or "UNKNOWN") for row in variant.values())
    return {
        "configuration": name,
        "records": len(variant),
        "common_records": len(common),
        "baseline_only": len(baseline_ids - variant_ids),
        "variant_only": len(variant_ids - baseline_ids),
        "semantic_stable": semantic_stable,
        "semantic_agreement_pct": (
            round(100.0 * semantic_stable / len(common), 4) if common else None
        ),
        "sink_semantic_baseline": sink_baseline,
        "sink_semantic_stable": sink_stable,
        "sink_semantic_agreement_pct": (
            round(100.0 * sink_stable / sink_baseline, 4) if sink_baseline else None
        ),
        "verdicts": dict(sorted(verdicts.items())),
        "verdict_transitions": dict(sorted(transitions.items())),
        "paired_metrics": {
            key: paired_bootstrap_delta(
                values,
                replicates=bootstrap_replicates,
                seed=BOOTSTRAP_SEED + index,
            )
            for index, (key, values) in enumerate(metric_pairs.items())
        },
        "mechanisms": mechanism_summary(variant.values()),
    }


def flatten_row(result: Mapping[str, Any]) -> dict[str, Any]:
    verdicts = result.get("verdicts") or {}
    mechanisms = result.get("mechanisms") or {}
    numeric = mechanisms.get("numeric_metrics") or {}
    elapsed = numeric.get("elapsed_sec", {}).get("distribution", {})
    rss = numeric.get("process_peak_rss_mib", {}).get("distribution", {})
    paired_elapsed = (result.get("paired_metrics") or {}).get("elapsed_sec", {})
    return {
        "configuration": result.get("configuration"),
        "records": result.get("records"),
        "common_records": result.get("common_records"),
        "vector_sat": verdicts.get("VECTOR_SAT", 0),
        "matrix_unsat": verdicts.get("MATRIX_UNSAT", 0),
        "no_modeled_source": verdicts.get("NO_MODELED_SOURCE", 0),
        "residual": verdicts.get("RESIDUAL", 0),
        "semantic_agreement_pct": result.get("semantic_agreement_pct"),
        "sink_semantic_agreement_pct": result.get("sink_semantic_agreement_pct"),
        "elapsed_p50_sec": elapsed.get("p50"),
        "elapsed_p95_sec": elapsed.get("p95"),
        "peak_rss_p95_mib": rss.get("p95"),
        "paired_elapsed_change_pct": paired_elapsed.get("paired_total_change_pct"),
        "paired_elapsed_delta_ci95": json.dumps(
            paired_elapsed.get("mean_delta_bootstrap_95")
        ),
        "projection_unsat_shortcuts": numeric.get(
            "matrix_projection_unsat_shortcuts", {}
        ).get("sum", 0),
        "scheduler_pruned": numeric.get("engine_scheduler_pruned", {}).get("sum", 0),
        "provenance_nodes": numeric.get("byte_provenance_node_count", {}).get("sum", 0),
        "refinement_rounds": (mechanisms.get("online_refinement") or {}).get("rounds", 0),
        "replay_summaries_installed": (mechanisms.get("summary_replay") or {}).get(
            "installed", 0
        ),
    }


def corpus_summary(records: Mapping[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "records": len(records),
        "verdicts": dict(
            sorted(Counter(str(row.get("verdict") or "UNKNOWN") for row in records.values()).items())
        ),
        "mechanisms": mechanism_summary(records.values()),
    }


def write_outputs(out_dir: Path, summary: Mapping[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "v19_ablation_analysis.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    rows = [flatten_row(item) for item in summary.get("configurations", [])]
    if rows:
        with (out_dir / "v19_ablation_summary.csv").open(
            "w", newline="", encoding="utf-8"
        ) as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
    lines = [
        "# TSDS v19 paired ablation analysis",
        "",
        summary["claim_boundary"],
        "",
        "## Full-corpus baseline",
        "",
        f"Records: **{summary['baseline_summary']['records']}**.",
        "",
        "Verdicts: `"
        + json.dumps(summary["baseline_summary"]["verdicts"], sort_keys=True)
        + "`.",
        "",
        "## Paired mechanism matrix",
        "",
        "| Configuration | Records | SV-SAT | M-Filt | NMS | Residual | Sink agreement | Elapsed p50 | Elapsed change | RSS p95 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| {configuration} | {records} | {vector_sat} | {matrix_unsat} | "
            "{no_modeled_source} | {residual} | {sink_semantic_agreement_pct} | "
            "{elapsed_p50_sec} | {paired_elapsed_change_pct} | {peak_rss_p95_mib} |".format(
                **row
            )
        )
    if summary.get("issues"):
        lines.extend(["", "## Integrity issues", ""])
        lines.extend(f"- `{issue}`" for issue in summary["issues"])
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    latex = [
        r"\begin{tabular}{lrrrrrr}",
        r"\toprule",
        r"Configuration & Records & SV-SAT & M-Filt & NMS & Residual & Sink agree. (\%) \\",
        r"\midrule",
    ]
    for row in rows:
        name = str(row["configuration"]).replace("_", r"\_")
        agreement = row["sink_semantic_agreement_pct"]
        agreement_text = "--" if agreement is None else f"{float(agreement):.2f}"
        latex.append(
            f"{name} & {row['records']} & {row['vector_sat']} & {row['matrix_unsat']} & "
            f"{row['no_modeled_source']} & {row['residual']} & {agreement_text} \\\\"
        )
    latex.extend([r"\bottomrule", r"\end{tabular}", ""])
    (out_dir / "v19_ablation_table.tex").write_text("\n".join(latex), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-dir", type=Path, required=True)
    parser.add_argument("--matrix-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--bootstrap-replicates", type=int, default=10_000)
    parser.add_argument("--fail-on-integrity-issues", action="store_true")
    args = parser.parse_args()
    try:
        baseline = load_campaign_records(args.baseline_dir.resolve())
        baseline_fingerprint = campaign_fingerprint(args.baseline_dir.resolve())
        campaign_root = args.matrix_dir.resolve() / "campaigns"
        results = []
        issues = []
        for campaign in sorted(path for path in campaign_root.iterdir() if path.is_dir()):
            variant = load_campaign_records(campaign)
            variant_fingerprint = campaign_fingerprint(campaign)
            result = compare_configuration(
                campaign.name,
                baseline,
                variant,
                bootstrap_replicates=args.bootstrap_replicates,
            )
            result["fingerprint"] = variant_fingerprint
            result["fingerprint_issues"] = fingerprint_issues(
                baseline_fingerprint, variant_fingerprint
            )
            issues.extend(f"{campaign.name}:{issue}" for issue in result["fingerprint_issues"])
            if result["common_records"] == 0:
                issues.append(f"{campaign.name}:no_common_record_identities")
            results.append(result)
        if not results:
            raise ValueError(f"no configuration campaigns found: {campaign_root}")
        summary = {
            "schema": SCHEMA,
            "baseline_dir": str(args.baseline_dir.resolve()),
            "matrix_dir": str(args.matrix_dir.resolve()),
            "baseline_records": len(baseline),
            "baseline_fingerprint": baseline_fingerprint,
            "baseline_summary": corpus_summary(baseline),
            "configurations": results,
            "issues": sorted(set(issues)),
            "valid": not issues,
            "claim_boundary": (
                "Paired changes describe mechanism attribution within TSDS on common "
                "closure identities. They do not establish cross-tool superiority or "
                "device-level exploitability."
            ),
        }
        write_outputs(args.out_dir.resolve(), summary)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"V19_ABLATION_ANALYSIS_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.fail_on_integrity_issues and issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
