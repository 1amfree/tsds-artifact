#!/usr/bin/env python3
"""Audit v20 paired cohorts and compute firmware-cluster uncertainty."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.audit_v20_downloaded_release import strict_json
from tsds.statistical_evidence import percentile_interval


SCHEMA = "tsds-v20-paired-experiment-audit-v1"
ANALYSIS_SCHEMA = "tsds-v19-paired-ablation-analysis-v1"
TRANSITION_SCHEMA = "tsds-v20-record-level-ablation-transitions-v1"
BOOTSTRAP_REPLICATES = 10_000
BOOTSTRAP_SEED = 0x54534453563230
EXPECTED_TARGETS = 8
BOUNDED_CONFIGURATIONS = (
    "full",
    "p0_scheduler_off",
    "p0_corridor_off",
    "p0_all_off",
    "p1_projection_off",
    "p1_spawn_backend",
    "p2_provenance_off",
    "p2_semantics_off",
    "p2_refinement_off",
    "p2_refinement_replay",
)
CONFIRMATORY_CONFIGURATIONS = ("p0_all_off", "p1_projection_off")
PAIRED_METRICS = {
    "elapsed_sec": "delta_elapsed_sec",
    "process_peak_rss_mib": "delta_process_peak_rss_mib",
    "engine_steps_total": "delta_engine_steps_total",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def finite_number(value: Any) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def integer(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} is not an integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not an integer") from exc
    if result < 0:
        raise ValueError(f"{label} is negative")
    return result


def configuration_map(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = document.get("configurations")
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get("configuration")): row
        for row in rows
        if isinstance(row, dict) and row.get("configuration")
    }


def load_transition_rows(
    summary_path: Path,
) -> tuple[dict[str, Any], Path, list[dict[str, str]]]:
    summary = strict_json(summary_path)
    identity = summary.get("transition_csv")
    if not isinstance(identity, dict) or not isinstance(identity.get("path"), str):
        raise ValueError(f"transition CSV identity is missing: {summary_path}")
    csv_path = summary_path.parent / identity["path"]
    if not csv_path.is_file():
        raise ValueError(f"transition CSV is missing: {csv_path}")
    if (
        identity.get("size") != csv_path.stat().st_size
        or identity.get("sha256") != sha256_file(csv_path)
    ):
        raise ValueError(f"transition CSV identity mismatch: {csv_path}")
    with csv_path.open("r", newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise ValueError(f"transition CSV is empty: {csv_path}")
    return summary, csv_path, rows


def record_identity(row: dict[str, str]) -> tuple[str, ...]:
    return tuple(
        row.get(field, "")
        for field in (
            "target",
            "closure_idx",
            "source_addr",
            "sink_addr",
            "closure_sink_signature",
        )
    )


def deterministic_seed(label: str) -> int:
    digest = hashlib.sha256(label.encode("utf-8")).digest()
    return BOOTSTRAP_SEED ^ int.from_bytes(digest[:8], "big")


def clustered_effect(
    rows: Iterable[dict[str, str]],
    delta_field: str,
    *,
    replicates: int = BOOTSTRAP_REPLICATES,
    seed: int = BOOTSTRAP_SEED,
) -> dict[str, Any]:
    if replicates < 0:
        raise ValueError("bootstrap replicates must be non-negative")
    by_target: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        value = finite_number(row.get(delta_field))
        target = str(row.get("target") or "")
        if value is not None and target:
            by_target[target].append(value)
    targets = sorted(by_target)
    values = [value for target in targets for value in by_target[target]]
    target_means = [statistics.mean(by_target[target]) for target in targets]
    target_balanced_samples: list[float] = []
    closure_weighted_samples: list[float] = []
    if targets and replicates:
        rng = random.Random(seed)
        for _ in range(replicates):
            sampled = [targets[rng.randrange(len(targets))] for _ in targets]
            sampled_target_means = [statistics.mean(by_target[target]) for target in sampled]
            sampled_values = [value for target in sampled for value in by_target[target]]
            target_balanced_samples.append(statistics.mean(sampled_target_means))
            closure_weighted_samples.append(statistics.mean(sampled_values))
    positive = sum(value > 0 for value in target_means)
    negative = sum(value < 0 for value in target_means)
    return {
        "records": len(values),
        "targets": len(targets),
        "target_record_counts": {
            target: len(by_target[target]) for target in targets
        },
        "closure_weighted_mean_delta": (
            round(statistics.mean(values), 4) if values else None
        ),
        "closure_weighted_cluster_bootstrap_95": percentile_interval(
            closure_weighted_samples
        ),
        "target_balanced_mean_delta": (
            round(statistics.mean(target_means), 4) if target_means else None
        ),
        "target_balanced_bootstrap_95": percentile_interval(
            target_balanced_samples
        ),
        "target_direction": {
            "positive": positive,
            "negative": negative,
            "zero": len(target_means) - positive - negative,
        },
        "bootstrap": {
            "unit": "firmware_target",
            "method": "cluster_percentile",
            "seed": seed,
            "requested_replicates": replicates,
            "valid_replicates": len(target_balanced_samples),
        },
    }


def audit_dataset(
    label: str,
    analysis: dict[str, Any],
    transition_summary: dict[str, Any],
    rows: list[dict[str, str]],
    *,
    expected_configurations: tuple[str, ...],
    accepted_records: int,
    full_corpus: bool,
    expected_targets: int = EXPECTED_TARGETS,
    bootstrap_replicates: int = BOOTSTRAP_REPLICATES,
) -> dict[str, Any]:
    issues: list[str] = []
    if analysis.get("schema") != ANALYSIS_SCHEMA:
        issues.append("analysis_schema")
    if analysis.get("valid") is not True or analysis.get("issues"):
        issues.append("analysis_integrity")
    if transition_summary.get("schema") != TRANSITION_SCHEMA:
        issues.append("transition_schema")
    if transition_summary.get("valid") is not True or transition_summary.get("issues"):
        issues.append("transition_integrity")
    baseline_records = integer(analysis.get("baseline_records"), f"{label} baseline records")
    if baseline_records != accepted_records:
        issues.append("baseline_accepted_record_mismatch")

    expected_set = set(expected_configurations)
    analysis_configs = configuration_map(analysis)
    transition_configs = configuration_map(transition_summary)
    row_groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        row_groups[str(row.get("configuration") or "")].append(row)
    if set(analysis_configs) != expected_set:
        issues.append("analysis_configuration_set")
    if set(transition_configs) != expected_set:
        issues.append("transition_configuration_set")
    if set(row_groups) != expected_set:
        issues.append("csv_configuration_set")
    if integer(transition_summary.get("transition_rows"), f"{label} transition rows") != len(rows):
        issues.append("transition_row_count")

    cohort_reference: set[tuple[str, ...]] | None = None
    configuration_audits: list[dict[str, Any]] = []
    effects: list[dict[str, Any]] = []
    for config_index, name in enumerate(expected_configurations):
        analysis_row = analysis_configs.get(name) or {}
        summary_row = transition_configs.get(name) or {}
        config_rows = row_groups.get(name) or []
        identities = [record_identity(row) for row in config_rows]
        if len(identities) != len(set(identities)):
            issues.append(f"{name}:duplicate_record_identity")
        presence = Counter(str(row.get("record_presence") or "") for row in config_rows)
        unknown_presence = sorted(set(presence) - {"both", "baseline_only", "variant_only"})
        if unknown_presence:
            issues.append(f"{name}:unknown_record_presence")
        common_rows = [row for row in config_rows if row.get("record_presence") == "both"]
        common_ids = {record_identity(row) for row in common_rows}
        target_count = len({row.get("target") for row in common_rows if row.get("target")})
        if target_count != expected_targets:
            issues.append(f"{name}:target_count")
        if cohort_reference is None:
            cohort_reference = common_ids
        elif common_ids != cohort_reference:
            issues.append(f"{name}:paired_cohort_mismatch")

        common = len(common_rows)
        baseline_only = presence.get("baseline_only", 0)
        variant_only = presence.get("variant_only", 0)
        union = len(config_rows)
        expected_values = {
            "common_records": common,
            "baseline_only": baseline_only,
            "variant_only": variant_only,
        }
        for field, observed in expected_values.items():
            if integer(analysis_row.get(field), f"{name} analysis {field}") != observed:
                issues.append(f"{name}:analysis_{field}")
            if integer(summary_row.get(field), f"{name} transition {field}") != observed:
                issues.append(f"{name}:transition_{field}")
        if integer(summary_row.get("records_union"), f"{name} records union") != union:
            issues.append(f"{name}:records_union")
        if integer(analysis_row.get("records"), f"{name} variant records") != common + variant_only:
            issues.append(f"{name}:variant_records")
        if analysis_row.get("fingerprint_issues") or summary_row.get("fingerprint_issues"):
            issues.append(f"{name}:fingerprint")
        if variant_only:
            issues.append(f"{name}:variant_only")
        if full_corpus:
            if common != accepted_records or baseline_only:
                issues.append(f"{name}:not_full_corpus")
        elif common <= 0 or common >= accepted_records or baseline_only != accepted_records - common:
            issues.append(f"{name}:invalid_bounded_cohort")

        paired_metrics = analysis_row.get("paired_metrics") or {}
        for metric_index, (metric, delta_field) in enumerate(PAIRED_METRICS.items()):
            paired = paired_metrics.get(metric) or {}
            bootstrap = paired.get("bootstrap") or {}
            if integer(paired.get("pairs"), f"{name} {metric} pairs") != common:
                issues.append(f"{name}:{metric}_pair_count")
            if (
                integer(
                    bootstrap.get("requested_replicates"),
                    f"{name} {metric} requested replicates",
                )
                != bootstrap_replicates
                or integer(
                    bootstrap.get("valid_replicates"),
                    f"{name} {metric} valid replicates",
                )
                != bootstrap_replicates
            ):
                issues.append(f"{name}:{metric}_bootstrap")
            effect = clustered_effect(
                common_rows,
                delta_field,
                replicates=bootstrap_replicates,
                seed=deterministic_seed(f"{label}:{config_index}:{metric_index}:{name}:{metric}"),
            )
            if effect["records"] != common or effect["targets"] != expected_targets:
                issues.append(f"{name}:{metric}_cluster_population")
            analysis_mean = finite_number(paired.get("mean_variant_minus_baseline"))
            effect_mean = finite_number(effect.get("closure_weighted_mean_delta"))
            if (
                analysis_mean is None
                or effect_mean is None
                or not math.isclose(analysis_mean, effect_mean, abs_tol=0.00011)
            ):
                issues.append(f"{name}:{metric}_mean_reconstruction")
            effects.append(
                {
                    "dataset": label,
                    "configuration": name,
                    "metric": metric,
                    **effect,
                }
            )
        configuration_audits.append(
            {
                "configuration": name,
                "records_union": union,
                "common_records": common,
                "baseline_only": baseline_only,
                "variant_only": variant_only,
                "targets": target_count,
                "cohort_sha256": hashlib.sha256(
                    json.dumps(sorted(common_ids), separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
            }
        )

    return {
        "dataset": label,
        "valid": not issues,
        "issues": sorted(set(issues)),
        "full_corpus": full_corpus,
        "baseline_records": baseline_records,
        "configurations": configuration_audits,
        "clustered_effects": effects,
    }


def build_audit(
    release_root: Path,
    tag: str,
    *,
    bootstrap_replicates: int = BOOTSTRAP_REPLICATES,
) -> dict[str, Any]:
    release_root = release_root.resolve()
    binding_path = release_root / "manuscript_binding" / "manuscript_binding.json"
    binding = strict_json(binding_path)
    if binding.get("ready") is not True:
        raise ValueError("manuscript binding is not ready")
    accepted_records = integer(binding.get("records"), "accepted records")

    datasets = []
    identities: dict[str, dict[str, Any]] = {}
    specifications = (
        (
            "bounded_matrix",
            release_root
            / f"tsds_v20_matrix_analysis_{tag}"
            / "v19_ablation_analysis.json",
            release_root
            / f"tsds_v20_matrix_transitions_{tag}"
            / "record_level_ablation_summary.json",
            BOUNDED_CONFIGURATIONS,
            False,
        ),
        (
            "full_corpus_confirmation",
            release_root
            / f"tsds_v20_confirmatory_analysis_{tag}"
            / "v19_ablation_analysis.json",
            release_root
            / f"tsds_v20_confirmatory_transitions_{tag}"
            / "record_level_ablation_summary.json",
            CONFIRMATORY_CONFIGURATIONS,
            True,
        ),
    )
    for label, analysis_path, transition_path, configurations, full_corpus in specifications:
        analysis = strict_json(analysis_path)
        transition, csv_path, rows = load_transition_rows(transition_path)
        datasets.append(
            audit_dataset(
                label,
                analysis,
                transition,
                rows,
                expected_configurations=configurations,
                accepted_records=accepted_records,
                full_corpus=full_corpus,
                bootstrap_replicates=bootstrap_replicates,
            )
        )
        identities[label] = {
            "analysis": {
                "path": analysis_path.relative_to(release_root).as_posix(),
                "size": analysis_path.stat().st_size,
                "sha256": sha256_file(analysis_path),
            },
            "transition_summary": {
                "path": transition_path.relative_to(release_root).as_posix(),
                "size": transition_path.stat().st_size,
                "sha256": sha256_file(transition_path),
            },
            "transition_csv": {
                "path": csv_path.relative_to(release_root).as_posix(),
                "size": csv_path.stat().st_size,
                "sha256": sha256_file(csv_path),
            },
        }
    issues = [
        f"{dataset['dataset']}:{issue}"
        for dataset in datasets
        for issue in dataset["issues"]
    ]
    return {
        "schema": SCHEMA,
        "tag": tag,
        "valid": not issues,
        "issues": sorted(issues),
        "accepted_records": accepted_records,
        "bootstrap": {
            "method": "firmware_cluster_percentile",
            "unit": "firmware_target",
            "requested_replicates": bootstrap_replicates,
            "expected_targets": EXPECTED_TARGETS,
        },
        "inputs": identities,
        "datasets": datasets,
        "claim_boundary": (
            "This audit validates paired within-TSDS cohorts and target-clustered "
            "uncertainty on the evaluated corpus. It does not establish causal effects "
            "outside the registered configurations, cross-tool superiority, or device "
            "exploitability."
        ),
    }


def write_outputs(out_dir: Path, document: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "paired_experiment_audit.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    configuration_rows = [
        {"dataset": dataset["dataset"], **row}
        for dataset in document["datasets"]
        for row in dataset["configurations"]
    ]
    with (out_dir / "paired_cohort_audit.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(
            stream, fieldnames=list(configuration_rows[0]), lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(configuration_rows)
    effect_rows = []
    for dataset in document["datasets"]:
        for effect in dataset["clustered_effects"]:
            effect_rows.append(
                {
                    "dataset": effect["dataset"],
                    "configuration": effect["configuration"],
                    "metric": effect["metric"],
                    "records": effect["records"],
                    "targets": effect["targets"],
                    "closure_weighted_mean_delta": effect[
                        "closure_weighted_mean_delta"
                    ],
                    "closure_weighted_cluster_bootstrap_95": json.dumps(
                        effect["closure_weighted_cluster_bootstrap_95"]
                    ),
                    "target_balanced_mean_delta": effect[
                        "target_balanced_mean_delta"
                    ],
                    "target_balanced_bootstrap_95": json.dumps(
                        effect["target_balanced_bootstrap_95"]
                    ),
                    "positive_targets": effect["target_direction"]["positive"],
                    "negative_targets": effect["target_direction"]["negative"],
                    "zero_targets": effect["target_direction"]["zero"],
                }
            )
    with (out_dir / "firmware_clustered_effects.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(
            stream, fieldnames=list(effect_rows[0]), lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(effect_rows)
    (out_dir / "README.md").write_text(
        "# TSDS v20 Paired Experiment Audit\n\n"
        f"Valid: **{document['valid']}**; issues: **{len(document['issues'])}**.\n\n"
        "The bounded matrix uses one identical closure cohort for every registered "
        "P0/P1/P2 configuration. The confirmation matrix covers the complete accepted "
        "corpus. Confidence intervals resample firmware targets rather than treating "
        "closures as independent experimental units.\n\n"
        + document["claim_boundary"]
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-root", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--bootstrap-replicates", type=int, default=BOOTSTRAP_REPLICATES)
    parser.add_argument("--fail-on-issues", action="store_true")
    args = parser.parse_args()
    try:
        document = build_audit(
            args.release_root,
            args.tag,
            bootstrap_replicates=args.bootstrap_replicates,
        )
        write_outputs(args.out_dir.resolve(), document)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"V20_PAIRED_EXPERIMENT_AUDIT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(document, indent=2, sort_keys=True))
    return 3 if args.fail_on_issues and not document["valid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
