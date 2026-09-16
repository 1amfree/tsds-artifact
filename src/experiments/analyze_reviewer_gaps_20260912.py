#!/usr/bin/env python3
"""Build a hash-bound audit for the reviewer gaps in the TSDS study.

The audit combines independent, already-frozen receipts.  It does not run the
symbolic executor and it deliberately treats engine-exit state cardinality as
an observation, not as evidence of exhaustive sink-state coverage.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean, median
from typing import Any, Iterable


SCHEMA = "tsds-reviewer-gap-audit-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) * quantile) + 0.999999) - 1))
    return ordered[index]


def target_from_path(path: Path) -> str:
    return path.name.removesuffix(".results.jsonl")


def load_campaign(campaign: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    for path in sorted(campaign.glob("*.results.jsonl")):
        target = target_from_path(path)
        file_hash = sha256_file(path)
        files.append({"name": path.name, "target": target, "sha256": file_hash})
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            row = json.loads(line)
            row["_target"] = target
            row["_source_line"] = line_number
            rows.append(row)
    return rows, files


def count_by(rows: Iterable[dict[str, Any]], key: str) -> dict[str, int]:
    return dict(sorted(Counter(str(row.get(key)) for row in rows).items()))


def state_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    values = [int(row.get("engine_exit_active_states") or 0) for row in rows]
    return {
        "records": len(values),
        "zero": sum(value == 0 for value in values),
        "one": sum(value == 1 for value in values),
        "more_than_one": sum(value > 1 for value in values),
        "more_than_one_pct": round(100.0 * sum(value > 1 for value in values) / len(values), 4)
        if values
        else None,
        "mean": round(mean(values), 4) if values else None,
        "median": median(values) if values else None,
        "p95_nearest_rank": percentile([float(value) for value in values], 0.95),
        "max": max(values) if values else None,
        "definition": (
            "engine_exit_active_states emitted at worker termination; it is not "
            "a count of all admissible sink captures or a proof of exhaustive coverage"
        ),
    }


def grouped_state_summary(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row.get(key))].append(row)
    return {
        name: state_summary(group)
        for name, group in sorted(groups.items(), key=lambda item: item[0])
    }


def recursive_diff(left: Any, right: Any, path: str = "$") -> list[str]:
    if type(left) is not type(right):
        return [path]
    if isinstance(left, dict):
        diffs: list[str] = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                diffs.append(f"{path}.{key}")
            else:
                diffs.extend(recursive_diff(left[key], right[key], f"{path}.{key}"))
        return diffs
    if isinstance(left, list):
        diffs: list[str] = []
        if len(left) != len(right):
            diffs.append(f"{path}.length")
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            diffs.extend(recursive_diff(left_item, right_item, f"{path}[{index}]"))
        return diffs
    return [] if left == right else [path]


def find_one(root: Path, name: str) -> Path:
    matches = sorted(root.rglob(name))
    if len(matches) != 1:
        raise FileNotFoundError(f"expected one {name}, found {len(matches)}")
    return matches[0]


def parse_contract_receipt(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    passed = re.search(r"^passed=(\d+)$", text, re.MULTILINE)
    warnings = re.search(r"^warnings=(\d+)$", text, re.MULTILINE)
    subtests = re.search(r"^subtests_passed=(\d+)$", text, re.MULTILINE)
    excluded = re.search(r"^sanitizer_tests_excluded=(\d+)$", text, re.MULTILINE)
    return {
        "receipt": path.name,
        "sha256": sha256_file(path),
        "passed": int(passed.group(1)) if passed else None,
        "warnings": int(warnings.group(1)) if warnings else None,
        "subtests_passed": int(subtests.group(1)) if subtests else None,
        "sanitizer_tests_excluded": int(excluded.group(1)) if excluded else None,
    }


def build_audit(
    campaign: Path,
    repeatability: Path,
    evidence_root: Path,
    contract_receipt: Path,
) -> dict[str, Any]:
    rows, campaign_files = load_campaign(campaign)
    aggregate_path = campaign / "full_campaign_aggregate.json"
    aggregate = read_json(aggregate_path)
    repeatability_summary = read_json(repeatability)

    identity_material = "\n".join(
        f"{entry['name']}\t{entry['sha256']}" for entry in campaign_files
    ).encode("utf-8")
    campaign_identity = hashlib.sha256(identity_material).hexdigest()

    id_counts = Counter(
        (row["_target"], row.get("closure_idx")) for row in rows
    )
    duplicate_ids = [
        {"target": target, "closure_idx": closure_idx, "count": count}
        for (target, closure_idx), count in sorted(id_counts.items())
        if count > 1
    ]

    vector_rows = [row for row in rows if row.get("verdict") == "VECTOR_SAT"]
    provenance = Counter(row.get("evidence_provenance") for row in vector_rows)

    strict_root = evidence_root / "strict_r7000"
    semantic_snapshot = find_one(strict_root, "semantic_snapshot.json")
    replay_snapshot = find_one(strict_root, "semantic_snapshot.replay_reference.json")
    semantic_left = read_json(semantic_snapshot)
    semantic_right = read_json(replay_snapshot)
    semantic_diffs = recursive_diff(semantic_left, semantic_right)

    runtime_replay = find_one(strict_root, "runtime_archive_replay_check.json")
    cache_replay = find_one(strict_root, "cache_replay_check.json")
    runtime_replay_data = read_json(runtime_replay)
    cache_replay_data = read_json(cache_replay)

    current_native = find_one(
        evidence_root, "tsds_current_eight_runtime_evidence_audit_20260911.json"
    )
    current_native_data = read_json(current_native)
    fair_audit = find_one(evidence_root, "v92_fair_common_callsite_audit.json")
    fair_data = read_json(fair_audit)
    cold_audit = find_one(evidence_root, "cold_cache_common_callsite_audit.json")
    cold_data = read_json(cold_audit)
    synthetic = find_one(evidence_root, "controlled_accuracy_summary.json")
    synthetic_data = read_json(synthetic)

    return {
        "schema": SCHEMA,
        "generated_from": {
            "campaign": str(campaign),
            "campaign_identity_sha256": campaign_identity,
            "campaign_files": campaign_files,
            "aggregate": str(aggregate_path),
            "aggregate_sha256": sha256_file(aggregate_path),
            "repeatability_summary": str(repeatability),
            "repeatability_summary_sha256": sha256_file(repeatability),
            "contract_receipt": str(contract_receipt),
        },
        "v20_record_audit": {
            "raw_closures_declared": aggregate.get("total", {}).get("candidate_closures"),
            "result_rows": len(rows),
            "verdict_counts": count_by(rows, "verdict"),
            "duplicate_target_closure_ids": duplicate_ids,
            "vector_sat_provenance": dict(sorted(provenance.items())),
            "engine_exit_active_states": state_summary(rows),
            "by_verdict": grouped_state_summary(rows, "verdict"),
            "by_target": grouped_state_summary(rows, "_target"),
            "stop_reason_counts": count_by(rows, "engine_stop_reason"),
            "semantic_frontier": {
                "records_with_buckets": sum(
                    int(row.get("engine_semantic_frontier_buckets") or 0) > 0
                    for row in rows
                ),
                "records_with_pruning": sum(
                    int(row.get("engine_semantic_frontier_pruned") or 0) > 0
                    for row in rows
                ),
                "total_buckets": sum(
                    int(row.get("engine_semantic_frontier_buckets") or 0)
                    for row in rows
                ),
                "total_pruned": sum(
                    int(row.get("engine_semantic_frontier_pruned") or 0)
                    for row in rows
                ),
            },
            "interpretation": (
                "The state-cardinality audit quantifies the state frontier emitted "
                "by the frozen worker. It does not count all sink states, prove "
                "multi-state aggregation, or convert local M-Filt/NMS profiles "
                "into candidate-wide conclusions."
            ),
        },
        "repeatability": repeatability_summary,
        "current_source_validation": {
            "semantic_replay": {
                "reference_path": str(semantic_snapshot),
                "replay_path": str(replay_snapshot),
                "reference_sha256": sha256_file(semantic_snapshot),
                "replay_sha256": sha256_file(replay_snapshot),
                "reference_canonical_sha256": canonical_sha256(semantic_left),
                "replay_canonical_sha256": canonical_sha256(semantic_right),
                "recursive_difference_count": len(semantic_diffs),
                "recursive_difference_examples": semantic_diffs[:10],
                "analysis_targets": len(semantic_left.get("analysis", [])),
                "dynamic_sinks": len(semantic_left.get("dynamic_sinks", [])),
                "passed": not semantic_diffs,
            },
            "runtime_archive_replay": {
                "path": str(runtime_replay),
                "sha256": sha256_file(runtime_replay),
                "passed": runtime_replay_data.get("passed"),
                "different_sections": runtime_replay_data.get("different_sections"),
                "process_count": runtime_replay_data.get("left", {}).get("process_count"),
                "service_count": runtime_replay_data.get("left", {}).get("service_count"),
                "candidate_count": runtime_replay_data.get("replay_provenance", {})
                .get("service_probe", {})
                .get("candidate_count"),
                "receipt_count": runtime_replay_data.get("replay_provenance", {})
                .get("service_probe", {})
                .get("cardinality_audit", {})
                .get("receipt_count"),
            },
            "cache_replay": {
                "path": str(cache_replay),
                "sha256": sha256_file(cache_replay),
                "passed": cache_replay_data.get("passed"),
                "comparable": cache_replay_data.get("comparable"),
                "left": cache_replay_data.get("comparison", {}).get("left"),
                "right": cache_replay_data.get("comparison", {}).get("right"),
            },
            "linux_contract_tests": parse_contract_receipt(contract_receipt),
            "source_binding": {
                "simulation_archive_sha256": current_native_data.get("source_binding", {}).get(
                    "source_archive_sha256"
                ),
                "sanitizer_archive_sha256": "08845f283ddfa5ad9fff5d878b007a469f365efb241f30770b0f957a6ff136b3",
            },
        },
        "current_eight_firmware_structural_runtime": {
            "path": str(current_native),
            "sha256": sha256_file(current_native),
            "status": current_native_data.get("status"),
            "passed": current_native_data.get("passed"),
            "claim_boundary": current_native_data.get("claim_boundary"),
            "targets": current_native_data.get("batch", {}).get("target_count"),
            "totals": current_native_data.get("totals"),
        },
        "controlled_accuracy": {
            "path": str(synthetic),
            "sha256": sha256_file(synthetic),
            "scope": synthetic_data.get("scope"),
            "truth_callsite_count": synthetic_data.get("input", {}).get("truth_callsite_count"),
            "stock": {
                key: synthetic_data.get("results", {}).get("stock", {}).get(key)
                for key in ["true_positive", "false_positive", "false_negative", "precision", "recall", "f1"]
            },
            "v92": {
                key: synthetic_data.get("results", {}).get("v92", {}).get(key)
                for key in ["true_positive", "false_positive", "false_negative", "precision", "recall", "f1"]
            },
            "claim_boundary": synthetic_data.get("claim_boundary"),
        },
        "component_efficiency": {
            "warm_fair": {
                "path": str(fair_audit),
                "sha256": sha256_file(fair_audit),
                "status": fair_data.get("status"),
                "aggregate": fair_data.get("aggregate"),
                "claim_boundary": fair_data.get("claim_boundary"),
            },
            "cold_cache": {
                "path": str(cold_audit),
                "sha256": sha256_file(cold_audit),
                "status": cold_data.get("status"),
                "aggregate": cold_data.get("aggregate"),
                "claim_boundary": cold_data.get("claim_boundary"),
            },
        },
        "claim_policy": {
            "real_firmware_closed_world_accuracy": False,
            "independent_human_ground_truth": False,
            "independent_solver_replay": False,
            "exhaustive_multi_state_coverage": False,
            "device_level_exploitability": False,
            "broad_sota_superiority": False,
        },
    }


def write_markdown(audit: dict[str, Any], path: Path) -> None:
    v20 = audit["v20_record_audit"]
    states = v20["engine_exit_active_states"]
    repeatability = audit["repeatability"]
    current = audit["current_source_validation"]
    native = audit["current_eight_firmware_structural_runtime"]
    truth = audit["controlled_accuracy"]
    warm = audit["component_efficiency"]["warm_fair"]["aggregate"]
    cold = audit["component_efficiency"]["cold_cache"]["aggregate"]

    lines = [
        "# TSDS reviewer-gap audit (2026-09-12)",
        "",
        "This report is generated from frozen receipts and raw ledgers. It is an",
        "audit of evidence scope, repeatability, state-frontier multiplicity, and",
        "bounded calibration; it is not a vulnerability ground-truth study.",
        "",
        "## V20 state-frontier audit",
        "",
        f"- Raw closures declared by the campaign: **{v20['raw_closures_declared']}**.",
        f"- Result rows audited: **{v20['result_rows']}**; duplicate target/closure IDs: **{len(v20['duplicate_target_closure_ids'])}**.",
        f"- Exit active-state cardinality: zero={states['zero']}, one={states['one']}, greater than one={states['more_than_one']} ({states['more_than_one_pct']:.2f}%), median={states['median']}, p95={states['p95_nearest_rank']}, max={states['max']}.",
        f"- Semantic-frontier metadata: {v20['semantic_frontier']['records_with_buckets']} records expose buckets and {v20['semantic_frontier']['records_with_pruning']} expose pruning.",
        "",
        "The cardinality is the number of active states emitted at worker termination.",
        "It is not the number of accepted sink captures and does not establish",
        "exhaustive multi-state aggregation. The result therefore supports the",
        "selected-instance interpretation of local M-Filt/NMS profiles, rather than",
        "a candidate-wide negative conclusion.",
        "",
        "## Frozen repeatability",
        "",
        f"- Common records: **{repeatability.get('common_records')}**; stable records: **{repeatability.get('stable_records')}**; semantic drift: **{repeatability.get('semantic_drift')}**; agreement: **{repeatability.get('agreement_pct')}%**.",
        f"- Sink-semantic-core agreement: **{repeatability.get('sink_semantic_core', {}).get('agreement_pct')}%**.",
        "",
        "## Current-source validation",
        "",
        f"- Warm-cache semantic snapshot replay: **{current['semantic_replay']['analysis_targets']}/{current['semantic_replay']['analysis_targets']} targets**, recursive differences={current['semantic_replay']['recursive_difference_count']}.",
        f"- Runtime archive replay: passed={current['runtime_archive_replay']['passed']}, processes={current['runtime_archive_replay']['process_count']}, services={current['runtime_archive_replay']['service_count']}, service-probe candidates/receipts={current['runtime_archive_replay']['candidate_count']}/{current['runtime_archive_replay']['receipt_count']}.",
        f"- Linux contract receipt: {current['linux_contract_tests']['passed']} passed, {current['linux_contract_tests']['warnings']} warnings, {current['linux_contract_tests']['subtests_passed']} subtests; sanitizer tests excluded={current['linux_contract_tests']['sanitizer_tests_excluded']}.",
        f"- Current-source eight-firmware structural/runtime totals: {native['totals']['run_count']}/{native['totals']['command_count']} runs/commands, {native['totals']['process_count']} processes, {native['totals']['edge_count']} edges, {native['totals']['runtime_service_count']} runtime services, {native['totals']['listener_confirmed_service_count']} listener-confirmed services.",
        f"- Controlled synthetic callsite calibration: four callsites; stock F1={truth['stock']['f1']:.2f}, v92 F1={truth['v92']['f1']:.2f}.",
        f"- Equal-work static component: {warm['total_common_work_units']} common work units, v92 faster on {warm['candidate_faster_target_count']}/{warm['target_count']} targets, warm geometric stock/candidate wall ratio={warm['wall_speedup_geometric_mean_stock_over_candidate']:.6f}; cold-cache {cold['candidate_faster_target_count']}/{cold['target_count']}, ratio={cold['wall_speedup_geometric_mean_stock_over_candidate']:.6f}.",
        "",
        "The current-source and controlled-calibration results are reported with",
        "their declared scopes. They do not provide independent human labels,",
        "closed-world firmware precision/recall, independent SMT replay, or device",
        "exploitability evidence.",
        "",
        "## Reproduction",
        "",
        "The machine-readable JSON next to this report records all input paths,",
        "source hashes, canonical replay digests, and claim gates.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_csv(audit: dict[str, Any], path: Path) -> None:
    rows = []
    for target, values in audit["v20_record_audit"]["by_target"].items():
        rows.append(
            {
                "group": "target",
                "name": target,
                "records": values["records"],
                "zero": values["zero"],
                "one": values["one"],
                "more_than_one": values["more_than_one"],
                "more_than_one_pct": values["more_than_one_pct"],
                "median": values["median"],
                "p95_nearest_rank": values["p95_nearest_rank"],
                "max": values["max"],
            }
        )
    for verdict, values in audit["v20_record_audit"]["by_verdict"].items():
        rows.append(
            {
                "group": "verdict",
                "name": verdict,
                "records": values["records"],
                "zero": values["zero"],
                "one": values["one"],
                "more_than_one": values["more_than_one"],
                "more_than_one_pct": values["more_than_one_pct"],
                "median": values["median"],
                "p95_nearest_rank": values["p95_nearest_rank"],
                "max": values["max"],
            }
        )
    fields = [
        "group",
        "name",
        "records",
        "zero",
        "one",
        "more_than_one",
        "more_than_one_pct",
        "median",
        "p95_nearest_rank",
        "max",
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v20-campaign", type=Path, required=True)
    parser.add_argument("--repeatability", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--contract-receipt", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    audit = build_audit(
        args.v20_campaign,
        args.repeatability,
        args.evidence_root,
        args.contract_receipt,
    )
    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "reviewer_gap_audit.json"
    markdown_path = args.out / "reviewer_gap_audit.md"
    csv_path = args.out / "v20_state_cardinality.csv"
    json_path.write_text(
        json.dumps(audit, ensure_ascii=True, indent=2) + "\n", encoding="utf-8"
    )
    write_markdown(audit, markdown_path)
    write_csv(audit, csv_path)
    print(json.dumps({"passed": True, "json": str(json_path), "markdown": str(markdown_path), "csv": str(csv_path)}, indent=2))


if __name__ == "__main__":
    main()
