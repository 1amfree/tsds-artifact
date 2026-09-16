#!/usr/bin/env python3
"""Export paper-facing TSDS v10 tables from contract-validated ledgers.

This is deliberately an artifact gate, not a reporting convenience: it refuses
to export a campaign with contract-invalid records or failed companion audits.
All headline counts are derived from ``verdict`` rather than legacy statuses.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


ALLOWED_VERDICTS = {
    "VECTOR_SAT",
    "MATRIX_UNSAT",
    "NO_MODELED_SOURCE",
    "STATIC_SOURCE_INFERENCE",
    "STATIC_WARNING_REDUCTION",
    "RESIDUAL",
}

VERDICT_ORDER = (
    "VECTOR_SAT",
    "MATRIX_UNSAT",
    "NO_MODELED_SOURCE",
    "STATIC_SOURCE_INFERENCE",
    "STATIC_WARNING_REDUCTION",
    "RESIDUAL",
)


def strict_json_object(payload: str | bytes, label: str) -> dict[str, Any]:
    """解析 JSON 对象并拒绝重复键，避免 paper 计数出现解析歧义。"""

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key {key!r} in {label}")
            value[key] = item
        return value

    value = json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not a JSON object")
    return value


def target_from_path(path: Path) -> str:
    suffix = ".results.jsonl"
    return path.name[: -len(suffix)] if path.name.endswith(suffix) else path.stem


def read_records(campaign_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(campaign_dir.rglob("*.results.jsonl")):
        target = target_from_path(path)
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                record = strict_json_object(line, f"{path}:{line_no}")
            except ValueError as exc:
                raise ValueError(f"invalid record at {path}:{line_no}: {exc}") from exc
            record["_artifact_target"] = target
            record["_artifact_path"] = str(path)
            record["_artifact_line"] = line_no
            records.append(record)
    if not records:
        raise ValueError(f"no TSDS results JSONL files under {campaign_dir}")
    return records


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def normalize_vector_decision(value: Any) -> str:
    """Normalize current TSDS labels and compact historical aliases."""
    label = str(value or "INCONCLUSIVE").upper()
    if label in {"SAT", "VECTOR_SAT"}:
        return "SAT"
    if label in {"UNSAT", "MATRIX_UNSAT"}:
        return "UNSAT"
    return "INCONCLUSIVE"


def display_token(value: Any) -> str:
    """Render control tokens safely in CSV/LaTeX-adjacent artifact tables."""
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")


def validate_record(record: dict[str, Any]) -> None:
    location = f"{record.get('_artifact_path')}:{record.get('_artifact_line')}"
    verdict = str(record.get("verdict") or "")
    _require(verdict in ALLOWED_VERDICTS, f"{location}: unsupported or missing verdict {verdict!r}")
    _require(record.get("evidence_contract_valid") is True, f"{location}: evidence contract invalid")
    provenance = str(record.get("evidence_provenance") or "")
    decisions = record.get("vector_decisions") or record.get("threat_matrix_decisions") or []
    if verdict == "VECTOR_SAT":
        _require(record.get("sink_reached_observed") is True, f"{location}: VECTOR_SAT without observed sink")
        _require(provenance in {"DIRECT_SINK_BYTE", "SINK_RECONCILED"}, f"{location}: invalid positive provenance")
        _require(bool(record.get("tainted_offsets")), f"{location}: VECTOR_SAT without controlled offsets")
        _require(
            any(normalize_vector_decision(row.get("decision")) == "SAT" for row in decisions),
            f"{location}: VECTOR_SAT without SAT vector",
        )
        witness = record.get("minimal_bypass_vector") or {}
        _require(bool(witness), f"{location}: VECTOR_SAT without minimal witness")
    elif verdict == "MATRIX_UNSAT":
        _require(provenance == "DIRECT_SINK_BYTE", f"{location}: MATRIX_UNSAT is not direct evidence")
        _require(record.get("sink_reached_observed") is True, f"{location}: MATRIX_UNSAT without observed sink")
        _require(bool(record.get("tainted_offsets")), f"{location}: MATRIX_UNSAT without controlled offsets")
        _require(bool(decisions), f"{location}: MATRIX_UNSAT without vector decisions")
        _require(
            all(normalize_vector_decision(row.get("decision")) == "UNSAT" for row in decisions),
            f"{location}: MATRIX_UNSAT has non-UNSAT vector decision",
        )
    elif verdict == "NO_MODELED_SOURCE":
        _require(record.get("sink_reached_observed") is True, f"{location}: NMS without observed sink")


def validate_contract_audit(path: Path | None, record_count: int) -> dict[str, Any] | None:
    if path is None:
        return None
    audit = strict_json_object(path.read_text(encoding="utf-8"), str(path))
    _require(int(audit.get("records") or 0) == record_count, "contract audit record count mismatch")
    _require(int(audit.get("records_with_contract_issues") or 0) == 0, "contract audit contains issues")
    _require(not (audit.get("contract_issue_counts") or {}), "contract audit issue counts are non-empty")
    return audit


def validate_syntax_audit(path: Path | None, vector_sat_count: int) -> dict[str, Any] | None:
    if path is None:
        return None
    audit = strict_json_object(path.read_text(encoding="utf-8"), str(path))
    outcomes = audit.get("record_outcomes") or {}
    _require(int(outcomes.get("records_all_witnesses_invalid") or 0) == 0, "syntax audit has fully invalid positive records")
    _require(
        int(outcomes.get("records_any_syntax_valid") or 0) >= vector_sat_count,
        "syntax audit does not cover every VECTOR_SAT record",
    )
    return audit


def validate_repeatability_consensus(
    path: Path | None, record_count: int
) -> dict[str, Any] | None:
    """验证 conservative consensus 与当前 campaign 使用相同 record set。"""

    if path is None:
        return None
    audit = strict_json_object(path.read_text(encoding="utf-8"), str(path))
    _require(
        audit.get("schema") == "tsds-repeatability-audit-v4",
        "repeatability audit schema mismatch",
    )
    _require(
        int(audit.get("baseline_records") or 0) == record_count,
        "repeatability baseline record count mismatch",
    )
    _require(
        int(audit.get("replay_records") or 0) == record_count,
        "repeatability replay record count mismatch",
    )
    _require(
        int(audit.get("baseline_only") or 0) == 0,
        "repeatability baseline-only records present",
    )
    _require(
        int(audit.get("replay_only") or 0) == 0,
        "repeatability replay-only records present",
    )
    core = audit.get("sink_semantic_core") or {}
    _require(
        int(core.get("baseline_records") or 0) > 0,
        "repeatability sink-semantic core is empty",
    )
    _require(
        core.get("baseline_reproduced") is True,
        "repeatability sink-semantic core drifted",
    )
    consensus = audit.get("conservative_consensus") or {}
    verdicts = consensus.get("verdicts") or {}
    _require(
        isinstance(verdicts, dict),
        "repeatability consensus verdicts are not an object",
    )
    _require(
        set(verdicts).issubset(ALLOWED_VERDICTS),
        "repeatability consensus has unknown verdicts",
    )
    _require(
        int(consensus.get("records") or 0) == record_count,
        "repeatability consensus record count mismatch",
    )
    _require(
        sum(int(value or 0) for value in verdicts.values()) == record_count,
        "repeatability consensus verdict total mismatch",
    )
    return audit


def percentile(values: list[float], percentile_value: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    index = max(0, math.ceil(percentile_value * len(values)) - 1)
    return round(values[index], 4)


def load_campaign_resources(campaign_dir: Path) -> dict[str, dict[str, Any]]:
    path = campaign_dir / "full_campaign_aggregate.json"
    if not path.is_file():
        return {}
    aggregate = json.loads(path.read_text(encoding="utf-8"))
    resources = {
        str(row.get("target")): row
        for row in aggregate.get("targets") or []
        if row.get("target")
    }
    if aggregate.get("total"):
        resources["TOTAL"] = aggregate["total"]
    return resources


def runtime_row(
    target: str,
    elapsed: list[float],
    resource: dict[str, Any],
) -> dict[str, Any]:
    analysis_total = round(sum(elapsed), 4)
    wall_raw = resource.get("wall_time_sec")
    campaign_wall = float(wall_raw) if wall_raw is not None else None
    if campaign_wall is not None:
        _require(
            int(resource.get("evaluated") or len(elapsed)) == len(elapsed),
            f"{target}: campaign evaluated count differs from JSONL records",
        )
        _require(
            campaign_wall + 0.001 >= analysis_total,
            f"{target}: record timers exceed campaign wall time",
        )
        startup_orchestration = round(max(0.0, campaign_wall - analysis_total), 4)
        amortized_wall = round(campaign_wall / len(elapsed), 4) if elapsed else None
        timer_coverage = (
            round(100.0 * analysis_total / campaign_wall, 2)
            if campaign_wall > 0
            else None
        )
    else:
        startup_orchestration = None
        amortized_wall = None
        timer_coverage = None
    return {
        "target": target,
        "records": len(elapsed),
        # Legacy names are retained for artifact compatibility. They describe
        # run_single_closure analysis timers, not end-to-end process cost.
        "total_sec": analysis_total,
        "mean_sec": round(statistics.mean(elapsed), 4),
        "median_sec": round(statistics.median(elapsed), 4),
        "p95_sec": percentile(elapsed, 0.95),
        "max_sec": round(max(elapsed), 4),
        "timing_scope": "run_single_closure_analysis_phase",
        "campaign_wall_sec": round(campaign_wall, 4) if campaign_wall is not None else None,
        "amortized_wall_sec_per_record": amortized_wall,
        "startup_orchestration_sec": startup_orchestration,
        "record_timer_coverage_pct": timer_coverage,
        "peak_rss_mb": resource.get("peak_rss_mb"),
        "user_cpu_sec": resource.get("user_cpu_sec"),
        "system_cpu_sec": resource.get("system_cpu_sec"),
    }


def aggregate_records(
    records: list[dict[str, Any]],
    campaign_resources: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    campaign_resources = campaign_resources or {}
    verdicts = Counter(str(record["verdict"]) for record in records)
    provenance = Counter(str(record.get("evidence_provenance") or "unspecified") for record in records)
    per_target: dict[str, Counter[str]] = defaultdict(Counter)
    target_elapsed: dict[str, list[float]] = defaultdict(list)
    vector_profile: dict[str, Counter[str]] = defaultdict(Counter)
    vector_metadata: dict[str, dict[str, str]] = {}
    workload: dict[str, Counter[str]] = defaultdict(Counter)
    residuals = Counter()
    for record in records:
        target = str(record["_artifact_target"])
        per_target[target][str(record["verdict"])] += 1
        target_elapsed[target].append(float(record.get("elapsed_sec") or 0.0))
        target_workload = workload[target]
        target_workload["matrix_solver_queries"] += int(record.get("matrix_solver_queries") or 0)
        target_workload["matrix_candidates"] += int(record.get("matrix_candidate_count") or 0)
        target_workload["engine_steps"] += int(record.get("engine_steps") or 0)
        target_workload["seed_states_tried"] += int(record.get("seed_states_tried") or 0)
        target_workload["seed_states_pruned"] += int(record.get("seed_states_pruned") or 0)
        target_workload["path_pruned_states"] += int(record.get("path_control_pruned_states") or 0)
        target_workload["max_active_states"] = max(
            target_workload["max_active_states"],
            int(record.get("engine_max_active") or 0),
        )
        for decision in record.get("vector_decisions") or record.get("threat_matrix_decisions") or []:
            vector_id = str(decision.get("vector_id") or decision.get("vector") or "unspecified")
            vector_profile[vector_id][normalize_vector_decision(decision.get("decision"))] += 1
            vector_metadata.setdefault(
                vector_id,
                {
                    "vector_id": vector_id,
                    "token": display_token(decision.get("vector") or vector_id),
                    "effect_class": str(decision.get("effect_class") or "unspecified"),
                },
            )
        if record["verdict"] == "RESIDUAL":
            residuals[
                str(
                    record.get("residual_diagnosis")
                    or record.get("engine_stop_reason")
                    or record.get("status")
                    or "unspecified"
                )
            ] += 1

    target_rows = []
    runtime_rows = []
    workload_rows = []
    for target in sorted(per_target):
        counts = per_target[target]
        target_rows.append({
            "target": target,
            "records": sum(counts.values()),
            **{verdict: counts.get(verdict, 0) for verdict in VERDICT_ORDER},
        })
        elapsed = target_elapsed[target]
        resource = campaign_resources.get(target) or {}
        runtime_rows.append(runtime_row(target, elapsed, resource))
        target_workload = workload[target]
        workload_rows.append({
            "target": target,
            "records": len(elapsed),
            "matrix_solver_queries": target_workload["matrix_solver_queries"],
            "matrix_candidates": target_workload["matrix_candidates"],
            "engine_steps": target_workload["engine_steps"],
            "seed_states_tried": target_workload["seed_states_tried"],
            "seed_states_pruned": target_workload["seed_states_pruned"],
            "path_pruned_states": target_workload["path_pruned_states"],
            "max_active_states": target_workload["max_active_states"],
            "peak_rss_mb": resource.get("peak_rss_mb"),
        })
    all_elapsed = [float(record.get("elapsed_sec") or 0.0) for record in records]
    runtime_rows.append(
        runtime_row("TOTAL", all_elapsed, campaign_resources.get("TOTAL") or {})
    )
    workload_rows.append({
        "target": "TOTAL",
        "records": len(records),
        "matrix_solver_queries": sum(row["matrix_solver_queries"] for row in workload_rows),
        "matrix_candidates": sum(row["matrix_candidates"] for row in workload_rows),
        "engine_steps": sum(row["engine_steps"] for row in workload_rows),
        "seed_states_tried": sum(row["seed_states_tried"] for row in workload_rows),
        "seed_states_pruned": sum(row["seed_states_pruned"] for row in workload_rows),
        "path_pruned_states": sum(row["path_pruned_states"] for row in workload_rows),
        "max_active_states": max((row["max_active_states"] for row in workload_rows), default=0),
        "peak_rss_mb": (campaign_resources.get("TOTAL") or {}).get("peak_rss_mb"),
    })
    vector_rows = [
        {
            **vector_metadata[vector],
            "SAT": counts.get("SAT", 0),
            "UNSAT": counts.get("UNSAT", 0),
            "INCONCLUSIVE": counts.get("INCONCLUSIVE", 0),
        }
        for vector, counts in sorted(vector_profile.items())
    ]
    overall_rows = [
        {"evidence_class": verdict, "count": verdicts.get(verdict, 0)}
        for verdict in VERDICT_ORDER
    ]
    return {
        "overall_rows": overall_rows,
        "per_target_rows": target_rows,
        "runtime_rows": runtime_rows,
        "workload_rows": workload_rows,
        "vector_rows": vector_rows,
        "residual_rows": [
            {"residual_class": key, "count": value}
            for key, value in sorted(residuals.items())
        ],
        "verdicts": dict(verdicts),
        "provenance": dict(provenance),
    }


def write_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    rows = list(rows)
    fields = list(rows[0]) if rows else ["empty"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_consensus_tables(
    out_dir: Path, repeatability: dict[str, Any]
) -> list[dict[str, Any]]:
    """生成与单次 observed 计数分离的保守共识 CSV 和 LaTeX 表。"""

    consensus = repeatability["conservative_consensus"]
    verdicts = consensus.get("verdicts") or {}
    rows = [
        {"evidence_class": verdict, "count": int(verdicts.get(verdict) or 0)}
        for verdict in VERDICT_ORDER
    ]
    write_csv(out_dir / "paper_repeatability_consensus.csv", rows)
    lines = [
        r"\begin{tabular}{lr}",
        r"\toprule",
        r"Conservative evidence class & Records \\",
        r"\midrule",
    ]
    for row in rows:
        label = str(row["evidence_class"]).replace("_", r"\_")
        lines.append(f"{label} & {row['count']} \\\\")
    lines.extend(
        [
            r"\midrule",
            f"Downgraded to residual & {int(consensus.get('downgraded_to_residual') or 0)} \\\\",
            r"\bottomrule",
            r"\end{tabular}",
            "",
        ]
    )
    (out_dir / "paper_repeatability_consensus.tex").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    return rows


def write_latex(path: Path, data: dict[str, Any]) -> None:
    def latex_escape(value: Any) -> str:
        return str(value).replace("_", r"\_")

    overall = data["overall_rows"]
    per_target = data["per_target_rows"]
    lines = [
        "% Generated by experiments/export_v10_paper_tables.py; do not edit counts manually.",
        "\\begin{tabular}{lr}",
        "\\toprule",
        "Evidence class & Records \\\\",
        "\\midrule",
    ]
    for row in overall:
        lines.append(f"{latex_escape(row['evidence_class'])} & {row['count']} \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", "", "\\begin{tabular}{lrrrrrr}", "\\toprule"])
    lines.append("Target & SV-SAT & M-Filt & NMS & Static-src & Static-red. & Residual \\\\")
    lines.append("\\midrule")
    for row in per_target:
        target = latex_escape(row["target"])
        lines.append(
            f"{target} & {row['VECTOR_SAT']} & {row['MATRIX_UNSAT']} & "
            f"{row['NO_MODELED_SOURCE']} & {row['STATIC_SOURCE_INFERENCE']} & "
            f"{row['STATIC_WARNING_REDUCTION']} & {row['RESIDUAL']} \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def export_tables(
    campaign_dir: Path,
    out_dir: Path,
    contract_audit_path: Path | None = None,
    syntax_audit_path: Path | None = None,
    repeatability_audit_path: Path | None = None,
) -> dict[str, Any]:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty paper-table directory: {out_dir}")
    records = read_records(campaign_dir)
    for record in records:
        validate_record(record)
    data = aggregate_records(records, load_campaign_resources(campaign_dir))
    contract_audit = validate_contract_audit(contract_audit_path, len(records))
    syntax_audit = validate_syntax_audit(
        syntax_audit_path, data["verdicts"].get("VECTOR_SAT", 0)
    )
    repeatability_audit = validate_repeatability_consensus(
        repeatability_audit_path, len(records)
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / "paper_overall.csv", data["overall_rows"])
    write_csv(out_dir / "paper_per_target.csv", data["per_target_rows"])
    write_csv(out_dir / "paper_vector_profile.csv", data["vector_rows"])
    write_csv(out_dir / "paper_runtime.csv", data["runtime_rows"])
    write_csv(out_dir / "paper_workload.csv", data["workload_rows"])
    write_csv(out_dir / "paper_residuals.csv", data["residual_rows"])
    write_latex(out_dir / "paper_tables.tex", data)
    consensus_rows = (
        write_consensus_tables(out_dir, repeatability_audit)
        if repeatability_audit is not None
        else []
    )
    summary = {
        "schema": "tsds-paper-table-export-v2",
        "claim_boundary": (
            "Counts are analyzer-level, contract-validated sink-byte evidence. "
            "They are not device-confirmed exploit counts."
        ),
        "campaign_dir": str(campaign_dir),
        "records": len(records),
        "all_contract_valid": True,
        "verdicts": data["verdicts"],
        "provenance": data["provenance"],
        "contract_audit": str(contract_audit_path) if contract_audit else None,
        "syntax_audit": str(syntax_audit_path) if syntax_audit else None,
        "contract_audit_schema": contract_audit and contract_audit.get("schema"),
        "syntax_audit_schema": syntax_audit and syntax_audit.get("schema"),
        "repeatability_audit": (
            str(repeatability_audit_path) if repeatability_audit is not None else None
        ),
        "repeatability_audit_sha256": (
            hashlib.sha256(repeatability_audit_path.read_bytes()).hexdigest()
            if repeatability_audit is not None and repeatability_audit_path is not None
            else None
        ),
        "repeatability_consensus": (
            repeatability_audit.get("conservative_consensus")
            if repeatability_audit is not None
            else None
        ),
        "repeatability_consensus_rows": consensus_rows,
    }
    (out_dir / "paper_data_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        "# TSDS v10 paper data export\n\n"
        "All tables in this directory were generated from contract-valid JSONL "
        "records. Use `paper_tables.tex` or the CSV files; do not transcribe "
        "legacy status counters manually.\n\n"
        + summary["claim_boundary"] + "\n",
        encoding="utf-8",
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--contract-audit", type=Path)
    parser.add_argument("--syntax-audit", type=Path)
    parser.add_argument("--repeatability-audit", type=Path)
    args = parser.parse_args()
    try:
        summary = export_tables(
            args.campaign_dir,
            args.out_dir,
            args.contract_audit,
            args.syntax_audit,
            args.repeatability_audit,
        )
    except ValueError as exc:
        print(f"PAPER_TABLE_EXPORT_ERROR: {exc}")
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
