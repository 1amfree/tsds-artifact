#!/usr/bin/env python3
"""Export record-level transitions for a TSDS mechanism matrix.

The paired matrix summary reports aggregate verdict and performance changes.
This companion export preserves the closure-level evidence needed to audit
those aggregates without embedding every record in the summary JSON.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.audit_repeatability import (  # noqa: E402
    SINK_SEMANTIC_VERDICTS,
    campaign_results_identity,
    differing_fields,
    load_campaign_records,
    semantic_signature,
)
from experiments.analyze_tsds_v19_experiment_matrix import (  # noqa: E402
    campaign_fingerprint,
    fingerprint_issues,
)


SCHEMA = "tsds-v20-record-level-ablation-transitions-v1"
METRICS = (
    "elapsed_sec",
    "process_peak_rss_mib",
    "engine_steps_total",
    "matrix_solver_queries",
    "engine_scheduler_pruned",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def finite_number(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def vector_signature(record: Mapping[str, Any] | None) -> str:
    if not record:
        return ""
    rows = []
    for item in record.get("vector_decisions") or record.get("threat_matrix_decisions") or []:
        rows.append(
            {
                "vector": item.get("vector_id") or item.get("vector"),
                "decision": item.get("decision"),
                "effect_class": item.get("effect_class"),
                "quote_context": item.get("quote_context"),
                "grammar_complete": item.get("grammar_complete"),
            }
        )
    encoded = compact_json(sorted(rows, key=lambda row: str(row["vector"]))).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def identity_fields(key: str) -> dict[str, Any]:
    value = json.loads(key)
    if not isinstance(value, dict):
        raise ValueError(f"record identity is not an object: {key}")
    return value


def transition_row(
    configuration: str,
    key: str,
    baseline_item: Mapping[str, Any] | None,
    variant_item: Mapping[str, Any] | None,
) -> dict[str, Any]:
    identity = identity_fields(key)
    baseline = baseline_item.get("record") if baseline_item else None
    variant = variant_item.get("record") if variant_item else None
    baseline_verdict = str((baseline or {}).get("verdict") or "MISSING")
    variant_verdict = str((variant or {}).get("verdict") or "MISSING")
    common = baseline is not None and variant is not None
    semantic_stable = common and semantic_signature(baseline) == semantic_signature(variant)
    row: dict[str, Any] = {
        "configuration": configuration,
        "target": identity.get("target"),
        "closure_idx": identity.get("closure_idx"),
        "source_addr": identity.get("source_addr"),
        "sink_addr": identity.get("sink_addr"),
        "closure_sink_signature": compact_json(identity.get("closure_sink_signature")),
        "record_presence": (
            "both" if common else ("baseline_only" if baseline is not None else "variant_only")
        ),
        "baseline_verdict": baseline_verdict,
        "variant_verdict": variant_verdict,
        "verdict_transition": f"{baseline_verdict}->{variant_verdict}",
        "baseline_sink_semantic": baseline_verdict in SINK_SEMANTIC_VERDICTS,
        "semantic_stable": semantic_stable if common else "",
        "differing_semantic_fields": (
            ";".join(differing_fields(baseline, variant)) if common and not semantic_stable else ""
        ),
        "baseline_semantic_sha256": semantic_signature(baseline) if baseline else "",
        "variant_semantic_sha256": semantic_signature(variant) if variant else "",
        "baseline_vector_sha256": vector_signature(baseline),
        "variant_vector_sha256": vector_signature(variant),
        "baseline_recovery": (baseline or {}).get("analysis_recovery") or "direct",
        "variant_recovery": (variant or {}).get("analysis_recovery") or "direct",
        "baseline_residual": (baseline or {}).get("residual_diagnosis") or "",
        "variant_residual": (variant or {}).get("residual_diagnosis") or "",
        "baseline_path_control": (baseline or {}).get("path_control_class") or "",
        "variant_path_control": (variant or {}).get("path_control_class") or "",
    }
    for metric in METRICS:
        left = finite_number((baseline or {}).get(metric))
        right = finite_number((variant or {}).get(metric))
        row[f"baseline_{metric}"] = left if left is not None else ""
        row[f"variant_{metric}"] = right if right is not None else ""
        row[f"delta_{metric}"] = (
            round(right - left, 6) if left is not None and right is not None else ""
        )
    return row


def export_transitions(
    baseline_dir: Path,
    matrix_dir: Path,
    out_dir: Path,
) -> dict[str, Any]:
    baseline_dir = baseline_dir.resolve()
    matrix_dir = matrix_dir.resolve()
    out_dir = out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    campaign_root = matrix_dir / "campaigns"
    campaigns = sorted(path for path in campaign_root.iterdir() if path.is_dir())
    if not campaigns:
        raise ValueError(f"no configuration campaigns found: {campaign_root}")
    out_dir.mkdir(parents=True, exist_ok=True)

    baseline = load_campaign_records(baseline_dir)
    baseline_fingerprint = campaign_fingerprint(baseline_dir)
    rows: list[dict[str, Any]] = []
    configuration_rows: list[dict[str, Any]] = []
    issues: list[str] = []
    for campaign in campaigns:
        variant = load_campaign_records(campaign)
        variant_fingerprint = campaign_fingerprint(campaign)
        local_issues = fingerprint_issues(baseline_fingerprint, variant_fingerprint)
        issues.extend(f"{campaign.name}:{item}" for item in local_issues)
        keys = sorted(set(baseline) | set(variant))
        local_rows = [
            transition_row(campaign.name, key, baseline.get(key), variant.get(key))
            for key in keys
        ]
        rows.extend(local_rows)
        presence = Counter(str(row["record_presence"]) for row in local_rows)
        transitions = Counter(str(row["verdict_transition"]) for row in local_rows)
        common = [row for row in local_rows if row["record_presence"] == "both"]
        stable = sum(row["semantic_stable"] is True for row in common)
        configuration_rows.append(
            {
                "configuration": campaign.name,
                "records_union": len(local_rows),
                "common_records": len(common),
                "baseline_only": presence.get("baseline_only", 0),
                "variant_only": presence.get("variant_only", 0),
                "semantic_stable": stable,
                "semantic_agreement_pct": (
                    round(100.0 * stable / len(common), 4) if common else None
                ),
                "verdict_transitions": dict(sorted(transitions.items())),
                "results_identity": campaign_results_identity(campaign),
                "fingerprint_issues": local_issues,
            }
        )
        if not common:
            issues.append(f"{campaign.name}:no_common_record_identities")

    csv_path = out_dir / "record_level_ablation_transitions.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "schema": SCHEMA,
        "valid": not issues,
        "issues": sorted(set(issues)),
        "baseline": campaign_results_identity(baseline_dir),
        "baseline_fingerprint": baseline_fingerprint,
        "matrix_dir": str(matrix_dir),
        "configurations": configuration_rows,
        "configuration_count": len(configuration_rows),
        "transition_rows": len(rows),
        "transition_csv": {
            "path": csv_path.name,
            "size": csv_path.stat().st_size,
            "sha256": sha256_file(csv_path),
        },
        "claim_boundary": (
            "Rows attribute within-TSDS mechanism changes on shared closure identities. "
            "They do not establish cross-tool superiority or device exploitability."
        ),
    }
    (out_dir / "record_level_ablation_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-dir", type=Path, required=True)
    parser.add_argument("--matrix-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--fail-on-issues", action="store_true")
    args = parser.parse_args()
    try:
        summary = export_transitions(args.baseline_dir, args.matrix_dir, args.out_dir)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ABLATION_TRANSITION_EXPORT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.fail_on_issues and not summary["valid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
