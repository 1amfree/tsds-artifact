#!/usr/bin/env python3
"""Compare two TSDS campaign runs for evidence-level repeatability.

The comparison deliberately ignores wall-clock and model-rendering noise.  It
checks both the reported class and its serialized evidence basis: controlled
sink offsets, sink binding, C-string boundary, shell-vector decisions, and
grammar-complete witnesses.
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


REPEATABILITY_SCHEMA = "tsds-repeatability-audit-v4"
SEMANTIC_PROJECTION_SCHEMA = "tsds-evidence-repeatability-projection-v2"
COMMAND_TEMPLATE_PROJECTION_SCHEMA = "tsds-command-template-projection-v1"


SEMANTIC_FIELDS = (
    "verdict",
    "evidence_provenance",
    "admissible_claim",
    "evidence_contract_valid",
    "status",  # retained only to expose migration drift explicitly
    "evidence_conditioning",
    "primary_aggregate_eligible",
)

# These classes are admitted only from reached sink semantics.  Static warning
# reductions, static source inferences, and residual obligations are reported
# separately so timing-sensitive search outcomes cannot obscure stability of
# the paper's sink-level evidence claims.
SINK_SEMANTIC_VERDICTS = {
    "VECTOR_SAT",
    "MATRIX_UNSAT",
    "NO_MODELED_SOURCE",
}


def _target_from_path(path: Path) -> str:
    suffix = ".results.jsonl"
    return path.name[: -len(suffix)] if path.name.endswith(suffix) else path.stem


def record_identity(target: str, record: dict[str, Any]) -> str:
    """Return a stable per-closure key independent of execution timing."""
    identity = {
        "target": target,
        "closure_idx": record.get("closure_idx"),
        "source_addr": record.get("source_addr"),
        "sink_addr": record.get("sink_addr"),
        "closure_sink_signature": record.get("closure_sink_signature"),
    }
    return json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str)


def normalized_vector_profile(record: dict[str, Any]) -> list[dict[str, Any]]:
    decisions = record.get("vector_decisions") or record.get("threat_matrix_decisions") or []
    profile = []
    for decision in decisions:
        profile.append(
            {
                "vector": decision.get("vector_id") or decision.get("vector"),
                "decision": decision.get("decision"),
                "effect_class": decision.get("effect_class"),
                "quote_context": decision.get("quote_context"),
                "witness_kind": decision.get("witness_kind"),
                "grammar_complete": decision.get("grammar_complete"),
                "category": decision.get("category"),
                "lexical_reason": decision.get("lexical_reason"),
                "lexical_gate": decision.get("lexical_gate"),
                "parser_calibration": decision.get("parser_calibration"),
                "schema": decision.get("schema"),
                "witness": decision.get("witness") or decision.get("poc"),
                "witness_template": decision.get("witness_template"),
                "controlled_witness_offsets": sorted(
                    int(value)
                    for value in (decision.get("controlled_witness_offsets") or [])
                    if isinstance(value, int) and not isinstance(value, bool)
                ),
            }
        )
    return sorted(profile, key=lambda item: str(item["vector"]))


def normalized_offsets(record: dict[str, Any]) -> list[int]:
    raw = record.get("controlled_offsets") or record.get("tainted_offsets") or []
    values = {
        int(value)
        for value in raw
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
    }
    return sorted(values)


def normalized_minimal_witness(record: dict[str, Any]) -> dict[str, Any]:
    witness = record.get("minimal_bypass_vector") or {}
    if not isinstance(witness, dict):
        return {}
    return {
        "vector_id": witness.get("vector_id") or witness.get("vector"),
        "vector": witness.get("vector"),
        "decision": witness.get("decision"),
        "effect_class": witness.get("effect_class"),
        "grammar_complete": witness.get("grammar_complete"),
        "parser_calibration": witness.get("parser_calibration"),
        "witness": witness.get("witness") or witness.get("poc"),
    }


def strict_json_object(payload: str | bytes, label: str) -> dict[str, Any]:
    """Parse one ledger row while rejecting duplicate object keys."""

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


def decode_rendered_preview(preview: Any) -> bytes:
    """Decode the byte escapes emitted by ``render_model_bytes``."""

    text = str(preview or "")
    decoded = bytearray()
    index = 0
    while index < len(text):
        if (
            index + 3 < len(text)
            and text[index : index + 2] == "\\x"
            and all(char in "0123456789abcdefABCDEF" for char in text[index + 2 : index + 4])
        ):
            decoded.append(int(text[index + 2 : index + 4], 16))
            index += 4
            continue
        decoded.extend(text[index].encode("latin-1", errors="replace"))
        index += 1
    return bytes(decoded)


def command_template_projection(record: dict[str, Any]) -> dict[str, Any] | None:
    """Project a model rendering to fixed bytes plus a controlled-byte mask.

    Solver-selected values inside source-controlled offsets are witnesses, not
    stable command-template literals.  NMS and residual claims do not depend on
    the concrete values chosen for unmodeled symbolic bytes, so their previews
    remain ledger diagnostics and are excluded from the semantic signature.
    """

    if str(record.get("verdict") or "") not in {"VECTOR_SAT", "MATRIX_UNSAT"}:
        return None
    preview = record.get("sink_preview")
    if preview is None:
        preview = record.get("no_taint_preview")
    if preview is None:
        return None
    rendered = bytearray(decode_rendered_preview(preview))
    controlled_mask = bytearray(len(rendered))
    outside_extent: list[int] = []
    for offset in normalized_offsets(record):
        if offset < len(rendered):
            rendered[offset] = 0
            controlled_mask[offset] = 1
        else:
            outside_extent.append(offset)
    return {
        "schema": COMMAND_TEMPLATE_PROJECTION_SCHEMA,
        "byte_length": len(rendered),
        "fixed_bytes_sha256": hashlib.sha256(bytes(rendered)).hexdigest(),
        "controlled_mask_sha256": hashlib.sha256(bytes(controlled_mask)).hexdigest(),
        "controlled_offsets_outside_preview": outside_extent,
    }


def semantic_projection(record: dict[str, Any]) -> dict[str, Any]:
    projection = {field: record.get(field) for field in SEMANTIC_FIELDS}
    projection["sink_evidence"] = {
        "reached": record.get("sink_reached_observed"),
        "captured_function": record.get("captured_sink_function_name")
        or record.get("sink_function"),
        "function_name_source": record.get("sink_function_name_source"),
        "semantics": record.get("sink_semantics"),
        "binding_source": record.get("sink_argument_binding_source"),
        "binding_trust": record.get("sink_argument_binding_trust"),
        "snapshot_cstring_complete": record.get("sink_snapshot_cstring_complete"),
        "snapshot_capture_length": record.get("sink_snapshot_capture_length"),
        "snapshot_terminator_offset": record.get("sink_snapshot_terminator_offset"),
        "command_template": command_template_projection(record),
    }
    projection["source_evidence"] = {
        "controlled_offsets": normalized_offsets(record),
        "tainted_byte_count": record.get("tainted_byte_count"),
        "source_kinds": sorted(
            str(value) for value in (record.get("source_kinds") or [])
        ),
    }
    projection["vector_profile"] = normalized_vector_profile(record)
    projection["minimal_witness"] = normalized_minimal_witness(record)
    projection["matrix_counts"] = {
        "vulnerable_vectors": record.get("vulnerable_vectors"),
        "secure_vectors": record.get("secure_vectors"),
        "inconclusive_vectors": record.get("inconclusive_vectors"),
    }
    projection["diagnostic_boundary"] = {
        "analysis_recovery": record.get("analysis_recovery"),
        "engine_stop_reason": record.get("engine_stop_reason"),
        "path_control_class": record.get("path_control_class"),
        "residual_diagnosis": record.get("residual_diagnosis"),
    }
    return projection


def semantic_signature(record: dict[str, Any]) -> str:
    encoded = json.dumps(
        semantic_projection(record), sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def campaign_results_identity(campaign_dir: Path) -> dict[str, Any]:
    """Bind an audit to the ordered result-ledger bytes it compared."""
    digest = hashlib.sha256()
    files = sorted(campaign_dir.rglob("*.results.jsonl"))
    for path in files:
        relative = path.relative_to(campaign_dir).as_posix().encode("utf-8")
        payload = path.read_bytes()
        digest.update(relative)
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).digest())
        digest.update(b"\0")
    return {
        "path": str(campaign_dir.resolve()),
        "result_files": len(files),
        "results_identity_sha256": digest.hexdigest(),
    }


def load_campaign_records(campaign_dir: Path) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for path in sorted(campaign_dir.rglob("*.results.jsonl")):
        target = _target_from_path(path)
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            record = strict_json_object(line, f"{path}:{line_no}")
            key = record_identity(target, record)
            if key in records:
                raise ValueError(f"duplicate repeatability key {key} in {path}:{line_no}")
            records[key] = {
                "target": target,
                "record": record,
                "path": str(path),
                "line": line_no,
            }
    if not records:
        raise ValueError(f"no results JSONL records in {campaign_dir}")
    return records


def differing_fields(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    left_projection = semantic_projection(left)
    right_projection = semantic_projection(right)
    return [
        field
        for field in left_projection
        if left_projection.get(field) != right_projection.get(field)
    ]


def compare_campaigns(
    baseline_dir: Path, replay_dir: Path
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    baseline = load_campaign_records(baseline_dir)
    replay = load_campaign_records(replay_dir)
    keys = sorted(set(baseline) | set(replay))
    rows: list[dict[str, Any]] = []
    summary = {
        "schema": REPEATABILITY_SCHEMA,
        "semantic_projection": {
            "schema": SEMANTIC_PROJECTION_SCHEMA,
            "command_template_schema": COMMAND_TEMPLATE_PROJECTION_SCHEMA,
            "model_preview_policy": (
                "VECTOR_SAT and MATRIX_UNSAT compare fixed command bytes after "
                "masking controlled offsets; NMS, static, and residual previews "
                "remain diagnostics and do not enter the evidence signature."
            ),
        },
        "claim_boundary": (
            "Agreement establishes analyzer-level repeatability of evidence labels; "
            "it does not establish device-level exploitability."
        ),
        "baseline_records": len(baseline),
        "replay_records": len(replay),
        "common_records": 0,
        "stable_records": 0,
        "semantic_drift": 0,
        "baseline_only": 0,
        "replay_only": 0,
        "implementation": {
            "path": str(Path(__file__).resolve()),
            "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
        "inputs": {
            "baseline": campaign_results_identity(baseline_dir),
            "replay": campaign_results_identity(replay_dir),
        },
    }
    per_baseline_verdict: dict[str, collections.Counter[str]] = {}
    sink_semantic_core: collections.Counter[str] = collections.Counter()
    consensus_counts: collections.Counter[str] = collections.Counter()
    consensus_downgrades = 0
    for key in keys:
        left = baseline.get(key)
        right = replay.get(key)
        if left is None:
            summary["replay_only"] += 1
            outcome = "replay_only"
            fields = ["record_missing_from_baseline"]
        elif right is None:
            summary["baseline_only"] += 1
            outcome = "baseline_only"
            fields = ["record_missing_from_replay"]
        else:
            summary["common_records"] += 1
            fields = differing_fields(left["record"], right["record"])
            if fields:
                summary["semantic_drift"] += 1
                outcome = "semantic_drift"
            else:
                summary["stable_records"] += 1
                outcome = "stable"
        baseline_verdict = (
            str(left["record"].get("verdict") or "UNKNOWN") if left else None
        )
        if baseline_verdict is not None:
            tier = per_baseline_verdict.setdefault(
                baseline_verdict, collections.Counter()
            )
            tier["baseline_records"] += 1
            if right is None:
                tier["baseline_only"] += 1
            else:
                tier["common_records"] += 1
                tier["semantic_drift" if fields else "stable_records"] += 1
            if baseline_verdict in SINK_SEMANTIC_VERDICTS:
                sink_semantic_core["baseline_records"] += 1
                if right is None:
                    sink_semantic_core["baseline_only"] += 1
                else:
                    sink_semantic_core["common_records"] += 1
                    sink_semantic_core[
                        "semantic_drift" if fields else "stable_records"
                    ] += 1
        exemplar = (left or right)["record"]
        if outcome == "stable":
            consensus_verdict = str(
                right["record"].get("verdict")
                or left["record"].get("verdict")
                or "RESIDUAL"
            )
        else:
            # Replication disagreement is never allowed to strengthen a claim.
            consensus_verdict = "RESIDUAL"
            consensus_downgrades += 1
        consensus_counts[consensus_verdict] += 1
        rows.append(
            {
                "record_id": key,
                "target": (left or right)["target"],
                "closure_idx": exemplar.get("closure_idx"),
                "source_addr": exemplar.get("source_addr"),
                "sink_addr": exemplar.get("sink_addr"),
                "baseline_verdict": left and left["record"].get("verdict"),
                "replay_verdict": right and right["record"].get("verdict"),
                "baseline_provenance": left and left["record"].get("evidence_provenance"),
                "replay_provenance": right and right["record"].get("evidence_provenance"),
                "outcome": outcome,
                "consensus_verdict": consensus_verdict,
                "differing_fields": ";".join(fields),
                "baseline_signature": left and semantic_signature(left["record"]),
                "replay_signature": right and semantic_signature(right["record"]),
            }
        )
    summary["agreement_pct"] = round(
        100.0 * summary["stable_records"] / summary["common_records"], 2
    ) if summary["common_records"] else 0.0
    summary["repeatable"] = not (
        summary["semantic_drift"]
        or summary["baseline_only"]
        or summary["replay_only"]
    )
    summary["baseline_reproduced"] = not (
        summary["semantic_drift"] or summary["baseline_only"]
    )
    def finalize_tier(counter: collections.Counter[str]) -> dict[str, Any]:
        values = {
            key: int(counter.get(key, 0))
            for key in (
                "baseline_records",
                "common_records",
                "stable_records",
                "semantic_drift",
                "baseline_only",
            )
        }
        values["agreement_pct"] = (
            round(
                100.0 * values["stable_records"] / values["common_records"],
                2,
            )
            if values["common_records"]
            else 0.0
        )
        values["baseline_reproduced"] = not (
            values["semantic_drift"] or values["baseline_only"]
        )
        return values

    summary["per_baseline_verdict"] = {
        verdict: finalize_tier(counter)
        for verdict, counter in sorted(per_baseline_verdict.items())
    }
    summary["sink_semantic_core"] = finalize_tier(sink_semantic_core)
    summary["conservative_consensus"] = {
        "records": int(sum(consensus_counts.values())),
        "downgraded_to_residual": int(consensus_downgrades),
        "verdicts": {
            verdict: int(count)
            for verdict, count in sorted(consensus_counts.items())
        },
        "claim_boundary": (
            "A record keeps its evidence verdict only when both runs have the "
            "same semantic projection; every drift or missing record is "
            "fail-closed to RESIDUAL."
        ),
    }
    return rows, summary


def repeatability_gate_issues(
    summary: dict[str, Any],
    *,
    fail_on_drift: bool = False,
    fail_on_sink_semantic_drift: bool = False,
    require_sink_semantic_records: bool = False,
    require_baseline_subset: bool = False,
    require_same_record_set: bool = False,
) -> list[str]:
    """按命令行门禁策略返回可机器审计的中文无关稳定错误码。"""

    issues: list[str] = []
    core = summary.get("sink_semantic_core") or {}
    if fail_on_drift and not summary.get("repeatable"):
        issues.append("repeatability_semantic_drift")
    if fail_on_sink_semantic_drift and not core.get("baseline_reproduced"):
        issues.append("sink_semantic_repeatability_failed")
    # 非空约束防止 0/0 agreement 被误解释为实验重复性证据。
    if require_sink_semantic_records and int(core.get("baseline_records") or 0) <= 0:
        issues.append("sink_semantic_baseline_empty")
    if require_baseline_subset and not summary.get("baseline_reproduced"):
        issues.append("repeatability_baseline_subset_failed")
    if require_same_record_set and (
        int(summary.get("baseline_only") or 0)
        or int(summary.get("replay_only") or 0)
    ):
        issues.append("repeatability_record_set_mismatch")
    return issues


def write_outputs(out_dir: Path, rows: Iterable[dict[str, Any]], summary: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = list(rows)
    fields = [
        "record_id", "target", "closure_idx", "source_addr", "sink_addr",
        "baseline_verdict", "replay_verdict", "baseline_provenance",
        "replay_provenance", "outcome", "differing_fields",
        "consensus_verdict", "baseline_signature", "replay_signature",
    ]
    with (out_dir / "repeatability_records.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "repeatability_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    tier_fields = [
        "verdict",
        "baseline_records",
        "common_records",
        "stable_records",
        "semantic_drift",
        "baseline_only",
        "agreement_pct",
        "baseline_reproduced",
    ]
    tier_rows = [
        {"verdict": verdict, **values}
        for verdict, values in summary.get("per_baseline_verdict", {}).items()
    ]
    with (out_dir / "repeatability_by_verdict.csv").open(
        "w", newline="", encoding="utf-8"
    ) as fh:
        writer = csv.DictWriter(fh, fieldnames=tier_fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(tier_rows)
    consensus = summary.get("conservative_consensus", {})
    with (out_dir / "repeatability_consensus.csv").open(
        "w", newline="", encoding="utf-8"
    ) as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["verdict", "records"], lineterminator="\n"
        )
        writer.writeheader()
        for verdict, count in consensus.get("verdicts", {}).items():
            writer.writerow({"verdict": verdict, "records": count})
    latex_lines = [
        r"\begin{tabular}{lrrrr}",
        r"\toprule",
        r"Baseline verdict & Records & Stable & Drift & Agreement (\%) \\",
        r"\midrule",
    ]
    for row in tier_rows:
        verdict = str(row["verdict"]).replace("_", r"\_")
        latex_lines.append(
            f"{verdict} & {row['baseline_records']} & {row['stable_records']} & "
            f"{row['semantic_drift']} & {row['agreement_pct']:.2f} \\\\"
        )
    core = summary.get("sink_semantic_core", {})
    latex_lines.extend(
        [
            r"\midrule",
            f"Sink-semantic core & {core.get('baseline_records', 0)} & "
            f"{core.get('stable_records', 0)} & {core.get('semantic_drift', 0)} & "
            f"{float(core.get('agreement_pct', 0.0)):.2f} \\\\ ".rstrip(),
            r"\bottomrule",
            r"\end{tabular}",
            "",
        ]
    )
    (out_dir / "repeatability_tables.tex").write_text(
        "\n".join(latex_lines), encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        "# TSDS repeatability audit\n\n"
        f"Common records: **{summary['common_records']}**; stable: "
        f"**{summary['stable_records']}**; semantic drift: "
        f"**{summary['semantic_drift']}**; agreement: "
        f"**{summary['agreement_pct']}%**.\n\n"
        + summary["claim_boundary"] + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-dir", type=Path, required=True)
    parser.add_argument("--replay-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--fail-on-drift", action="store_true")
    parser.add_argument(
        "--fail-on-sink-semantic-drift",
        action="store_true",
        help=(
            "Fail only when a baseline VECTOR_SAT, MATRIX_UNSAT, or "
            "NO_MODELED_SOURCE record is missing or semantically changed."
        ),
    )
    parser.add_argument(
        "--require-baseline-subset",
        action="store_true",
        help="Require every baseline record to be stable while allowing extra replay records.",
    )
    parser.add_argument(
        "--require-sink-semantic-records",
        action="store_true",
        help=(
            "Require at least one baseline VECTOR_SAT, MATRIX_UNSAT, or "
            "NO_MODELED_SOURCE record; this rejects vacuous 0/0 agreement."
        ),
    )
    parser.add_argument(
        "--require-same-record-set",
        action="store_true",
        help="Require baseline and replay to contain exactly the same closure identities.",
    )
    args = parser.parse_args()
    rows, summary = compare_campaigns(args.baseline_dir, args.replay_dir)
    gate_issues = repeatability_gate_issues(
        summary,
        fail_on_drift=args.fail_on_drift,
        fail_on_sink_semantic_drift=args.fail_on_sink_semantic_drift,
        require_sink_semantic_records=args.require_sink_semantic_records,
        require_baseline_subset=args.require_baseline_subset,
        require_same_record_set=args.require_same_record_set,
    )
    summary["gate_issues"] = gate_issues
    write_outputs(args.out_dir, rows, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if gate_issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
