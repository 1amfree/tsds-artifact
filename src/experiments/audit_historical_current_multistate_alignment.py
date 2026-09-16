#!/usr/bin/env python3
"""Audit exact-key alignment between a frozen V20 run and a current rerun.

The audit is deliberately narrower than a historical completeness claim.  It
checks that both campaigns describe the same target-level binary/Mango inputs,
that their serialized result ledgers contain the same target/source/sink keys,
and that the current ledger carries the bounded multi-state receipts.  Changes
in outcomes are reported descriptively; they are not silently treated as
regressions or semantic ground truth.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "tsds-historical-current-multistate-alignment-v1"
COMPARE_FIELDS = (
    "status",
    "verdict",
    "evidence_provenance",
    "evidence_conditioning",
    "sink_reached_observed",
)
INPUT_FIELDS = (
    "binary",
    "binary_sha256",
    "mango",
    "mango_sha256",
    "binary_exists",
    "mango_exists",
)


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _target_name(result_path: Path) -> str:
    suffix = ".results.jsonl"
    if not result_path.name.endswith(suffix):
        raise ValueError(f"unexpected result filename: {result_path}")
    return result_path.name[: -len(suffix)]


def _load_campaign(campaign_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    rows_by_key: dict[str, dict[str, Any]] = {}
    target_rows: dict[str, list[dict[str, Any]]] = {}
    result_paths = sorted(campaign_dir.rglob("*.results.jsonl"))
    if not result_paths:
        raise ValueError(f"no result JSONL files found under {campaign_dir}")
    for path in result_paths:
        target = _target_name(path)
        if target in target_rows:
            raise ValueError(f"duplicate target result file: {target}")
        rows: list[dict[str, Any]] = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected JSON object")
            source = str(value.get("source_addr") or "")
            sink = str(value.get("sink_addr") or "")
            key = "\x1f".join((target, source, sink))
            rows.append(value)
            if not source or not sink:
                # Keep the row in the accounting, but use a unique marker so
                # the caller can report malformed identities without masking
                # another malformed row as a duplicate.
                key = "\x1f".join((target, source, sink, str(line_number)))
            if key in rows_by_key:
                raise ValueError(f"duplicate result identity: {target}/{source}/{sink}")
            rows_by_key[key] = value
        target_rows[target] = rows
    return rows_by_key, {
        "result_file_count": len(result_paths),
        "target_record_counts": {
            target: len(rows) for target, rows in sorted(target_rows.items())
        },
        "rows_by_target": target_rows,
    }


def _load_config(path: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    config = _load_json(path)
    targets = config.get("targets")
    if not isinstance(targets, list):
        raise ValueError(f"configuration has no target list: {path}")
    by_name: dict[str, dict[str, Any]] = {}
    for item in targets:
        if not isinstance(item, dict) or not item.get("name"):
            raise ValueError(f"invalid target descriptor in {path}")
        name = str(item["name"])
        if name in by_name:
            raise ValueError(f"duplicate configured target: {name}")
        by_name[name] = item
    return by_name, config


def _input_alignment(
    old_targets: dict[str, dict[str, Any]],
    new_targets: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    old_names = set(old_targets)
    new_names = set(new_targets)
    rows: list[dict[str, Any]] = []
    for name in sorted(old_names | new_names):
        old = old_targets.get(name)
        new = new_targets.get(name)
        if old is None or new is None:
            rows.append({"target": name, "present_old": old is not None, "present_new": new is not None, "exact_input_match": False})
            issues.append("configured_target_set_mismatch")
            continue
        differences = [field for field in INPUT_FIELDS if old.get(field) != new.get(field)]
        exact = not differences
        if not exact:
            issues.append("target_input_descriptor_mismatch")
        rows.append(
            {
                "target": name,
                "binary": new.get("binary"),
                "binary_sha256": new.get("binary_sha256"),
                "mango": new.get("mango"),
                "mango_sha256": new.get("mango_sha256"),
                "differences": differences,
                "exact_input_match": exact,
            }
        )
    return {
        "old_target_count": len(old_targets),
        "new_target_count": len(new_targets),
        "common_target_count": len(old_names & new_names),
        "all_target_inputs_match": bool(rows) and all(row.get("exact_input_match") for row in rows),
        "targets": rows,
    }, issues


def _display_key(key: str) -> list[str]:
    return key.split("\x1f")[:3]


def _row_alignment(
    old_rows: dict[str, dict[str, Any]],
    new_rows: dict[str, dict[str, Any]],
    old_meta: dict[str, Any],
    new_meta: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    old_keys = set(old_rows)
    new_keys = set(new_rows)
    old_only = sorted(old_keys - new_keys)
    new_only = sorted(new_keys - old_keys)
    common = sorted(old_keys & new_keys)
    if old_only or new_only:
        issues.append("serialized_key_set_mismatch")
    if old_meta["target_record_counts"] != new_meta["target_record_counts"]:
        issues.append("target_record_count_mismatch")
    missing_identity_rows = sum(
        not str(row.get("source_addr") or "") or not str(row.get("sink_addr") or "")
        for row in list(old_rows.values()) + list(new_rows.values())
    )
    if missing_identity_rows:
        issues.append("missing_source_or_sink_identity")
    return {
        "old_record_count": len(old_rows),
        "new_record_count": len(new_rows),
        "old_unique_key_count": len(old_keys),
        "new_unique_key_count": len(new_keys),
        "exact_key_intersection_count": len(common),
        "old_only_key_count": len(old_only),
        "new_only_key_count": len(new_only),
        "old_only_examples": [_display_key(key) for key in old_only[:10]],
        "new_only_examples": [_display_key(key) for key in new_only[:10]],
        "target_record_counts_equal": old_meta["target_record_counts"] == new_meta["target_record_counts"],
        "missing_identity_rows": missing_identity_rows,
    }, issues


def _field_differences(
    old_rows: dict[str, dict[str, Any]],
    new_rows: dict[str, dict[str, Any]],
    common_keys: list[str],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field in COMPARE_FIELDS:
        pairs: Counter[str] = Counter()
        changed_keys: list[str] = []
        for key in common_keys:
            old_value = old_rows[key].get(field)
            new_value = new_rows[key].get(field)
            if old_value != new_value:
                changed_keys.append(key)
                pairs[f"{_canonical(old_value)} => {_canonical(new_value)}"] += 1
        result[field] = {
            "changed_row_count": len(changed_keys),
            "unchanged_row_count": len(common_keys) - len(changed_keys),
            "top_value_transitions": [
                {"transition": transition, "rows": count}
                for transition, count in pairs.most_common(12)
            ],
            "changed_examples": [
                {
                    "key": _display_key(key),
                    "old": old_rows[key].get(field),
                    "new": new_rows[key].get(field),
                }
                for key in changed_keys[:5]
            ],
        }
    return result


def _bounded_multistate_summary(rows: dict[str, dict[str, Any]]) -> dict[str, Any]:
    audited = 0
    engine_flagged = 0
    sink_reached = 0
    complete = 0
    incomplete = 0
    unknown_completion = 0
    profile_count = 0
    first_nonpositive_later_positive = 0
    selected_later_positive = 0
    selected_nonpositive_later_positive = 0
    candidate_wide_negative = 0
    aggregate_classes: Counter[str] = Counter()
    late_cases: list[dict[str, Any]] = []

    for key, row in rows.items():
        if row.get("engine_multi_state_audit") is True:
            engine_flagged += 1
        if row.get("sink_reached_observed"):
            sink_reached += 1
        audit = row.get("multi_state_audit")
        if not isinstance(audit, dict):
            continue
        audited += 1
        aggregate = audit.get("aggregate")
        if not isinstance(aggregate, dict):
            aggregate = {}
        profiles = audit.get("profiles")
        if not isinstance(profiles, list):
            profiles = []
        profile_count += len(profiles)
        completion = audit.get("collection_complete")
        if not isinstance(completion, bool):
            completion = aggregate.get("collection_complete")
        if completion is True:
            complete += 1
        elif completion is False:
            incomplete += 1
        else:
            unknown_completion += 1
        aggregate_classes[str(aggregate.get("aggregate_class") or "unspecified")] += 1
        if bool(aggregate.get("candidate_wide_negative")):
            candidate_wide_negative += 1

        positive_indices = [
            index
            for index, profile in enumerate(profiles)
            if isinstance(profile, dict) and str(profile.get("status") or "") == "VECTOR_SAT"
        ]
        later_positive = any(index > 0 for index in positive_indices)
        first_positive = 0 in positive_indices
        selection = audit.get("primary_selection")
        if not isinstance(selection, dict):
            selection = {}
        selected = selection.get("selected_state_index")
        try:
            selected_index = int(selected) if selected is not None else None
        except (TypeError, ValueError):
            selected_index = None
        selected_positive = selected_index in positive_indices if selected_index is not None else False
        if profiles and not first_positive and later_positive:
            first_nonpositive_later_positive += 1
            late_cases.append(
                {
                    "key": _display_key(key),
                    "closure_idx": row.get("closure_idx"),
                    "profile_count": len(profiles),
                    "positive_indices": positive_indices,
                    "selected_state_index": selected_index,
                    "selected_positive": selected_positive,
                }
            )
        if selected_positive and selected_index is not None and selected_index > 0:
            selected_later_positive += 1
        if selected_index is not None and not selected_positive and later_positive:
            selected_nonpositive_later_positive += 1

    return {
        "engine_multi_state_flag_rows": engine_flagged,
        "multi_state_audit_rows": audited,
        "sink_reached_rows": sink_reached,
        "collection_complete_rows": complete,
        "collection_incomplete_rows": incomplete,
        "collection_completion_unknown_rows": unknown_completion,
        "serialized_profile_count": profile_count,
        "first_nonpositive_later_positive_rows": first_nonpositive_later_positive,
        "selected_later_positive_rows": selected_later_positive,
        "selected_nonpositive_later_positive_rows": selected_nonpositive_later_positive,
        "candidate_wide_negative_flags": candidate_wide_negative,
        "aggregate_classes": dict(sorted(aggregate_classes.items())),
        "late_positive_cases": late_cases,
    }


def build_alignment(
    old_campaign: Path,
    new_campaign: Path,
    old_config: Path,
    new_config: Path,
) -> dict[str, Any]:
    old_rows, old_meta = _load_campaign(old_campaign.resolve())
    new_rows, new_meta = _load_campaign(new_campaign.resolve())
    old_targets, old_config_value = _load_config(old_config.resolve())
    new_targets, new_config_value = _load_config(new_config.resolve())

    input_alignment, input_issues = _input_alignment(old_targets, new_targets)
    row_alignment, row_issues = _row_alignment(
        old_rows, new_rows, old_meta, new_meta
    )
    common_keys = sorted(set(old_rows) & set(new_rows))
    issues = sorted(set(input_issues + row_issues))
    return {
        "schema": SCHEMA,
        "claim_boundary": (
            "This receipt proves exact-key and declared-input alignment between "
            "two serialized campaign ledgers.  It does not prove historical "
            "exhaustive state coverage, solver soundness, source realizability, "
            "firmware-wide precision/recall, or device exploitability."
        ),
        "old_campaign": str(old_campaign.resolve()),
        "new_campaign": str(new_campaign.resolve()),
        "old_configuration": str(old_config.resolve()),
        "new_configuration": str(new_config.resolve()),
        "configuration": {
            "old_schema": old_config_value.get("schema"),
            "new_schema": new_config_value.get("schema"),
            "old_global_campaign_driver_sha256": old_config_value.get("campaign_driver_sha256"),
            "new_global_campaign_driver_sha256": new_config_value.get("campaign_driver_sha256"),
            "old_global_evaluator_sha256": old_config_value.get("evaluator_sha256"),
            "new_global_evaluator_sha256": new_config_value.get("evaluator_sha256"),
            "old_new_argument_descriptors_equal": old_config_value.get("arguments") == new_config_value.get("arguments"),
            "input_alignment": input_alignment,
        },
        "ledger_alignment": {
            **row_alignment,
            "old_target_record_counts": old_meta["target_record_counts"],
            "new_target_record_counts": new_meta["target_record_counts"],
        },
        "outcome_field_differences": _field_differences(old_rows, new_rows, common_keys),
        "current_bounded_multistate": _bounded_multistate_summary(new_rows),
        "issues": issues,
        "valid": not issues,
        "input_sha256": {
            "old_configuration": _sha256(old_config.resolve()),
            "new_configuration": _sha256(new_config.resolve()),
        },
    }


def _write_outputs(out_dir: Path, result: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "historical_current_multistate_alignment.json"
    summary_path.write_text(
        json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    ledger = result["ledger_alignment"]
    current = result["current_bounded_multistate"]
    lines = [
        "# Historical/current multi-state alignment audit",
        "",
        f"Valid: **{result['valid']}**",
        f"Declared target inputs matching: **{result['configuration']['input_alignment']['common_target_count']}/{result['configuration']['input_alignment']['new_target_count']}**",
        f"Exact serialized key intersection: **{ledger['exact_key_intersection_count']}**",
        f"Old/new records: **{ledger['old_record_count']} / {ledger['new_record_count']}**",
        f"Current audited sink-reached rows: **{current['multi_state_audit_rows']}**",
        f"Current serialized profiles: **{current['serialized_profile_count']}**",
        f"Current complete/incomplete collections: **{current['collection_complete_rows']} / {current['collection_incomplete_rows']}**",
        f"First non-positive, later positive: **{current['first_nonpositive_later_positive_rows']}**",
        f"Selected non-positive despite later positive: **{current['selected_nonpositive_later_positive_rows']}**",
        "",
        "## Interpretation",
        "",
        "The exact-key result establishes that the current bounded rerun covers the same serialized target/source/sink identities as the frozen ledger, while the declared binary and Mango input descriptors match for every common target.",
        "",
        "This is an alignment and metadata receipt.  It does not retroactively add multi-state profiles to the frozen run and does not establish exhaustive path coverage, solver soundness, source realizability, firmware-wide ground truth, or device exploitability.",
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    digest_lines = []
    for path in sorted(out_dir.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            digest_lines.append(f"{_sha256(path)}  {path.name}")
    (out_dir / "SHA256SUMS").write_text("\n".join(digest_lines) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-campaign", type=Path, required=True)
    parser.add_argument("--new-campaign", type=Path, required=True)
    parser.add_argument("--old-config", type=Path, required=True)
    parser.add_argument("--new-config", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_alignment(
            args.old_campaign,
            args.new_campaign,
            args.old_config,
            args.new_config,
        )
        _write_outputs(args.out_dir.resolve(), result)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"HISTORICAL_CURRENT_MULTISTATE_ALIGNMENT_ERROR: {exc}")
        return 2
    print(
        json.dumps(
            {
                "valid": result["valid"],
                "issues": result["issues"],
                "old_records": result["ledger_alignment"]["old_record_count"],
                "new_records": result["ledger_alignment"]["new_record_count"],
                "exact_key_intersection": result["ledger_alignment"]["exact_key_intersection_count"],
                "current_profiles": result["current_bounded_multistate"]["serialized_profile_count"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
