"""Audit non-promotion of historical conditioned records on a hardened rerun.

This audit compares the frozen V20 campaign with the current query-export
campaign.  It only joins records when target, source address, and sink address
match exactly, and it verifies that the two campaigns refer to the same local
binary and Mango-input digests.  The result is rerun-boundary evidence: it
does not infer a missing source link and does not claim semantic validity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "tsds-historical-conditioned-rerun-boundary-audit-v1"
DIRECT_PROVENANCE = "DIRECT_SINK_BYTE"
CONDITIONED_PROVENANCE = "SINK_RECONCILED"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def load_jsonl(path: Path, target: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"non-object row at {path}:{line_number}")
        row = dict(value)
        row["_campaign_target"] = target
        row["_source_file"] = str(path)
        rows.append(row)
    return rows


def target_from_results_path(path: Path) -> str:
    suffix = ".results.jsonl"
    if not path.name.endswith(suffix):
        raise ValueError(f"not a results JSONL path: {path}")
    return path.name[: -len(suffix)]


def result_files(campaign_dir: Path) -> dict[str, Path]:
    files = sorted(campaign_dir.rglob("*.results.jsonl"))
    by_target: dict[str, Path] = {}
    for path in files:
        target = target_from_results_path(path)
        if target in by_target:
            raise ValueError(
                f"multiple result files for target {target}: "
                f"{by_target[target]} and {path}"
            )
        by_target[target] = path
    return by_target


def input_fingerprints(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for target in config.get("targets") or []:
        if not isinstance(target, dict) or not target.get("name"):
            continue
        name = str(target["name"])
        result[name] = {
            "binary": target.get("binary"),
            "binary_sha256": target.get("binary_sha256"),
            "mango": target.get("mango"),
            "mango_sha256": target.get("mango_sha256"),
        }
    return result


def local_input_checks(root: Path, fingerprints: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for target, values in sorted(fingerprints.items()):
        row: dict[str, Any] = {"target": target}
        for kind in ("binary", "mango"):
            relative = values.get(kind)
            expected = str(values.get(f"{kind}_sha256") or "").lower()
            path = root / str(relative) if relative else root / "__missing__"
            exists = path.is_file()
            actual = sha256_file(path).lower() if exists else None
            row[f"{kind}_path"] = str(path)
            row[f"{kind}_exists"] = exists
            row[f"{kind}_expected_sha256"] = expected
            row[f"{kind}_actual_sha256"] = actual
            row[f"{kind}_matches"] = bool(exists and expected and actual == expected)
        row["matches"] = bool(row["binary_matches"] and row["mango_matches"])
        checks.append(row)
    return checks


def row_key(row: dict[str, Any]) -> tuple[str, str, str]:
    target = str(row.get("_campaign_target") or "")
    source = str(row.get("source_addr") or "")
    sink = str(row.get("sink_addr") or "")
    if not target or not source or not sink:
        raise ValueError(f"missing join key: {target!r}, {source!r}, {sink!r}")
    return target, source, sink


def is_conditioned(row: dict[str, Any]) -> bool:
    return bool(
        row.get("evidence_provenance") == CONDITIONED_PROVENANCE
        or row.get("analysis_recovery") == "static_dynamic_taint_reconciliation"
        or row.get("verdict") == "CT_SAT"
    )


def is_nonpromoted_current(row: dict[str, Any]) -> bool:
    link = row.get("reconciliation_link")
    return bool(
        row.get("evidence_provenance") not in {DIRECT_PROVENANCE, CONDITIONED_PROVENANCE}
        and row.get("analysis_recovery") != "static_dynamic_taint_reconciliation"
        and not isinstance(link, dict)
        and int(row.get("solver_query_bundle_count") or 0) == 0
    )


def build_audit(
    root: Path,
    historical_campaign: Path,
    current_campaign: Path,
    output_dir: Path,
) -> dict[str, Any]:
    historical_config_path = historical_campaign / "campaign_configuration.json"
    current_config_path = current_campaign / "campaign_configuration.json"
    historical_config = load_json(historical_config_path)
    current_config = load_json(current_config_path)
    historical_inputs = input_fingerprints(historical_config)
    current_inputs = input_fingerprints(current_config)

    common_targets = sorted(set(historical_inputs) & set(current_inputs))
    input_differences = {
        target: {
            "historical": historical_inputs.get(target),
            "current": current_inputs.get(target),
        }
        for target in common_targets
        if historical_inputs.get(target) != current_inputs.get(target)
    }
    target_set_match = set(historical_inputs) == set(current_inputs)
    local_inputs = local_input_checks(root, historical_inputs)

    old_files = result_files(historical_campaign)
    new_files = result_files(current_campaign)
    old_rows = [row for target, path in sorted(old_files.items()) for row in load_jsonl(path, target)]
    new_rows = [row for target, path in sorted(new_files.items()) for row in load_jsonl(path, target)]
    old_conditioned = [row for row in old_rows if is_conditioned(row)]

    old_keys = [row_key(row) for row in old_conditioned]
    new_keys = [row_key(row) for row in new_rows]
    old_key_counts = Counter(old_keys)
    new_key_counts = Counter(new_keys)
    duplicate_old_keys = sorted("|".join(key) for key, count in old_key_counts.items() if count > 1)
    duplicate_new_keys = sorted("|".join(key) for key, count in new_key_counts.items() if count > 1)
    new_by_key = {row_key(row): row for row in new_rows}

    joined: list[dict[str, Any]] = []
    for old in old_conditioned:
        key = row_key(old)
        current = new_by_key.get(key)
        joined.append(
            {
                "target": key[0],
                "source_addr": key[1],
                "sink_addr": key[2],
                "historical_status": old.get("status"),
                "historical_verdict": old.get("verdict"),
                "historical_provenance": old.get("evidence_provenance"),
                "historical_recovery": old.get("analysis_recovery"),
                "current_found": current is not None,
                "current_status": current.get("status") if current else None,
                "current_verdict": current.get("verdict") if current else None,
                "current_provenance": current.get("evidence_provenance") if current else None,
                "current_recovery": current.get("analysis_recovery") if current else None,
                "current_conditioning": current.get("evidence_conditioning") if current else None,
                "current_solver_query_bundle_count": (
                    int(current.get("solver_query_bundle_count") or 0) if current else None
                ),
                "current_link_present": bool(
                    isinstance(current.get("reconciliation_link"), dict)
                )
                if current
                else False,
                "current_nonpromotion": is_nonpromoted_current(current) if current else False,
            }
        )

    matched = [row for row in joined if row["current_found"]]
    current_provenance_counts = Counter(
        str(row["current_provenance"] or "") for row in matched
    )
    current_status_counts = Counter(str(row["current_status"] or "") for row in matched)
    current_direct = sum(row["current_provenance"] == DIRECT_PROVENANCE for row in matched)
    current_conditioned = sum(
        row["current_provenance"] == CONDITIONED_PROVENANCE
        or row["current_recovery"] == "static_dynamic_taint_reconciliation"
        for row in matched
    )
    missing = [row for row in joined if not row["current_found"]]
    nonpromoted = [row for row in matched if row["current_nonpromotion"]]

    checks = [
        {
            "name": "same_target_set",
            "pass": target_set_match and not input_differences,
            "details": {"historical_targets": sorted(historical_inputs), "current_targets": sorted(current_inputs), "differences": input_differences},
        },
        {
            "name": "same_declared_binary_and_mango_digests",
            "pass": target_set_match and not input_differences,
            "details": {
                "targets": len(common_targets),
                "declared_input_differences": input_differences,
                "local_workspace_digest_matches": [
                    row["target"] for row in local_inputs if row["matches"]
                ],
                "local_workspace_digest_mismatches": [
                    row["target"] for row in local_inputs if not row["matches"]
                ],
            },
        },
        {
            "name": "historical_conditioned_rows_present",
            "pass": len(old_conditioned) == 44,
            "details": {"conditioned_rows": len(old_conditioned)},
        },
        {
            "name": "no_duplicate_join_keys",
            "pass": not duplicate_old_keys and not duplicate_new_keys,
            "details": {"historical_duplicates": duplicate_old_keys, "current_duplicates": duplicate_new_keys},
        },
        {
            "name": "exact_rerun_join",
            "pass": len(joined) == 44 and len(matched) == 44 and not missing,
            "details": {"historical_rows": len(joined), "matched_rows": len(matched), "missing_rows": missing},
        },
        {
            "name": "no_direct_or_conditioned_promotion",
            "pass": current_direct == 0 and current_conditioned == 0,
            "details": {"current_direct_rows": current_direct, "current_conditioned_rows": current_conditioned},
        },
        {
            "name": "all_matched_rows_fail_closed",
            "pass": len(nonpromoted) == len(matched) == 44,
            "details": {"nonpromoted_rows": len(nonpromoted), "matched_rows": len(matched)},
        },
    ]

    summary = {
        "schema": SCHEMA,
        "valid": all(check["pass"] for check in checks),
        "historical_campaign": str(historical_campaign),
        "current_campaign": str(current_campaign),
        "historical_configuration_sha256": sha256_file(historical_config_path),
        "current_configuration_sha256": sha256_file(current_config_path),
        "local_workspace_input_digest_checks": local_inputs,
        "historical_conditioned_rows": len(old_conditioned),
        "historical_conditioned_status_counts": dict(Counter(str(row.get("status") or "") for row in old_conditioned)),
        "exactly_joined_rows": len(matched),
        "missing_join_rows": len(missing),
        "current_provenance_counts": dict(current_provenance_counts),
        "current_status_counts": dict(current_status_counts),
        "current_direct_promotion_rows": current_direct,
        "current_conditioned_promotion_rows": current_conditioned,
        "current_nonpromoted_rows": len(nonpromoted),
        "current_link_present_rows": sum(row["current_link_present"] for row in matched),
        "claim_boundary": (
            "This audit establishes exact-key non-promotion on a rerun whose two "
            "campaign configurations declare the same binary and Mango-input digests. "
            "It does not claim that the current workspace contains those remote input "
            "files, and it does not infer a source "
            "link for historical records, prove solver semantics, establish firmware "
            "precision/recall, or establish device-level exploitability."
        ),
        "checks": checks,
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    with (output_dir / "conditioned_rerun_boundary.jsonl").open(
        "w", encoding="utf-8", newline="\n"
    ) as handle:
        for row in joined:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    (output_dir / "README.md").write_text(
        "# Historical conditioned rerun-boundary audit\n\n"
        f"- Status: **{'PASS' if summary['valid'] else 'FAIL'}**\n"
        f"- Historical conditioned/reconciled rows: **{summary['historical_conditioned_rows']}**\n"
        f"- Exact-key rerun matches: **{summary['exactly_joined_rows']}**\n"
        f"- Current direct promotions: **{summary['current_direct_promotion_rows']}**\n"
        f"- Current conditioned promotions: **{summary['current_conditioned_promotion_rows']}**\n"
        f"- Current fail-closed non-promotions: **{summary['current_nonpromoted_rows']}**\n\n"
        "The join key is `(target, source_addr, sink_addr)`. The historical and "
        "current campaign configurations declare the same binary and Mango input "
        "digests. The current rerun classified the matched historical rows "
        f"as `{dict(current_provenance_counts)}` and did not emit a direct or "
        "conditioned positive for any of them.\n\n"
        "This is rerun-boundary evidence only. No source link was inferred or "
        "synthesized, no shell was executed, and the result does not establish "
        "solver soundness, firmware-wide precision/recall, or exploitability.\n",
        encoding="utf-8",
    )
    sums_path = output_dir / "SHA256SUMS"
    lines = []
    for path in sorted(p for p in output_dir.rglob("*") if p.is_file() and p != sums_path):
        lines.append(f"{sha256_file(path)}  {path.relative_to(output_dir).as_posix()}")
    sums_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--historical-campaign",
        type=Path,
        default=Path(
            "experiment_reports/tsds_v20_release_20260718_r7_v8/"
            "tsds_v20_accepted_repeat_20260718_r7/campaign"
        ),
    )
    parser.add_argument(
        "--current-campaign",
        type=Path,
        default=Path(
            "experiment_reports/full_firmware_campaign_current_tsds_query_export_20260915"
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("paper_work/iceccs_historical_conditioned_rerun_boundary_20260916"),
    )
    args = parser.parse_args()
    summary = build_audit(
        args.root.resolve(),
        args.historical_campaign.resolve(),
        args.current_campaign.resolve(),
        args.out.resolve(),
    )
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0 if summary["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
