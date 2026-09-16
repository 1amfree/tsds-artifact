#!/usr/bin/env python3
"""Audit runtime canaries against a later campaign without identity inflation.

The runtime canaries were collected for an earlier V20 analysis ledger.  This
audit checks whether the underlying binary/Mango inputs are unchanged before
joining the recorded sink callsites to a later campaign.  It deliberately
keeps analysis-ledger and evaluator-version drift visible and never promotes
the result to source realizability, shell execution, or device exploitability.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "tsds-runtime-current-input-alignment-audit-v1"
HEX_ADDRESS = re.compile(r"0x[0-9a-fA-F]+")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"non-object JSON row: {path}:{line_number}")
            rows.append(value)
    return rows


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as stream:
        return list(csv.DictReader(stream))


def canonical_target(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def config_targets(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item["name"]): item
        for item in config.get("targets", [])
        if isinstance(item, dict) and item.get("name")
    }


def target_lookup(config: dict[str, Any]) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for item in config.get("targets", []):
        if not isinstance(item, dict) or not item.get("name"):
            continue
        name = str(item["name"])
        for alias in (name, item.get("label"), item.get("binary")):
            key = canonical_target(alias)
            if key:
                lookup[key] = name
    return lookup


def input_descriptors(config: dict[str, Any]) -> dict[str, dict[str, str]]:
    return {
        name: {
            "binary_sha256": str(item.get("binary_sha256") or ""),
            "mango_sha256": str(item.get("mango_sha256") or ""),
        }
        for name, item in config_targets(config).items()
    }


def campaign_identity(campaign_dir: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    files = sorted(campaign_dir.glob("*.results.jsonl"))
    for path in files:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
        digest.update(b"\0")
    return {"result_files": len(files), "results_identity_sha256": digest.hexdigest()}


def parse_address(value: Any) -> int | None:
    text = str(value or "").strip()
    if not HEX_ADDRESS.fullmatch(text):
        return None
    return int(text, 16)


def canonical_sink(value: Any) -> str:
    text = str(value or "").strip().lower().replace("@plt", "").replace(" wrapper", "")
    return re.sub(r"[^a-z0-9]+", "", text)


def load_campaign(campaign_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(campaign_dir.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        for row in read_jsonl(path):
            item = dict(row)
            item["_target"] = target
            item["_result_file"] = path.name
            rows.append(item)
    return rows


def result_join(
    runtime: dict[str, str],
    *,
    target_name: str | None,
    result_rows: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]]]:
    callsite = parse_address(runtime.get("callsite"))
    runtime_sink = canonical_sink(runtime.get("sink"))
    target_rows = [row for row in result_rows if row.get("_target") == target_name]
    address_rows = [
        row for row in target_rows
        if callsite is not None and parse_address(row.get("sink_addr")) == callsite
    ]
    compatible = [
        row for row in address_rows
        if not runtime_sink or canonical_sink(row.get("sink_function")) == runtime_sink
    ]
    if compatible:
        return ("exact_sink_callsite" if len(compatible) == 1 else "ambiguous_exact_sink_callsite", compatible)
    if address_rows:
        return "exact_address_sink_mismatch", address_rows
    return "target_callsite_not_found" if callsite is not None else "target_only_missing_callsite", []


def result_fact(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "result_file": row.get("_result_file"),
        "closure_idx": row.get("closure_idx"),
        "sink_addr": row.get("sink_addr"),
        "sink_function": row.get("sink_function"),
        "source_addr": row.get("source_addr"),
        "source_function": row.get("source_function"),
        "status": row.get("status"),
        "verdict": row.get("verdict"),
        "evidence_provenance": row.get("evidence_provenance"),
    }


def audit(
    *,
    workspace_root: Path,
    runtime_csv: Path,
    runtime_summary_path: Path,
    runtime_campaign_dir: Path,
    runtime_campaign_config_path: Path,
    current_campaign_dir: Path,
    current_campaign_config_path: Path,
) -> dict[str, Any]:
    runtime_rows = read_csv(runtime_csv)
    runtime_summary = read_json(runtime_summary_path)
    runtime_config = read_json(runtime_campaign_config_path)
    current_config = read_json(current_campaign_config_path)
    current_rows = load_campaign(current_campaign_dir)
    runtime_targets = input_descriptors(runtime_config)
    current_targets = input_descriptors(current_config)
    target_map = target_lookup(current_config)
    issues: list[str] = []

    old_identity = campaign_identity(runtime_campaign_dir)
    declared_identity = runtime_summary.get("campaign_identity") or {}
    old_identity_match = old_identity == {
        key: declared_identity.get(key) for key in ("result_files", "results_identity_sha256")
    }
    if not old_identity_match:
        issues.append("runtime_pack_identity_not_bound_to_declared_runtime_campaign")
    if int(runtime_summary.get("runtime_attempts") or -1) != len(runtime_rows):
        issues.append("runtime_attempt_count_mismatch")
    if not current_rows:
        issues.append("current_campaign_has_no_result_rows")

    descriptor_rows: list[dict[str, Any]] = []
    for name in sorted(set(runtime_targets) | set(current_targets)):
        old = runtime_targets.get(name, {})
        new = current_targets.get(name, {})
        same = old == new and bool(old.get("binary_sha256")) and bool(old.get("mango_sha256"))
        descriptor_rows.append({"target": name, "runtime": old, "current": new, "input_identity_match": same})
    input_identity_match = bool(descriptor_rows) and all(row["input_identity_match"] for row in descriptor_rows)
    if not input_identity_match:
        issues.append("runtime_current_input_descriptor_mismatch")

    old_result_identity = old_identity
    current_result_identity = campaign_identity(current_campaign_dir)
    evaluator_match = str(runtime_config.get("evaluator_sha256") or "") == str(current_config.get("evaluator_sha256") or "")
    driver_match = str(runtime_config.get("campaign_driver_sha256") or "") == str(current_config.get("campaign_driver_sha256") or "")

    audit_rows: list[dict[str, Any]] = []
    summary_checks: list[dict[str, Any]] = []
    for index, runtime in enumerate(runtime_rows, 1):
        evidence_dir = Path(str(runtime.get("evidence_dir") or ""))
        if not evidence_dir.is_absolute():
            evidence_dir = workspace_root / evidence_dir
        summary_path = evidence_dir / "canary_summary.json"
        expected_digest = str(runtime.get("summary_sha256") or "")
        actual_digest = sha256_file(summary_path) if summary_path.is_file() else ""
        digest_match = bool(expected_digest and actual_digest == expected_digest)
        summary_checks.append({
            "row": index,
            "path": str(summary_path),
            "exists": summary_path.is_file(),
            "expected_sha256": expected_digest,
            "actual_sha256": actual_digest,
            "sha256_match": digest_match,
        })
        if not digest_match:
            issues.append(f"runtime_summary_digest_mismatch:{index}")
        target_name = target_map.get(canonical_target(runtime.get("target")))
        match_kind, matched = result_join(runtime, target_name=target_name, result_rows=current_rows)
        token = str(runtime.get("token") or "")
        observed = str(runtime.get("observed_command") or "")
        evidence_summary = read_json(summary_path) if summary_path.is_file() else {}
        observed = observed or str(evidence_summary.get("observed_command") or "")
        audit_rows.append({
            "row": index,
            "id": runtime.get("id"),
            "target": runtime.get("target"),
            "current_target": target_name,
            "callsite": runtime.get("callsite"),
            "sink": runtime.get("sink"),
            "attempt_class": runtime.get("attempt_class"),
            "token_observed_in_command": bool(token and token in observed),
            "summary_sha256_match": digest_match,
            "current_match_kind": match_kind,
            "current_matched_result_count": len(matched),
            "current_matched_results": [result_fact(row) for row in matched],
            "claim_boundary": "Same binary/Mango input identity plus conservative callsite correspondence; no source, solver, shell-execution, or device-exploitability claim.",
        })

    positive_rows = [row for row in audit_rows if row["attempt_class"] == "positive_token_to_sink"]
    exact_rows = [row for row in audit_rows if row["current_match_kind"] == "exact_sink_callsite"]
    summary = {
        "schema": SCHEMA,
        "valid": not issues and bool(audit_rows) and input_identity_match,
        "runtime_attempts": len(audit_rows),
        "runtime_positive_attempts": len(positive_rows),
        "runtime_summary_hash_matches": sum(bool(row["summary_sha256_match"]) for row in audit_rows),
        "current_campaign_result_rows": len(current_rows),
        "runtime_campaign_identity_match": old_identity_match,
        "input_identity_match": input_identity_match,
        "input_descriptor_targets": len(descriptor_rows),
        "current_exact_sink_joins": len(exact_rows),
        "current_exact_sink_join_unique_keys": len({(row.get("current_target"), row.get("callsite")) for row in exact_rows}),
        "current_match_kinds": dict(sorted(Counter(row["current_match_kind"] for row in audit_rows).items())),
        "runtime_current_evaluator_sha_match": evaluator_match,
        "runtime_current_campaign_driver_sha_match": driver_match,
        "runtime_result_identity": old_result_identity,
        "current_result_identity": current_result_identity,
        "analysis_result_identity_match": old_result_identity == current_result_identity,
        "issues": sorted(set(issues)),
        "claim_boundary": (
            "The runtime package is bound to the earlier campaign ledger, while all "
            "binary/Mango input descriptors match the current campaign. Current joins "
            "therefore establish only same-input sink-callsite correspondence. The "
            "runtime and current evaluator/driver and result-ledger identities remain "
            "visible; no semantic promotion, source-realizability, shell-execution, "
            "firmware-ground-truth, or device-exploitability claim is made."
        ),
    }
    return {
        "summary": summary,
        "inputs": {
            "runtime_csv": str(runtime_csv),
            "runtime_summary": str(runtime_summary_path),
            "runtime_campaign_dir": str(runtime_campaign_dir),
            "runtime_campaign_config": str(runtime_campaign_config_path),
            "current_campaign_dir": str(current_campaign_dir),
            "current_campaign_config": str(current_campaign_config_path),
        },
        "input_descriptor_rows": descriptor_rows,
        "summary_file_checks": summary_checks,
        "rows": audit_rows,
    }


def write_outputs(out_dir: Path, result: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "runtime_current_input_alignment.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    fields = [
        "row", "id", "target", "current_target", "callsite", "sink", "attempt_class",
        "token_observed_in_command", "summary_sha256_match", "current_match_kind",
        "current_matched_result_count",
    ]
    with (out_dir / "runtime_current_input_alignment.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in result["rows"]:
            writer.writerow({field: row.get(field, "") for field in fields})
    summary = result["summary"]
    lines = [
        "# Runtime/current-campaign input alignment audit",
        "",
        f"Status: **{'PASS' if summary['valid'] else 'FAIL'}**",
        "",
        summary["claim_boundary"],
        "",
        f"- Runtime attempts: **{summary['runtime_attempts']}**; positive attempts: **{summary['runtime_positive_attempts']}**.",
        f"- Runtime summary hashes: **{summary['runtime_summary_hash_matches']}/{summary['runtime_attempts']}**.",
        f"- Binary/Mango input descriptors equal: **{summary['input_descriptor_targets']} targets; {summary['input_identity_match']}**.",
        f"- Conservative current-campaign exact sink-callsite joins: **{summary['current_exact_sink_joins']}**.",
        f"- Evaluator SHA equal: **{summary['runtime_current_evaluator_sha_match']}**; campaign-driver SHA equal: **{summary['runtime_current_campaign_driver_sha_match']}**.",
        f"- Result-ledger identity equal: **{summary['analysis_result_identity_match']}** (must remain visible, not repaired).",
        "",
        "An input-identity match does not make an earlier runtime observation a rerun of the current analyzer. Rows with missing or mismatched callsites remain non-exact boundaries.",
    ]
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    sums: list[str] = []
    for path in sorted(out_dir.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            sums.append(f"{sha256_file(path)}  {path.name}")
    (out_dir / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, default=Path("."))
    parser.add_argument("--runtime-csv", type=Path, required=True)
    parser.add_argument("--runtime-summary", type=Path, required=True)
    parser.add_argument("--runtime-campaign-dir", type=Path, required=True)
    parser.add_argument("--runtime-campaign-config", type=Path, required=True)
    parser.add_argument("--current-campaign-dir", type=Path, required=True)
    parser.add_argument("--current-campaign-config", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = audit(
            workspace_root=args.workspace_root.resolve(),
            runtime_csv=args.runtime_csv.resolve(),
            runtime_summary_path=args.runtime_summary.resolve(),
            runtime_campaign_dir=args.runtime_campaign_dir.resolve(),
            runtime_campaign_config_path=args.runtime_campaign_config.resolve(),
            current_campaign_dir=args.current_campaign_dir.resolve(),
            current_campaign_config_path=args.current_campaign_config.resolve(),
        )
        write_outputs(args.out_dir.resolve(), result)
    except (OSError, TypeError, ValueError, json.JSONDecodeError, csv.Error) as exc:
        print(f"RUNTIME_CURRENT_INPUT_ALIGNMENT_ERROR: {exc}")
        return 2
    print(json.dumps(result["summary"], indent=2, sort_keys=True))
    return 0 if result["summary"]["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
