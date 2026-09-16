#!/usr/bin/env python3
"""Audit correspondence between runtime canaries and a historical TSDS ledger.

The audit is deliberately non-semantic: it verifies evidence-file hashes,
campaign identity, and conservative target/sink joins.  It never promotes a
runtime observation to source realizability, exploitability, or device-level
validity.  Address mismatches and missing callsites are retained as explicit
boundary rows instead of being inferred as exact joins.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "tsds-runtime-historical-alignment-audit-v1"
HEX_ADDRESS = re.compile(r"0x[0-9a-fA-F]+")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"non-object JSON row: {path}:{line_number}")
            yield row


def canonical_target(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def canonical_sink(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = text.replace("@plt", "")
    text = text.replace(" wrapper", "")
    return re.sub(r"[^a-z0-9]+", "", text)


def parse_address(value: Any) -> int | None:
    match = HEX_ADDRESS.fullmatch(str(value or "").strip())
    return int(match.group(0), 16) if match else None


def address_tokens(*values: Any) -> set[int]:
    tokens: set[int] = set()
    for value in values:
        tokens.update(int(token, 16) for token in HEX_ADDRESS.findall(str(value or "")))
    return tokens


def campaign_identity(campaign_dir: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    files = sorted(campaign_dir.glob("*.results.jsonl"))
    for path in files:
        payload = path.read_bytes()
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).digest())
        digest.update(b"\0")
    return {
        "result_files": len(files),
        "results_identity_sha256": digest.hexdigest(),
    }


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


def load_runtime_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as stream:
        return list(csv.DictReader(stream))


def target_lookup(config: dict[str, Any]) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for target in config.get("targets", []):
        if not isinstance(target, dict):
            continue
        name = str(target.get("name") or "")
        if not name:
            continue
        for alias in (name, target.get("label"), target.get("binary")):
            key = canonical_target(alias)
            if key:
                lookup[key] = name
    return lookup


def config_targets(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item["name"]): item
        for item in config.get("targets", [])
        if isinstance(item, dict) and item.get("name")
    }


def result_join(
    runtime: dict[str, str],
    *,
    target_name: str | None,
    result_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    callsite = parse_address(runtime.get("callsite"))
    runtime_sink = canonical_sink(runtime.get("sink"))
    target_rows = [row for row in result_rows if row.get("_target") == target_name]
    address_rows = [
        row for row in target_rows if callsite is not None and parse_address(row.get("sink_addr")) == callsite
    ]
    compatible_address_rows = [
        row for row in address_rows
        if not runtime_sink or canonical_sink(row.get("sink_function")) == runtime_sink
    ]

    if callsite is None:
        return {
            "match_kind": "target_only_missing_callsite",
            "matched_rows": [],
            "target_result_rows": len(target_rows),
        }
    if compatible_address_rows:
        return {
            "match_kind": "exact_sink_callsite" if len(compatible_address_rows) == 1 else "ambiguous_exact_sink_callsite",
            "matched_rows": compatible_address_rows,
            "target_result_rows": len(target_rows),
        }
    if address_rows:
        return {
            "match_kind": "exact_address_sink_mismatch",
            "matched_rows": address_rows,
            "target_result_rows": len(target_rows),
        }

    entry_addresses = address_tokens(runtime.get("handler_or_entry"))
    source_rows = [
        row
        for row in target_rows
        if parse_address(row.get("source_addr")) in entry_addresses
        and (not runtime_sink or canonical_sink(row.get("sink_function")) == runtime_sink)
    ]
    if source_rows:
        return {
            "match_kind": "source_entry_sink_address_mismatch" if len(source_rows) == 1 else "ambiguous_source_entry_sink_address_mismatch",
            "matched_rows": source_rows,
            "target_result_rows": len(target_rows),
        }
    return {
        "match_kind": "target_callsite_not_found",
        "matched_rows": [],
        "target_result_rows": len(target_rows),
    }


def result_fact(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "result_file": row.get("_result_file"),
        "closure_idx": row.get("closure_idx"),
        "closure_ordinal": row.get("closure_ordinal"),
        "source_addr": row.get("source_addr"),
        "sink_addr": row.get("sink_addr"),
        "source_function": row.get("source_function"),
        "sink_function": row.get("sink_function"),
        "status": row.get("status"),
        "verdict": row.get("verdict"),
        "evidence_provenance": row.get("evidence_provenance"),
        "evidence_conditioning": row.get("evidence_conditioning"),
    }


def relation_for(runtime: dict[str, str], match_kind: str, matched: list[dict[str, Any]]) -> str:
    if not matched or match_kind != "exact_sink_callsite":
        return "not_joined"
    if runtime.get("attempt_class") == "positive_token_to_sink":
        verdicts = {str(row.get("verdict") or "") for row in matched}
        if "VECTOR_SAT" in verdicts:
            return "runtime_positive_with_vector_sat_record"
        if "NO_MODELED_SOURCE" in verdicts:
            return "runtime_positive_with_no_modeled_source_record"
        if "RESIDUAL" in verdicts:
            return "runtime_positive_with_residual_record"
        return "runtime_positive_with_other_record"
    return "runtime_boundary_with_joined_record"


def audit(
    *,
    workspace_root: Path,
    runtime_csv: Path,
    runtime_summary_path: Path,
    campaign_dir: Path,
    campaign_config_path: Path,
) -> dict[str, Any]:
    runtime_rows = load_runtime_rows(runtime_csv)
    runtime_summary = read_json(runtime_summary_path)
    campaign_config = read_json(campaign_config_path)
    result_rows = load_campaign(campaign_dir)
    targets = config_targets(campaign_config)
    lookup = target_lookup(campaign_config)
    campaign_actual = campaign_identity(campaign_dir)
    campaign_declared = runtime_summary.get("campaign_identity") or {}
    issues: list[str] = []
    summary_file_checks: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []

    if campaign_actual != {
        key: campaign_declared.get(key) for key in ("result_files", "results_identity_sha256")
    }:
        issues.append("runtime_pack_campaign_identity_mismatch")
    if int(runtime_summary.get("runtime_attempts") or -1) != len(runtime_rows):
        issues.append("runtime_attempt_count_mismatch")
    if not result_rows:
        issues.append("campaign_has_no_result_rows")

    for index, runtime in enumerate(runtime_rows, 1):
        evidence_dir = Path(str(runtime.get("evidence_dir") or ""))
        if not evidence_dir.is_absolute():
            evidence_dir = workspace_root / evidence_dir
        summary_path = evidence_dir / "canary_summary.json"
        expected_digest = str(runtime.get("summary_sha256") or "")
        summary_exists = summary_path.is_file()
        actual_digest = sha256_file(summary_path) if summary_exists else ""
        digest_match = bool(summary_exists and expected_digest and actual_digest == expected_digest)
        summary_file_checks.append(
            {
                "row": index,
                "path": str(summary_path),
                "exists": summary_exists,
                "expected_sha256": expected_digest,
                "actual_sha256": actual_digest,
                "sha256_match": digest_match,
            }
        )
        if not digest_match:
            issues.append(f"runtime_summary_digest_mismatch:{index}")

        evidence_summary = read_json(summary_path) if summary_exists else {}
        target_name = lookup.get(canonical_target(runtime.get("target")))
        join = result_join(runtime, target_name=target_name, result_rows=result_rows)
        matched = join["matched_rows"]
        facts = [result_fact(row) for row in matched]
        config_target = targets.get(target_name or "", {})
        runtime_binary = str(evidence_summary.get("binary_sha256") or "")
        campaign_binary = str(config_target.get("binary_sha256") or "")
        if runtime_binary and campaign_binary:
            binary_relation = "match" if runtime_binary == campaign_binary else "mismatch"
        else:
            binary_relation = "unknown"
        token = str(runtime.get("token") or "")
        observed_command = str(runtime.get("observed_command") or "")
        summary_command = str(evidence_summary.get("observed_command") or "")
        positive = runtime.get("attempt_class") == "positive_token_to_sink"
        token_in_command = bool(token and (token in observed_command or token in summary_command))
        audit_rows.append(
            {
                "row": index,
                "id": runtime.get("id"),
                "target": runtime.get("target"),
                "campaign_target": target_name,
                "callsite": runtime.get("callsite"),
                "sink": runtime.get("sink"),
                "attempt_class": runtime.get("attempt_class"),
                "token_observed_in_command": token_in_command,
                "token_observed_in_summary_command": bool(token and token in summary_command),
                "evidence_summary_sha256_match": digest_match,
                "runtime_binary_sha256_present": bool(runtime_binary),
                "runtime_binary_vs_campaign_binary": binary_relation,
                "match_kind": join["match_kind"],
                "target_result_rows": join["target_result_rows"],
                "matched_result_count": len(matched),
                "analysis_relation": relation_for(runtime, join["match_kind"], matched),
                "matched_results": facts,
                "claim_boundary": "sink-intercept correspondence only; no source-realizability, shell-execution, or device-exploitability claim",
            }
        )
        if positive and not token_in_command:
            issues.append(f"positive_runtime_token_not_in_observed_command:{index}")

    match_counts = Counter(row["match_kind"] for row in audit_rows)
    relation_counts = Counter(row["analysis_relation"] for row in audit_rows)
    attempt_counts = Counter(row.get("attempt_class") for row in runtime_rows)
    exact_rows = [row for row in audit_rows if row["match_kind"] == "exact_sink_callsite"]
    near_rows = [row for row in audit_rows if row["match_kind"] == "source_entry_sink_address_mismatch"]
    positive_rows = [row for row in audit_rows if row["attempt_class"] == "positive_token_to_sink"]
    summary = {
        "schema": SCHEMA,
        "valid": not issues and bool(audit_rows) and campaign_actual["result_files"] > 0,
        "runtime_attempts": len(audit_rows),
        "campaign_result_rows": len(result_rows),
        "campaign_identity_actual": campaign_actual,
        "campaign_identity_declared_by_runtime_pack": {
            "result_files": campaign_declared.get("result_files"),
            "results_identity_sha256": campaign_declared.get("results_identity_sha256"),
        },
        "campaign_identity_match": campaign_actual == {
            key: campaign_declared.get(key) for key in ("result_files", "results_identity_sha256")
        },
        "attempt_classes": dict(sorted(attempt_counts.items())),
        "match_kinds": dict(sorted(match_counts.items())),
        "analysis_relations": dict(sorted(relation_counts.items())),
        "positive_attempts": len(positive_rows),
        "positive_exact_sink_joins": sum(row["match_kind"] == "exact_sink_callsite" for row in positive_rows),
        "positive_entry_join_address_mismatches": sum(row["match_kind"] == "source_entry_sink_address_mismatch" for row in positive_rows),
        "exact_sink_join_attempts": len(exact_rows),
        "exact_sink_join_unique_target_callsite_keys": len({
            (row.get("campaign_target"), row.get("callsite")) for row in exact_rows
        }),
        "entry_join_address_mismatch_attempts": len(near_rows),
        "summary_files_checked": len(summary_file_checks),
        "summary_files_sha256_passed": sum(bool(item["sha256_match"]) for item in summary_file_checks),
        "runtime_binary_hash_relations": dict(sorted(Counter(row["runtime_binary_vs_campaign_binary"] for row in audit_rows).items())),
        "issues": issues,
        "claim_boundary": (
            "This finite audit checks the runtime-pack campaign identity, canary-summary hashes, "
            "and conservative target/sink correspondence against the historical V20 ledger. "
            "An exact join means only that the recorded target and sink callsite agree. "
            "An entry join with an address mismatch is retained as a boundary row. "
            "The audit does not establish source realizability, exhaustive path coverage, "
            "shell execution, firmware-wide precision/recall, or device exploitability."
        ),
    }
    return {
        "summary": summary,
        "rows": audit_rows,
        "summary_file_checks": summary_file_checks,
        "inputs": {
            "runtime_csv": str(runtime_csv),
            "runtime_summary": str(runtime_summary_path),
            "campaign_dir": str(campaign_dir),
            "campaign_config": str(campaign_config_path),
        },
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "row",
        "id",
        "target",
        "campaign_target",
        "callsite",
        "sink",
        "attempt_class",
        "token_observed_in_command",
        "token_observed_in_summary_command",
        "evidence_summary_sha256_match",
        "runtime_binary_sha256_present",
        "runtime_binary_vs_campaign_binary",
        "match_kind",
        "target_result_rows",
        "matched_result_count",
        "analysis_relation",
    ]
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def sha256sums(directory: Path) -> str:
    lines = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            lines.append(f"{sha256_file(path)}  {path.name}")
    return "\n".join(lines) + "\n"


def write_outputs(out_dir: Path, audit_result: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = audit_result["summary"]
    full = {
        "schema": SCHEMA,
        "summary": summary,
        "inputs": audit_result["inputs"],
        "summary_file_checks": audit_result["summary_file_checks"],
        "rows": audit_result["rows"],
    }
    (out_dir / "runtime_alignment_audit.json").write_text(
        json.dumps(full, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_csv(out_dir / "runtime_alignment_rows.csv", audit_result["rows"])
    lines = [
        "# Runtime-to-historical-ledger alignment audit",
        "",
        f"Schema: `{SCHEMA}`",
        f"Status: **{'PASS' if summary['valid'] else 'FAIL'}**",
        "",
        "This is a read-only correspondence audit. It checks content identity and conservative target/sink joins; it does not execute a shell or firmware command and does not establish exploitability.",
        "",
        "## Counts",
        "",
        f"- Runtime attempts: **{summary['runtime_attempts']}**; positive token-to-sink attempts: **{summary['positive_attempts']}**.",
        f"- Exact target/sink-callsite joins: **{summary['exact_sink_join_attempts']}** across **{summary['exact_sink_join_unique_target_callsite_keys']}** unique target/callsite keys.",
        f"- Entry/function joins with a sink-address mismatch: **{summary['entry_join_address_mismatch_attempts']}**.",
        f"- Missing or non-exact callsite rows are retained as boundary rows; no address is inferred as exact.",
        f"- Canary-summary SHA-256 checks: **{summary['summary_files_sha256_passed']}/{summary['summary_files_checked']}**.",
        "",
        "## Match Kinds",
        "",
        "| Match kind | Rows |",
        "|---|---:|",
    ]
    for key, count in summary["match_kinds"].items():
        lines.append(f"| `{key}` | {count} |")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "An exact join means that the runtime record's normalized target and recorded sink callsite match one historical ledger row. It does not imply that the canary token is an attacker-controlled source byte or that the generated witness was executed.",
            "",
            "A source-entry join with a different sink address is reported as an address-mismatch boundary. Rows without a callsite are not joined by sink function alone, because doing so could merge distinct callsites.",
            "",
            summary["claim_boundary"],
        ]
    )
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out_dir / "SHA256SUMS").write_text(sha256sums(out_dir), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, default=Path("."))
    parser.add_argument("--runtime-csv", type=Path, required=True)
    parser.add_argument("--runtime-summary", type=Path, required=True)
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--campaign-config", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = audit(
            workspace_root=args.workspace_root.resolve(),
            runtime_csv=args.runtime_csv.resolve(),
            runtime_summary_path=args.runtime_summary.resolve(),
            campaign_dir=args.campaign_dir.resolve(),
            campaign_config_path=args.campaign_config.resolve(),
        )
        write_outputs(args.out_dir.resolve(), result)
    except (OSError, TypeError, ValueError, json.JSONDecodeError, csv.Error) as exc:
        print(f"RUNTIME_HISTORICAL_ALIGNMENT_AUDIT_ERROR: {exc}")
        return 2
    print(json.dumps(result["summary"], indent=2, sort_keys=True))
    return 0 if result["summary"]["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
