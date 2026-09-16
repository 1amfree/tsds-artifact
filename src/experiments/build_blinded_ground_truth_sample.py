#!/usr/bin/env python3
"""Build a deterministic, stratified, verdict-blinded audit sample."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping


BLINDED_SAMPLE_SCHEMA = "tsds-blinded-ground-truth-sample-v4"
PROTOCOL_DECLARATION_SCHEMA = "tsds-ground-truth-protocol-declaration-v3"
LABEL_DEFINITION_VERSION = "tsds-sink-evidence-labels-v1"


def target_from_path(path: Path) -> str:
    suffix = ".results.jsonl"
    return path.name[: -len(suffix)] if path.name.endswith(suffix) else path.stem


def normalize_addr(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    try:
        return hex(int(text, 16 if text.startswith("0x") else 0))
    except ValueError:
        return text


def record_identity(record: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(record.get("_target") or record.get("target") or ""),
        str(record.get("closure_idx")),
        normalize_addr(record.get("source_addr")),
        normalize_addr(record.get("sink_addr")),
    )


def load_repeatability_consensus(path: Path) -> dict[tuple[str, str, str, str], dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    consensus = {}
    for line_no, row in enumerate(rows, start=2):
        key = record_identity(row)
        verdict = str(row.get("consensus_verdict") or "").strip()
        if not all(key) or not verdict:
            raise ValueError(f"invalid repeatability row at line {line_no}")
        if key in consensus:
            raise ValueError(f"duplicate repeatability identity at line {line_no}: {key}")
        consensus[key] = row
    if not consensus:
        raise ValueError(f"no repeatability records in {path}")
    return consensus


def load_records(campaign_dir: Path) -> list[dict[str, Any]]:
    records = []
    for path in sorted(campaign_dir.rglob("*.results.jsonl")):
        target = target_from_path(path)
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            row["_target"] = target
            records.append(row)
    if not records:
        raise ValueError(f"no campaign records in {campaign_dir}")
    return records


def audit_stratum(record: dict[str, Any]) -> str:
    verdict = str(record.get("verdict") or "RESIDUAL")
    provenance = str(record.get("evidence_provenance") or "RESIDUAL")
    if verdict == "VECTOR_SAT" and provenance == "DIRECT_SINK_BYTE":
        return "direct_vector_sat"
    if verdict == "VECTOR_SAT" and provenance == "SINK_RECONCILED":
        return "reconciled_vector_sat"
    if verdict == "MATRIX_UNSAT":
        return "matrix_unsat"
    if verdict == "NO_MODELED_SOURCE":
        return "no_modeled_source"
    if verdict == "STATIC_SOURCE_INFERENCE":
        return "static_source_inference"
    if verdict == "STATIC_WARNING_REDUCTION":
        return "static_warning_reduction"
    return "residual"


def stable_record_id(record: dict[str, Any], seed: int) -> str:
    identity = "|".join(
        [
            str(seed),
            str(record.get("_target")),
            str(record.get("closure_idx")),
            str(record.get("source_addr")),
            str(record.get("sink_addr")),
        ]
    )
    return "GT-" + hashlib.sha256(identity.encode()).hexdigest()[:12].upper()


def round_robin_target_sample(
    records: list[dict[str, Any]], limit: int, rng: random.Random
) -> list[dict[str, Any]]:
    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_target[str(record.get("_target"))].append(record)
    for queue in by_target.values():
        rng.shuffle(queue)
    targets = sorted(by_target)
    rng.shuffle(targets)
    selected = []
    while len(selected) < limit and any(by_target.values()):
        for target in targets:
            if by_target[target] and len(selected) < limit:
                selected.append(by_target[target].pop())
    return selected


def select_sample(
    records: list[dict[str, Any]],
    per_stratum: int,
    seed: int,
    quotas: Mapping[str, int] | None = None,
) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[audit_stratum(record)].append(record)
    rng = random.Random(seed)
    selected = []
    if quotas is not None:
        unknown = sorted(set(quotas) - set(groups))
        if unknown:
            raise ValueError("quota file names unknown strata: " + ", ".join(unknown))
        missing = sorted(set(groups) - set(quotas))
        if missing:
            raise ValueError("quota file omits strata: " + ", ".join(missing))
        for stratum, quota in quotas.items():
            if not isinstance(quota, int) or isinstance(quota, bool) or quota < 0:
                raise ValueError(f"quota for {stratum!r} must be a non-negative integer")
            if quota > len(groups[stratum]):
                raise ValueError(
                    f"quota for {stratum!r} exceeds population ({quota}>{len(groups[stratum])})"
                )
    for stratum in sorted(groups):
        limit = (
            int(quotas[stratum])
            if quotas is not None
            else min(per_stratum, len(groups[stratum]))
        )
        selected.extend(
            round_robin_target_sample(
                groups[stratum], limit, rng
            )
        )
    return sorted(selected, key=lambda row: stable_record_id(row, seed))


def load_quota_file(path: Path) -> dict[str, int]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"quota file is not an object: {path}")
    quotas = value.get("quotas", value)
    if not isinstance(quotas, dict):
        raise ValueError(f"quota file has no object-valued 'quotas': {path}")
    normalized: dict[str, int] = {}
    for key, item in quotas.items():
        name = str(key).strip()
        if not name:
            raise ValueError(f"quota file contains an empty stratum name: {path}")
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise ValueError(f"quota for {name!r} must be a non-negative integer")
        normalized[name] = int(item)
    return normalized


def safe_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def campaign_results_identity(campaign_dir: Path) -> dict[str, Any]:
    rows = []
    for path in sorted(campaign_dir.rglob("*.results.jsonl")):
        rows.append({
            "path": path.relative_to(campaign_dir).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return {
        "files": len(rows),
        "result_files": rows,
        "aggregate_sha256": hashlib.sha256(payload).hexdigest(),
    }


def build_corpus_commitment(
    campaign_identity: dict[str, Any],
    records: list[dict[str, Any]],
    pipeline_manifest: Path | None,
) -> dict[str, Any]:
    """Bind auditors to raw corpus inputs without exposing TSDS outcomes."""

    base = {
        "schema": "tsds-ground-truth-corpus-commitment-v1",
        "campaign_results_sha256": campaign_identity["aggregate_sha256"],
        "campaign_result_files": campaign_identity["result_files"],
        "targets": sorted({str(record.get("_target") or "") for record in records}),
        "claim_boundary": (
            "This manifest identifies binaries and candidate inputs for independent "
            "review. It contains no TSDS verdict, witness, provenance, or stratum."
        ),
    }
    if pipeline_manifest is None:
        return {
            **base,
            "available": False,
            "reason": "pipeline_manifest_not_supplied",
            "pipeline_manifest_sha256": None,
            "pipeline_schema": None,
            "campaign_inputs": [],
        }
    pipeline_manifest = pipeline_manifest.resolve()
    document = json.loads(pipeline_manifest.read_text(encoding="utf-8"))
    if document.get("success") is not True:
        raise ValueError("ground-truth corpus must bind an accepted pipeline manifest")
    reproducibility = document.get("reproducibility") or {}
    campaign_inputs = []
    for row in reproducibility.get("campaign_inputs") or []:
        campaign_inputs.append(
            {
                "target": row.get("target"),
                "label": row.get("label"),
                "binary": row.get("binary"),
                "mango": row.get("mango"),
            }
        )
    by_target = {str(row.get("target") or ""): row for row in campaign_inputs}
    missing_targets = sorted(set(base["targets"]) - set(by_target))
    if missing_targets:
        raise ValueError(
            "pipeline manifest is missing sampled targets: " + ", ".join(missing_targets)
        )
    artifacts = {
        str(row.get("path") or "").replace("\\", "/"): row
        for row in document.get("artifacts") or []
    }
    unbound_results = []
    for row in campaign_identity["result_files"]:
        suffix = f"campaign/{row['path']}"
        matches = [entry for path, entry in artifacts.items() if path.endswith(suffix)]
        if len(matches) != 1 or matches[0].get("sha256") != row.get("sha256"):
            unbound_results.append(row["path"])
    if unbound_results:
        raise ValueError(
            "campaign result ledgers are not bound by the pipeline manifest: "
            + ", ".join(unbound_results)
        )
    return {
        **base,
        "available": True,
        "pipeline_manifest_sha256": sha256_file(pipeline_manifest),
        "pipeline_schema": document.get("schema"),
        "campaign_inputs": sorted(campaign_inputs, key=lambda row: str(row["target"])),
    }


def write_sample(
    campaign_dir: Path,
    out_dir: Path,
    per_stratum: int,
    seed: int,
    repeatability_records: Path | None = None,
    pipeline_manifest: Path | None = None,
    quota_file: Path | None = None,
) -> dict[str, Any]:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty audit directory: {out_dir}")
    records = load_records(campaign_dir)
    campaign_identity = campaign_results_identity(campaign_dir)
    corpus_commitment = build_corpus_commitment(
        campaign_identity, records, pipeline_manifest
    )
    consensus_sha256 = None
    if repeatability_records is not None:
        consensus = load_repeatability_consensus(repeatability_records)
        missing = []
        for record in records:
            row = consensus.get(record_identity(record))
            if row is None:
                missing.append(record_identity(record))
                continue
            record["_single_run_verdict"] = record.get("verdict")
            record["_repeatability_outcome"] = row.get("outcome")
            record["verdict"] = row.get("consensus_verdict")
        if missing:
            raise ValueError(
                f"repeatability consensus missing {len(missing)} campaign identities"
            )
        consensus_sha256 = sha256_file(repeatability_records)
    quotas = load_quota_file(quota_file) if quota_file is not None else None
    sample = select_sample(records, per_stratum, seed, quotas=quotas)
    population_distribution = Counter(audit_stratum(record) for record in records)
    out_dir.mkdir(parents=True, exist_ok=True)
    blinded = []
    key_rows = []
    annotations = []
    adjudications = []
    for record in sample:
        record_id = stable_record_id(record, seed)
        blinded.append({
            "record_id": record_id,
            "target": record.get("_target"),
            "closure_idx": record.get("closure_idx"),
            "source_function": record.get("source_function"),
            "source_addr": record.get("source_addr"),
            "sink_function": record.get("sink_function"),
            "sink_addr": record.get("sink_addr"),
            "trace_summary": record.get("trace_summary"),
        })
        key_rows.append({
            "record_id": record_id,
            "stratum": audit_stratum(record),
            "tsds_verdict": record.get("verdict"),
            "single_run_verdict": record.get("_single_run_verdict") or record.get("verdict"),
            "repeatability_outcome": record.get("_repeatability_outcome") or "not_applied",
            "evidence_provenance": record.get("evidence_provenance"),
            "admissible_claim": record.get("admissible_claim"),
            "contract_valid": record.get("evidence_contract_valid"),
            "minimal_witness": safe_json(record.get("minimal_bypass_vector") or {}),
            "controlled_offsets": safe_json(record.get("tainted_offsets") or []),
        })
        annotations.append({
            "record_id": record_id,
            "auditor_id": "",
            "label": "",
            "evidence_type": "",
            "evidence_locator": "",
            "rationale": "",
        })
        adjudications.append({
            "record_id": record_id,
            "adjudicator_id": "",
            "label": "",
            "evidence_locator": "",
            "rationale": "",
        })

    def write_csv(name: str, rows: list[dict[str, Any]]) -> None:
        with (out_dir / name).open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    write_csv("audit_blinded.csv", blinded)
    write_csv("audit_key.csv", key_rows)
    write_csv("auditor_a_template.csv", annotations)
    write_csv("auditor_b_template.csv", annotations)
    write_csv("adjudication_template.csv", adjudications)
    label_definitions = {
        "schema": "tsds-ground-truth-label-definitions-v1",
        "version": LABEL_DEFINITION_VERSION,
        "labels": {
            "POSITIVE": {
                "required_evidence": (
                    "Source-dependent bytes reach a shell-parsed final command "
                    "argument and at least one grammar-changing shell vector is feasible."
                ),
                "non_claim": "Does not by itself establish remote or device-level exploitability.",
            },
            "NEGATIVE": {
                "required_evidence": (
                    "The reached command is source-independent, or the explicitly "
                    "audited vector boundary is blocked by independently checkable evidence."
                ),
                "non_claim": "Does not establish universal benignness beyond the audited boundary.",
            },
            "UNRESOLVED": {
                "required_evidence": (
                    "Use when reachability, source binding, shell interpretation, or "
                    "filtering cannot be established from the available evidence budget."
                ),
                "non_claim": "Must not be converted into a positive or negative result.",
            },
        },
    }
    (out_dir / "label_definitions.json").write_text(
        json.dumps(label_definitions, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "corpus_commitment.json").write_text(
        json.dumps(corpus_commitment, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    blinded_sha256 = sha256_file(out_dir / "audit_blinded.csv")
    audit_key_sha256 = sha256_file(out_dir / "audit_key.csv")
    label_definitions_sha256 = sha256_file(out_dir / "label_definitions.json")
    corpus_commitment_sha256 = sha256_file(out_dir / "corpus_commitment.json")
    protocol_template = {
        "schema": PROTOCOL_DECLARATION_SCHEMA,
        "label_definition_version": LABEL_DEFINITION_VERSION,
        "blinded_sample_sha256": blinded_sha256,
        "audit_key_commitment_sha256": audit_key_sha256,
        "campaign_results_sha256": campaign_identity["aggregate_sha256"],
        "label_definitions_sha256": label_definitions_sha256,
        "corpus_commitment_sha256": corpus_commitment_sha256,
        "repeatability_records_sha256": consensus_sha256,
        "sample_records": len(sample),
        "sample_seed": seed,
        "auditor_a_id": "",
        "auditor_b_id": "",
        "adjudicator_id": "",
        "independent_of_tools": False,
        "labels_frozen_before_unblinding": False,
        "audit_key_withheld_until_freeze": False,
        "labels_frozen_at_utc": "",
        "notes": "",
    }
    (out_dir / "protocol_declaration_template.json").write_text(
        json.dumps(protocol_template, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    distribution = Counter(row["stratum"] for row in key_rows)
    stratum_coverage = {
        stratum: {
            "population": int(population_distribution[stratum]),
            "sample": int(distribution.get(stratum, 0)),
            "sampling_fraction": round(
                distribution.get(stratum, 0) / population_distribution[stratum], 6
            ),
        }
        for stratum in sorted(population_distribution)
    }
    summary = {
        "schema": BLINDED_SAMPLE_SCHEMA,
        "label_definition_version": LABEL_DEFINITION_VERSION,
        "implementation": {
            "path": str(Path(__file__).resolve()),
            "sha256": sha256_file(Path(__file__).resolve()),
        },
        "campaign_dir": str(campaign_dir),
        "seed": seed,
        "per_stratum": per_stratum,
        "quota_file": str(quota_file) if quota_file is not None else None,
        "quota_file_sha256": sha256_file(quota_file) if quota_file is not None else None,
        "quotas": dict(sorted(quotas.items())) if quotas is not None else None,
        "campaign_records": len(records),
        "campaign_result_files": campaign_identity["files"],
        "campaign_results_sha256": campaign_identity["aggregate_sha256"],
        "pipeline_manifest": str(pipeline_manifest) if pipeline_manifest else None,
        "pipeline_manifest_sha256": corpus_commitment.get(
            "pipeline_manifest_sha256"
        ),
        "aggregate_basis": "repeatability_consensus"
        if repeatability_records is not None
        else "single_run",
        "repeatability_records": str(repeatability_records)
        if repeatability_records is not None
        else None,
        "repeatability_records_sha256": consensus_sha256,
        "sample_records": len(sample),
        "sample_fraction": round(len(sample) / len(records), 6),
        "population_distribution": dict(population_distribution),
        "distribution": dict(distribution),
        "stratum_coverage": stratum_coverage,
        "audit_blinded_sha256": blinded_sha256,
        "audit_key_sha256": audit_key_sha256,
        "label_definitions_sha256": label_definitions_sha256,
        "corpus_commitment_sha256": corpus_commitment_sha256,
        "protocol_declaration_template_sha256": sha256_file(
            out_dir / "protocol_declaration_template.json"
        ),
        "claim_boundary": (
        "The blinded file contains candidate identity only. It omits TSDS "
            "verdict, provenance, sink preview, stop reason, witness, static-input "
            "inference, and controlled offsets. audit_key.csv must remain hidden "
        "until both auditors freeze their labels. When a repeatability ledger "
        "is supplied, stratification and hidden TSDS outcomes use the fail-closed "
        "consensus verdict rather than a single-run verdict."
        ),
    }
    (out_dir / "sample_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        "# Blinded ground-truth audit\n\n"
        "Give `audit_blinded.csv` plus `auditor_a_template.csv` and "
        "`auditor_b_template.csv` separately to the two auditors. Do not exchange "
        "their files before both are frozen. Use `adjudication_template.csv` only "
        "for disagreements and complete the protocol declaration. Keep "
        "`audit_key.csv` hidden until then. Allowed labels are `POSITIVE`, "
        "`NEGATIVE`, and `UNRESOLVED`; every label requires an independently "
        "checkable evidence locator and rationale. `POSITIVE` requires evidence "
        "that source-dependent bytes reach a shell-parsed command and permit a "
        "grammar-changing vector. `NEGATIVE` requires evidence that the command "
        "is source-independent or that the audited vector boundary is blocked. "
        "Use `UNRESOLVED` whenever reachability, binding, shell interpretation, "
        "or filtering cannot be established. The protocol declaration commits "
        "to both the blinded sample and the withheld audit key by SHA-256.\n\n"
        "Use `corpus_commitment.json` to locate the exact firmware binary and "
        "candidate input by path and SHA-256; do not request TSDS result ledgers "
        "or the hidden audit key before labels are frozen.\n\n"
        + summary["claim_boundary"] + "\n",
        encoding="utf-8",
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--per-stratum", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20260711)
    parser.add_argument("--repeatability-records", type=Path)
    parser.add_argument("--pipeline-manifest", type=Path)
    parser.add_argument(
        "--quota-file",
        type=Path,
        help="JSON object (or {'quotas': object}) specifying an exact count per stratum.",
    )
    args = parser.parse_args()
    summary = write_sample(
        args.campaign_dir,
        args.out_dir,
        args.per_stratum,
        args.seed,
        repeatability_records=args.repeatability_records,
        pipeline_manifest=args.pipeline_manifest,
        quota_file=args.quota_file,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
