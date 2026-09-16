#!/usr/bin/env python3
"""Create deterministic, role-separated TSDS blinded-audit packages."""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import Any


FORBIDDEN_BLINDED_FIELDS = {
    "verdict",
    "tsds_verdict",
    "evidence_provenance",
    "admissible_claim",
    "contract_valid",
    "minimal_witness",
    "controlled_offsets",
    "stratum",
    "repeatability_outcome",
    "single_run_verdict",
}
FORBIDDEN_CORPUS_VALUES = {
    "VECTOR_SAT",
    "MATRIX_UNSAT",
    "NO_MODELED_SOURCE",
    "STATIC_SOURCE_INFERENCE",
    "STATIC_WARNING_REDUCTION",
    "RESIDUAL",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def deterministic_tar_gz(
    destination: Path, members: list[tuple[Path | bytes, str]]
) -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for source, arcname in sorted(members, key=lambda item: item[1]):
            data = source if isinstance(source, bytes) else source.read_bytes()
            info = tarfile.TarInfo(arcname)
            info.size = len(data)
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    with destination.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            compressed.write(buffer.getvalue())


def forbidden_json_keys(value: Any, prefix: str = "") -> list[str]:
    issues = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if str(key) in FORBIDDEN_BLINDED_FIELDS:
                issues.append(path)
            issues.extend(forbidden_json_keys(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            issues.extend(forbidden_json_keys(child, f"{prefix}[{index}]"))
    return issues


def forbidden_json_values(value: Any, prefix: str = "") -> list[str]:
    issues = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            issues.extend(forbidden_json_values(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            issues.extend(forbidden_json_values(child, f"{prefix}[{index}]"))
    elif isinstance(value, str) and value.upper() in FORBIDDEN_CORPUS_VALUES:
        issues.append(prefix)
    return issues


def package(sample_dir: Path, out_dir: Path) -> dict[str, Any]:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty package directory: {out_dir}")
    required = {
        "blinded": sample_dir / "audit_blinded.csv",
        "key": sample_dir / "audit_key.csv",
        "auditor_a": sample_dir / "auditor_a_template.csv",
        "auditor_b": sample_dir / "auditor_b_template.csv",
        "adjudication": sample_dir / "adjudication_template.csv",
        "protocol": sample_dir / "protocol_declaration_template.json",
        "labels": sample_dir / "label_definitions.json",
        "corpus": sample_dir / "corpus_commitment.json",
        "summary": sample_dir / "sample_summary.json",
        "readme": sample_dir / "README.md",
    }
    missing = [name for name, path in required.items() if not path.is_file()]
    if missing:
        raise ValueError("missing blinded-audit files: " + ", ".join(missing))

    summary = json.loads(required["summary"].read_text(encoding="utf-8"))
    protocol = json.loads(required["protocol"].read_text(encoding="utf-8"))
    issues = []
    if sha256_file(required["blinded"]) != summary.get("audit_blinded_sha256"):
        issues.append("blinded_sample_sha256_mismatch")
    if sha256_file(required["key"]) != summary.get("audit_key_sha256"):
        issues.append("audit_key_sha256_mismatch")
    if sha256_file(required["labels"]) != summary.get("label_definitions_sha256"):
        issues.append("label_definitions_sha256_mismatch")
    if sha256_file(required["corpus"]) != summary.get("corpus_commitment_sha256"):
        issues.append("corpus_commitment_sha256_mismatch")
    if protocol.get("blinded_sample_sha256") != summary.get("audit_blinded_sha256"):
        issues.append("protocol_blinded_sample_commitment_mismatch")
    if protocol.get("audit_key_commitment_sha256") != summary.get("audit_key_sha256"):
        issues.append("protocol_audit_key_commitment_mismatch")
    if protocol.get("label_definitions_sha256") != summary.get(
        "label_definitions_sha256"
    ):
        issues.append("protocol_label_definitions_commitment_mismatch")
    if protocol.get("campaign_results_sha256") != summary.get(
        "campaign_results_sha256"
    ):
        issues.append("protocol_campaign_results_commitment_mismatch")
    if protocol.get("corpus_commitment_sha256") != summary.get(
        "corpus_commitment_sha256"
    ):
        issues.append("protocol_corpus_commitment_mismatch")

    corpus = json.loads(required["corpus"].read_text(encoding="utf-8"))
    corpus_leaks = forbidden_json_keys(corpus)
    corpus_value_leaks = forbidden_json_values(corpus)
    issues.extend(f"corpus_field_leak:{path}" for path in corpus_leaks)
    issues.extend(f"corpus_value_leak:{path}" for path in corpus_value_leaks)

    with required["blinded"].open(newline="", encoding="utf-8") as fh:
        fields = set(csv.DictReader(fh).fieldnames or [])
    leaked = sorted(fields & FORBIDDEN_BLINDED_FIELDS)
    if leaked:
        issues.extend(f"blinded_field_leak:{field}" for field in leaked)
    if issues:
        raise ValueError("invalid blinded sample: " + ", ".join(issues))

    out_dir.mkdir(parents=True, exist_ok=True)
    common = [
        (required["blinded"], "audit_blinded.csv"),
        (required["labels"], "label_definitions.json"),
        (required["corpus"], "corpus_commitment.json"),
        (required["protocol"], "protocol_commitment.json"),
        (required["readme"], "README.md"),
    ]
    roles = {
        "auditor_a": common
        + [
            (required["auditor_a"], "annotations.csv"),
            (b"Role: auditor_a\nDo not exchange annotations before the freeze.\n", "ROLE.txt"),
        ],
        "auditor_b": common
        + [
            (required["auditor_b"], "annotations.csv"),
            (b"Role: auditor_b\nDo not exchange annotations before the freeze.\n", "ROLE.txt"),
        ],
        "adjudicator": common
        + [
            (required["adjudication"], "adjudication.csv"),
            (b"Role: adjudicator\nReview only frozen auditor disagreements.\n", "ROLE.txt"),
        ],
    }
    packages = {}
    forbidden_members = {"audit_key.csv", "sample_summary.json"}
    for role, members in roles.items():
        path = out_dir / f"{role}.tar.gz"
        deterministic_tar_gz(path, members)
        with tarfile.open(path, "r:gz") as archive:
            names = set(archive.getnames())
        if names & forbidden_members:
            raise RuntimeError(f"withheld evidence leaked into {role} package")
        packages[role] = {
            "path": path.name,
            "sha256": sha256_file(path),
            "members": sorted(names),
        }
    manifest = {
        "schema": "tsds-blinded-audit-packages-v2",
        "sample_schema": summary.get("schema"),
        "sample_records": summary.get("sample_records"),
        "blinded_sample_sha256": summary.get("audit_blinded_sha256"),
        "campaign_results_sha256": summary.get("campaign_results_sha256"),
        "label_definitions_sha256": summary.get("label_definitions_sha256"),
        "corpus_commitment_sha256": summary.get("corpus_commitment_sha256"),
        "repeatability_records_sha256": summary.get(
            "repeatability_records_sha256"
        ),
        "withheld_audit_key_sha256": summary.get("audit_key_sha256"),
        "packages": packages,
        "leak_audit": {
            "forbidden_blinded_fields": sorted(FORBIDDEN_BLINDED_FIELDS),
            "observed_blinded_fields": sorted(fields),
            "corpus_forbidden_key_paths": corpus_leaks,
            "corpus_forbidden_value_paths": corpus_value_leaks,
            "issues": [],
            "valid": True,
        },
        "claim_boundary": (
            "Role packages exclude the hidden audit key and sample summary. "
            "The package manifest records only their commitments."
        ),
    }
    (out_dir / "package_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    manifest = package(args.sample_dir, args.out_dir)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
