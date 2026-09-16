#!/usr/bin/env python3
"""Bind paper-facing TSDS counts to a ready v20 evidence release.

This is a reporting gate, not an analyzer.  It refuses to emit LaTeX values
until the claim matrix, accepted pipeline, and paper export agree by content
identity.  The generated macros keep manuscript prose from drifting back to
historical campaign counts after a new release is accepted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "tsds-v20-manuscript-binding-v1"
CLAIM_SCHEMA = "tsds-v20-claim-evidence-matrix-v1"
PIPELINE_SCHEMA = "tsds-v18-pipeline-v7"
VERDICT_ORDER = (
    "VECTOR_SAT",
    "MATRIX_UNSAT",
    "NO_MODELED_SOURCE",
    "STATIC_SOURCE_INFERENCE",
    "STATIC_WARNING_REDUCTION",
    "RESIDUAL",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def strict_json(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key {key!r}: {path}")
            value[key] = item
        return value

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def as_nonnegative_integer(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} is not an integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not an integer") from exc
    if result < 0:
        raise ValueError(f"{label} is negative")
    return result


def identity_matches(entry: Any, path: Path, label: str) -> None:
    require(isinstance(entry, dict), f"claim matrix is missing {label} identity")
    expected = entry.get("sha256")
    require(isinstance(expected, str) and len(expected) == 64, f"invalid {label} digest")
    actual = sha256_file(path)
    require(actual == expected, f"{label} digest mismatch")


def build_binding(claim_matrix_path: Path, accepted_run: Path) -> dict[str, Any]:
    claim_matrix_path = claim_matrix_path.resolve()
    accepted_run = accepted_run.resolve()
    claim_matrix = strict_json(claim_matrix_path)
    require(claim_matrix.get("schema") == CLAIM_SCHEMA, "claim matrix schema mismatch")
    require(
        claim_matrix.get("ready_for_full_paper_writing") is True,
        "claim matrix is not ready for full paper writing",
    )
    claims = claim_matrix.get("claims")
    require(isinstance(claims, list) and claims, "claim matrix has no claims")
    unsupported = [
        str(row.get("claim_id") or "unknown")
        for row in claims
        if not isinstance(row, dict) or row.get("status") != "supported"
    ]
    require(not unsupported, "unsupported claims: " + ",".join(unsupported))

    manifest_path = accepted_run / "pipeline_manifest.json"
    paper_path = accepted_run / "paper_tables" / "paper_data_summary.json"
    require(manifest_path.is_file(), f"missing accepted manifest: {manifest_path}")
    require(paper_path.is_file(), f"missing paper export: {paper_path}")
    manifest = strict_json(manifest_path)
    paper = strict_json(paper_path)
    require(manifest.get("schema") == PIPELINE_SCHEMA, "accepted pipeline schema mismatch")
    require(manifest.get("success") is True, "accepted pipeline is not successful")
    require(paper.get("all_contract_valid") is True, "paper export is not contract valid")

    evidence = claim_matrix.get("evidence")
    require(isinstance(evidence, dict), "claim matrix has no evidence identity map")
    identity_matches(evidence.get("accepted_manifest"), manifest_path, "accepted manifest")
    identity_matches(evidence.get("paper_tables"), paper_path, "paper table export")

    records = as_nonnegative_integer(paper.get("records"), "paper records")
    require(records > 0, "paper export contains no records")
    input_summary = claim_matrix.get("input_summary") or {}
    require(
        as_nonnegative_integer(input_summary.get("accepted_records"), "claim matrix accepted records")
        == records,
        "claim matrix record count mismatch",
    )
    raw_verdicts = paper.get("verdicts")
    require(isinstance(raw_verdicts, dict), "paper export verdicts are missing")
    unknown = sorted(set(raw_verdicts) - set(VERDICT_ORDER))
    require(not unknown, "unknown evidence classes: " + ",".join(unknown))
    verdicts = {
        name: as_nonnegative_integer(raw_verdicts.get(name, 0), f"verdict {name}")
        for name in VERDICT_ORDER
    }
    require(sum(verdicts.values()) == records, "verdict counts do not conserve records")

    return {
        "schema": SCHEMA,
        "ready": True,
        "claim_boundary": (
            "Generated values are analyzer-level, contract-validated evidence "
            "counts. They do not establish device reachability, shell execution, "
            "exploitability, or cross-tool superiority."
        ),
        "accepted_run": str(accepted_run),
        "identities": {
            "claim_matrix": {
                "path": str(claim_matrix_path),
                "sha256": sha256_file(claim_matrix_path),
                "size": claim_matrix_path.stat().st_size,
            },
            "pipeline_manifest": {
                "path": str(manifest_path),
                "sha256": sha256_file(manifest_path),
                "size": manifest_path.stat().st_size,
            },
            "paper_data_summary": {
                "path": str(paper_path),
                "sha256": sha256_file(paper_path),
                "size": paper_path.stat().st_size,
            },
        },
        "claims": [str(row["claim_id"]) for row in claims],
        "records": records,
        "verdicts": verdicts,
    }


def latex_counts(binding: dict[str, Any]) -> str:
    verdicts = binding["verdicts"]
    macros = {
        "TSDSRecords": binding["records"],
        "TSDSVectorSatRecords": verdicts["VECTOR_SAT"],
        "TSDSMatrixUnsatRecords": verdicts["MATRIX_UNSAT"],
        "TSDSNoModeledSourceRecords": verdicts["NO_MODELED_SOURCE"],
        "TSDSStaticSourceInferenceRecords": verdicts["STATIC_SOURCE_INFERENCE"],
        "TSDSStaticWarningReductionRecords": verdicts["STATIC_WARNING_REDUCTION"],
        "TSDSResidualRecords": verdicts["RESIDUAL"],
    }
    lines = [
        "% Generated by experiments/build_v20_manuscript_binding.py; do not edit counts manually.",
        "% Values are contract-gated analyzer-level evidence counts.",
    ]
    lines.extend(f"\\newcommand{{\\{name}}}{{{value}}}" for name, value in macros.items())
    return "\n".join(lines) + "\n"


def write_outputs(out_dir: Path, binding: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "manuscript_binding.json").write_text(
        json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "manuscript_counts.tex").write_text(latex_counts(binding), encoding="utf-8")
    (out_dir / "README.md").write_text(
        "# TSDS v20 manuscript binding\n\n"
        "This directory binds paper-facing counts to the ready claim matrix and "
        "accepted pipeline by SHA-256. Use `manuscript_counts.tex` rather than "
        "transcribing counts into the manuscript.\n\n"
        + binding["claim_boundary"]
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--claim-matrix", type=Path, required=True)
    parser.add_argument("--accepted-run", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        binding = build_binding(args.claim_matrix, args.accepted_run)
        write_outputs(args.out_dir.resolve(), binding)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"MANUSCRIPT_BINDING_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(binding, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
