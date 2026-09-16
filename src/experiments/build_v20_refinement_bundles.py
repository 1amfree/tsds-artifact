#!/usr/bin/env python3
"""Regenerate residual-only, target-bound CEGAR bundles from a TSDS campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.model_refinement import load_refinement_bundle, write_refinement_bundle  # noqa: E402


SCHEMA = "tsds-v20-refinement-bundle-build-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_records(path: Path) -> list[dict[str, Any]]:
    values = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"record is not an object: {path}:{line_number}")
        values.append(value)
    return values


def build_bundles(campaign: Path, out_dir: Path) -> dict[str, Any]:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    paths = sorted(campaign.glob("*.results.jsonl"))
    if not paths:
        raise ValueError(f"no result ledgers found: {campaign}")
    out_dir.mkdir(parents=True, exist_ok=True)
    targets = []
    for path in paths:
        target = path.name.removesuffix(".results.jsonl")
        records = read_records(path)
        output = out_dir / f"{target}.refinement.json"
        bundle = write_refinement_bundle(output, records)
        loaded = load_refinement_bundle(output)
        if loaded != bundle:
            raise ValueError(f"round-trip mismatch: {output}")
        targets.append(
            {
                "target": target,
                "source_ledger": path.name,
                "source_ledger_sha256": sha256_file(path),
                "bundle": output.name,
                "bundle_sha256": bundle["bundle_sha256"],
                "input_records": bundle["input_records"],
                "residual_records_with_candidates": len(bundle["records"]),
                "candidate_count": bundle["candidate_count"],
                "skipped_non_residual_records": bundle[
                    "skipped_non_residual_records"
                ],
            }
        )
    manifest = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_campaign": str(campaign.resolve()),
        "selection_policy": "explicit_residual_verdict_only",
        "targets": targets,
        "totals": {
            "input_records": sum(item["input_records"] for item in targets),
            "candidate_count": sum(item["candidate_count"] for item in targets),
            "skipped_non_residual_records": sum(
                item["skipped_non_residual_records"] for item in targets
            ),
        },
    }
    (out_dir / "bundle_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = build_bundles(args.campaign.resolve(), args.out_dir.resolve())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"REFINEMENT_BUNDLE_BUILD_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
