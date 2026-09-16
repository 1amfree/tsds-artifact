#!/usr/bin/env python3
"""Build a content-bound root-cause ledger for every TSDS residual."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.residual_root_causes import summarize_residuals  # noqa: E402


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_residuals(campaign: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    identities: list[dict[str, Any]] = []
    for path in sorted(campaign.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        identities.append(
            {"path": path.name, "size": path.stat().st_size, "sha256": sha256_file(path)}
        )
        with path.open("r", encoding="utf-8") as stream:
            for line_no, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
                if not isinstance(record, dict):
                    raise ValueError(f"{path}:{line_no}: record is not an object")
                if record.get("verdict") == "RESIDUAL":
                    record["_target"] = target
                    rows.append(record)
    if not identities:
        raise ValueError(f"no campaign ledgers under {campaign}")
    return rows, identities


def verify_pipeline_binding(
    manifest_path: Path | None, identities: list[dict[str, Any]]
) -> dict[str, Any]:
    result = {
        "manifest": str(manifest_path) if manifest_path else None,
        "manifest_sha256": sha256_file(manifest_path) if manifest_path else None,
        "verified_files": 0,
        "issues": [],
        "verified": False,
    }
    if manifest_path is None:
        result["issues"].append("pipeline_manifest_not_supplied")
        return result
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    if document.get("success") is not True:
        result["issues"].append("pipeline_manifest_not_successful")
    artifacts = {
        str(row.get("path") or "").replace("\\", "/"): row
        for row in document.get("artifacts") or []
    }
    for identity in identities:
        suffix = "campaign/" + identity["path"]
        matches = [row for path, row in artifacts.items() if path.endswith(suffix)]
        if len(matches) != 1:
            result["issues"].append(f"campaign_artifact_missing:{identity['path']}")
        elif matches[0].get("sha256") != identity["sha256"]:
            result["issues"].append(f"campaign_artifact_hash_mismatch:{identity['path']}")
        else:
            result["verified_files"] += 1
    result["issues"] = sorted(set(result["issues"]))
    result["verified"] = not result["issues"] and result["verified_files"] == len(identities)
    return result


def write_outputs(
    out_dir: Path, rows: list[dict[str, Any]], summary: dict[str, Any]
) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"output directory is non-empty: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else ["schema", "root_cause"]
    with (out_dir / "residual_root_causes.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "residual_root_cause_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# TSDS residual root-cause audit",
        "",
        summary["claim_boundary"],
        "",
        f"Residual records: **{summary['records']}**; classification complete: "
        f"**{summary['classification_complete']}**.",
        "",
        "| Root cause | Records | Follow-up obligation |",
        "|---|---:|---|",
    ]
    action_by_cause = {row["root_cause"]: row["follow_up_obligation"] for row in rows}
    for cause, count in summary["root_cause_counts"].items():
        lines.append(f"| `{cause}` | {count} | {action_by_cause.get(cause, '')} |")
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--pipeline-manifest", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--expected-residuals", type=int)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()

    residuals, identities = load_residuals(args.campaign.resolve())
    rows, summary = summarize_residuals(residuals)
    binding = verify_pipeline_binding(args.pipeline_manifest, identities)
    summary["campaign"] = str(args.campaign.resolve())
    summary["campaign_files"] = identities
    summary["pipeline_binding"] = binding
    summary["issues"] = []
    if args.expected_residuals is not None and len(rows) != args.expected_residuals:
        summary["issues"].append(
            f"residual_count_mismatch:{len(rows)}!={args.expected_residuals}"
        )
    if args.pipeline_manifest and not binding["verified"]:
        summary["issues"].extend(binding["issues"])
    if not summary["classification_complete"]:
        summary["issues"].append("root_cause_classification_incomplete")
    summary["issues"] = sorted(set(summary["issues"]))
    summary["valid"] = bool(rows) and not summary["issues"]
    write_outputs(args.out_dir.resolve(), rows, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.require_complete and not summary["valid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
