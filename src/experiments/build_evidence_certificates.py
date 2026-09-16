#!/usr/bin/env python3
"""Create and independently verify TSDS evidence certificates from JSONL ledgers.

The script is intentionally offline and read-only with respect to firmware
inputs.  It validates serialized proof obligations; it never starts a target,
executes a command, or upgrades a ledger claim.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.evidence_certificates import (  # noqa: E402
    CERTIFICATE_SCHEMA,
    build_certificate,
    certificate_summary,
    verify_record_certificate,
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            text = line.strip()
            if not text:
                continue
            try:
                value = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: JSONL row is not an object")
            rows.append(value)
    return rows


def target_from_path(path: Path) -> str:
    name = path.name
    if name.endswith(".results.jsonl"):
        return name[: -len(".results.jsonl")]
    return path.stem


def collect_input_paths(input_dir: Path | None, input_jsonl: list[Path]) -> list[Path]:
    paths = [path.resolve() for path in input_jsonl]
    if input_dir:
        paths.extend(sorted(input_dir.resolve().glob("*.results.jsonl")))
    deduped: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        if not path.is_file():
            raise FileNotFoundError(path)
        deduped.append(path)
    if not deduped:
        raise ValueError("no JSONL ledger input was selected")
    return deduped


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = [
        "target",
        "closure_idx",
        "status",
        "verdict",
        "admissible_claim",
        "claim_scope",
        "certificate_sha256",
        "issues",
    ]
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path)
    parser.add_argument("--input-jsonl", type=Path, action="append", default=[])
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--fail-on-issues", action="store_true")
    args = parser.parse_args()

    try:
        paths = collect_input_paths(args.input_dir, args.input_jsonl)
    except (ValueError, FileNotFoundError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to reuse non-empty output directory: {out_dir}", file=sys.stderr)
        return 3
    out_dir.mkdir(parents=True, exist_ok=True)

    certificates: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    issues = Counter()
    per_target = Counter()
    for path in paths:
        target = target_from_path(path)
        for record in load_jsonl(path):
            certificate = build_certificate(record, target=target)
            record_issues = verify_record_certificate(record, certificate)
            certificates.append(certificate)
            per_target[target] += 1
            for issue in record_issues:
                issues[issue] += 1
            analysis = certificate.get("analysis") or {}
            rows.append(
                {
                    "target": target,
                    "closure_idx": (certificate.get("identity") or {}).get("closure_idx"),
                    "status": analysis.get("status"),
                    "verdict": analysis.get("verdict"),
                    "admissible_claim": analysis.get("admissible_claim"),
                    "claim_scope": analysis.get("claim_scope"),
                    "certificate_sha256": certificate.get("certificate_sha256"),
                    "issues": ";".join(record_issues),
                }
            )

    summary = certificate_summary(certificates)
    summary.update(
        {
            "schema": "tsds-evidence-certificate-audit-v2",
            "certificate_schema": CERTIFICATE_SCHEMA,
            "input_files": [str(path) for path in paths],
            "per_target": dict(sorted(per_target.items())),
            "record_binding_issue_counts": dict(sorted(issues.items())),
            "records_with_record_binding_issues": sum(1 for row in rows if row["issues"]),
        }
    )
    write_jsonl(out_dir / "evidence_certificates.jsonl", certificates)
    write_csv(out_dir / "evidence_certificate_records.csv", rows)
    (out_dir / "evidence_certificate_audit.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        "# TSDS evidence certificates\n\n"
        f"Records: **{summary['records']}**; certificate-local issues: "
        f"**{summary['records_with_issues']}**; record-binding issues: "
        f"**{summary['records_with_record_binding_issues']}**.\n\n"
        + summary["claim_boundary"]
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    has_issues = bool(summary["records_with_issues"] or summary["records_with_record_binding_issues"])
    return 2 if args.fail_on_issues and has_issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
