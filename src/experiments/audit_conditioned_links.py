#!/usr/bin/env python3
"""Audit conditioned TSDS records without fabricating source links.

The audit is intentionally read-only.  It identifies records that were
historically produced by static/dynamic reconciliation and asks whether the
new serialized source-to-sink link contract is present and internally
consistent.  Missing links remain ``OPEN``; they are not synthesized from a
static preview or a freshly created symbolic variable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tsds.reconciliation_link import reconciliation_link_admission  # noqa: E402


DEFAULT_INPUT = Path(
    "experiment_reports/tsds_v20_release_20260718_r7_v8/"
    "tsds_v20_accepted_repeat_20260718_r7/campaign"
)
DEFAULT_OUTPUT = Path(
    "experiment_reports/saner2027_remediation_20260913_t00_t01/T04_conditioned_link_audit_v1"
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _records(campaign: Path) -> Iterable[dict[str, Any]]:
    for path in sorted(campaign.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if isinstance(value, dict):
                    value["_target"] = target
                    value["_line"] = line_no
                    value["_source"] = str(path)
                    yield value


def run_audit(campaign: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    reason_counts: Counter[str] = Counter()
    for record in _records(campaign):
        provenance = str(record.get("evidence_provenance") or "")
        recovery = str(record.get("analysis_recovery") or "")
        is_conditioned = provenance == "SINK_RECONCILED" or recovery == "static_dynamic_taint_reconciliation" or str(record.get("verdict") or "") == "CT_SAT"
        if not is_conditioned:
            continue
        admission = reconciliation_link_admission(record.get("reconciliation_link"), record=record)
        issues = list(admission.get("issues") or [])
        state = "ADMITTED" if admission.get("admitted") else "OPEN"
        for issue in issues:
            reason_counts[str(issue)] += 1
        rows.append(
            {
                "target": record.get("_target"),
                "line": record.get("_line"),
                "closure_idx": record.get("closure_idx"),
                "source_addr": record.get("source_addr"),
                "sink_addr": record.get("sink_addr"),
                "historical_verdict": record.get("verdict"),
                "historical_status": record.get("status"),
                "historical_provenance": provenance,
                "historical_recovery": recovery,
                "record_kind": (
                    "historical_ct_sat"
                    if provenance == "SINK_RECONCILED"
                    and str(record.get("verdict") or "") in {"VECTOR_SAT", "CT_SAT"}
                    else "reconciled_residual"
                ),
                "admission_state": state,
                "link_status": admission.get("link_status"),
                "issues": issues,
                "source_file": record.get("_source"),
                "claim_boundary": "conditioned template feasibility; no direct source-realizability claim",
            }
        )
    ct_count = sum(row["record_kind"] == "historical_ct_sat" for row in rows)
    residual_count = sum(row["record_kind"] == "reconciled_residual" for row in rows)
    summary = {
        "schema": "tsds-saner2027-conditioned-link-audit-v1",
        "input_campaign": str(campaign),
        "input_campaign_sha256": _sha256_file(campaign / "campaign_configuration.json") if (campaign / "campaign_configuration.json").is_file() else None,
        "reconciliation_records": len(rows),
        "conditioned_records": ct_count,
        "reconciled_residual_records": residual_count,
        "admitted_records": sum(row["admission_state"] == "ADMITTED" for row in rows),
        "open_records": sum(row["admission_state"] == "OPEN" for row in rows),
        "reason_counts": dict(sorted(reason_counts.items())),
        "no_links_synthesized": True,
        "claim_boundary": (
            "This audit checks whether conditioned records carry a complete serialized source-to-sink link. "
            "It does not prove the historical solver result, source realizability, or exploitability."
        ),
    }
    return rows, summary


def write_outputs(out_dir: Path, rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (out_dir / "conditioned_link_audit.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")
    (out_dir / "README.md").write_text(
        "# Conditioned source-link audit\n\n"
        + summary["claim_boundary"]
        + "\n\n"
        + f"- Reconciliation records: `{summary['reconciliation_records']}` (`{summary['conditioned_records']}` historical CT-SAT, `{summary['reconciled_residual_records']}` residual).\n"
        + f"- Link-admitted: `{summary['admitted_records']}`.\n"
        + f"- Open: `{summary['open_records']}`.\n"
        + "- No source link was synthesized.\n",
        encoding="utf-8",
    )
    rows_for_hash = []
    for path in sorted(out_dir.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            rows_for_hash.append(f"{_sha256_file(path)}  {path.relative_to(out_dir).as_posix()}")
    (out_dir / "SHA256SUMS").write_text("\n".join(rows_for_hash) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    campaign = args.input_dir.resolve()
    output = args.out_dir.resolve()
    if output.exists() and any(output.iterdir()):
        print(f"refusing to overwrite non-empty output: {output}", file=sys.stderr)
        return 2
    if not campaign.is_dir():
        print(f"missing campaign: {campaign}", file=sys.stderr)
        return 2
    rows, summary = run_audit(campaign)
    write_outputs(output, rows, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
