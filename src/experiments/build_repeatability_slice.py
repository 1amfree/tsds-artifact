#!/usr/bin/env python3
"""Build a deterministic, content-bound subset of a TSDS campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "tsds-repeatability-slice-v1"


def sha256_file(path: Path) -> str:
    """计算输入 ledger 的字节身份，防止 slice 与源 campaign 脱钩。"""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def record_identity(target: str, record: dict[str, Any]) -> str:
    """按 closure/sink 字段构造与重复性审计一致的稳定身份。"""

    identity = {
        "target": target,
        "closure_idx": record.get("closure_idx"),
        "source_addr": record.get("source_addr"),
        "sink_addr": record.get("sink_addr"),
        "closure_sink_signature": record.get("closure_sink_signature"),
    }
    return json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str)


def build_slice(
    campaign_dir: Path,
    out_dir: Path,
    *,
    targets: set[str] | None = None,
    max_records_per_target: int = 1,
) -> dict[str, Any]:
    """按目标和原始行序构造不可覆盖的 repeatability baseline slice。"""

    campaign_dir = campaign_dir.resolve()
    out_dir = out_dir.resolve()
    if not campaign_dir.is_dir():
        raise ValueError(f"campaign directory is missing: {campaign_dir}")
    if max_records_per_target <= 0:
        raise ValueError("max_records_per_target must be positive")
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)

    source_rows: list[dict[str, Any]] = []
    selected_rows: list[dict[str, Any]] = []
    seen_identities: set[str] = set()
    for source_path in sorted(campaign_dir.glob("*.results.jsonl")):
        target = source_path.name[: -len(".results.jsonl")]
        if targets and target not in targets:
            continue
        payload = source_path.read_bytes()
        source_rows.append(
            {
                "path": source_path.relative_to(campaign_dir).as_posix(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        count = 0
        output_lines: list[str] = []
        for line_number, line in enumerate(
            payload.decode("utf-8").splitlines(keepends=True), start=1
        ):
            if not line.strip() or count >= max_records_per_target:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {source_path}:{line_number}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"record is not an object at {source_path}:{line_number}")
            identity = record_identity(target, record)
            if identity in seen_identities:
                raise ValueError(f"duplicate record identity in slice: {target}:{line_number}")
            seen_identities.add(identity)
            output_lines.append(line if line.endswith("\n") else line + "\n")
            selected_rows.append(
                {
                    "target": target,
                    "source_path": source_path.relative_to(campaign_dir).as_posix(),
                    "source_line": line_number,
                    "closure_idx": record.get("closure_idx"),
                    "record_id": identity,
                }
            )
            count += 1
        if output_lines:
            (out_dir / source_path.name).write_text(
                "".join(output_lines), encoding="utf-8"
            )

    if not selected_rows:
        raise ValueError("slice selection is empty")
    output_rows = [
        {
            "path": path.relative_to(out_dir).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(out_dir.glob("*.results.jsonl"))
    ]
    summary = {
        "schema": SCHEMA,
        "source_campaign": str(campaign_dir),
        "source_ledgers": source_rows,
        "selected_records": selected_rows,
        "output_ledgers": output_rows,
        "records": len(selected_rows),
        "targets": sorted({row["target"] for row in selected_rows}),
        "max_records_per_target": max_records_per_target,
        "claim_boundary": (
            "This slice preserves selected analyzer records for repeatability "
            "testing; it is not a new effectiveness corpus or ground truth."
        ),
    }
    (out_dir / "repeatability_slice_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        "# TSDS repeatability slice\n\n"
        f"Records: **{summary['records']}**; targets: **{', '.join(summary['targets'])}**.\n\n"
        + summary["claim_boundary"]
        + "\n",
        encoding="utf-8",
    )
    return summary


def main() -> int:
    """解析 slice 参数并以返回码 2 表示输入或选择失败。"""

    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--target", action="append", dest="targets")
    parser.add_argument("--max-records-per-target", type=int, default=1)
    args = parser.parse_args()
    try:
        summary = build_slice(
            args.campaign_dir,
            args.out_dir,
            targets=set(args.targets or []) or None,
            max_records_per_target=args.max_records_per_target,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"REPEATABILITY_SLICE_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
