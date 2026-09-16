#!/usr/bin/env python3
"""Run the second-implementation verifier over TSDS certificate JSONL."""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsds.independent_certificate_verifier import (  # noqa: E402
    decode_rendered_witness,
    sha256_json,
    strict_json_object,
    summarize_verification,
    verify_certificate,
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if line.strip():
                rows.append(strict_json_object(line, f"{path}:{line_no}"))
    if not rows:
        raise ValueError(f"no certificate records in {path}")
    return rows


def source_digests(directory: Path | None) -> set[str] | None:
    if directory is None:
        return None
    digests: set[str] = set()
    for path in sorted(directory.glob("*.results.jsonl")):
        with path.open("r", encoding="utf-8") as stream:
            for line_no, line in enumerate(stream, 1):
                if line.strip():
                    digests.add(sha256_json(strict_json_object(line, f"{path}:{line_no}")))
    if not digests:
        raise ValueError(f"no source records under {directory}")
    return digests


def parser_preflight(shell: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="tsds-cert-parser-") as temporary:
        marker = Path(temporary) / "marker"
        command = f"printf x > '{marker}'; printf '%s' \"$(printf y > '{marker}.sub')\""
        result = subprocess.run(
            [shell, "-n", "-c", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
        safe = not marker.exists() and not Path(str(marker) + ".sub").exists()
        return {"shell": shell, "returncode": result.returncode, "no_execution": safe}


def parse_witness(shell: str, witness: str) -> bool:
    if "\x00" in witness:
        return False
    result = subprocess.run(
        [shell, "-n", "-c", witness],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "LC_ALL": "C"},
        timeout=5,
        check=False,
    )
    return result.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificates", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--shell", action="append", default=[])
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--fail-on-issues", action="store_true")
    args = parser.parse_args()

    certificates = load_jsonl(args.certificates)
    source_hashes = source_digests(args.source_dir)
    preflight = [parser_preflight(shell) for shell in args.shell]
    if any(item["no_execution"] is not True for item in preflight):
        print("shell parser preflight did not preserve no-execution semantics", file=sys.stderr)
        return 4
    rows = []
    for certificate in certificates:
        issues = verify_certificate(certificate, source_hashes)
        analysis = certificate.get("analysis") or {}
        parser_outcome = "not_applicable"
        if analysis.get("status") == "vulnerable" and args.shell:
            witness = decode_rendered_witness(
                ((certificate.get("matrix") or {}).get("minimal_witness") or {}).get("witness")
            )
            accepted = [parse_witness(shell, witness) for shell in args.shell]
            parser_outcome = "accepted_all" if all(accepted) else "parser_rejection"
            if not all(accepted):
                issues.append("minimal_witness_parser_rejection")
        identity = certificate.get("identity") or {}
        rows.append(
            {
                "target": identity.get("target"),
                "closure_idx": identity.get("closure_idx"),
                "status": analysis.get("status"),
                "certificate_sha256": certificate.get("certificate_sha256"),
                "parser_outcome": parser_outcome,
                "issues": sorted(set(issues)),
            }
        )
    summary = summarize_verification(rows)
    summary["certificate_file"] = str(args.certificates.resolve())
    summary["source_dir"] = str(args.source_dir.resolve()) if args.source_dir else None
    summary["source_records"] = len(source_hashes) if source_hashes is not None else None
    summary["parser_preflight"] = preflight
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"output directory is non-empty: {out_dir}", file=sys.stderr)
        return 3
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_rows = [{**row, "issues": ";".join(row["issues"])} for row in rows]
    with (out_dir / "independent_certificate_records.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=list(csv_rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(csv_rows)
    (out_dir / "independent_certificate_verification.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2 if args.fail_on_issues and not summary["valid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
