#!/usr/bin/env python3
"""Create an immutable source snapshot manifest for a SaTC front-end run."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.satc_source_snapshot import build_snapshot


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--satc-root", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    out_dir = args.out_dir.resolve()
    try:
        if out_dir.exists() and any(out_dir.iterdir()):
            raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
        out_dir.mkdir(parents=True, exist_ok=True)
        snapshot = build_snapshot(args.satc_root)
        (out_dir / "satc_source_snapshot.json").write_text(
            json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (out_dir / "README.md").write_text(
            "# SaTC Source Snapshot\n\n" + snapshot["claim_boundary"] + "\n",
            encoding="utf-8",
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"SATC_SOURCE_SNAPSHOT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(snapshot, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
