#!/usr/bin/env python3
"""Build a deterministic, content-bound SaTC keyword workload slice."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.run_satc_ghidra_experiment import file_identity, sha256_file


SCHEMA = "tsds-satc-keyword-slice-v1"


def load_canonical_tokens(path: Path) -> list[str]:
    tokens = path.read_text(encoding="utf-8", errors="strict").splitlines()
    if not tokens:
        raise ValueError("canonical keyword input is empty")
    if any(not token or token.strip() != token for token in tokens):
        raise ValueError("canonical keyword input contains blank or padded tokens")
    if tokens != sorted(set(tokens)):
        raise ValueError("canonical keyword input is not sorted and unique")
    return tokens


def validate_parent_manifest(path: Path, keyword_input: Path) -> dict[str, Any]:
    try:
        parent = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unreadable parent keyword manifest: {exc}") from exc
    if parent.get("schema") != "tsds-satc-keyword-extraction-v1":
        raise ValueError("parent keyword manifest has an unexpected schema")
    if parent.get("success") is not True:
        raise ValueError("parent keyword manifest is not successful")
    if (parent.get("environment") or {}).get("js_parser_environment_bound") is not True:
        raise ValueError("parent keyword manifest does not bind the JavaScript parser environment")
    output = parent.get("keyword_output") or {}
    if output.get("size") != keyword_input.stat().st_size:
        raise ValueError("parent keyword manifest size does not bind input")
    if output.get("sha256") != sha256_file(keyword_input):
        raise ValueError("parent keyword manifest hash does not bind input")
    return parent


def build_slice(args: argparse.Namespace) -> dict[str, Any]:
    input_path = args.input.resolve()
    if not input_path.is_file():
        raise ValueError(f"missing canonical keyword input: {input_path}")
    tokens = load_canonical_tokens(input_path)
    if args.count <= 0 or args.count > len(tokens):
        raise ValueError(f"slice count must be in [1, {len(tokens)}]")
    out_dir = args.out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    parent_identity = None
    parent_js_parser_environment_bound = False
    if args.parent_manifest is not None:
        parent = validate_parent_manifest(args.parent_manifest, input_path)
        parent_identity = file_identity(args.parent_manifest)
        parent_js_parser_environment_bound = bool(
            (parent.get("environment") or {}).get("js_parser_environment_bound")
        )
    selected = tokens[: args.count]
    slice_path = out_dir / f"keywords.sorted_prefix_{args.count}.txt"
    with slice_path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write("\n".join(selected) + "\n")
    manifest = {
        "schema": SCHEMA,
        "success": True,
        "claim_boundary": (
            "This deterministic subset is an integration and resource workload. "
            "It is not a coverage, accuracy, or superiority evaluation of SaTC or TSDS."
        ),
        "input_keyword_output": file_identity(input_path),
        "parent_keyword_manifest": parent_identity,
        "parent_js_parser_environment_bound": parent_js_parser_environment_bound,
        "selection": {
            "strategy": "sorted_prefix",
            "count": args.count,
            "input_tokens": len(tokens),
        },
        "slice_output": file_identity(slice_path, out_dir),
    }
    (out_dir / "experiment_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--parent-manifest", type=Path)
    args = parser.parse_args()
    try:
        manifest = build_slice(args)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"success": True, "slice_output": manifest["slice_output"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
