#!/usr/bin/env python3
"""Capture the local JavaScript-parser service used by SaTC keyword extraction."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen


SCHEMA = "tsds-satc-js-parser-environment-v1"
DEFAULT_ENDPOINT = "http://127.0.0.1:3000/codeparse"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_identity(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "size": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }


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
        raise ValueError(f"JavaScript parser manifest is not an object: {path}")
    return value


def validate_loopback_endpoint(endpoint: str) -> str:
    parsed = urlparse(endpoint)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.path != "/codeparse"
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"JavaScript parser endpoint must be local /codeparse: {endpoint}")
    return endpoint


def run_command(command: list[str], cwd: Path) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
            check=False,
        )
        output = proc.stdout
        returncode = proc.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        output = f"{type(exc).__name__}:{exc}"
        returncode = 127 if isinstance(exc, OSError) else 124
    return {
        "command": command,
        "returncode": returncode,
        "elapsed_sec": round(time.perf_counter() - started, 4),
        "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
    }


def probe_service(endpoint: str) -> dict[str, Any]:
    payload = json.dumps(
        {"engine": "esprima", "code": "var tsds_parser_probe = 1;"},
        separators=(",", ":"),
    ).encode("utf-8")
    started = time.perf_counter()
    try:
        request = Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=15) as response:  # noqa: S310 - endpoint is loopback-validated.
            body = response.read()
            status = response.status
        document = json.loads(body.decode("utf-8"))
        success = bool(status == 200 and document.get("code") == 200 and document.get("data") is not None)
        error = None
    except (OSError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        body = b""
        status = None
        success = False
        error = f"{type(exc).__name__}:{exc}"
    return {
        "endpoint": endpoint,
        "success": success,
        "http_status": status,
        "response_sha256": hashlib.sha256(body).hexdigest(),
        "elapsed_sec": round(time.perf_counter() - started, 4),
        "error": error,
    }


def validate_js_parser_manifest(path: Path, js_parser_root: Path) -> dict[str, Any]:
    manifest = strict_json(path)
    if manifest.get("schema") != SCHEMA or manifest.get("success") is not True:
        raise ValueError("JavaScript parser manifest schema or success check failed")
    root = js_parser_root.resolve()
    package = root / "package.json"
    if not package.is_file() or package.is_symlink():
        raise ValueError(f"missing or unsafe JavaScript parser package file: {package}")
    package_row = (manifest.get("inputs") or {}).get("package_json") or {}
    actual = file_identity(package)
    if (
        package_row.get("size") != actual["size"]
        or package_row.get("sha256") != actual["sha256"]
    ):
        raise ValueError("JavaScript parser package manifest drift")
    endpoint = validate_loopback_endpoint(str((manifest.get("service_probe") or {}).get("endpoint") or ""))
    probe = manifest.get("service_probe") or {}
    if probe.get("success") is not True or not isinstance(probe.get("response_sha256"), str) or len(probe["response_sha256"]) != 64:
        raise ValueError("JavaScript parser service probe is not successful")
    for key in ("node", "npm_dependencies"):
        returncode = ((manifest.get("environment") or {}).get(key) or {}).get("returncode")
        if isinstance(returncode, bool) or not isinstance(returncode, int) or returncode != 0:
            raise ValueError(f"JavaScript parser environment command failed: {key}")
    return {"endpoint": endpoint, "package_json": actual}


def capture_environment(
    js_parser_root: Path,
    node: str,
    npm: str,
    endpoint: str,
    out_dir: Path,
) -> dict[str, Any]:
    root = js_parser_root.resolve()
    endpoint = validate_loopback_endpoint(endpoint)
    package = root / "package.json"
    if not package.is_file() or package.is_symlink():
        raise ValueError(f"missing JavaScript parser package file: {package}")
    # Parse once here so malformed package metadata cannot be hidden behind a
    # successful service process from a different working tree.
    package_document = strict_json(package)
    if not package_document.get("name"):
        raise ValueError("JavaScript parser package has no name")
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty JavaScript parser output: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    node_result = run_command([node, "--version"], root)
    npm_result = run_command([npm, "ls", "--omit=dev", "--json"], root)
    probe = probe_service(endpoint)
    success = bool(
        node_result["returncode"] == 0
        and npm_result["returncode"] == 0
        and probe["success"] is True
    )
    manifest = {
        "schema": SCHEMA,
        "success": success,
        "inputs": {"package_json": file_identity(package)},
        "environment": {"node": node_result, "npm_dependencies": npm_result},
        "service_probe": probe,
        "claim_boundary": (
            "This manifest records the local parser dependency used by SaTC keyword extraction. "
            "It does not establish parser completeness, candidate accuracy, or TSDS outcomes."
        ),
    }
    (out_dir / "js_parser_environment_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--js-parser-root", type=Path, required=True)
    parser.add_argument("--node", default="node")
    parser.add_argument("--npm", default="npm")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = capture_environment(
            args.js_parser_root,
            args.node,
            args.npm,
            args.endpoint,
            args.out_dir.resolve(),
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"SATC_JS_PARSER_CAPTURE_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0 if manifest["success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
