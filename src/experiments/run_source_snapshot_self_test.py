#!/usr/bin/env python3
"""Execute the packaged TSDS test suite from an immutable source snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


SCHEMA = "tsds-source-snapshot-self-test-v1"
DETERMINISTIC_ENVIRONMENT = {
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "LC_ALL": "C",
    "LANG": "C",
    "TZ": "UTC",
}


def sha256_file(path: Path) -> str:
    """计算普通文件的 SHA-256，供快照树身份复核。"""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_tree_identity(root: Path) -> dict[str, Any]:
    """计算路径敏感、内容敏感且排序确定的源快照 Merkle 身份。"""

    root = root.resolve()
    digest = hashlib.sha256()
    files = 0
    total_bytes = 0
    paths = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
    for path in paths:
        if path.is_symlink():
            raise ValueError(f"source snapshot contains a symlink: {path}")
        if "__pycache__" in path.parts or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        file_sha256 = sha256_file(path)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(size.to_bytes(8, "big", signed=False))
        digest.update(bytes.fromhex(file_sha256))
        digest.update(b"\0")
        files += 1
        total_bytes += size
    return {
        "schema": "tsds-source-tree-identity-v1",
        "files": files,
        "bytes": total_bytes,
        "sha256": digest.hexdigest(),
    }


def parse_junit(path: Path) -> dict[str, int]:
    """从 pytest JUnit XML 中提取不依赖展示格式的测试计数。"""

    root = ET.parse(path).getroot()
    if root.tag == "testsuite":
        suites = [root]
    elif root.tag == "testsuites" and root.attrib.get("tests") is not None:
        suites = [root]
    else:
        suites = list(root.iter("testsuite"))

    def total(attribute: str) -> int:
        return sum(int(float(suite.attrib.get(attribute, "0") or 0)) for suite in suites)

    return {
        "tests": total("tests"),
        "failures": total("failures"),
        "errors": total("errors"),
        "skipped": total("skipped"),
    }


def run_self_test(
    source_root: Path,
    out_dir: Path,
    *,
    python: Path,
    timeout: int,
) -> dict[str, Any]:
    """在隔离子进程中执行快照测试，并输出失败关闭的机器可读摘要。"""

    source_root = source_root.resolve()
    out_dir = out_dir.resolve()
    # Preserve a virtual-environment launcher path. Resolving a venv's
    # ``bin/python`` symlink to the base interpreter discards ``pyvenv.cfg``
    # discovery and therefore runs the self-test outside the locked runtime.
    python = python.expanduser().absolute()
    if not source_root.is_dir():
        raise ValueError(f"source snapshot is not a directory: {source_root}")
    if not python.is_file():
        raise ValueError(f"python executable is not a file: {python}")
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    junit_path = out_dir / "pytest-junit.xml"
    stdout_path = out_dir / "pytest.stdout.log"
    stderr_path = out_dir / "pytest.stderr.log"
    before = source_tree_identity(source_root)
    command = [
        str(python),
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "-m",
        "not workspace_data",
        "--junitxml",
        str(junit_path),
    ]
    environment = os.environ.copy()
    environment.update(DETERMINISTIC_ENVIRONMENT)
    started = time.perf_counter()
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            cwd=source_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        returncode = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = 124
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        stderr += f"\n测试超时：{timeout}s\n"
    elapsed = round(time.perf_counter() - started, 4)
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    after = source_tree_identity(source_root)
    counts = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    junit_error = None
    if junit_path.is_file():
        try:
            counts = parse_junit(junit_path)
        except (OSError, ValueError, ET.ParseError) as exc:
            junit_error = f"{type(exc).__name__}:{exc}"
    else:
        junit_error = "missing_junit_xml"
    identity_stable = before == after
    valid = bool(
        returncode == 0
        and not timed_out
        and junit_error is None
        and counts["tests"] > 0
        and counts["failures"] == 0
        and counts["errors"] == 0
        and identity_stable
    )
    return {
        "schema": SCHEMA,
        "source_root": str(source_root),
        "python": str(python),
        "command": command,
        "returncode": returncode,
        "elapsed_sec": elapsed,
        "timed_out": timed_out,
        "counts": counts,
        "junit_error": junit_error,
        "source_identity_before": before,
        "source_identity_after": after,
        "source_identity_stable": identity_stable,
        "valid": valid,
        "claim_boundary": (
            "This self-test validates the packaged implementation and test harness; "
            "it does not establish analyzer soundness, completeness, or exploitability."
        ),
    }


def write_summary(out_dir: Path, summary: dict[str, Any]) -> None:
    """写出 JSON 和简短 README，供 pipeline 与 artifact 审计共同消费。"""

    (out_dir / "source_snapshot_self_test.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    counts = summary["counts"]
    (out_dir / "README.md").write_text(
        "# TSDS source-snapshot self-test\n\n"
        f"Valid: **{summary['valid']}**; tests: **{counts['tests']}**; "
        f"failures: **{counts['failures']}**; errors: **{counts['errors']}**; "
        f"skipped: **{counts['skipped']}**.\n\n"
        + summary["claim_boundary"]
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    """解析命令行并以返回码 2 表示 self-test 未通过。"""

    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        summary = run_self_test(
            args.source_root,
            args.out_dir,
            python=args.python,
            timeout=args.timeout,
        )
        write_summary(args.out_dir.resolve(), summary)
    except (OSError, ValueError) as exc:
        print(f"源快照自测失败：{exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
