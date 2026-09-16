#!/usr/bin/env python3
"""Preflight checker for TSDS sink-intercept canary validation.

This script checks whether selected sink-intercept scaffolds can be advanced
from analyzer-level reproducibility to isolated dynamic validation.  It does
not run firmware services and does not execute command sinks.  Its purpose is
to make missing emulation resources explicit and auditable.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


DEFAULT_PACK = Path("experiment_reports/sink_intercept_harness_pack_v9_20260626")
DEFAULT_OUT = Path("experiment_reports/dynamic_validation_preflight_v9_20260626")
DEFAULT_REMOTE_ROOT = "/home/ubuntu/work/sanitizer"

REMOTE_BINARIES = {
    "Tenda AC15": "/home/ubuntu/work/sanitizer/Tenda_AC15/httpd",
    "Tenda AC18": "/home/ubuntu/work/sanitizer/Tenda_AC18/httpd",
    "D-Link DIR-878": "/home/ubuntu/work/sanitizer/DIR-878/rc",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    rows = list(rows)
    fields: List[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


class Remote:
    def __init__(self, host: str, user: str, password: str, timeout: int = 30) -> None:
        try:
            import paramiko  # type: ignore
        except ImportError as exc:
            raise SystemExit("paramiko is required for SSH preflight checks") from exc
        self._paramiko = paramiko
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            host,
            username=user,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )

    def run(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        return {"returncode": rc, "stdout": out, "stderr": err, "command": command}

    def close(self) -> None:
        self.client.close()


def shell_quote(value: str) -> str:
    return shlex.quote(value)


def command_exists(remote: Remote, command: str) -> bool:
    result = remote.run(f"command -v {shell_quote(command)} >/dev/null 2>&1")
    return result["returncode"] == 0


def remote_file(remote: Remote, path: str) -> str:
    return remote.run(f"file {shell_quote(path)} 2>&1 || true")["stdout"].strip()


def remote_exists(remote: Remote, path: str) -> bool:
    return remote.run(f"test -e {shell_quote(path)}")["returncode"] == 0


def remote_root_probe(remote: Remote, binary_path: str) -> Dict[str, Any]:
    binary_dir = str(Path(binary_path).parent).replace("\\", "/")
    command = f"""
set -u
base={shell_quote(binary_dir)}
printf 'dirs='
find "$base" -maxdepth 8 \\( -name lib -o -name etc -o -name bin -o -name sbin -o -name www -o -name squashfs-root -o -name rootfs -o -name cpio-root \\) -type d 2>/dev/null | tr '\\n' ';'
printf '\\ninterp='
find "$base" -maxdepth 10 \\( -name 'ld-uClibc.so.0' -o -name 'ld-musl-*.so*' -o -name 'ld-linux*.so*' \\) \\( -type f -o -type l \\) 2>/dev/null | tr '\\n' ';'
printf '\\nlibc='
find "$base" -maxdepth 10 \\( -name 'libc.so*' -o -name 'libuClibc*.so*' \\) \\( -type f -o -type l \\) 2>/dev/null | tr '\\n' ';'
"""
    out = remote.run(command)["stdout"]
    parsed: Dict[str, Any] = {"raw": out}
    for line in out.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            parsed[key] = [item for item in value.split(";") if item]
    return parsed


def remote_global_rootfs_probe(remote: Remote, search_root: str) -> List[Dict[str, Any]]:
    command = f"""
set -u
root={shell_quote(search_root)}
find "$root" -maxdepth 8 \\( -name squashfs-root -o -name rootfs -o -name cpio-root \\) -type d 2>/dev/null | sort | while IFS= read -r d; do
  interp=$(find "$d" -maxdepth 5 \\( -name 'ld-uClibc.so.0' -o -name 'ld-musl-*.so*' -o -name 'ld-linux*.so*' \\) \\( -type f -o -type l \\) 2>/dev/null | head -3 | tr '\\n' ',')
  libc=$(find "$d" -maxdepth 5 \\( -name 'libc.so*' -o -name 'libuClibc*.so*' \\) \\( -type f -o -type l \\) 2>/dev/null | head -3 | tr '\\n' ',')
  dirs=$(find "$d" -maxdepth 2 \\( -name lib -o -name etc -o -name bin -o -name sbin \\) -type d 2>/dev/null | sed "s#$d/##" | tr '\\n' ',')
  if [ -n "$interp$libc$dirs" ]; then
    printf 'candidate=%s|interp=%s|libc=%s|dirs=%s\\n' "$d" "$interp" "$libc" "$dirs"
  fi
done
"""
    out = remote.run(command, timeout=60)["stdout"]
    candidates: List[Dict[str, Any]] = []
    for line in out.splitlines():
        if not line.startswith("candidate="):
            continue
        item: Dict[str, Any] = {}
        for part in line.split("|"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            item[key] = [entry for entry in value.split(",") if entry] if key in {"interp", "libc", "dirs"} else value
        candidates.append(item)
    return candidates


def strings_hits(remote: Remote, binary_path: str, clues: List[str]) -> Dict[str, bool]:
    hits: Dict[str, bool] = {}
    for clue in clues:
        if not clue:
            continue
        cmd = f"strings -a {shell_quote(binary_path)} | grep -F -- {shell_quote(clue)} >/dev/null 2>&1"
        hits[clue] = remote.run(cmd, timeout=30)["returncode"] == 0
    return hits


def required_qemu(arch_hint: str, file_text: str) -> List[str]:
    text = f"{arch_hint} {file_text}".lower()
    if "mips" in text:
        if "lsb" in text or "mipsel" in text:
            return ["qemu-mipsel"]
        return ["qemu-mips", "qemu-mipsel"]
    if "arm" in text:
        return ["qemu-arm"]
    return []


def local_artifact_check(task_dir: Path) -> Dict[str, bool]:
    files = [
        "manifest.json",
        "README.md",
        "fixtures/config_fixture.env",
        "fixtures/config_fixture.json",
        "hooks/sink_intercept.c",
        "hooks/qemu_gdb_sink_intercept.gdb",
        "verification_log_template.json",
    ]
    return {name: (task_dir / name).exists() for name in files}


def blocker_categories(blockers: List[str]) -> List[str]:
    categories: List[str] = []
    for blocker in blockers:
        if "qemu" in blocker:
            category = "qemu"
        elif "rootfs" in blocker or "libc" in blocker or "interpreter" in blocker:
            category = "rootfs"
        elif "gdb" in blocker:
            category = "debugger"
        elif "entry clue" in blocker:
            category = "entry"
        elif "scaffold" in blocker:
            category = "scaffold"
        elif "binary" in blocker:
            category = "binary"
        else:
            category = "other"
        if category not in categories:
            categories.append(category)
    return categories


def readiness_level(blockers: List[str]) -> str:
    cats = set(blocker_categories(blockers))
    if not cats:
        return "ready"
    if cats == {"rootfs"}:
        return "rootfs_blocked"
    if cats <= {"qemu", "rootfs"}:
        return "emulation_resource_blocked"
    if cats & {"binary", "scaffold", "entry"}:
        return "task_definition_blocked"
    return "blocked"


def global_rootfs_summary(candidates: List[Dict[str, Any]], limit: int = 3) -> str:
    chunks: List[str] = []
    for candidate in candidates[:limit]:
        interp = ",".join(Path(item).name for item in candidate.get("interp", [])) or "no-interp"
        libc = ",".join(Path(item).name for item in candidate.get("libc", [])) or "no-libc"
        chunks.append(f"{candidate.get('candidate', '')} ({interp}; {libc})")
    if len(candidates) > limit:
        chunks.append(f"+{len(candidates) - limit} more")
    return "; ".join(chunks)


def infer_rootfs_path(root_probe: Dict[str, Any]) -> str:
    for key in ("interp", "libc"):
        for item in root_probe.get(key) or []:
            path = Path(str(item))
            for parent in path.parents:
                if parent.name in {"squashfs-root", "rootfs", "cpio-root"}:
                    return str(parent).replace("\\", "/")
    for item in root_probe.get("dirs") or []:
        path = Path(str(item))
        if path.name in {"squashfs-root", "rootfs", "cpio-root"}:
            return str(path).replace("\\", "/")
    return ""


def remote_binary_alignment(remote: Remote, binary_path: str, rootfs_path: str) -> Dict[str, Any]:
    if not binary_path or not rootfs_path:
        return {}
    command = f"""
set -u
binary={shell_quote(binary_path)}
root={shell_quote(rootfs_path)}
name=$(basename "$binary")
match=$(find "$root" -maxdepth 5 -type f -name "$name" 2>/dev/null | sort | head -1)
printf 'rootfs_binary='
printf '%s\\n' "$match"
printf 'analysis_md5='
if [ -n "$binary" ] && [ -f "$binary" ]; then md5sum "$binary" | awk '{{print $1}}'; else echo missing; fi
printf 'rootfs_md5='
if [ -n "$match" ] && [ -f "$match" ]; then md5sum "$match" | awk '{{print $1}}'; else echo missing; fi
"""
    out = remote.run(command, timeout=30)["stdout"]
    parsed: Dict[str, Any] = {}
    for line in out.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            parsed[key] = value.strip()
    analysis_md5 = parsed.get("analysis_md5", "")
    rootfs_md5 = parsed.get("rootfs_md5", "")
    parsed["binary_rootfs_aligned"] = bool(analysis_md5 and rootfs_md5 and analysis_md5 == rootfs_md5)
    return parsed


def evaluate_task(remote: Remote, pack_dir: Path, row: Dict[str, Any], global_rootfs: List[Dict[str, Any]]) -> Dict[str, Any]:
    task_dir = pack_dir / str(row["artifact_dir"])
    manifest = load_json(task_dir / "manifest.json")
    target = str(manifest["target"])
    binary_path = REMOTE_BINARIES.get(target, "")
    file_text = remote_file(remote, binary_path) if binary_path else ""
    arch_hint = str((manifest.get("architecture_hint") or {}).get("arch") or "")
    qemu_options = required_qemu(arch_hint, file_text)
    qemu_available = {name: command_exists(remote, name) for name in qemu_options}
    gdb_available = command_exists(remote, "gdb-multiarch")
    root_probe = remote_root_probe(remote, binary_path) if binary_path and remote_exists(remote, binary_path) else {}
    local_artifacts = local_artifact_check(task_dir)
    clue_hits = strings_hits(remote, binary_path, list(manifest.get("entry_clues") or [])) if binary_path else {}

    blockers: List[str] = []
    if not binary_path or not remote_exists(remote, binary_path):
        blockers.append("target binary is missing on the remote VM")
    if qemu_options and not any(qemu_available.values()):
        blockers.append("required qemu-user emulator is missing")
    if not gdb_available:
        blockers.append("gdb-multiarch is missing for internal-sink breakpoint validation")
    if not root_probe.get("interp"):
        blockers.append("target rootfs/interpreter is missing near the binary")
    if not root_probe.get("libc"):
        blockers.append("target libc/uClibc is missing near the binary")
    if not any(clue_hits.values()):
        blockers.append("no static entry clue was found in binary strings")
    missing_local = [name for name, ok in local_artifacts.items() if not ok]
    if missing_local:
        blockers.append("local validation scaffold is incomplete: " + ", ".join(missing_local))

    ready = not blockers
    categories = blocker_categories(blockers)
    target_rootfs_ready = bool(root_probe.get("interp")) and bool(root_probe.get("libc"))
    target_rootfs_path = infer_rootfs_path(root_probe)
    alignment = remote_binary_alignment(remote, binary_path, target_rootfs_path) if target_rootfs_path else {}
    return {
        "candidate_id": manifest["candidate_id"],
        "target": target,
        "theme": manifest["functional_theme"],
        "binary_path": binary_path,
        "file": file_text,
        "sink": manifest["sink"],
        "canary_token": manifest["canary_token"],
        "qemu_required": "; ".join(qemu_options) if qemu_options else "unknown",
        "qemu_available": "; ".join(name for name, ok in qemu_available.items() if ok) or "none",
        "gdb_multiarch": gdb_available,
        "rootfs_dirs": "; ".join(root_probe.get("dirs") or []),
        "interpreters": "; ".join(root_probe.get("interp") or []),
        "libc": "; ".join(root_probe.get("libc") or []),
        "target_rootfs_ready": target_rootfs_ready,
        "target_rootfs_path": target_rootfs_path,
        "rootfs_binary_path": alignment.get("rootfs_binary", ""),
        "analysis_binary_md5": alignment.get("analysis_md5", ""),
        "rootfs_binary_md5": alignment.get("rootfs_md5", ""),
        "binary_rootfs_aligned": alignment.get("binary_rootfs_aligned", False),
        "ready_for_exact_rootfs_canary": ready and bool(alignment.get("binary_rootfs_aligned", False)),
        "global_rootfs_candidates": len(global_rootfs),
        "global_rootfs_summary": global_rootfs_summary(global_rootfs),
        "entry_clue_hits": sum(1 for ok in clue_hits.values() if ok),
        "entry_clue_total": len(clue_hits),
        "local_scaffold_complete": all(local_artifacts.values()),
        "ready_for_isolated_run": ready,
        "status": "ready" if ready else "blocked",
        "readiness_level": readiness_level(blockers),
        "blocker_categories": "; ".join(categories),
        "blockers": "; ".join(blockers),
        "resource_request": resource_request(blockers, qemu_options, target),
    }


def resource_request(blockers: List[str], qemu_options: List[str], target: str) -> str:
    requests: List[str] = []
    if any("qemu" in item for item in blockers):
        requests.append("install qemu-user for " + "/".join(qemu_options or ["target arch"]))
    if any("rootfs" in item or "libc" in item for item in blockers):
        requests.append(f"provide extracted {target} firmware rootfs with /lib, /etc, /bin, and service scripts")
    if any(item == "target binary is missing on the remote VM" for item in blockers):
        requests.append("provide target binary at the expected remote path")
    if any("entry clue" in item for item in blockers):
        requests.append("provide handler mapping or debug symbols for the selected source function")
    return "; ".join(requests)


def markdown(rows: List[Dict[str, Any]]) -> str:
    ready = sum(1 for row in rows if row["ready_for_isolated_run"])
    exact_ready = sum(1 for row in rows if row.get("ready_for_exact_rootfs_canary"))
    lines = [
        "# TSDS Dynamic Validation Preflight",
        "",
        "This report checks whether first-wave sink-intercept canary scaffolds can be executed in an isolated firmware environment. It does not start firmware services or execute command sinks.",
        "",
        f"- Tasks checked: `{len(rows)}`",
        f"- Substrate-ready tasks: `{ready}`",
        f"- Exact rootfs-binary aligned tasks: `{exact_ready}`",
        f"- Blocked: `{len(rows) - ready}`",
        "",
        "| ID | Target | Sink | QEMU | Target rootfs | Binary match | Clues | Status | Blockers |",
        "|---|---|---|---|---|---|---:|---|---|",
    ]
    for row in rows:
        target_rootfs = "ready" if row["target_rootfs_ready"] else "missing"
        binary_match = "yes" if row.get("binary_rootfs_aligned") else "no"
        qemu = row["qemu_available"] if row["qemu_available"] != "none" else f"missing ({row['qemu_required']})"
        lines.append(
            f"| `{row['candidate_id']}` | {row['target']} | `{row['sink']}` | {qemu} | {target_rootfs} | {binary_match} | {row['entry_clue_hits']}/{row['entry_clue_total']} | `{row['readiness_level']}` | {row['blockers']} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
        ]
    )
    if ready == len(rows):
        lines.append(
            "All first-wave tasks have QEMU, target rootfs, interpreter/libc, entry-clue, and local scaffold resources for substrate-level isolated validation. Exact canary validation still requires a handler/service trigger map and, for strict rootfs replay, version alignment between the analyzed binary and the rootfs binary."
        )
    else:
        lines.append(
            "A blocked preflight is still useful evidence: it prevents the paper from overstating dynamic confirmation and identifies the concrete resources needed for the next validation run. Once QEMU and the target rootfs are available, the generated sink-intercept scaffold can be used to log the benign canary token at the command sink while preventing shell execution."
        )
    lines.extend(["", "## Resource Requests", ""])
    for row in rows:
        lines.append(f"- `{row['candidate_id']}`: {row['resource_request'] or 'none'}")
    lines.extend(["", "## Binary/Rootfs Alignment", ""])
    for row in rows:
        status = "aligned" if row.get("binary_rootfs_aligned") else "mismatch"
        lines.append(
            f"- `{row['candidate_id']}`: {status}; analysis `{row.get('analysis_binary_md5', '')}` vs rootfs `{row.get('rootfs_binary_md5', '')}` at `{row.get('rootfs_binary_path', '')}`"
        )
    return "\n".join(lines) + "\n"


def latex_table(rows: List[Dict[str, Any]]) -> str:
    lines = [
        "% Auto-generated by experiments/build_dynamic_validation_preflight.py",
        "\\begin{tabularx}{\\textwidth}{@{}lP{0.17\\textwidth}P{0.18\\textwidth}P{0.17\\textwidth}Y@{}}",
        "\\toprule",
        "ID & Target & Required run support & Current status & Next resource\\\\",
        "\\midrule",
    ]
    for row in rows:
        support = f"{row['qemu_required']}; rootfs/interpreter"
        status = "ready" if row["ready_for_isolated_run"] else "blocked"
        resource = row["resource_request"] or "none"
        lines.append(
            "{} & {} & {} & {} & {}\\\\".format(
                row["candidate_id"].replace("_", "\\_"),
                row["target"].replace("&", "\\&"),
                support.replace("_", "\\_").replace("&", "\\&"),
                status,
                resource.replace("_", "\\_").replace("&", "\\&"),
            )
        )
    lines.extend(["\\bottomrule", "\\end{tabularx}", ""])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--pack-dir", default=str(DEFAULT_PACK))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--host", default=os.environ.get("TSDS_SSH_HOST", "192.168.206.137"))
    parser.add_argument("--user", default=os.environ.get("TSDS_SSH_USER", "ubuntu"))
    parser.add_argument("--password", default=os.environ.get("TSDS_SSH_PASSWORD", "ubuntu"))
    parser.add_argument("--remote-root", default=os.environ.get("TSDS_REMOTE_ROOT", DEFAULT_REMOTE_ROOT))
    args = parser.parse_args()

    root = Path(args.root).resolve()
    pack_dir = (root / args.pack_dir).resolve()
    index = load_json(pack_dir / "harness_pack_index.json")
    remote = Remote(args.host, args.user, args.password)
    try:
        global_rootfs = remote_global_rootfs_probe(remote, args.remote_root)
        rows = [evaluate_task(remote, pack_dir, row, global_rootfs) for row in index]
    finally:
        remote.close()

    out_dir = (root / args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / "dynamic_validation_preflight.csv", rows)
    write_json(out_dir / "dynamic_validation_preflight.json", rows)
    (out_dir / "dynamic_validation_preflight.md").write_text(markdown(rows), encoding="utf-8")
    (out_dir / "dynamic_validation_preflight_table.tex").write_text(latex_table(rows), encoding="utf-8")
    summary = {
        "tasks": len(rows),
        "ready": sum(1 for row in rows if row["ready_for_isolated_run"]),
        "blocked": sum(1 for row in rows if not row["ready_for_isolated_run"]),
        "readiness_level_counts": {
            level: sum(1 for row in rows if row["readiness_level"] == level)
            for level in sorted({str(row["readiness_level"]) for row in rows})
        },
        "blocker_category_counts": {
            category: sum(1 for row in rows if category in str(row["blocker_categories"]).split("; "))
            for category in sorted({cat for row in rows for cat in str(row["blocker_categories"]).split("; ") if cat})
        },
        "global_rootfs_candidates": len(global_rootfs),
        "exact_rootfs_binary_aligned": sum(1 for row in rows if row.get("binary_rootfs_aligned")),
        "ready_for_exact_rootfs_canary": sum(1 for row in rows if row.get("ready_for_exact_rootfs_canary")),
        "boundary": "preflight only; no firmware service execution; no shell execution",
        "out_dir": str(out_dir),
    }
    write_json(out_dir / "dynamic_validation_preflight_summary.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
