#!/usr/bin/env python3
"""Build a corpus-level firmware resource inventory for TSDS.

The report answers a narrow reproducibility question: for every firmware target
in the v9 campaign, do we have the analyzed binary, an extracted target rootfs,
the matching QEMU user-mode emulator, and an inert rootfs ABI smoke result?

It deliberately does not start firmware services, trigger handlers, or execute
command sinks.  A PASS row is only target-rootfs substrate evidence.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


DEFAULT_CAMPAIGN = Path("experiment_reports/full_firmware_campaign_v9_20260625")
DEFAULT_OUT = Path("experiment_reports/firmware_resource_inventory_v9_20260626")
DEFAULT_REMOTE_ROOT = "/home/ubuntu/work/sanitizer"


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


def quote(value: str) -> str:
    return shlex.quote(value)


def normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def parse_pipe_kv(line: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for part in line.split("|"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        parsed[key] = value
    return parsed


def parse_kv_lines(text: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def target_aliases(target_id: str, binary_path: str) -> List[str]:
    binary_dir = Path(binary_path).parts[0] if Path(binary_path).parts else target_id
    seeds = {target_id, binary_dir}
    normalized = {normalize(item) for item in seeds if item}
    target_norm = normalize(target_id)
    if "asus" in target_norm and "be57" in target_norm:
        normalized.update({"asusrtbe57", "rtbe57", "be57"})
    if "dir878" in target_norm:
        normalized.update({"dir878", "dlinkdir878"})
    if "r6400" in target_norm:
        normalized.update({"r6400", "r6400v2"})
    if "r7000" in target_norm:
        normalized.add("r7000")
    if "xr300" in target_norm:
        normalized.add("xr300")
    if "ac15" in target_norm:
        normalized.update({"ac15", "tendaac15"})
    if "ac18" in target_norm:
        normalized.update({"ac18", "tendaac18"})
    if "w20e" in target_norm:
        normalized.update({"w20e", "tendaw20e"})
    # Drop aliases that are too broad for corpus-wide rootfs matching.  Vendor
    # names and pure numeric fragments can otherwise bind one firmware to a
    # sibling target's extracted rootfs.
    broad = {"asus", "tenda", "netgear", "dlink", "300"}
    normalized = {item for item in normalized if item and item not in broad and not item.isdigit()}
    return sorted(normalized, key=lambda item: (-len(item), item))


def qemu_for_file(file_text: str) -> str:
    text = file_text.lower()
    if "mips" in text:
        if "lsb" in text or "mipsel" in text:
            return "qemu-mipsel"
        return "qemu-mips"
    if "arm" in text:
        return "qemu-arm"
    return ""


def arch_label(file_text: str) -> str:
    text = file_text.lower()
    if "mips" in text:
        return "mipsel" if ("lsb" in text or "mipsel" in text) else "mips"
    if "arm" in text:
        return "arm"
    return "unknown"


class Remote:
    def __init__(self, host: str, user: str, password: str, timeout: int = 30) -> None:
        try:
            import paramiko  # type: ignore
        except ImportError as exc:
            raise SystemExit("paramiko is required for firmware resource inventory") from exc
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

    def run(self, command: str, timeout: int = 60) -> Dict[str, Any]:
        _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        return {"returncode": rc, "stdout": out, "stderr": err, "command": command}

    def close(self) -> None:
        self.client.close()


def command_exists(remote: Remote, command: str) -> bool:
    return remote.run(f"command -v {quote(command)} >/dev/null 2>&1")["returncode"] == 0


def remote_file_info(remote: Remote, path: str) -> Dict[str, str]:
    command = f"""
set -u
path={quote(path)}
printf 'exists='
if [ -e "$path" ]; then echo yes; else echo no; fi
printf 'file='
file "$path" 2>&1 || true
printf 'md5='
if [ -f "$path" ]; then md5sum "$path" | awk '{{print $1}}'; else echo missing; fi
"""
    return parse_kv_lines(remote.run(command, timeout=30)["stdout"])


def discover_firmware_images(remote: Remote, target_dir: str) -> List[str]:
    command = f"""
set -u
dir={quote(target_dir)}
find "$dir" -maxdepth 3 -type f \\( -iname '*.bin' -o -iname '*.trx' -o -iname '*.chk' -o -iname '*.img' -o -iname '*.fw' \\) 2>/dev/null | sort
"""
    return [line.strip() for line in remote.run(command, timeout=60)["stdout"].splitlines() if line.strip()]


def extract_missing_rootfs(remote: Remote, target_dir: str, firmware_images: List[str], timeout: int) -> Dict[str, Any]:
    if not firmware_images:
        return {"attempted": False, "returncode": "", "log": "no firmware image found"}
    # Extract only the most plausible first image; repeated binwalk extraction is expensive
    # and does not improve the inventory if the target directory already holds one image.
    firmware = firmware_images[0]
    out_dir = f"{target_dir.rstrip('/')}/extracted_rootfs"
    log_path = f"{out_dir}/_{Path(firmware).name}.inventory_binwalk.log"
    command = f"""
set -u
fw={quote(firmware)}
out={quote(out_dir)}
log={quote(log_path)}
mkdir -p "$out"
if ! command -v binwalk >/dev/null 2>&1; then
  echo 'binwalk missing' > "$log"
  printf 'attempted=yes\\nreturncode=127\\nfirmware=%s\\nlog=%s\\n' "$fw" "$log"
  exit 0
fi
timeout {int(timeout)}s binwalk -Me -C "$out" "$fw" > "$log" 2>&1
rc=$?
printf 'attempted=yes\\nreturncode=%s\\nfirmware=%s\\nlog=%s\\n' "$rc" "$fw" "$log"
"""
    result = remote.run(command, timeout=timeout + 30)
    parsed: Dict[str, Any] = parse_kv_lines(result["stdout"])
    parsed["attempted"] = True
    parsed["stderr"] = result["stderr"]
    return parsed


def global_rootfs_candidates(remote: Remote, remote_root: str) -> List[Dict[str, str]]:
    command = f"""
set -u
root={quote(remote_root)}
find "$root" -maxdepth 11 \\( -name squashfs-root -o -name rootfs -o -name cpio-root \\) -type d 2>/dev/null | sort | while IFS= read -r d; do
  interp=$(find "$d" -maxdepth 5 \\( -name 'ld-uClibc.so.0' -o -name 'ld-musl-*.so*' -o -name 'ld-linux*.so*' \\) \\( -type f -o -type l \\) 2>/dev/null | head -3 | tr '\\n' ',')
  libc=$(find "$d" -maxdepth 5 \\( -name 'libc.so*' -o -name 'libuClibc*.so*' \\) \\( -type f -o -type l \\) 2>/dev/null | head -3 | tr '\\n' ',')
  busybox=""
  for candidate in "$d/bin/busybox" "$d/sbin/busybox" "$d/usr/bin/busybox"; do
    if [ -x "$candidate" ]; then busybox="$candidate"; break; fi
  done
  dirs=$(find "$d" -maxdepth 2 \\( -name lib -o -name etc -o -name bin -o -name sbin -o -name usr \\) -type d 2>/dev/null | sed "s#$d/##" | tr '\\n' ',')
  printf 'path=%s|interp=%s|libc=%s|busybox=%s|dirs=%s\\n' "$d" "$interp" "$libc" "$busybox" "$dirs"
done
"""
    rows: List[Dict[str, str]] = []
    for line in remote.run(command, timeout=120)["stdout"].splitlines():
        if line.startswith("path="):
            rows.append(parse_pipe_kv(line))
    return rows


def matching_candidates(
    all_candidates: List[Dict[str, str]],
    target_id: str,
    binary_path: str,
    target_dir: str,
) -> List[Dict[str, str]]:
    aliases = target_aliases(target_id, binary_path)
    target_dir_norm = normalize(target_dir)
    matched: List[Dict[str, str]] = []
    for candidate in all_candidates:
        path = candidate.get("path", "")
        path_norm = normalize(path)
        if normalize(str(Path(path).parent)).startswith(target_dir_norm) or any(alias and alias in path_norm for alias in aliases):
            matched.append(candidate)
    return matched


def add_rootfs_binary_info(remote: Remote, candidates: List[Dict[str, str]], binary_basename: str) -> None:
    for candidate in candidates:
        rootfs = candidate.get("path", "")
        command = f"""
set -u
root={quote(rootfs)}
name={quote(binary_basename)}
match=$(find "$root" -maxdepth 6 -type f -name "$name" 2>/dev/null | sort | head -1)
printf 'rootfs_binary=%s\\n' "$match"
printf 'rootfs_md5='
if [ -n "$match" ] && [ -f "$match" ]; then md5sum "$match" | awk '{{print $1}}'; else echo missing; fi
"""
        candidate.update(parse_kv_lines(remote.run(command, timeout=30)["stdout"]))


def candidate_score(candidate: Dict[str, str], analysis_md5: str, target_dir: str) -> Tuple[int, int, int, int, int]:
    path = candidate.get("path", "")
    exact = int(bool(analysis_md5 and candidate.get("rootfs_md5") == analysis_md5))
    has_binary = int(bool(candidate.get("rootfs_binary")))
    has_runtime = int(bool(candidate.get("interp")) and bool(candidate.get("libc")))
    has_busybox = int(bool(candidate.get("busybox")))
    local = int(path.startswith(target_dir.rstrip("/") + "/"))
    return (exact, has_binary, has_runtime, has_busybox, local)


def select_best_candidate(candidates: List[Dict[str, str]], analysis_md5: str, target_dir: str) -> Optional[Dict[str, str]]:
    if not candidates:
        return None
    return sorted(candidates, key=lambda row: candidate_score(row, analysis_md5, target_dir), reverse=True)[0]


def run_rootfs_smoke(remote: Remote, rootfs: str, qemu: str, target_id: str) -> Dict[str, Any]:
    if not rootfs or not qemu:
        return {"pass": False, "reason": "missing rootfs or qemu"}
    token = f"TSDS_CORPUS_SMOKE_{normalize(target_id).upper()}"
    command = f"""
set -u
root={quote(rootfs)}
qemu={quote(qemu)}
token={quote(token)}
busybox=""
for candidate in "$root/bin/busybox" "$root/sbin/busybox" "$root/usr/bin/busybox"; do
  if [ -x "$candidate" ]; then busybox="$candidate"; break; fi
done
printf 'busybox=%s\\n' "$busybox"
printf 'smoke='
if [ -n "$busybox" ]; then timeout 20s "$qemu" -L "$root" "$busybox" echo "$token" 2>&1; else echo missing_busybox; fi
printf 'smoke_rc=%s\\n' "$?"
"""
    result = remote.run(command, timeout=60)
    parsed: Dict[str, Any] = parse_kv_lines(result["stdout"])
    parsed["pass"] = result["returncode"] == 0 and token in result["stdout"] and parsed.get("smoke_rc") == "0"
    parsed["token"] = token
    parsed["stdout"] = result["stdout"]
    parsed["stderr"] = result["stderr"]
    return parsed


def run_loader_trace(remote: Remote, binary: str, rootfs: str, qemu: str) -> Dict[str, Any]:
    if not binary or not rootfs or not qemu:
        return {"pass": False, "reason": "missing binary, rootfs, or qemu"}
    command = f"""
set -u
binary={quote(binary)}
root={quote(rootfs)}
qemu={quote(qemu)}
timeout 20s "$qemu" -L "$root" -E LD_TRACE_LOADED_OBJECTS=1 "$binary" 2>&1
printf '\\nloader_rc=%s\\n' "$?"
"""
    result = remote.run(command, timeout=60)
    text = result["stdout"]
    parsed = parse_kv_lines(text)
    has_guest_deps = ".so" in text or "ld-uClibc" in text or "libc" in text
    host_leak = "x86_64-linux-gnu" in text
    passed = result["returncode"] == 0 and parsed.get("loader_rc") == "0" and has_guest_deps and not host_leak
    return {
        "pass": passed,
        "loader_rc": parsed.get("loader_rc", ""),
        "host_leak": host_leak,
        "stdout_preview": " ".join(text.split())[:240],
        "stderr": result["stderr"],
    }


def check_elf_dependencies(remote: Remote, binary: str, rootfs: str) -> Dict[str, Any]:
    if not binary or not rootfs:
        return {"pass": False, "needed_libraries": "", "missing_libraries": "", "interpreter": ""}
    command = f"""
set -u
binary={quote(binary)}
root={quote(rootfs)}
interp=$(readelf -l "$binary" 2>/dev/null | awk -F': ' '/program interpreter/ {{gsub(/\\]/,"",$2); print $2; exit}}')
needed=$(readelf -d "$binary" 2>/dev/null | awk '/Shared library/ {{gsub(/\\[/,"",$5); gsub(/\\]/,"",$5); print $5}}' | sort -u)
missing=""
for lib in $needed; do
  if ! find "$root" -type f -o -type l 2>/dev/null | grep -E "/$lib$" >/dev/null 2>&1; then
    missing="$missing,$lib"
  fi
done
interp_missing=""
if [ -n "$interp" ] && [ ! -e "$root$interp" ]; then
  interp_missing="$interp"
fi
printf 'interpreter=%s\\n' "$interp"
printf 'interpreter_missing=%s\\n' "$interp_missing"
printf 'needed_libraries=%s\\n' "$(printf '%s' "$needed" | tr '\\n' ',' | sed 's/,$//')"
printf 'missing_libraries=%s\\n' "$(printf '%s' "$missing" | sed 's/^,//')"
"""
    parsed = parse_kv_lines(remote.run(command, timeout=60)["stdout"])
    missing = parsed.get("missing_libraries", "")
    interp_missing = parsed.get("interpreter_missing", "")
    parsed["pass"] = not missing and not interp_missing
    return parsed


def load_campaign_targets(campaign_dir: Path) -> List[Dict[str, Any]]:
    targets: List[Dict[str, Any]] = []
    for path in sorted(campaign_dir.glob("*.summary.json")):
        data = load_json(path)
        if not data.get("binary_path"):
            continue
        targets.append(
            {
                "target_id": path.name.replace(".summary.json", ""),
                "binary_path": data["binary_path"],
                "records": data.get("unique_pairs_analyzed", data.get("records", 0)),
                "vulnerable": data.get("results", {}).get("vulnerable", 0),
                "resolved_semantic": data.get("results", {}).get("vulnerable", 0)
                + data.get("results", {}).get("filtered", 0)
                + data.get("results", {}).get("no_taint_sink", 0),
            }
        )
    return targets


def evaluate_target(
    remote: Remote,
    target: Dict[str, Any],
    all_rootfs: List[Dict[str, str]],
    remote_root: str,
    extract_missing: bool,
    extract_timeout: int,
) -> Dict[str, Any]:
    target_id = target["target_id"]
    rel_binary = str(target["binary_path"]).replace("\\", "/")
    binary_abs = f"{remote_root.rstrip('/')}/{rel_binary}"
    target_dir = str(Path(binary_abs).parent).replace("\\", "/")
    binary_name = Path(rel_binary).name
    binary_info = remote_file_info(remote, binary_abs)
    file_text = binary_info.get("file", "")
    qemu = qemu_for_file(file_text)
    qemu_available = command_exists(remote, qemu) if qemu else False
    firmware_images = discover_firmware_images(remote, target_dir)
    candidates = matching_candidates(all_rootfs, target_id, rel_binary, target_dir)
    extraction: Dict[str, Any] = {"attempted": False}
    if not candidates and extract_missing:
        extraction = extract_missing_rootfs(remote, target_dir, firmware_images, extract_timeout)
        refreshed = global_rootfs_candidates(remote, remote_root)
        candidates = matching_candidates(refreshed, target_id, rel_binary, target_dir)
    add_rootfs_binary_info(remote, candidates, binary_name)
    best = select_best_candidate(candidates, binary_info.get("md5", ""), target_dir)
    smoke = run_rootfs_smoke(remote, best.get("path", "") if best else "", qemu, target_id) if qemu_available else {"pass": False, "reason": "qemu unavailable"}
    loader = run_loader_trace(remote, binary_abs, best.get("path", "") if best else "", qemu) if qemu_available and best else {"pass": False, "reason": "missing qemu or rootfs"}
    deps = check_elf_dependencies(remote, binary_abs, best.get("path", "") if best else "") if best else {
        "pass": False,
        "needed_libraries": "",
        "missing_libraries": "",
        "interpreter": "",
    }
    exact = bool(best and binary_info.get("md5") and best.get("rootfs_md5") == binary_info.get("md5"))
    return {
        "target": target_id,
        "records": target.get("records", 0),
        "vulnerable": target.get("vulnerable", 0),
        "resolved_semantic": target.get("resolved_semantic", 0),
        "analysis_binary": binary_abs,
        "analysis_binary_present": binary_info.get("exists") == "yes",
        "analysis_md5": binary_info.get("md5", ""),
        "arch": arch_label(file_text),
        "qemu": qemu,
        "qemu_available": qemu_available,
        "firmware_images": len(firmware_images),
        "rootfs_candidates": len(candidates),
        "best_rootfs": best.get("path", "") if best else "",
        "interpreter_present": bool(best and best.get("interp")),
        "libc_present": bool(best and best.get("libc")),
        "busybox_present": bool(best and best.get("busybox")),
        "rootfs_binary": best.get("rootfs_binary", "") if best else "",
        "rootfs_md5": best.get("rootfs_md5", "") if best else "",
        "binary_rootfs_aligned": exact,
        "rootfs_smoke_pass": bool(smoke.get("pass")),
        "dependency_resolution_pass": bool(deps.get("pass")),
        "needed_libraries": deps.get("needed_libraries", ""),
        "missing_libraries": deps.get("missing_libraries", ""),
        "interpreter": deps.get("interpreter", ""),
        "interpreter_missing": deps.get("interpreter_missing", ""),
        "loader_trace_pass": bool(loader.get("pass")),
        "loader_trace_note": loader.get("stdout_preview", loader.get("reason", "")),
        "extraction_attempted": bool(extraction.get("attempted")),
        "extraction_returncode": extraction.get("returncode", ""),
        "extraction_log": extraction.get("log", ""),
        "boundary": "corpus resource inventory; rootfs ABI smoke only; no service, handler, or command sink execution",
    }


def markdown(rows: List[Dict[str, Any]], summary: Dict[str, Any]) -> str:
    lines = [
        "# TSDS Firmware Resource Inventory",
        "",
        "This report inventories dynamic-validation resources for every firmware target in the v9 TSDS campaign. It does not start firmware services, trigger handlers, or execute command sinks.",
        "",
        f"- Targets: `{summary['targets']}`",
        f"- Analyzed binaries present: `{summary['analysis_binaries_present']}/{summary['targets']}`",
        f"- Rootfs candidates found: `{summary['rootfs_available']}/{summary['targets']}`",
        f"- QEMU available: `{summary['qemu_available']}/{summary['targets']}`",
        f"- Rootfs ABI smoke PASS: `{summary['rootfs_smoke_pass']}/{summary['targets']}`",
        f"- Static ELF dependency resolution PASS: `{summary['dependency_resolution_pass']}/{summary['targets']}`",
        f"- Loader-trace smoke PASS: `{summary['loader_trace_pass']}/{summary['targets']}`",
        f"- Exact analyzed-binary/rootfs-binary match: `{summary['binary_rootfs_aligned']}/{summary['targets']}`",
        "",
        "| Target | Arch | QEMU | Rootfs | Binary match | ABI smoke | ELF deps | Loader trace | Note |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        rootfs = "yes" if row["best_rootfs"] else "no"
        match = "yes" if row["binary_rootfs_aligned"] else "no"
        smoke = "PASS" if row["rootfs_smoke_pass"] else "FAIL"
        deps = "PASS" if row["dependency_resolution_pass"] else "FAIL"
        loader = "PASS" if row["loader_trace_pass"] else "FAIL"
        note = "exact replay candidate" if row["binary_rootfs_aligned"] else "version/resource alignment needed"
        lines.append(
            f"| `{row['target']}` | {row['arch']} | `{row['qemu'] or 'unknown'}` | {rootfs} | {match} | {smoke} | {deps} | {loader} | {note} |"
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "A rootfs smoke PASS means that the target architecture emulator can run an inert BusyBox command inside the selected rootfs. The ELF dependency check is static and does not execute the target binary. Loader-trace results are retained as a cautious diagnostic only, because some firmware loaders do not honor LD_TRACE_LOADED_OBJECTS. None of these rows is evidence that TSDS has dynamically confirmed exploitation on the device.",
        ]
    )
    return "\n".join(lines) + "\n"


def latex_table(rows: List[Dict[str, Any]]) -> str:
    def esc(value: Any) -> str:
        text = str(value)
        repl = {
            "\\": r"\textbackslash{}",
            "&": r"\&",
            "%": r"\%",
            "$": r"\$",
            "#": r"\#",
            "_": r"\_",
            "{": r"\{",
            "}": r"\}",
        }
        return "".join(repl.get(ch, ch) for ch in text)

    lines = [
        "% Auto-generated by experiments/build_firmware_resource_inventory.py",
        r"\begin{tabularx}{\textwidth}{@{}lccccccY@{}}",
        r"\toprule",
        r"Target & Arch & Rootfs & ABI smoke & ELF deps & Loader & Exact match & Interpretation\\",
        r"\midrule",
    ]
    for row in rows:
        interp = "exact replay candidate" if row["binary_rootfs_aligned"] else "alignment needed"
        lines.append(
            "{} & {} & {} & {} & {} & {} & {}\\\\".format(
                esc(row["target"]),
                esc(row["arch"]),
                "yes" if row["best_rootfs"] else "no",
                "PASS" if row["rootfs_smoke_pass"] else "FAIL",
                "PASS" if row["dependency_resolution_pass"] else "FAIL",
                "PASS" if row["loader_trace_pass"] else "FAIL",
                "yes" if row["binary_rootfs_aligned"] else "no",
                esc(interp),
            )
        )
    lines.extend([r"\bottomrule", r"\end{tabularx}", ""])
    return "\n".join(lines)


def summarize(rows: List[Dict[str, Any]], out_dir: Path) -> Dict[str, Any]:
    def count(key: str) -> int:
        return sum(1 for row in rows if row.get(key))

    return {
        "targets": len(rows),
        "analysis_binaries_present": count("analysis_binary_present"),
        "rootfs_available": sum(1 for row in rows if row.get("best_rootfs")),
        "qemu_available": count("qemu_available"),
        "rootfs_smoke_pass": count("rootfs_smoke_pass"),
        "dependency_resolution_pass": count("dependency_resolution_pass"),
        "loader_trace_pass": count("loader_trace_pass"),
        "binary_rootfs_aligned": count("binary_rootfs_aligned"),
        "extraction_attempted": count("extraction_attempted"),
        "boundary": "corpus resource inventory; rootfs ABI smoke only; no service, handler, or command sink execution",
        "out_dir": str(out_dir),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--campaign-dir", default=str(DEFAULT_CAMPAIGN))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--remote-root", default=os.environ.get("TSDS_REMOTE_ROOT", DEFAULT_REMOTE_ROOT))
    parser.add_argument("--host", default=os.environ.get("TSDS_SSH_HOST", "192.168.206.137"))
    parser.add_argument("--user", default=os.environ.get("TSDS_SSH_USER", "ubuntu"))
    parser.add_argument("--password", default=os.environ.get("TSDS_SSH_PASSWORD", "ubuntu"))
    parser.add_argument("--extract-missing-rootfs", action="store_true")
    parser.add_argument("--extract-timeout", type=int, default=600)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    targets = load_campaign_targets(root / args.campaign_dir)
    remote = Remote(args.host, args.user, args.password)
    try:
        all_rootfs = global_rootfs_candidates(remote, args.remote_root)
        rows = [
            evaluate_target(
                remote,
                target,
                all_rootfs,
                args.remote_root,
                args.extract_missing_rootfs,
                args.extract_timeout,
            )
            for target in targets
        ]
    finally:
        remote.close()

    out_dir = root / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = summarize(rows, out_dir)
    write_json(out_dir / "firmware_resource_inventory.json", rows)
    write_json(out_dir / "firmware_resource_inventory_summary.json", summary)
    write_csv(out_dir / "firmware_resource_inventory.csv", rows)
    (out_dir / "firmware_resource_inventory.md").write_text(markdown(rows, summary), encoding="utf-8")
    (out_dir / "firmware_resource_inventory_table.tex").write_text(latex_table(rows), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
