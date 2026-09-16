#!/usr/bin/env python3
"""Convert SaTC-style command-injection candidates to TSDS closure JSON.

TSDS consumes a front-end-neutral JSON shape:

    {"closures": [{"trace": [...], "sink": {...}, "inputs": {...}}]}

Operation Mango already emits that structure. SaTC emits a mixture of Ghidra
candidate files and optional taint-check result files. This converter keeps the
front-end boundary explicit: it normalizes SaTC candidates without changing the
TSDS evaluator or weakening the existing Mango pipeline.
"""

from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import pathlib
import re
from typing import Any


ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")
FOUND_RE = re.compile(
    r"^(?P<taint>0x[0-9a-fA-F]+)\s+"
    r"(?P<start>0x[0-9a-fA-F]+)\s+"
    r"found\s*:\s*(?P<sinks>.*)$",
    re.IGNORECASE,
)
NOT_FOUND_RE = re.compile(
    r"^(?P<taint>0x[0-9a-fA-F]+)\s+"
    r"(?P<start>0x[0-9a-fA-F]+)\s+not\s+found\s*$",
    re.IGNORECASE,
)
HEADER_RE = re.compile(r"^(?P<key>binary|configfile)\s*:\s*(?P<value>.+)$", re.IGNORECASE)
RAW_GHIDRA_RE = re.compile(
    r'^\[Param\s+"(?P<keyword>.*?)"\((?P<string_addr>0x[0-9a-fA-F]+)\),\s*'
    r'Referenced\s+at\s+.*?\s*:\s*(?P<start_addr>0x[0-9a-fA-F]+)\]\s*'
    r'(?P<path>.*)$'
)
RAW_GHIDRA_CALLEE_RE = re.compile(r"(?:->|>>)\s*(?P<callee>[A-Za-z_.$][\w.$@]*)\s*$")


def file_identity(path: pathlib.Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": digest.hexdigest(),
    }


def normalize_addr(value: Any, addr_shift: int = 0) -> str:
    """Return a lowercase hex address string."""
    if value is None:
        raise ValueError("missing address")
    text = str(value).strip()
    if not text:
        raise ValueError("empty address")
    if text.lower().startswith("0x"):
        return hex(int(text, 16) + addr_shift)
    return hex(int(text, 0) + addr_shift)


def function_name_for_addr(addr: str) -> str:
    return f"sub_{int(addr, 16):x}"


def node_for_addr(addr: str, role: str = "source") -> dict[str, str]:
    func = function_name_for_addr(addr)
    return {
        "function": func,
        "ins_addr": addr,
        "string": f"{func}() @ {addr} [{role}]",
    }


def sink_for_addr(addr: str, sink_function: str) -> dict[str, str]:
    return {
        "function": sink_function or "system",
        "ins_addr": addr,
        "string": f"{sink_function or 'system'}(<satc_candidate>) @ {addr}",
    }


def closure_key(source_addr: str, sink_addr: str, trace_addrs: list[str]) -> str:
    digest = hashlib.sha1("|".join([source_addr, sink_addr] + trace_addrs).encode()).hexdigest()
    return digest[:16]


def make_closure(
    *,
    source_addr: str,
    sink_addr: str,
    sink_function: str = "system",
    taint_addr: str | None = None,
    trace_addrs: list[str] | None = None,
    keywords: list[str] | None = None,
    satc_status: str = "candidate",
    origin_file: str | None = None,
    origin_line: int | None = None,
    addr_shift: int = 0,
    raw: str | None = None,
) -> dict[str, Any]:
    source_addr = normalize_addr(source_addr, addr_shift)
    sink_addr = normalize_addr(sink_addr, addr_shift)
    taint_addr = normalize_addr(taint_addr, addr_shift) if taint_addr else None
    trace_addrs = [normalize_addr(addr, addr_shift) for addr in (trace_addrs or []) if str(addr).strip()]
    trace = [node_for_addr(source_addr, "satc_start")]
    for addr in trace_addrs:
        if addr != source_addr:
            trace.append(node_for_addr(addr, "satc_follow"))
    # SaTC addresses identify a static candidate and must not be promoted to
    # TSDS source semantics.  A taint-site address is provenance, not proof
    # that the reached command bytes are attacker-controlled.  Only explicit
    # front-end keywords are carried as source hints; the raw addresses remain
    # in the namespaced ``satc`` metadata for audit and replay.
    likely_inputs = [str(kw) for kw in (keywords or []) if str(kw).strip()]
    source_tags = ["satc", satc_status]
    if taint_addr:
        source_tags.append("satc_taint_site")
    return {
        "frontend": "satc",
        "id": closure_key(source_addr, sink_addr, trace_addrs),
        "rank": 1.0 if satc_status == "found" else 2.0,
        "depth": len(trace),
        "reachable_from_main": None,
        "sanitized": False,
        "trace": trace,
        "sink": sink_for_addr(sink_addr, sink_function),
        "inputs": {
            "likely": sorted(set(likely_inputs)),
            "possibly": [],
            "tags": sorted(set(source_tags)),
            "valid_funcs": [int(source_addr, 16)],
        },
        "satc": {
            "status": satc_status,
            "taint_addr": taint_addr,
            "source_addr": source_addr,
            "sink_addr": sink_addr,
            "origin_file": origin_file,
            "origin_line": origin_line,
            "addr_shift": addr_shift,
            "raw": raw,
        },
    }


def parse_satc_alter2(path: pathlib.Path, sink_function: str, addr_shift: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse SaTC Ghidra output after conv_Ghidra_output.py (*-alter2).

    The format is three lines per candidate:
      taint_addr start_addr
      optional follow-trace addresses
      sink target addresses
    """
    lines = path.read_text(errors="ignore").splitlines()
    records: list[dict[str, Any]] = []
    chunks_seen = 0
    for idx in range(0, len(lines), 3):
        chunk = lines[idx:idx + 3]
        if len(chunk) < 3:
            continue
        chunks_seen += 1
        head = ADDR_RE.findall(chunk[0])
        if len(head) < 2:
            continue
        taint_addr, start_addr = head[0], head[1]
        trace_addrs = ADDR_RE.findall(chunk[1])
        sink_addrs = ADDR_RE.findall(chunk[2])
        for sink_addr in sink_addrs:
            records.append(make_closure(
                source_addr=start_addr,
                sink_addr=sink_addr,
                sink_function=sink_function,
                taint_addr=taint_addr,
                trace_addrs=trace_addrs,
                satc_status="ghidra_candidate",
                origin_file=str(path),
                origin_line=idx + 1,
                addr_shift=addr_shift,
                raw="\n".join(chunk),
            ))
    return records, {"alter2_chunks_seen": chunks_seen, "alter2_closures": len(records)}


def parse_satc_raw_ghidra(
    path: pathlib.Path, sink_function: str, addr_shift: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse SaTC's native ``ref2sink_cmdi`` Ghidra output directly.

    A candidate line binds one shared keyword and its string address to the
    reference instruction, followed by callsites ending at the sink callsite.
    Direct parsing avoids the artifact's Python-2-only conversion helper and
    preserves the keyword that helper discards.
    """

    records: list[dict[str, Any]] = []
    candidate_lines = 0
    malformed_candidate_lines = 0
    for line_no, raw in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        text = raw.strip()
        if not text.startswith("[Param "):
            continue
        candidate_lines += 1
        match = RAW_GHIDRA_RE.match(text)
        if match is None:
            malformed_candidate_lines += 1
            continue
        path_addrs = ADDR_RE.findall(match.group("path"))
        if not path_addrs:
            malformed_candidate_lines += 1
            continue
        callee = RAW_GHIDRA_CALLEE_RE.search(match.group("path"))
        reached_sink_function = callee.group("callee") if callee else sink_function
        records.append(
            make_closure(
                source_addr=match.group("start_addr"),
                sink_addr=path_addrs[-1],
                sink_function=reached_sink_function,
                taint_addr=match.group("string_addr"),
                trace_addrs=path_addrs[:-1],
                keywords=[match.group("keyword")],
                satc_status="ghidra_candidate_raw",
                origin_file=str(path),
                origin_line=line_no,
                addr_shift=addr_shift,
                raw=text,
            )
        )
    return records, {
        "raw_ghidra_candidate_lines": candidate_lines,
        "raw_ghidra_malformed_candidate_lines": malformed_candidate_lines,
        "raw_ghidra_closures": len(records),
    }


def parse_satc_result(path: pathlib.Path, sink_function: str, include_not_found: bool, addr_shift: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse SaTC taint-check result-*.txt files.

    Found lines look like:
      0xTAINT 0xSTART found : 0xSINK [0xSINK...]

    Not-found lines do not carry sink target addresses, so they are included
    only when explicitly requested and represented without a sink closure.
    """
    records: list[dict[str, Any]] = []
    counters = {"result_found_lines": 0, "result_not_found_lines": 0, "result_found_closures": 0}
    headers: dict[str, str] = {}
    for line_no, line in enumerate(path.read_text(errors="ignore").splitlines(), start=1):
        text = line.strip()
        if not text:
            continue
        header = HEADER_RE.match(text)
        if header:
            headers[header.group("key").lower()] = header.group("value").strip()
            continue
        if text.startswith("total cases") or text.startswith("find cases"):
            continue
        m = FOUND_RE.match(text)
        if m:
            counters["result_found_lines"] += 1
            sinks = ADDR_RE.findall(m.group("sinks"))
            for sink_addr in sinks:
                records.append(make_closure(
                    source_addr=m.group("start"),
                    sink_addr=sink_addr,
                    sink_function=sink_function,
                    taint_addr=m.group("taint"),
                    satc_status="found",
                    origin_file=str(path),
                    origin_line=line_no,
                    addr_shift=addr_shift,
                    raw=text,
                ))
                counters["result_found_closures"] += 1
            continue
        if include_not_found and NOT_FOUND_RE.match(text):
            counters["result_not_found_lines"] += 1
            # A not-found result lacks sink addresses in SaTC's result file.
            # It is preserved only in metadata by callers that need accounting.
            continue
    return records, {**counters, "headers": headers}


def parse_json_records(path: pathlib.Path, sink_function: str, addr_shift: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    data = json.loads(path.read_text())
    if isinstance(data, dict):
        items = data.get("records") or data.get("closures") or data.get("items") or []
    else:
        items = data
    records = []
    for item in items:
        if "trace" in item and "sink" in item:
            closure = dict(item)
            closure.setdefault("frontend", "satc")
            closure.setdefault("satc", {"status": "json_closure", "origin_file": str(path)})
            records.append(closure)
            continue
        source_addr = item.get("source_addr") or item.get("start_addr") or item.get("source")
        sink_addr = item.get("sink_addr") or item.get("sink")
        if not source_addr or not sink_addr:
            continue
        trace_addrs = item.get("trace_addrs") or item.get("trace") or []
        if isinstance(trace_addrs, str):
            trace_addrs = ADDR_RE.findall(trace_addrs)
        keywords = item.get("keywords") or item.get("inputs") or []
        if isinstance(keywords, str):
            keywords = [part.strip() for part in re.split(r"[,;\s]+", keywords) if part.strip()]
        records.append(make_closure(
            source_addr=source_addr,
            sink_addr=sink_addr,
            sink_function=item.get("sink_function") or sink_function,
            taint_addr=item.get("taint_addr"),
            trace_addrs=trace_addrs,
            keywords=keywords,
            satc_status=item.get("status") or "json_candidate",
            origin_file=str(path),
            addr_shift=addr_shift,
            raw=json.dumps(item, sort_keys=True),
        ))
    return records, {"json_items_seen": len(items), "json_closures": len(records)}


def parse_csv_records(path: pathlib.Path, sink_function: str, addr_shift: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records = []
    rows_seen = 0
    with path.open(newline="", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows_seen += 1
            source_addr = row.get("source_addr") or row.get("start_addr") or row.get("source")
            sink_addr = row.get("sink_addr") or row.get("sink")
            if not source_addr or not sink_addr:
                continue
            trace_text = row.get("trace_addrs") or row.get("trace") or ""
            keyword_text = row.get("keywords") or row.get("inputs") or ""
            records.append(make_closure(
                source_addr=source_addr,
                sink_addr=sink_addr,
                sink_function=row.get("sink_function") or sink_function,
                taint_addr=row.get("taint_addr"),
                trace_addrs=ADDR_RE.findall(trace_text),
                keywords=[part.strip() for part in re.split(r"[,;\s]+", keyword_text) if part.strip()],
                satc_status=row.get("status") or "csv_candidate",
                origin_file=str(path),
                addr_shift=addr_shift,
                raw=json.dumps(row, sort_keys=True),
            ))
    return records, {"csv_rows_seen": rows_seen, "csv_closures": len(records)}


def dedupe_closures(closures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    out = []
    for closure in closures:
        trace = closure.get("trace") or []
        source = trace[0].get("ins_addr") if trace else ""
        sink = (closure.get("sink") or {}).get("ins_addr", "")
        trace_key = tuple(node.get("ins_addr", "") for node in trace)
        key = (source, sink, trace_key)
        if key in seen:
            continue
        seen.add(key)
        out.append(closure)
    return out


def expand_inputs(inputs: list[str]) -> list[pathlib.Path]:
    """Expand files, directories, and globs into deterministic SaTC input paths."""
    paths: list[pathlib.Path] = []
    for item in inputs:
        matched = [pathlib.Path(p) for p in sorted(glob.glob(item, recursive=True))] if any(ch in item for ch in "*?[]") else []
        candidates = matched or [pathlib.Path(item)]
        for path in candidates:
            if path.is_dir():
                known = []
                known.extend(path.rglob("*_ref2sink_cmdi.result"))
                known.extend(path.rglob("*-alter2"))
                known.extend(path.rglob("*.result-alter2"))
                known.extend(path.rglob("result-*.txt"))
                known.extend(path.rglob("*.json"))
                known.extend(path.rglob("*.csv"))
                paths.extend(sorted({p.resolve() for p in known}))
            else:
                paths.append(path)
    return sorted(dict.fromkeys(paths))


def merge_stats(stats: dict[str, Any], update: dict[str, Any]) -> None:
    for key, value in update.items():
        if isinstance(value, int):
            stats[key] = int(stats.get(key, 0) or 0) + value
        elif isinstance(value, dict):
            bucket = stats.setdefault(key, {})
            if isinstance(bucket, dict):
                bucket.update(value)
            else:
                stats[key] = value
        else:
            stats[key] = value


def convert(paths: list[pathlib.Path], args: argparse.Namespace) -> dict[str, Any]:
    closures: list[dict[str, Any]] = []
    stats: dict[str, Any] = {"input_files_expanded": len(paths)}
    for path in paths:
        name = path.name.lower()
        if args.input_format == "auto":
            if name.endswith(".json"):
                fmt = "json"
            elif name.endswith(".csv"):
                fmt = "csv"
            elif name.endswith("-alter2") or name.endswith(".result-alter2"):
                fmt = "alter2"
            elif name.endswith(".result"):
                fmt = "ghidra"
            elif name.startswith("result-") or name.endswith(".txt"):
                fmt = "result"
            else:
                fmt = "alter2"
        else:
            fmt = args.input_format
        if fmt == "alter2":
            parsed, parsed_stats = parse_satc_alter2(path, args.sink_function, args.addr_shift)
        elif fmt == "ghidra":
            parsed, parsed_stats = parse_satc_raw_ghidra(
                path, args.sink_function, args.addr_shift
            )
        elif fmt == "result":
            parsed, parsed_stats = parse_satc_result(path, args.sink_function, args.include_not_found, args.addr_shift)
        elif fmt == "json":
            parsed, parsed_stats = parse_json_records(path, args.sink_function, args.addr_shift)
        elif fmt == "csv":
            parsed, parsed_stats = parse_csv_records(path, args.sink_function, args.addr_shift)
        else:
            raise ValueError(f"unsupported input format: {fmt}")
        identity = file_identity(path)
        for closure in parsed:
            satc = closure.setdefault("satc", {})
            satc["origin_file_sha256"] = identity["sha256"]
            satc["source_semantics_policy"] = "address_provenance_only"
        closures.extend(parsed)
        merge_stats(stats, {"formats": {str(path): fmt}, **parsed_stats})
    before_dedupe = len(closures)
    if args.dedupe:
        closures = dedupe_closures(closures)
    stats["closures_before_dedupe"] = before_dedupe
    stats["closures_after_dedupe"] = len(closures)
    stats["deduped_closures"] = before_dedupe - len(closures)
    binary_identity = None
    binary = getattr(args, "binary", None)
    if binary is not None:
        binary_path = pathlib.Path(binary).expanduser().resolve()
        if not binary_path.is_file():
            raise ValueError(f"binary does not exist: {binary_path}")
        binary_identity = file_identity(binary_path)
    return {
        "schema": "tsds-closures-v1",
        "frontend": "satc",
        "metadata": {
            "converter": "experiments/convert_satc_to_tsds.py",
            "converter_identity": file_identity(pathlib.Path(__file__).resolve()),
            "input_files": [str(path) for path in paths],
            "input_identities": [file_identity(path) for path in paths],
            "binary_identity": binary_identity,
            "input_format": args.input_format,
            "default_sink_function": args.sink_function,
            "addr_shift": args.addr_shift,
            "closure_count": len(closures),
            "stats": stats,
            "notes": [
                "SaTC result files contain found sink addresses only.",
                "SaTC *-alter2 files contain static Ghidra candidates before taint confirmation.",
                "Native SaTC ref2sink_cmdi Ghidra output is parsed without the Python-2 conversion helper.",
                "SaTC addresses are preserved as provenance and do not create TSDS source semantics.",
            ],
            "claim_boundary": (
                "The adapter normalizes front-end candidates and binds their bytes; "
                "it does not promote SaTC addresses to attacker-control evidence."
            ),
        },
        "closures": closures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert SaTC candidates to TSDS closure JSON.")
    parser.add_argument("inputs", nargs="+", help="SaTC result/config JSON/CSV files to convert.")
    parser.add_argument("-o", "--output", required=True, help="Output TSDS closure JSON path.")
    parser.add_argument("--input-format", choices=["auto", "ghidra", "alter2", "result", "json", "csv"], default="auto")
    parser.add_argument("--sink-function", default="system", help="Default sink function name when SaTC omits it.")
    parser.add_argument("--addr-shift", type=lambda value: int(value, 0), default=0, help="Signed offset added to all parsed SaTC addresses, useful when Ghidra and loader image bases differ.")
    parser.add_argument("--include-not-found", action="store_true", help="Keep not-found accounting where representable.")
    parser.add_argument("--binary", type=pathlib.Path, help="Optional analyzed binary to bind by SHA-256 in conversion metadata.")
    parser.add_argument("--no-dedupe", dest="dedupe", action="store_false", help="Do not deduplicate identical source/sink/trace records.")
    parser.set_defaults(dedupe=True)
    args = parser.parse_args()

    paths = expand_inputs(args.inputs)
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        raise SystemExit(f"missing input file(s): {', '.join(missing)}")
    out = convert(paths, args)
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(out, indent=2, sort_keys=True))
    print(f"WROTE {output} closures={len(out['closures'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
