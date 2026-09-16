#!/usr/bin/env python3
"""Build paper-ready evidence summaries for reviewer-response gaps.

The script consumes TSDS JSONL ledgers and produces compact tables for:
   * direct vs guarded shell-vector SAT evidence,
   * typed NoT (no modeled source) evidence,
  * W20E evidence-unit diversity,
  * record-level full-vs-no-path-control comparison, and
  * reproducibility manifest entries.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


CLAIM_BUCKET_ALIASES = {
    "positive_vulnerability_evidence": "modeled_sink_byte_sv_sat_evidence",
    "guarded_static_vulnerability_evidence": "guarded_static_sv_sat_evidence",
    "negative_sanitizer_evidence": "modeled_vector_filtered_evidence",
    "false_positive_reduction_evidence": "no_modeled_source_evidence",
}


def normalize_claim_bucket(bucket: Any) -> str:
    text = str(bucket or "unspecified")
    return CLAIM_BUCKET_ALIASES.get(text, text)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_campaign(campaign_dir: Path) -> dict[str, list[dict[str, Any]]]:
    targets: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(campaign_dir.glob("*.results.jsonl")):
        targets[path.name.replace(".results.jsonl", "")] = read_jsonl(path)
    return targets


def evidence_split(targets: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    bucket_counts: Counter[str] = Counter()
    sat_split: Counter[str] = Counter()
    not_split: Counter[str] = Counter()
    filtered_count = 0
    guarded_examples: list[dict[str, Any]] = []

    for target, rows in targets.items():
        for row in rows:
            bucket = normalize_claim_bucket(row.get("paper_claim_bucket"))
            bucket_counts[bucket] += 1
            status = row.get("status")
            if status == "vulnerable":
                if bucket == "guarded_static_sv_sat_evidence":
                    sat_split["guarded_static_sv_sat"] += 1
                    guarded_examples.append(
                        {
                            "target": target,
                            "closure_idx": row.get("closure_idx"),
                            "sink": row.get("sink_addr"),
                            "source": row.get("source_addr"),
                            "preview": row.get("sink_preview"),
                            "confidence": row.get("evidence_confidence"),
                        }
                    )
                else:
                    sat_split["direct_sink_byte_sv_sat"] += 1
            elif status == "filtered":
                filtered_count += 1
            elif status == "no_taint_sink":
                label = row.get("residual_diagnosis_class") or row.get("engine_stop_reason") or "unspecified"
                not_split[label] += 1

    return {
        "paper_claim_buckets": dict(bucket_counts),
        "sv_sat_split": dict(sat_split),
        "modeled_vector_filtered": filtered_count,
        "not_breakdown": dict(not_split),
        "guarded_examples": guarded_examples,
    }


def dedup_summary(targets: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    per_target: dict[str, dict[str, Any]] = {}
    total = {
        "records": 0,
        "sv_sat_records": 0,
        "sv_sat_sink_callsites": set(),
        "sv_sat_source_sink_pairs": set(),
        "trace_shapes": set(),
    }
    for target, rows in targets.items():
        status_counts = Counter(row.get("status") for row in rows)
        sv_rows = [r for r in rows if r.get("status") == "vulnerable"]
        sink_calls = {(r.get("sink_addr"), r.get("sink_function")) for r in sv_rows}
        pairs = {(r.get("source_addr"), r.get("sink_addr")) for r in sv_rows}
        traces = {r.get("trace_summary") or tuple(r.get("trace_nodes") or []) for r in rows}
        per_target[target] = {
            "records": len(rows),
            "status_counts": dict(status_counts),
            "sv_sat_records": len(sv_rows),
            "sv_sat_sink_callsites": len(sink_calls),
            "sv_sat_source_sink_pairs": len(pairs),
            "trace_shapes": len(traces),
        }
        total["records"] += len(rows)
        total["sv_sat_records"] += len(sv_rows)
        total["sv_sat_sink_callsites"].update((target, x) for x in sink_calls)
        total["sv_sat_source_sink_pairs"].update((target, x) for x in pairs)
        total["trace_shapes"].update((target, x) for x in traces)

    total_out = {
        "records": total["records"],
        "sv_sat_records": total["sv_sat_records"],
        "sv_sat_sink_callsites": len(total["sv_sat_sink_callsites"]),
        "sv_sat_source_sink_pairs": len(total["sv_sat_source_sink_pairs"]),
        "trace_shapes": len(total["trace_shapes"]),
    }
    return {"per_target": per_target, "total": total_out}


def load_ablation_pairs(ablation_dir: Path) -> dict[str, dict[str, list[dict[str, Any]]]]:
    out: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(dict)
    for path in sorted(ablation_dir.glob("*.results.jsonl")):
        name = path.name.replace(".results.jsonl", "")
        if name.endswith("_no_path_control"):
            target = name[: -len("_no_path_control")]
            out[target]["no_path_control"] = read_jsonl(path)
        elif name.endswith("_full"):
            target = name[: -len("_full")]
            out[target]["full"] = read_jsonl(path)
    return out


def status_class(row: dict[str, Any] | None) -> str:
    if not row:
        return "missing"
    return str(row.get("status") or "missing")


def vector_signature(row: dict[str, Any] | None) -> tuple[Any, ...]:
    if not row:
        return ()
    return (
        row.get("status"),
        tuple(sorted(row.get("bypass_vector_categories") or [])),
        tuple(sorted(row.get("blocked_vector_categories") or [])),
        row.get("partially_filtered"),
        row.get("paper_claim_bucket"),
    )


def path_control_record_audit(ablation_dir: Path) -> dict[str, Any]:
    pairs = load_ablation_pairs(ablation_dir)
    per_target: dict[str, Any] = {}
    global_counts = Counter()
    changed_examples: list[dict[str, Any]] = []

    for target, configs in sorted(pairs.items()):
        full = {r.get("closure_idx"): r for r in configs.get("full", [])}
        nopc = {r.get("closure_idx"): r for r in configs.get("no_path_control", [])}
        keys = sorted(set(full) | set(nopc), key=lambda x: (-1 if x is None else int(x)))
        counts = Counter()
        for key in keys:
            f = full.get(key)
            n = nopc.get(key)
            fs = status_class(f)
            ns = status_class(n)
            counts["matched_records"] += 1
            if fs == ns:
                counts["same_status"] += 1
            else:
                counts[f"{fs}_to_{ns}"] += 1
                if len(changed_examples) < 12:
                    changed_examples.append(
                        {
                            "target": target,
                            "closure_idx": key,
                            "full_status": fs,
                            "no_path_status": ns,
                            "full_stop": (f or {}).get("engine_stop_reason"),
                            "no_path_stop": (n or {}).get("engine_stop_reason"),
                            "sink": (f or n or {}).get("sink_addr"),
                            "trace": (f or n or {}).get("trace_summary"),
                        }
                    )
            if vector_signature(f) == vector_signature(n):
                counts["same_vector_signature"] += 1
        per_target[target] = dict(counts)
        global_counts.update(counts)

    return {
        "boundary": "Record-level comparison between full TSDS and no-path-control ablation under the same campaign budget; this is empirical equivalence evidence, not a formal completeness proof.",
        "global": dict(global_counts),
        "per_target": per_target,
        "changed_examples": changed_examples,
    }


def artifact_manifest(root: Path, manifest_path: Path | None) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    if manifest_path and manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for target, item in sorted(manifest.items()):
            for key in ("binary", "json"):
                rel = Path(item[key])
                path = root / rel
                entries.append(
                    {
                        "target": target,
                        "kind": key,
                        "path": str(rel).replace("\\", "/"),
                        "available_locally": path.exists(),
                        "size": path.stat().st_size if path.exists() else None,
                        "sha256": sha256_file(path) if path.exists() else None,
                    }
                )
    return {
        "boundary": "Hashes identify local evaluation inputs. Vendor firmware redistribution may require replacing binaries with hashes and acquisition instructions.",
        "entries": entries,
    }


def runtime_canary_summary(path: Path | None) -> dict[str, Any]:
    if not path or not path.exists():
        return {
            "available": False,
            "boundary": "No runtime canary summary was provided to this evidence-pack run.",
        }
    data = json.loads(path.read_text(encoding="utf-8"))
    positives = data.get("positive_canaries") or data.get("successful_sinks") or []
    probes = data.get("boundary_probes") or []
    return {
        "available": True,
        "source": str(path),
        "positive_count": int(data.get("positive_count") or data.get("successful_runtime_consistency_checks") or len(positives)),
        "positive_vendor_count": data.get("positive_vendor_count"),
        "positive_firmware_count": data.get("positive_firmware_count"),
        "handler_level_positive_count": data.get("handler_level_positive_count"),
        "service_level_positive_count": data.get("service_level_positive_count"),
        "boundary_probe_count": int(data.get("boundary_probe_count") or len(probes)),
        "claim_boundary": data.get("claim_boundary"),
        "positive_ids": [item.get("id") or item.get("candidate") for item in positives],
        "boundary_probe_ids": [item.get("id") or item.get("candidate") or item.get("artifact_name") for item in probes],
    }


def satc_adapter_smoke(root: Path, enabled: bool) -> dict[str, Any]:
    if not enabled:
        return {
            "run": False,
            "boundary": "SaTC adapter smoke tests were not requested for this evidence-pack run.",
        }
    cmd = [sys.executable, "-m", "unittest", "experiments.test_satc_adapter", "-v"]
    completed = subprocess.run(
        cmd,
        cwd=root,
        text=True,
        capture_output=True,
        timeout=60,
    )
    return {
        "run": True,
        "command": " ".join(cmd),
        "returncode": completed.returncode,
        "passed": completed.returncode == 0,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "boundary": "Adapter smoke tests validate conversion of SaTC-style candidates into TSDS closure JSON; they are not a full SaTC-vs-TSDS accuracy evaluation.",
    }


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign-dir", type=Path, required=True)
    ap.add_argument("--ablation-dir", type=Path, required=True)
    ap.add_argument("--manifest", type=Path)
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument("--runtime-canary-summary", type=Path)
    ap.add_argument("--run-satc-adapter-smoke", action="store_true")
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    targets = load_campaign(args.campaign_dir)
    evidence = evidence_split(targets)
    dedup = dedup_summary(targets)
    path_audit = path_control_record_audit(args.ablation_dir)
    manifest = artifact_manifest(args.root, args.manifest)
    canary = runtime_canary_summary(args.runtime_canary_summary)
    satc_smoke = satc_adapter_smoke(args.root, args.run_satc_adapter_smoke)

    summary = {
        "evidence_split": evidence,
        "dedup": dedup,
        "path_control_record_audit": path_audit,
        "artifact_manifest": manifest,
        "runtime_canaries": canary,
        "satc_adapter_smoke": satc_smoke,
    }
    (args.out_dir / "reviewer_response_evidence.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    no_taint_rows = [
        {"class": k, "count": v}
        for k, v in sorted(evidence["not_breakdown"].items(), key=lambda x: (-x[1], x[0]))
    ]
    write_csv(args.out_dir / "not_breakdown.csv", no_taint_rows, ["class", "count"])
    write_csv(args.out_dir / "no_taint_breakdown.csv", no_taint_rows, ["class", "count"])

    pc_rows = []
    for target, vals in path_audit["per_target"].items():
        row = {"target": target}
        row.update(vals)
        pc_rows.append(row)
    pc_fields = sorted({k for row in pc_rows for k in row})
    if "target" in pc_fields:
        pc_fields.remove("target")
    write_csv(args.out_dir / "path_control_record_audit.csv", pc_rows, ["target"] + pc_fields)

    dedup_rows = []
    for target, vals in dedup["per_target"].items():
        row = {"target": target}
        row.update({k: v for k, v in vals.items() if k != "status_counts"})
        dedup_rows.append(row)
    write_csv(
        args.out_dir / "dedup_units.csv",
        dedup_rows,
        [
            "target",
            "records",
            "sv_sat_records",
            "sv_sat_sink_callsites",
            "sv_sat_source_sink_pairs",
            "trace_shapes",
        ],
    )

    manifest_rows = manifest["entries"]
    write_csv(
        args.out_dir / "artifact_manifest_hashes.csv",
        manifest_rows,
        ["target", "kind", "path", "available_locally", "size", "sha256"],
    )

    md: list[str] = []
    sv = evidence["sv_sat_split"]
    md.append("# Reviewer-response evidence summary\n\n")
    md.append("## Shell-vector SAT evidence split\n\n")
    md.append(
        f"- Direct sink-byte SV-SAT records: {sv.get('direct_sink_byte_sv_sat', 0)}\n"
    )
    md.append(
        f"- Guarded static SV-SAT records: {sv.get('guarded_static_sv_sat', 0)}\n"
    )
    md.append(f"- Modeled-vector filtered records: {evidence['modeled_vector_filtered']}\n\n")
    md.append("## NoT evidence breakdown\n\n")
    md.append("| Class | Count |\n|---|---:|\n")
    for row in no_taint_rows:
        md.append(f"| `{row['class']}` | {row['count']} |\n")
    md.append("\n## Path-control record-level audit\n\n")
    g = path_audit["global"]
    matched = g.get("matched_records", 0)
    same = g.get("same_status", 0)
    same_sig = g.get("same_vector_signature", 0)
    md.append(
        f"Compared {matched} full/no-path-control record pairs. "
        f"Same status: {same}; same vector signature: {same_sig}. "
        "This is empirical stability evidence, not a completeness proof.\n\n"
    )
    md.append("| Target | Pairs | Same status | Same vector signature |\n|---|---:|---:|---:|\n")
    for target, vals in path_audit["per_target"].items():
        md.append(
            f"| {target} | {vals.get('matched_records', 0)} | "
            f"{vals.get('same_status', 0)} | {vals.get('same_vector_signature', 0)} |\n"
        )
    md.append("\n## Artifact manifest\n\n")
    md.append(
        "The hash manifest records binary and Operation Mango JSON inputs available in the local evaluation tree. "
        "If vendor firmware cannot be redistributed, these hashes should be released with acquisition instructions.\n"
    )
    md.append("\n## Runtime canary boundary\n\n")
    if canary.get("available"):
        md.append(
            f"Positive runtime-consistency canaries: {canary.get('positive_count')} "
            f"across {canary.get('positive_firmware_count')} firmware images and "
            f"{canary.get('positive_vendor_count')} vendors. Handler-level positives: "
            f"{canary.get('handler_level_positive_count')}; service-level positives: "
            f"{canary.get('service_level_positive_count')}. Boundary probes retained separately: "
            f"{canary.get('boundary_probe_count')}. These are qemu/gdb sink-callsite observations, "
            "not physical-device exploit confirmations.\n"
        )
    else:
        md.append("No runtime canary summary was provided.\n")
    md.append("\n## Front-end adapter smoke test\n\n")
    if satc_smoke.get("run"):
        status = "passed" if satc_smoke.get("passed") else "failed"
        md.append(
            f"SaTC adapter smoke test {status} with return code {satc_smoke.get('returncode')}. "
            "This demonstrates front-end-neutral closure normalization, not a full alternate-front-end evaluation.\n"
        )
    else:
        md.append("SaTC adapter smoke test was not requested.\n")
    (args.out_dir / "reviewer_response_evidence.md").write_text("".join(md), encoding="utf-8")


if __name__ == "__main__":
    main()
