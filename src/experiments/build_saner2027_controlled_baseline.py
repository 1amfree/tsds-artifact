#!/usr/bin/env python3
"""Build transparent B0/B1/B2 comparisons for the controlled benchmark.

The baselines operate on the same fixed native command observations as the
benchmark.  They are deliberately simple counterfactual validators, not
independent vulnerability tools or SOTA claims:

* B0: every reached system call is treated as positive;
* B1: the exact input remains in the final command and contains a shell meta
  character;
* B2: the final command contains any shell meta character, without a source
  offset restriction.

The independent benchmark labels remain the semantic reference for this
calibration.  Unknown TSDS results are never converted into negatives.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Any


META = set(";|\n&`$><'\"")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("benchmark summary must be a JSON object")
    return value


def command_from_log(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"\ALEN=\d+\n(.*?)\n---\n\Z", text, flags=re.DOTALL)
    if not match:
        raise ValueError(f"command log is malformed: {path}")
    return match.group(1)


def metrics(predictions: list[bool], truth: list[bool]) -> dict[str, Any]:
    tp = sum(p and t for p, t in zip(predictions, truth))
    fp = sum(p and not t for p, t in zip(predictions, truth))
    tn = sum(not p and not t for p, t in zip(predictions, truth))
    fn = sum(not p and t for p, t in zip(predictions, truth))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall and precision + recall else None
    return {
        "n": len(truth),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark-dir", type=Path, required=True)
    args = parser.parse_args()
    benchmark_dir = args.benchmark_dir.resolve()
    summary = load(benchmark_dir / "summary.json")
    rows = []
    truth = []
    for item in summary.get("cases") or []:
        native = item.get("native") or {}
        tsds_record = item.get("tsds") or {}
        input_text = str(item.get("input") or "")
        if not input_text:
            # The benchmark summary intentionally stores only input hashes.
            # Recovering the fixed input from its versioned experiment module
            # keeps the result bound to source code rather than copying labels.
            from experiments.run_saner2027_controlled_benchmark import CASES

            index = int(item["index"])
            input_text = str(CASES[index]["input"])
        command_path = Path(str(native.get("command_log") or ""))
        command = command_from_log(command_path)
        expected = str(item.get("expected") or "").upper() == "POSITIVE"
        # B0 models the original source-to-sink warning as positive.
        b0 = bool(native.get("returncode") == 0 and not native.get("timed_out"))
        # B1 requires the concrete source input to survive into the command and
        # contain a shell-significant character.
        b1 = input_text in command and any(char in META for char in input_text)
        # B2 deliberately ignores source ownership and scans the complete
        # command, exposing the false-positive risk of fixed shell syntax.
        b2 = any(char in META for char in command)
        tsds_positive = bool(tsds_record.get("tsds_positive"))
        rows.append({
            "index": item.get("index"),
            "case_id": item.get("id"),
            "truth": expected,
            "native_trigger": bool(native.get("trigger_observed")),
            "B0_reached_sink": b0,
            "B1_source_meta": b1,
            "B2_full_string_meta": b2,
            "TSDS": tsds_positive,
            "TSDS_class": tsds_record.get("tsds_class"),
            "TSDS_comparison": tsds_record.get("comparison"),
        })
        truth.append(expected)
    validators = {
        "B0_original_source_to_sink": [bool(row["B0_reached_sink"]) for row in rows],
        "B1_source_owned_meta": [bool(row["B1_source_meta"]) for row in rows],
        "B2_full_string_meta": [bool(row["B2_full_string_meta"]) for row in rows],
        "TSDS": [bool(row["TSDS"]) for row in rows],
    }
    result = {
        "schema": "tsds-saner2027-controlled-baseline-v1",
        "benchmark_summary": str((benchmark_dir / "summary.json").resolve()),
        "case_count": len(rows),
        "truth_positive": sum(truth),
        "validators": {name: metrics(prediction, truth) for name, prediction in validators.items()},
        "rows": rows,
        "claim_boundary": (
            "Same-input controlled counterfactual comparison. Labels come from "
            "the independently specified native benchmark semantics. B0/B1/B2 "
            "are simple validators, not independent firmware accuracy baselines."
        ),
    }
    (benchmark_dir / "baseline_comparison.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (benchmark_dir / "baseline_comparison.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = list(rows[0]) if rows else []
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    lines = [
        "# Controlled baseline comparison",
        "",
        "This is a same-input calibration, not firmware ground truth.",
        "",
        f"- Cases: `{len(rows)}`; independent positive labels: `{sum(truth)}`.",
        "- B0 treats every reached `system` call as positive.",
        "- B1 requires the exact input to survive in the final command and contain a shell meta character.",
        "- B2 scans the full command for shell meta characters and ignores source ownership.",
        "- TSDS uses the actual evaluator result; residuals would be unknown, not negative.",
        "",
        "| Validator | TP | FP | TN | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, report in result["validators"].items():
        lines.append("| {} | {} | {} | {} | {} | {} | {} | {} |".format(
            name,
            report["tp"], report["fp"], report["tn"], report["fn"],
            report["precision"], report["recall"], report["f1"],
        ))
    lines.extend(["", result["claim_boundary"]])
    (benchmark_dir / "baseline_comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"case_count": len(rows), "validators": result["validators"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
