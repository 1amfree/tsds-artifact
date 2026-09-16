#!/usr/bin/env python3

from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from experiments.export_v20_ablation_transitions import export_transitions


def record(index: int, verdict: str = "MATRIX_UNSAT", **updates):
    value = {
        "closure_idx": index,
        "source_addr": hex(0x1000 + index),
        "sink_addr": "0x2000",
        "closure_sink_signature": [hex(0x1000 + index), "0x2000"],
        "status": "filtered",
        "verdict": verdict,
        "evidence_provenance": "DIRECT_SINK_BYTE",
        "admissible_claim": "matrix_bounded_filtering",
        "evidence_contract_valid": True,
        "controlled_offsets": [1],
        "sink_semantics": "shell_command",
        "sink_argument_binding_trust": "direct_abi_arg0",
        "sink_snapshot_cstring_complete": True,
        "elapsed_sec": 2.0,
        "process_peak_rss_mib": 100.0,
        "engine_steps_total": 20,
        "vector_decisions": [],
    }
    value.update(updates)
    return value


def write_campaign(path: Path, rows: list[dict], evaluator: str = "eval") -> None:
    path.mkdir(parents=True)
    (path / "target.results.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )
    (path / "campaign_configuration.json").write_text(
        json.dumps(
            {
                "evaluator_sha256": evaluator,
                "targets": [
                    {
                        "name": "target",
                        "binary_sha256": "binary",
                        "mango_sha256": "mango",
                    }
                ],
                "arguments": {},
            }
        ),
        encoding="utf-8",
    )


class RecordLevelAblationExportTest(unittest.TestCase):
    def test_exports_stable_changed_and_missing_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline"
            matrix = root / "matrix"
            variant = matrix / "campaigns" / "projection_off"
            out = root / "out"
            write_campaign(baseline, [record(0), record(1), record(2)])
            write_campaign(
                variant,
                [
                    record(0, elapsed_sec=3.5),
                    record(1, verdict="RESIDUAL", status="residual"),
                    record(3),
                ],
            )

            summary = export_transitions(baseline, matrix, out)

            self.assertTrue(summary["valid"])
            self.assertEqual(4, summary["transition_rows"])
            config = summary["configurations"][0]
            self.assertEqual(2, config["common_records"])
            self.assertEqual(1, config["baseline_only"])
            self.assertEqual(1, config["variant_only"])
            with (out / "record_level_ablation_transitions.csv").open(
                newline="", encoding="utf-8"
            ) as stream:
                rows = list(csv.DictReader(stream))
            by_idx = {int(row["closure_idx"]): row for row in rows}
            self.assertEqual("MATRIX_UNSAT->RESIDUAL", by_idx[1]["verdict_transition"])
            self.assertEqual("baseline_only", by_idx[2]["record_presence"])
            self.assertEqual("variant_only", by_idx[3]["record_presence"])
            self.assertEqual("1.5", by_idx[0]["delta_elapsed_sec"])
            self.assertRegex(summary["transition_csv"]["sha256"], r"^[0-9a-f]{64}$")

    def test_fingerprint_drift_fails_validity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline"
            matrix = root / "matrix"
            variant = matrix / "campaigns" / "bad"
            write_campaign(baseline, [record(0)], evaluator="left")
            write_campaign(variant, [record(0)], evaluator="right")

            summary = export_transitions(baseline, matrix, root / "out")

            self.assertFalse(summary["valid"])
            self.assertIn("bad:evaluator_sha256_mismatch", summary["issues"])

    def test_refuses_nonempty_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline"
            matrix = root / "matrix"
            write_campaign(baseline, [record(0)])
            write_campaign(matrix / "campaigns" / "full", [record(0)])
            out = root / "out"
            out.mkdir()
            (out / "existing").write_text("keep", encoding="utf-8")
            with self.assertRaises(ValueError):
                export_transitions(baseline, matrix, out)


if __name__ == "__main__":
    unittest.main()
