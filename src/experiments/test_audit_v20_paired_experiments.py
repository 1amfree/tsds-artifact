from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.audit_v20_paired_experiments import (
    ANALYSIS_SCHEMA,
    BOUNDED_CONFIGURATIONS,
    CONFIRMATORY_CONFIGURATIONS,
    PAIRED_METRICS,
    TRANSITION_SCHEMA,
    audit_dataset,
    build_audit,
    clustered_effect,
    write_outputs,
)


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def row(configuration: str, target: str, closure: int, presence: str) -> dict[str, str]:
    both = presence == "both"
    return {
        "configuration": configuration,
        "target": target,
        "closure_idx": str(closure),
        "source_addr": hex(0x1000 + closure),
        "sink_addr": "0x2000",
        "closure_sink_signature": json.dumps([closure, "0x2000"]),
        "record_presence": presence,
        "delta_elapsed_sec": "1.0" if both else "",
        "delta_process_peak_rss_mib": "1.0" if both else "",
        "delta_engine_steps_total": "1.0" if both else "",
    }


def documents(
    configurations: tuple[str, ...],
    rows: list[dict[str, str]],
    baseline_records: int,
    replicates: int,
) -> tuple[dict, dict]:
    analysis_rows = []
    transition_rows = []
    for name in configurations:
        values = [item for item in rows if item["configuration"] == name]
        common = sum(item["record_presence"] == "both" for item in values)
        baseline_only = sum(item["record_presence"] == "baseline_only" for item in values)
        variant_only = sum(item["record_presence"] == "variant_only" for item in values)
        analysis_rows.append(
            {
                "configuration": name,
                "records": common + variant_only,
                "common_records": common,
                "baseline_only": baseline_only,
                "variant_only": variant_only,
                "fingerprint_issues": [],
                "paired_metrics": {
                    metric: {
                        "pairs": common,
                        "mean_variant_minus_baseline": 1.0,
                        "bootstrap": {
                            "requested_replicates": replicates,
                            "valid_replicates": replicates,
                        },
                    }
                    for metric in PAIRED_METRICS
                },
            }
        )
        transition_rows.append(
            {
                "configuration": name,
                "records_union": len(values),
                "common_records": common,
                "baseline_only": baseline_only,
                "variant_only": variant_only,
                "fingerprint_issues": [],
            }
        )
    analysis = {
        "schema": ANALYSIS_SCHEMA,
        "valid": True,
        "issues": [],
        "baseline_records": baseline_records,
        "configurations": analysis_rows,
    }
    transitions = {
        "schema": TRANSITION_SCHEMA,
        "valid": True,
        "issues": [],
        "transition_rows": len(rows),
        "configurations": transition_rows,
    }
    return analysis, transitions


def dataset_rows(
    configurations: tuple[str, ...], *, full: bool
) -> list[dict[str, str]]:
    rows = []
    for configuration in configurations:
        for target_index in range(8):
            target = f"target_{target_index}"
            rows.append(row(configuration, target, target_index * 2, "both"))
            rows.append(
                row(
                    configuration,
                    target,
                    target_index * 2 + 1,
                    "both" if full else "baseline_only",
                )
            )
    return rows


def write_dataset(
    release: Path,
    tag: str,
    label: str,
    configurations: tuple[str, ...],
    *,
    full: bool,
    replicates: int,
) -> None:
    if label == "matrix":
        analysis_dir = release / f"tsds_v20_matrix_analysis_{tag}"
        transition_dir = release / f"tsds_v20_matrix_transitions_{tag}"
    else:
        analysis_dir = release / f"tsds_v20_confirmatory_analysis_{tag}"
        transition_dir = release / f"tsds_v20_confirmatory_transitions_{tag}"
    rows = dataset_rows(configurations, full=full)
    analysis, transitions = documents(configurations, rows, 16, replicates)
    write_json(analysis_dir / "v19_ablation_analysis.json", analysis)
    transition_dir.mkdir(parents=True)
    csv_path = transition_dir / "record_level_ablation_transitions.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    transitions["transition_csv"] = {
        "path": csv_path.name,
        "size": csv_path.stat().st_size,
        "sha256": digest(csv_path),
    }
    write_json(transition_dir / "record_level_ablation_summary.json", transitions)


class V20PairedExperimentAuditTest(unittest.TestCase):
    def test_cluster_bootstrap_is_deterministic_and_target_balanced(self) -> None:
        rows = [
            {"target": "a", "delta": "1"},
            {"target": "a", "delta": "1"},
            {"target": "b", "delta": "3"},
        ]
        first = clustered_effect(rows, "delta", replicates=200, seed=7)
        second = clustered_effect(rows, "delta", replicates=200, seed=7)
        self.assertEqual(first, second)
        self.assertEqual(1.6667, first["closure_weighted_mean_delta"])
        self.assertEqual(2.0, first["target_balanced_mean_delta"])
        self.assertEqual(2, first["target_direction"]["positive"])

    def test_identical_bounded_cohorts_are_valid(self) -> None:
        configurations = ("a", "b")
        rows = dataset_rows(configurations, full=False)
        analysis, transitions = documents(configurations, rows, 16, 20)
        result = audit_dataset(
            "bounded",
            analysis,
            transitions,
            rows,
            expected_configurations=configurations,
            accepted_records=16,
            full_corpus=False,
            bootstrap_replicates=20,
        )
        self.assertTrue(result["valid"], result["issues"])

    def test_equal_sized_but_different_cohort_is_rejected(self) -> None:
        configurations = ("a", "b")
        rows = dataset_rows(configurations, full=False)
        changed = [item for item in rows if item["configuration"] == "b"]
        changed[0]["record_presence"] = "baseline_only"
        changed[0]["delta_elapsed_sec"] = ""
        changed[0]["delta_process_peak_rss_mib"] = ""
        changed[0]["delta_engine_steps_total"] = ""
        changed[1]["record_presence"] = "both"
        changed[1]["delta_elapsed_sec"] = "1"
        changed[1]["delta_process_peak_rss_mib"] = "1"
        changed[1]["delta_engine_steps_total"] = "1"
        analysis, transitions = documents(configurations, rows, 16, 20)
        result = audit_dataset(
            "bounded",
            analysis,
            transitions,
            rows,
            expected_configurations=configurations,
            accepted_records=16,
            full_corpus=False,
            bootstrap_replicates=20,
        )
        self.assertFalse(result["valid"])
        self.assertIn("b:paired_cohort_mismatch", result["issues"])

    def test_full_release_integration_and_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release"
            tag = "r5"
            write_json(
                release / "manuscript_binding" / "manuscript_binding.json",
                {"ready": True, "records": 16},
            )
            write_dataset(
                release,
                tag,
                "matrix",
                BOUNDED_CONFIGURATIONS,
                full=False,
                replicates=10,
            )
            write_dataset(
                release,
                tag,
                "confirmatory",
                CONFIRMATORY_CONFIGURATIONS,
                full=True,
                replicates=10,
            )
            document = build_audit(release, tag, bootstrap_replicates=10)
            self.assertTrue(document["valid"], document["issues"])
            self.assertEqual(2, len(document["datasets"]))
            out = Path(directory) / "out"
            write_outputs(out, document)
            self.assertTrue((out / "paired_experiment_audit.json").is_file())
            self.assertTrue((out / "paired_cohort_audit.csv").is_file())
            self.assertTrue((out / "firmware_clustered_effects.csv").is_file())


if __name__ == "__main__":
    unittest.main()
