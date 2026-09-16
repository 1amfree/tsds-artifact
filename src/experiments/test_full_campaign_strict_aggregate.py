import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from run_full_firmware_campaign import (
    TARGETS,
    artifact_fingerprint,
    build_command,
    refinement_bundle_for_target,
    parse_gnu_time_file,
    prepare_fresh_output_dir,
    row_from_summary,
    select_targets,
    summarize_campaign,
)


class FullCampaignStrictAggregateTest(unittest.TestCase):
    def test_build_command_forwards_p0_p1_p2_ablation_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = SimpleNamespace(
                python=Path("python"),
                evaluator=Path("evaluator.py"),
                root=root,
                engine_timeout=45,
                max_steps=500,
                closure_timeout=90,
                subprocess_timeout=150,
                subprocess_memory_limit_mib=8192,
                execution_backend="forkserver",
                scheduler_base_active_cap=61,
                scheduler_min_active_cap=21,
                scheduler_max_active_cap=121,
                scheduler_constraint_soft_limit=801,
                scheduler_escape_quota=5,
                constraint_projection_cache_size=4096,
                online_refinement_rounds=0,
                online_refinement_candidates=4,
                no_evidence_cache=True,
                no_evidence_aware_scheduler=True,
                no_sink_corridor=True,
                no_source_projected_constraints=True,
                no_byte_provenance=True,
                no_sink_semantic_plugins=True,
                summary_database=root / "summaries.json",
                refinement_bundle=root / "refinement.json",
                refinement_bundle_dir=None,
                generate_refinement_bundles=True,
                export_solver_queries=False,
                max_closures=3,
            )
            command = build_command(args, root / "out", TARGETS[0])
            joined = " ".join(str(part) for part in command)
            for expected in (
                "--execution-backend forkserver",
                "--multi-state-audit",
                "--scheduler-base-active-cap 61",
                "--scheduler-min-active-cap 21",
                "--scheduler-max-active-cap 121",
                "--scheduler-constraint-soft-limit 801",
                "--scheduler-escape-quota 5",
                "--constraint-projection-cache-size 4096",
                "--online-refinement-rounds 0",
                "--online-refinement-candidates 4",
                "--no-evidence-aware-scheduler",
                "--no-sink-corridor",
                "--no-source-projected-constraints",
                "--no-byte-provenance",
                "--no-sink-semantic-plugins",
                "--summary-database",
                "--refinement-bundle",
                "--refinement-bundle-output",
                "--max-closures 3",
            ):
                with self.subTest(expected=expected):
                    self.assertIn(expected, joined)

    def test_build_command_namespaces_solver_query_exports_per_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = SimpleNamespace(
                python=Path("python"),
                evaluator=Path("evaluator.py"),
                root=root,
                engine_timeout=45,
                max_steps=500,
                closure_timeout=90,
                subprocess_timeout=150,
                subprocess_memory_limit_mib=0,
                execution_backend="forkserver",
                scheduler_base_active_cap=60,
                scheduler_min_active_cap=20,
                scheduler_max_active_cap=120,
                scheduler_constraint_soft_limit=800,
                scheduler_escape_quota=4,
                constraint_projection_cache_size=2048,
                online_refinement_rounds=1,
                online_refinement_candidates=3,
                no_evidence_cache=True,
                no_evidence_aware_scheduler=False,
                no_sink_corridor=False,
                no_source_projected_constraints=False,
                no_byte_provenance=False,
                no_sink_semantic_plugins=False,
                summary_database=None,
                refinement_bundle=None,
                refinement_bundle_dir=None,
                generate_refinement_bundles=False,
                export_solver_queries=True,
                max_closures=None,
            )
            command = build_command(args, root / "out", TARGETS[0])
            self.assertIn("--export-solver-queries", command)
            export_index = command.index("--export-solver-queries")
            self.assertEqual(
                str(root / "out" / "asus_rt_be57.solver_queries"),
                command[export_index + 1],
            )

    def test_dry_run_records_configuration_without_firmware_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "campaign"
            evaluator = root / "evaluator.py"
            evaluator.write_text("# fixture\n", encoding="utf-8")
            script = Path(__file__).with_name("run_full_firmware_campaign.py")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--root",
                    str(root),
                    "--python",
                    sys.executable,
                    "--evaluator",
                    str(evaluator),
                    "--out-dir",
                    str(out),
                    "--target",
                    "dir878",
                    "--dry-run",
                    "--online-refinement-rounds",
                    "0",
                    "--no-byte-provenance",
                    "--no-sink-semantic-plugins",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            configuration = json.loads(
                (out / "campaign_configuration.json").read_text(encoding="utf-8")
            )
            self.assertEqual("forkserver", configuration["arguments"]["execution_backend"])
            self.assertEqual(0, configuration["arguments"]["online_refinement_rounds"])
            self.assertTrue(configuration["arguments"]["no_byte_provenance"])
            self.assertTrue(configuration["arguments"]["no_sink_semantic_plugins"])
            self.assertTrue(configuration["evaluator_exists"])
            self.assertEqual(64, len(configuration["evaluator_sha256"]))
            self.assertFalse(configuration["aggregation_module_exists"])
            self.assertIsNone(configuration["aggregation_module_sha256"])
            self.assertFalse(configuration["matrix_spec_module_exists"])
            self.assertIsNone(configuration["matrix_spec_module_sha256"])
            self.assertFalse(configuration["targets"][0]["binary_exists"])
            self.assertIsNone(configuration["targets"][0]["binary_sha256"])
            self.assertFalse(configuration["targets"][0]["mango_exists"])
            self.assertIsNone(configuration["targets"][0]["mango_sha256"])
            self.assertIn("--execution-backend forkserver", completed.stdout)

    def test_artifact_fingerprint_fails_closed_outside_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.bin"
            with self.assertRaises(FileNotFoundError):
                artifact_fingerprint(missing)
            self.assertEqual(
                {"path": str(missing), "exists": False, "sha256": None},
                artifact_fingerprint(missing, allow_missing=True),
            )

    def test_target_specific_refinement_bundle_is_forwarded(self):
        args = SimpleNamespace(
            refinement_bundle=None,
            refinement_bundle_dir=Path("bundles"),
        )
        self.assertEqual(
            Path("bundles/asus_rt_be57.refinement.json"),
            refinement_bundle_for_target(args, TARGETS[0]),
        )

    def test_target_subset_preserves_canonical_order_and_rejects_unknowns(self):
        selected, unknown = select_targets(["xr300", "dir878", "not-a-target"])
        self.assertEqual([row["name"] for row in selected], ["dir878", "xr300"])
        self.assertEqual(unknown, ["not-a-target"])

    def test_gnu_time_resource_metrics_are_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "resource.txt"
            path.write_text(
                "\tUser time (seconds): 12.50\n"
                "\tSystem time (seconds): 1.25\n"
                "\tPercent of CPU this job got: 87%\n"
                "\tMaximum resident set size (kbytes): 262144\n"
                "\tMajor (requiring I/O) page faults: 3\n"
                "\tMinor (reclaiming a frame) page faults: 900\n",
                encoding="utf-8",
            )
            metrics = parse_gnu_time_file(path)
            self.assertEqual(metrics["peak_rss_mb"], 256.0)
            self.assertEqual(metrics["cpu_percent"], 87.0)
            self.assertEqual(metrics["major_page_faults"], 3)

    def test_row_prefers_contract_verdicts_over_legacy_status_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            target = {"name": "fixture", "label": "Fixture"}
            summary = {
                "total_closures": 6,
                "unique_pairs_analyzed": 6,
                "results": {
                    "vulnerable": 2,
                    "filtered": 1,
                    "no_taint_sink": 1,
                    "unreachable": 2,
                },
                "evidence_contract_ledger": {
                    "contract_valid": 6,
                    "contract_downgraded": 0,
                    "verdicts": {
                        "VECTOR_SAT": 2,
                        "MATRIX_UNSAT": 1,
                        "NO_MODELED_SOURCE": 1,
                        "RESIDUAL": 2,
                    },
                },
            }
            (out / "fixture.summary.json").write_text(json.dumps(summary), encoding="utf-8")
            row = row_from_summary(out, target, 0, 1.0)
            self.assertEqual(row["candidate_closures"], 6)
            self.assertEqual(row["selected_closures"], 6)
            self.assertEqual(row["vector_sat"], 2)
            self.assertEqual(row["matrix_unsat"], 1)
            self.assertEqual(row["no_modeled_source"], 1)
            self.assertEqual(row["contract_residual"], 2)
            self.assertEqual(row["vector_sat_rate_pct"], 33.33)

    def test_row_distinguishes_candidate_inputs_from_selected_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            target = {"name": "fixture", "label": "Fixture"}
            summary = {
                "total_closures": 10,
                "unique_pairs_analyzed": 4,
                "results": {},
                "evidence_contract_ledger": {
                    "contract_valid": 4,
                    "contract_downgraded": 0,
                    "verdicts": {"RESIDUAL": 4},
                },
            }
            (out / "fixture.summary.json").write_text(
                json.dumps(summary), encoding="utf-8"
            )
            row = row_from_summary(out, target, 0, 1.0)
            self.assertEqual(row["closures"], 10)
            self.assertEqual(row["candidate_closures"], 10)
            self.assertEqual(row["selected_closures"], 4)
            self.assertEqual(row["evaluated"], 4)
            self.assertEqual(row["selection_rate_pct"], 40.0)

    def test_campaign_artifacts_expose_strict_and_legacy_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            aggregate = summarize_campaign(
                out,
                [
                    {
                        "target": "fixture",
                        "label": "Fixture",
                        "evaluated": 4,
                        "closures": 4,
                        "candidate_closures": 10,
                        "selected_closures": 4,
                        "vector_sat": 1,
                        "matrix_unsat": 1,
                        "no_modeled_source": 1,
                        "contract_residual": 1,
                        "vulnerable": 1,
                        "filtered": 1,
                        "no_taint_sink": 1,
                        "unreachable": 1,
                        "contract_valid": 4,
                        "contract_downgraded": 0,
                    }
                ],
            )
            total = aggregate["total"]
            self.assertEqual(total["candidate_closures"], 10)
            self.assertEqual(total["selected_closures"], 4)
            self.assertEqual(total["selection_rate_pct"], 40.0)
            self.assertEqual(total["vector_sat"], 1)
            self.assertEqual(total["contract_residual"], 1)
            self.assertEqual(total["vulnerable"], 1)
            markdown = (out / "full_campaign_aggregate.md").read_text(encoding="utf-8")
            self.assertIn("evidence_contract_ledger.verdicts", markdown)
            self.assertIn("Candidate closures", markdown)
            self.assertIn("Operational stop breakdown", markdown)

    def test_explicit_zero_contract_count_never_falls_back_to_legacy_positive(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            target = {"name": "fixture", "label": "Fixture"}
            summary = {
                "total_closures": 1,
                "unique_pairs_analyzed": 1,
                "results": {"vulnerable": 1},
                "evidence_contract_ledger": {
                    "contract_valid": 0,
                    "contract_downgraded": 1,
                    "verdicts": {"VECTOR_SAT": 0, "RESIDUAL": 1},
                },
            }
            (out / "fixture.summary.json").write_text(json.dumps(summary), encoding="utf-8")
            row = row_from_summary(out, target, 0, 1.0)
            self.assertEqual(row["vector_sat"], 0)
            self.assertEqual(row["contract_residual"], 1)

    def test_campaign_directory_is_immutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "campaign"
            prepare_fresh_output_dir(out)
            (out / "record.jsonl").write_text("{}\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                prepare_fresh_output_dir(out)


if __name__ == "__main__":
    unittest.main()
