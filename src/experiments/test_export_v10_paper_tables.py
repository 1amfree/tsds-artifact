import json
import tempfile
import unittest
from pathlib import Path

from export_v10_paper_tables import aggregate_records, display_token, export_tables


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def record(verdict, provenance, **updates):
    base = {
        "closure_idx": 1,
        "evidence_contract_valid": True,
        "verdict": verdict,
        "evidence_provenance": provenance,
        "elapsed_sec": 2.0,
        "sink_reached_observed": True,
        "tainted_offsets": [1, 2],
        "vector_decisions": [],
    }
    if verdict == "VECTOR_SAT":
        base.update({
            "minimal_bypass_vector": {"vector": ";", "witness": ":;:;#"},
            "vector_decisions": [{"vector": ";", "decision": "VECTOR_SAT"}],
        })
    elif verdict == "MATRIX_UNSAT":
        base["vector_decisions"] = [{"vector": ";", "decision": "MATRIX_UNSAT"}]
    base.update(updates)
    return base


class PaperTableExportTest(unittest.TestCase):
    def test_control_tokens_are_rendered_without_csv_control_characters(self):
        self.assertEqual(display_token("\n"), "\\n")
        self.assertEqual(display_token("\t"), "\\t")
        self.assertEqual(display_token("$()"), "$()")

    def test_export_uses_verdicts_and_validates_companion_audits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            rows = [
                record("VECTOR_SAT", "DIRECT_SINK_BYTE"),
                record("MATRIX_UNSAT", "DIRECT_SINK_BYTE", closure_idx=2),
                record("STATIC_WARNING_REDUCTION", "STATIC_WARNING_REDUCTION", closure_idx=3, sink_reached_observed=False, tainted_offsets=[]),
                record("RESIDUAL", "RESIDUAL", closure_idx=4, sink_reached_observed=False, tainted_offsets=[]),
            ]
            (campaign / "fixture.results.jsonl").parent.mkdir(parents=True)
            (campaign / "fixture.results.jsonl").write_text(
                "".join(json.dumps(item) + "\n" for item in rows), encoding="utf-8"
            )
            contract = root / "contract.json"
            syntax = root / "syntax.json"
            repeatability = root / "repeatability.json"
            write_json(contract, {"records": 4, "records_with_contract_issues": 0, "contract_issue_counts": {}})
            write_json(syntax, {"record_outcomes": {"records_all_witnesses_invalid": 0, "records_any_syntax_valid": 1}})
            write_json(
                repeatability,
                {
                    "schema": "tsds-repeatability-audit-v4",
                    "baseline_records": 4,
                    "replay_records": 4,
                    "baseline_only": 0,
                    "replay_only": 0,
                    "sink_semantic_core": {
                        "baseline_records": 2,
                        "baseline_reproduced": True,
                    },
                    "conservative_consensus": {
                        "records": 4,
                        "downgraded_to_residual": 1,
                        "verdicts": {
                            "VECTOR_SAT": 1,
                            "MATRIX_UNSAT": 1,
                            "RESIDUAL": 2,
                        },
                    },
                },
            )
            out = root / "tables"
            summary = export_tables(
                campaign, out, contract, syntax, repeatability
            )
            self.assertEqual(summary["verdicts"]["VECTOR_SAT"], 1)
            self.assertEqual(summary["verdicts"]["MATRIX_UNSAT"], 1)
            self.assertTrue((out / "paper_tables.tex").is_file())
            self.assertTrue((out / "paper_workload.csv").is_file())
            self.assertTrue((out / "paper_repeatability_consensus.csv").is_file())
            self.assertEqual(
                1,
                summary["repeatability_consensus"]["downgraded_to_residual"],
            )
            self.assertEqual("tsds-paper-table-export-v2", summary["schema"])
            self.assertIn("VECTOR_SAT", (out / "paper_overall.csv").read_text(encoding="utf-8"))

    def test_contract_invalid_record_blocks_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            invalid = record("VECTOR_SAT", "DIRECT_SINK_BYTE", evidence_contract_valid=False)
            (campaign / "fixture.results.jsonl").parent.mkdir(parents=True)
            (campaign / "fixture.results.jsonl").write_text(json.dumps(invalid) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                export_tables(campaign, root / "tables")

    def test_malformed_or_nonobject_record_blocks_export_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            campaign.mkdir()
            (campaign / "fixture.results.jsonl").write_text(
                "[1, 2]\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "invalid record"):
                export_tables(campaign, root / "tables")

    def test_duplicate_record_key_blocks_export_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            campaign.mkdir()
            (campaign / "fixture.results.jsonl").write_text(
                '{"verdict":"RESIDUAL","verdict":"VECTOR_SAT"}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                export_tables(campaign, root / "tables")

    def test_runtime_table_separates_analysis_timer_from_campaign_wall(self):
        rows = [
            record("VECTOR_SAT", "DIRECT_SINK_BYTE", elapsed_sec=2.0),
            record("MATRIX_UNSAT", "DIRECT_SINK_BYTE", closure_idx=2, elapsed_sec=3.0),
        ]
        for row in rows:
            row["_artifact_target"] = "fixture"
        data = aggregate_records(
            rows,
            {
                "fixture": {
                    "evaluated": 2,
                    "wall_time_sec": 20.0,
                    "peak_rss_mb": 100.0,
                },
                "TOTAL": {
                    "evaluated": 2,
                    "wall_time_sec": 20.0,
                    "peak_rss_mb": 100.0,
                },
            },
        )
        runtime = data["runtime_rows"][0]
        self.assertEqual(runtime["total_sec"], 5.0)
        self.assertEqual(runtime["campaign_wall_sec"], 20.0)
        self.assertEqual(runtime["amortized_wall_sec_per_record"], 10.0)
        self.assertEqual(runtime["startup_orchestration_sec"], 15.0)
        self.assertEqual(runtime["record_timer_coverage_pct"], 25.0)

    def test_runtime_accounting_rejects_impossible_wall_time(self):
        row = record("VECTOR_SAT", "DIRECT_SINK_BYTE", elapsed_sec=5.0)
        row["_artifact_target"] = "fixture"
        with self.assertRaises(ValueError):
            aggregate_records(
                [row],
                {
                    "fixture": {"evaluated": 1, "wall_time_sec": 1.0},
                    "TOTAL": {"evaluated": 1, "wall_time_sec": 1.0},
                },
            )


if __name__ == "__main__":
    unittest.main()
