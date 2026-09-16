import json
import tempfile
import unittest
from pathlib import Path

from experiments.audit_repeatability import (
    REPEATABILITY_SCHEMA,
    command_template_projection,
    compare_campaigns,
    load_campaign_records,
    record_identity,
    repeatability_gate_issues,
    semantic_signature,
    write_outputs,
)


def write_records(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def record(**updates):
    base = {
        "closure_idx": 7,
        "source_addr": "0x1000",
        "sink_addr": "0x2000",
        "closure_sink_signature": ["0x1000", "0x2000"],
        "status": "vulnerable",
        "verdict": "VECTOR_SAT",
        "evidence_provenance": "DIRECT_SINK_BYTE",
        "admissible_claim": "direct_sink_byte_vector_sat",
        "evidence_contract_valid": True,
        "elapsed_sec": 1.0,
        "vector_decisions": [
            {
                "vector_id": "semicolon",
                "decision": "SAT",
                "effect_class": "execution_control",
                "quote_context": "unquoted",
                "witness_kind": "grammar_complete",
                "grammar_complete": True,
            }
        ],
    }
    base.update(updates)
    return base


class RepeatabilityAuditTest(unittest.TestCase):
    def test_timing_does_not_create_semantic_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left, right = root / "left", root / "right"
            write_records(left / "target.results.jsonl", [record(elapsed_sec=1.2)])
            write_records(right / "target.results.jsonl", [record(elapsed_sec=9.8)])
            rows, summary = compare_campaigns(left, right)
            self.assertTrue(summary["repeatable"])
            self.assertEqual(summary["stable_records"], 1)
            self.assertEqual(rows[0]["outcome"], "stable")

    def test_vector_profile_change_is_semantic_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left, right = root / "left", root / "right"
            write_records(left / "target.results.jsonl", [record()])
            changed = record()
            changed["vector_decisions"][0]["decision"] = "UNSAT"
            write_records(right / "target.results.jsonl", [changed])
            rows, summary = compare_campaigns(left, right)
            self.assertFalse(summary["repeatable"])
            self.assertEqual(summary["semantic_drift"], 1)
            self.assertIn("vector_profile", rows[0]["differing_fields"])

    def test_witness_change_is_semantic_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left, right = root / "left", root / "right"
            write_records(left / "target.results.jsonl", [record()])
            changed = record()
            changed["vector_decisions"][0]["witness"] = ":|:;#"
            write_records(right / "target.results.jsonl", [changed])
            rows, summary = compare_campaigns(left, right)
            self.assertFalse(summary["repeatable"])
            self.assertIn("vector_profile", rows[0]["differing_fields"])

    def test_model_values_at_controlled_offsets_do_not_create_drift(self):
        evidence = {
            "sink_reached_observed": True,
            "sink_semantics": "shell_command",
            "sink_argument_binding_source": "abi_arg0:r0",
            "sink_argument_binding_trust": "direct_abi_arg0",
            "sink_function_name_source": "closure_sink_at_exact_callsite",
            "sink_snapshot_cstring_complete": True,
            "sink_snapshot_capture_length": 12,
            "sink_snapshot_terminator_offset": 11,
            "controlled_offsets": [4, 5, 6],
        }
        baseline = record(**evidence, sink_preview="cmd AAA end")
        replay = record(**evidence, sink_preview="cmd ;|& end")
        self.assertEqual(
            command_template_projection(baseline),
            command_template_projection(replay),
        )
        self.assertEqual(semantic_signature(baseline), semantic_signature(replay))

    def test_fixed_command_literal_change_is_semantic_drift(self):
        evidence = {
            "sink_reached_observed": True,
            "sink_semantics": "shell_command",
            "sink_argument_binding_source": "abi_arg0:r0",
            "sink_argument_binding_trust": "direct_abi_arg0",
            "sink_function_name_source": "closure_sink_at_exact_callsite",
            "sink_snapshot_cstring_complete": True,
            "sink_snapshot_capture_length": 12,
            "sink_snapshot_terminator_offset": 11,
            "controlled_offsets": [4, 5, 6],
        }
        baseline = record(**evidence, sink_preview="cmd AAA end")
        changed = record(**evidence, sink_preview="run AAA end")
        self.assertNotEqual(semantic_signature(baseline), semantic_signature(changed))

    def test_nms_model_preview_is_diagnostic_not_signature_evidence(self):
        evidence = {
            "status": "no_taint_sink",
            "verdict": "NO_MODELED_SOURCE",
            "admissible_claim": "dynamic_warning_reduction",
            "sink_reached_observed": True,
            "sink_semantics": "shell_command",
            "sink_argument_binding_source": "abi_arg0:r0",
            "sink_argument_binding_trust": "direct_abi_arg0",
            "sink_function_name_source": "closure_sink_at_exact_callsite",
            "sink_snapshot_cstring_complete": True,
        }
        baseline = record(**evidence, sink_preview="nvram set key=20200000")
        replay = record(**evidence, sink_preview="nvram set key=20220000")
        self.assertIsNone(command_template_projection(baseline))
        self.assertEqual(semantic_signature(baseline), semantic_signature(replay))

    def test_sink_binding_and_offsets_are_part_of_evidence_signature(self):
        evidence = {
            "sink_reached_observed": True,
            "sink_semantics": "shell_command",
            "sink_argument_binding_source": "abi_arg0:r0",
            "sink_argument_binding_trust": "direct_abi_arg0",
            "sink_function_name_source": "closure_sink_at_exact_callsite",
            "sink_snapshot_cstring_complete": True,
        }
        baseline = record(**evidence, controlled_offsets=[2, 1])
        same = record(**evidence, controlled_offsets=[1, 2])
        self.assertEqual(semantic_signature(baseline), semantic_signature(same))

        changed_binding = record(
            **evidence,
            controlled_offsets=[1, 2],
        )
        changed_binding["sink_argument_binding_trust"] = "heuristic_register"
        self.assertNotEqual(
            semantic_signature(baseline), semantic_signature(changed_binding)
        )

        changed_offsets = record(**evidence, controlled_offsets=[1, 3])
        self.assertNotEqual(
            semantic_signature(baseline), semantic_signature(changed_offsets)
        )

    def test_identity_is_stable_and_distinguishes_sink(self):
        one = record()
        two = record(sink_addr="0x3000")
        self.assertNotEqual(record_identity("target", one), record_identity("target", two))
        self.assertEqual(semantic_signature(one), semantic_signature(record(elapsed_sec=99.0)))

    def test_larger_replay_can_reproduce_baseline_as_subset(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left, right = root / "left", root / "right"
            write_records(left / "target.results.jsonl", [record()])
            write_records(
                right / "target.results.jsonl",
                [record(), record(closure_idx=8, source_addr="0x1100")],
            )
            _, summary = compare_campaigns(left, right)
            self.assertFalse(summary["repeatable"])
            self.assertTrue(summary["baseline_reproduced"])
            self.assertEqual(summary["replay_only"], 1)

    def test_sink_semantic_stability_is_separate_from_residual_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left, right = root / "left", root / "right"
            stable_positive = record()
            baseline_residual = record(
                closure_idx=8,
                source_addr="0x1100",
                status="timeout",
                verdict="RESIDUAL",
                evidence_provenance="RESIDUAL",
                admissible_claim="explicit_residual_obligation",
                vector_decisions=[],
            )
            changed_residual = dict(baseline_residual, status="unreachable")
            write_records(
                left / "target.results.jsonl",
                [stable_positive, baseline_residual],
            )
            write_records(
                right / "target.results.jsonl",
                [stable_positive, changed_residual],
            )
            _, summary = compare_campaigns(left, right)
            self.assertEqual(summary["semantic_drift"], 1)
            self.assertEqual(100.0, summary["sink_semantic_core"]["agreement_pct"])
            self.assertTrue(
                summary["sink_semantic_core"]["baseline_reproduced"]
            )
            self.assertEqual(
                1,
                summary["per_baseline_verdict"]["RESIDUAL"]["semantic_drift"],
            )
            self.assertEqual(
                {"RESIDUAL": 1, "VECTOR_SAT": 1},
                summary["conservative_consensus"]["verdicts"],
            )
            self.assertEqual(
                1, summary["conservative_consensus"]["downgraded_to_residual"]
            )

    def test_output_pack_contains_paper_ready_consensus_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left, right, out = root / "left", root / "right", root / "out"
            write_records(left / "target.results.jsonl", [record()])
            write_records(right / "target.results.jsonl", [record()])
            rows, summary = compare_campaigns(left, right)
            self.assertEqual(REPEATABILITY_SCHEMA, summary["schema"])
            write_outputs(out, rows, summary)
            self.assertTrue((out / "repeatability_by_verdict.csv").is_file())
            self.assertTrue((out / "repeatability_consensus.csv").is_file())
            table = (out / "repeatability_tables.tex").read_text(encoding="utf-8")
            self.assertIn("Sink-semantic core", table)
            self.assertIn("VECTOR\\_SAT", table)

    def test_nonempty_sink_semantic_gate_rejects_vacuous_agreement(self):
        # 0/0 一致率不能作为重复性证据，必须由显式门禁拒绝。
        summary = {
            "repeatable": True,
            "baseline_reproduced": True,
            "sink_semantic_core": {
                "baseline_records": 0,
                "baseline_reproduced": True,
            },
        }
        self.assertEqual(
            ["sink_semantic_baseline_empty"],
            repeatability_gate_issues(
                summary,
                fail_on_sink_semantic_drift=True,
                require_sink_semantic_records=True,
            ),
        )

    def test_nonempty_sink_semantic_gate_accepts_stable_evidence(self):
        summary = {
            "repeatable": True,
            "baseline_reproduced": True,
            "sink_semantic_core": {
                "baseline_records": 3,
                "baseline_reproduced": True,
            },
        }
        self.assertEqual(
            [],
            repeatability_gate_issues(
                summary,
                fail_on_sink_semantic_drift=True,
                require_sink_semantic_records=True,
            ),
        )

    def test_same_record_set_gate_rejects_missing_or_extra_closures(self):
        summary = {
            "repeatable": False,
            "baseline_reproduced": True,
            "baseline_only": 0,
            "replay_only": 1,
            "sink_semantic_core": {
                "baseline_records": 1,
                "baseline_reproduced": True,
            },
        }
        self.assertEqual(
            ["repeatability_record_set_mismatch"],
            repeatability_gate_issues(summary, require_same_record_set=True),
        )

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_records(root / "target.results.jsonl", [record()])
            path = root / "target.results.jsonl"
            path.write_text(
                '{"closure_idx":7,"closure_idx":8,"source_addr":"0x1000",'
                '"sink_addr":"0x2000"}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                load_campaign_records(root)


if __name__ == "__main__":
    unittest.main()
