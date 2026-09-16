import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from compare_external_baseline import (
    compare,
    load_baseline,
    load_tsds_records,
    manifest_input_hashes,
    validate_baseline_document,
    verify_runtime_manifest,
)


class ExternalBaselineComparisonTest(unittest.TestCase):
    def test_missing_reproducibility_metadata_blocks_comparison_claim(self):
        issues = validate_baseline_document({"records": []})
        self.assertIn("missing_or_invalid_comparison_mode", issues)
        self.assertIn("missing_tool_name", issues)
        self.assertIn("missing_input_hashes", issues)
        self.assertIn("missing_records", issues)

    def test_aligned_ground_truth_metrics_and_significance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            campaign.mkdir()
            tsds_rows = [
                {"closure_idx": 1, "source_addr": "0x100", "sink_addr": "0x200", "verdict": "VECTOR_SAT", "evidence_provenance": "DIRECT_SINK_BYTE", "evidence_contract_valid": True},
                {"closure_idx": 2, "source_addr": "0x101", "sink_addr": "0x201", "verdict": "MATRIX_UNSAT", "evidence_provenance": "DIRECT_SINK_BYTE", "evidence_contract_valid": True},
            ]
            (campaign / "fixture.results.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in tsds_rows), encoding="utf-8"
            )
            baseline_doc = {
                "comparison_mode": "same_candidate_validator",
                "tool": {"name": "Fixture", "version": "1", "commit": "abc", "command": "fixture --run"},
                "budget": {
                    "per_record_timeout_sec": 60,
                    "max_memory_mb": 2048,
                    "host": "test-host",
                    "architecture": "x86_64",
                    "cpu_count": 1,
                    "cache_policy": "cold",
                    "external_runtime_repetitions": 1,
                    "tsds_runtime_repetitions": 1,
                },
                "input_hashes": ["sha256:abc"],
                "ground_truth_protocol": {
                    "independent_of_tools": True,
                    "labels_frozen_before_unblinding": True,
                    "auditor_count": 2,
                    "adjudication_complete": True,
                    "annotation_sha256": "a" * 64,
                    "blinded_sample_sha256": "b" * 64,
                    "protocol_declaration_sha256": "c" * 64,
                },
                "records": [
                    {"target": "fixture", "closure_idx": 1, "source_addr": "0x100", "sink_addr": "0x200", "verdict": "NEGATIVE", "ground_truth": "POSITIVE"},
                    {"target": "fixture", "closure_idx": 2, "source_addr": "0x101", "sink_addr": "0x201", "verdict": "NEGATIVE", "ground_truth": "NEGATIVE"},
                ],
            }
            baseline_path = root / "baseline.json"
            baseline_path.write_text(json.dumps(baseline_doc), encoding="utf-8")
            tsds = load_tsds_records(campaign)
            baseline, _, issues = load_baseline(baseline_path)
            _, summary = compare(tsds, baseline, issues, baseline_doc)
            self.assertTrue(summary["comparison_admissible"])
            self.assertTrue(summary["accuracy_claim_admissible"])
            self.assertFalse(summary["performance_claim_admissible"])
            self.assertFalse(summary["superiority_claim_admissible"])
            self.assertEqual(summary["tsds_metrics"]["f1"], 1.0)
            self.assertEqual(summary["tsds_metrics"]["coverage"], 1.0)
            self.assertIsNotNone(summary["tsds_metrics"]["accuracy_wilson_95"])
            self.assertEqual(summary["external_metrics"]["fn"], 1)
            self.assertEqual(summary["paired_disagreement"]["tsds_only_correct"], 1)
            self.assertTrue(summary["alignment_complete"])
            self.assertIn("accuracy", summary["paired_effect_uncertainty"]["metrics"])

    def test_same_candidate_comparison_requires_full_external_alignment(self):
        tsds = {
            "fixture|0x100|0x200|1": {
                "target": "fixture",
                "closure_idx": 1,
                "source_addr": "0x100",
                "sink_addr": "0x200",
                "verdict": "VECTOR_SAT",
                "contract_valid": True,
            }
        }
        baseline = {
            "fixture|0x999|0x888|9": {
                "target": "fixture",
                "closure_idx": 9,
                "source_addr": "0x999",
                "sink_addr": "0x888",
                "verdict": "POSITIVE",
            }
        }
        _, summary = compare(
            tsds,
            baseline,
            [],
            {"comparison_mode": "same_candidate_validator", "records": list(baseline.values())},
        )
        self.assertFalse(summary["alignment_complete"])
        self.assertFalse(summary["comparison_admissible"])
        self.assertIn("external_candidates_missing_from_tsds", summary["alignment_issues"])

    def test_unresolved_truth_is_excluded_and_invalid_contract_is_not_comparable(self):
        tsds = {
            "fixture|0x100|0x200|1": {
                "target": "fixture",
                "closure_idx": 1,
                "source_addr": "0x100",
                "sink_addr": "0x200",
                "verdict": "VECTOR_SAT",
                "contract_valid": False,
            },
            "fixture|0x101|0x201|2": {
                "target": "fixture",
                "closure_idx": 2,
                "source_addr": "0x101",
                "sink_addr": "0x201",
                "verdict": "MATRIX_UNSAT",
                "contract_valid": True,
            },
        }
        baseline = {
            "fixture|0x100|0x200|1": {
                "target": "fixture",
                "closure_idx": 1,
                "source_addr": "0x100",
                "sink_addr": "0x200",
                "verdict": "POSITIVE",
                "ground_truth": "POSITIVE",
            },
            "fixture|0x101|0x201|2": {
                "target": "fixture",
                "closure_idx": 2,
                "source_addr": "0x101",
                "sink_addr": "0x201",
                "verdict": "NEGATIVE",
                "ground_truth": "UNRESOLVED",
            },
        }
        _, summary = compare(tsds, baseline, [], {})
        self.assertEqual(summary["ground_truth_records"], 1)
        self.assertEqual(summary["paired_ground_truth_records"], 0)
        self.assertEqual(summary["tsds_metrics"]["coverage"], 0.0)
        self.assertEqual(summary["tsds_metrics"]["abstentions"], 1)
        self.assertFalse(summary["accuracy_claim_admissible"])

    def test_superiority_gate_requires_paired_significant_difference(self):
        tsds = {}
        baseline = {}
        records = []
        for index in range(8):
            truth = "POSITIVE" if index % 2 == 0 else "NEGATIVE"
            tsds_verdict = "VECTOR_SAT" if truth == "POSITIVE" else "MATRIX_UNSAT"
            external_verdict = "NEGATIVE" if truth == "POSITIVE" else "POSITIVE"
            key = f"fixture|{hex(0x100 + index)}|{hex(0x200 + index)}|{index}"
            tsds[key] = {
                "target": "fixture",
                "closure_idx": index,
                "source_addr": hex(0x100 + index),
                "sink_addr": hex(0x200 + index),
                "verdict": tsds_verdict,
                "contract_valid": True,
            }
            baseline[key] = {
                "target": "fixture",
                "closure_idx": index,
                "source_addr": hex(0x100 + index),
                "sink_addr": hex(0x200 + index),
                "verdict": external_verdict,
                "ground_truth": truth,
            }
            records.append(dict(baseline[key]))
        document = {
            "comparison_mode": "same_candidate_validator",
            "records": records,
            "budget": {
                "external_runtime_repetitions": 3,
                "tsds_runtime_repetitions": 3,
                "external_runtime_manifest_sha256": "b" * 64,
                "tsds_runtime_manifest_sha256": "c" * 64,
            },
            "ground_truth_protocol": {
                "independent_of_tools": True,
                "labels_frozen_before_unblinding": True,
                "auditor_count": 2,
                "adjudication_complete": True,
                "annotation_sha256": "a" * 64,
                "blinded_sample_sha256": "b" * 64,
                "protocol_declaration_sha256": "c" * 64,
            },
        }
        _, summary = compare(
            tsds,
            baseline,
            [],
            document,
            runtime_manifest_verification={
                "external": {"verified": True},
                "tsds": {"verified": True},
            },
        )
        self.assertTrue(summary["accuracy_claim_admissible"])
        self.assertTrue(summary["performance_claim_admissible"])
        self.assertTrue(summary["superiority_claim_admissible"])
        self.assertLessEqual(
            summary["paired_disagreement"]["exact_mcnemar_pvalue"], 0.05
        )

    def test_manifest_hash_gate_detects_different_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {
                "reproducibility": {
                    "campaign_inputs": [{
                        "target": "fixture",
                        "binary": {"sha256": "aaa"},
                        "mango": {"sha256": "bbb"},
                    }]
                }
            }
            path = root / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            expected = manifest_input_hashes(path, {"fixture"})
            self.assertEqual(expected, {"aaa", "bbb"})
            document = {
                "comparison_mode": "same_candidate_validator",
                "tool": {"name": "Fixture", "version": "1", "commit": "abc", "command": "run"},
                "budget": {
                    "per_record_timeout_sec": 60,
                    "max_memory_mb": 2048,
                    "host": "host",
                    "architecture": "x86_64",
                    "cpu_count": 1,
                    "cache_policy": "cold",
                },
                "input_hashes": ["sha256:aaa", "sha256:wrong"],
                "records": [{"target": "fixture", "source_addr": "0x1", "sink_addr": "0x2", "verdict": "POSITIVE"}],
            }
            self.assertIn("input_hash_mismatch", validate_baseline_document(document, expected))

    def test_native_frontend_mode_deduplicates_pairs_and_limits_claim_to_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            campaign.mkdir()
            rows = [
                {"closure_idx": 1, "source_addr": "0x100", "sink_addr": "0x200", "verdict": "VECTOR_SAT", "evidence_contract_valid": True},
                {"closure_idx": 2, "source_addr": "0x100", "sink_addr": "0x200", "verdict": "RESIDUAL", "evidence_contract_valid": True},
            ]
            (campaign / "fixture.results.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )
            document = {
                "comparison_mode": "native_frontend",
                "tool": {"name": "SaTC", "version": "1", "commit": "abc", "command": "satc.py"},
                "budget": {
                    "per_record_timeout_sec": 90,
                    "max_memory_mb": 2048,
                    "host": "host",
                    "architecture": "x86_64",
                    "cpu_count": 1,
                    "cache_policy": "cold",
                },
                "input_hashes": ["sha256:ccc"],
                "shared_input_hashes": ["sha256:aaa"],
                "records": [
                    {"target": "fixture", "source_addr": "0x100", "sink_addr": "0x200", "verdict": "POSITIVE"},
                    {"target": "fixture", "source_addr": "0x300", "sink_addr": "0x400", "verdict": "POSITIVE"},
                ],
            }
            baseline_path = root / "baseline.json"
            baseline_path.write_text(json.dumps(document), encoding="utf-8")
            tsds = load_tsds_records(campaign, "native_frontend")
            baseline, _, issues = load_baseline(baseline_path)
            issues = validate_baseline_document(document, {"aaa"})
            _, summary = compare(tsds, baseline, issues, document)
            self.assertEqual(len(tsds), 1)
            collapsed = next(iter(tsds.values()))
            self.assertEqual(collapsed["collapsed_records"], 2)
            self.assertEqual("MIXED", collapsed["verdict"])
            self.assertEqual(["RESIDUAL", "VECTOR_SAT"], collapsed["collapsed_verdicts"])
            self.assertTrue(summary["comparison_admissible"])
            self.assertEqual(summary["candidate_overlap"]["intersection"], 1)
            self.assertEqual(summary["candidate_overlap"]["union"], 2)
            self.assertFalse(summary["accuracy_claim_admissible"])
            self.assertFalse(summary["superiority_claim_admissible"])

    def test_runtime_manifest_requires_actual_hash_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runtime.json"
            path.write_text('{"runs": 3}\n', encoding="utf-8")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            verified = verify_runtime_manifest(path, expected)
            self.assertTrue(verified["verified"])
            mismatch = verify_runtime_manifest(path, "0" * 64)
            self.assertFalse(mismatch["verified"])


if __name__ == "__main__":
    unittest.main()
