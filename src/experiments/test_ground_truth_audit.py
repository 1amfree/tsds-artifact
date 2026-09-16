import csv
import json
import tempfile
import unittest
from pathlib import Path

from build_blinded_ground_truth_sample import (
    audit_stratum,
    select_sample,
    sha256_file,
    write_sample,
)
from package_blinded_audit import package
from unblind_ground_truth_audit import unblind
from validate_ground_truth_annotations import (
    cohen_kappa,
    validate_independent_annotations,
    validate_rows,
    write_outputs,
)


class GroundTruthAuditTest(unittest.TestCase):
    def test_sampling_is_deterministic_and_stratified(self):
        records = [
            {"_target": "a", "closure_idx": 1, "source_addr": "0x1", "sink_addr": "0x2", "verdict": "VECTOR_SAT", "evidence_provenance": "DIRECT_SINK_BYTE"},
            {"_target": "b", "closure_idx": 2, "source_addr": "0x3", "sink_addr": "0x4", "verdict": "MATRIX_UNSAT", "evidence_provenance": "DIRECT_SINK_BYTE"},
            {"_target": "c", "closure_idx": 3, "source_addr": "0x5", "sink_addr": "0x6", "verdict": "RESIDUAL", "evidence_provenance": "RESIDUAL"},
        ]
        first = select_sample(records, 1, 42)
        second = select_sample(records, 1, 42)
        self.assertEqual(first, second)
        self.assertEqual({audit_stratum(row) for row in first}, {"direct_vector_sat", "matrix_unsat", "residual"})

    def test_dual_auditor_agreement_and_adjudication(self):
        rows = [
            {"record_id": "A", "auditor_a_label": "POSITIVE", "auditor_b_label": "POSITIVE", "adjudicated_label": ""},
            {"record_id": "B", "auditor_a_label": "NEGATIVE", "auditor_b_label": "UNRESOLVED", "adjudicated_label": "NEGATIVE"},
        ]
        final_rows, summary = validate_rows(rows)
        self.assertTrue(summary["valid"])
        self.assertEqual(summary["agreements"], 1)
        self.assertEqual(summary["disagreements"], 1)
        self.assertEqual(len(final_rows), 2)
        self.assertIsNotNone(cohen_kappa([("POSITIVE", "POSITIVE"), ("NEGATIVE", "UNRESOLVED")]))
        self.assertEqual("tsds-ground-truth-annotation-audit-v3", summary["schema"])
        self.assertIsNotNone(summary["cohen_kappa_bootstrap_95"])
        self.assertEqual(
            1,
            summary["agreement_statistics"]["confusion_matrix"]["NEGATIVE"]["UNRESOLVED"],
        )

    def test_independent_protocol_requires_evidence_and_distinct_reviewers(self):
        base = {
            "evidence_type": "DISASSEMBLY",
            "evidence_locator": "binary@0x100",
            "rationale": "Source-dependent bytes are present at the sink.",
        }
        auditor_a = [
            {"record_id": "A", "auditor_id": "reviewer-a", "label": "POSITIVE", **base},
            {"record_id": "B", "auditor_id": "reviewer-a", "label": "NEGATIVE", **base},
        ]
        auditor_b = [
            {"record_id": "A", "auditor_id": "reviewer-b", "label": "POSITIVE", **base},
            {"record_id": "B", "auditor_id": "reviewer-b", "label": "UNRESOLVED", **base},
        ]
        adjudication = [{
            "record_id": "B",
            "adjudicator_id": "reviewer-c",
            "label": "NEGATIVE",
            "evidence_locator": "manual-audit:B",
            "rationale": "Independent review confirms a fixed sink argument.",
        }]
        protocol = {
            "auditor_a_id": "reviewer-a",
            "auditor_b_id": "reviewer-b",
            "adjudicator_id": "reviewer-c",
            "independent_of_tools": True,
            "labels_frozen_before_unblinding": True,
            "audit_key_withheld_until_freeze": True,
        }
        final_rows, summary = validate_independent_annotations(
            auditor_a, auditor_b, adjudication, protocol, {"A", "B"}
        )
        self.assertTrue(summary["valid"])
        self.assertTrue(summary["independent_protocol_ready"])
        self.assertEqual(len(final_rows), 2)

        auditor_b[0]["auditor_id"] = "reviewer-a"
        _, invalid = validate_independent_annotations(
            auditor_a, auditor_b, adjudication, protocol, {"A", "B"}
        )
        self.assertFalse(invalid["valid"])
        self.assertIn("auditors_not_distinct", invalid["issues"])

    def test_duplicate_record_id_is_rejected(self):
        row = {
            "record_id": "A",
            "auditor_a_label": "POSITIVE",
            "auditor_b_label": "POSITIVE",
            "adjudicated_label": "",
        }
        _, summary = validate_rows([row, dict(row)])
        self.assertFalse(summary["valid"])
        self.assertIn("combined_A_duplicate_record_id", summary["issues"])

    def test_blinded_sample_excludes_tsds_outcome_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            campaign.mkdir()
            record = {
                "closure_idx": 1,
                "source_addr": "0x1",
                "sink_addr": "0x2",
                "source_function": "source",
                "sink_function": "system",
                "trace_summary": "0x1 -> 0x2",
                "verdict": "VECTOR_SAT",
                "evidence_provenance": "DIRECT_SINK_BYTE",
                "sink_preview": "echo controlled",
                "engine_stop_reason": "sink_reached",
                "static_inputs_likely": ["web"],
                "minimal_bypass_vector": {"vector": "semicolon"},
                "tainted_offsets": [5],
            }
            (campaign / "fixture.results.jsonl").write_text(
                json.dumps(record) + "\n", encoding="utf-8"
            )
            out_dir = root / "sample"
            summary = write_sample(campaign, out_dir, per_stratum=1, seed=42)
            with (out_dir / "audit_blinded.csv").open(newline="", encoding="utf-8") as fh:
                row = next(csv.DictReader(fh))
            forbidden = {
                "verdict",
                "evidence_provenance",
                "sink_preview",
                "engine_stop_reason",
                "static_inputs_likely",
                "minimal_bypass_vector",
                "tainted_offsets",
            }
            self.assertFalse(forbidden & set(row))
            self.assertEqual(summary["schema"], "tsds-blinded-ground-truth-sample-v4")
            self.assertTrue((out_dir / "auditor_a_template.csv").is_file())
            self.assertTrue((out_dir / "auditor_b_template.csv").is_file())
            self.assertTrue((out_dir / "corpus_commitment.json").is_file())

    def test_corpus_commitment_binds_pipeline_inputs_without_outcomes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "run" / "campaign"
            campaign.mkdir(parents=True)
            result = campaign / "fixture.results.jsonl"
            result.write_text(
                json.dumps({
                    "closure_idx": 1,
                    "source_addr": "0x1",
                    "sink_addr": "0x2",
                    "source_function": "source",
                    "sink_function": "system",
                    "trace_summary": "0x1 -> 0x2",
                    "verdict": "VECTOR_SAT",
                    "evidence_provenance": "DIRECT_SINK_BYTE",
                })
                + "\n",
                encoding="utf-8",
            )
            manifest = root / "run" / "pipeline_manifest.json"
            manifest.write_text(
                json.dumps({
                    "schema": "tsds-v17-pipeline-v5",
                    "success": True,
                    "reproducibility": {
                        "campaign_inputs": [{
                            "target": "fixture",
                            "label": "Fixture",
                            "binary": {"path": "fixture.bin", "size": 1, "sha256": "a" * 64},
                            "mango": {"path": "fixture.json", "size": 1, "sha256": "b" * 64},
                        }],
                    },
                    "artifacts": [{
                        "path": "campaign/fixture.results.jsonl",
                        "size": result.stat().st_size,
                        "sha256": sha256_file(result),
                    }],
                }),
                encoding="utf-8",
            )
            sample = root / "sample"
            write_sample(
                campaign,
                sample,
                per_stratum=1,
                seed=42,
                pipeline_manifest=manifest,
            )
            corpus = json.loads(
                (sample / "corpus_commitment.json").read_text(encoding="utf-8")
            )
            self.assertTrue(corpus["available"])
            encoded = json.dumps(corpus, sort_keys=True)
            self.assertNotIn("VECTOR_SAT", encoded)
            self.assertNotIn("evidence_provenance", encoded)
            self.assertEqual(corpus["campaign_inputs"][0]["target"], "fixture")

    def test_sampling_can_bind_fail_closed_repeatability_consensus(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            campaign.mkdir()
            record = {
                "closure_idx": 1,
                "source_addr": "0x1",
                "sink_addr": "0x2",
                "source_function": "source",
                "sink_function": "system",
                "trace_summary": "0x1 -> 0x2",
                "verdict": "STATIC_WARNING_REDUCTION",
                "evidence_provenance": "STATIC_WARNING_REDUCTION",
                "evidence_contract_valid": True,
            }
            (campaign / "fixture.results.jsonl").write_text(
                json.dumps(record) + "\n", encoding="utf-8"
            )
            consensus = root / "repeatability_records.csv"
            with consensus.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(
                    fh,
                    fieldnames=[
                        "target",
                        "closure_idx",
                        "source_addr",
                        "sink_addr",
                        "outcome",
                        "consensus_verdict",
                    ],
                    lineterminator="\n",
                )
                writer.writeheader()
                writer.writerow({
                    "target": "fixture",
                    "closure_idx": 1,
                    "source_addr": "0x1",
                    "sink_addr": "0x2",
                    "outcome": "semantic_drift",
                    "consensus_verdict": "RESIDUAL",
                })
            out_dir = root / "sample"
            summary = write_sample(
                campaign,
                out_dir,
                per_stratum=1,
                seed=42,
                repeatability_records=consensus,
            )
            self.assertEqual(summary["aggregate_basis"], "repeatability_consensus")
            self.assertEqual(summary["distribution"], {"residual": 1})
            with (out_dir / "audit_key.csv").open(newline="", encoding="utf-8") as fh:
                key = next(csv.DictReader(fh))
            self.assertEqual(key["tsds_verdict"], "RESIDUAL")
            self.assertEqual(key["single_run_verdict"], "STATIC_WARNING_REDUCTION")
            self.assertEqual(key["repeatability_outcome"], "semantic_drift")

    def test_role_packages_exclude_key_and_prevalence_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            campaign.mkdir()
            (campaign / "fixture.results.jsonl").write_text(
                json.dumps({
                    "closure_idx": 1,
                    "source_addr": "0x1",
                    "sink_addr": "0x2",
                    "source_function": "source",
                    "sink_function": "system",
                    "trace_summary": "0x1 -> 0x2",
                    "verdict": "VECTOR_SAT",
                    "evidence_provenance": "DIRECT_SINK_BYTE",
                    "evidence_contract_valid": True,
                })
                + "\n",
                encoding="utf-8",
            )
            sample = root / "sample"
            write_sample(campaign, sample, per_stratum=1, seed=42)
            first = package(sample, root / "packages-a")
            second = package(sample, root / "packages-b")
            for role in ("auditor_a", "auditor_b", "adjudicator"):
                self.assertEqual(
                    first["packages"][role]["sha256"],
                    second["packages"][role]["sha256"],
                )
                members = set(first["packages"][role]["members"])
                self.assertIn("ROLE.txt", members)
                self.assertIn("corpus_commitment.json", members)
                self.assertNotIn("audit_key.csv", members)
                self.assertNotIn("sample_summary.json", members)
            self.assertTrue(first["leak_audit"]["valid"])
            self.assertNotEqual(
                first["packages"]["auditor_a"]["sha256"],
                first["packages"]["auditor_b"]["sha256"],
            )

    def test_bound_protocol_and_post_freeze_unblinding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            campaign.mkdir()
            record = {
                "closure_idx": 1,
                "source_addr": "0x1",
                "sink_addr": "0x2",
                "source_function": "source",
                "sink_function": "system",
                "trace_summary": "0x1 -> 0x2",
                "verdict": "VECTOR_SAT",
                "evidence_provenance": "DIRECT_SINK_BYTE",
                "evidence_contract_valid": True,
            }
            (campaign / "fixture.results.jsonl").write_text(
                json.dumps(record) + "\n", encoding="utf-8"
            )
            sample_dir = root / "sample"
            write_sample(campaign, sample_dir, per_stratum=1, seed=42)

            def read_rows(path):
                with path.open(newline="", encoding="utf-8") as fh:
                    return list(csv.DictReader(fh))

            auditor_a = read_rows(sample_dir / "auditor_a_template.csv")
            auditor_b = read_rows(sample_dir / "auditor_b_template.csv")
            for row, auditor in ((auditor_a[0], "reviewer-a"), (auditor_b[0], "reviewer-b")):
                row.update({
                    "auditor_id": auditor,
                    "label": "POSITIVE",
                    "evidence_type": "DISASSEMBLY",
                    "evidence_locator": "fixture@0x2",
                    "rationale": "Source-dependent shell bytes are independently confirmed.",
                })
            protocol_path = sample_dir / "protocol_declaration_template.json"
            protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
            protocol.update({
                "auditor_a_id": "reviewer-a",
                "auditor_b_id": "reviewer-b",
                "independent_of_tools": True,
                "labels_frozen_before_unblinding": True,
                "audit_key_withheld_until_freeze": True,
                "labels_frozen_at_utc": "2026-07-13T00:00:00Z",
            })
            protocol_path.write_text(
                json.dumps(protocol, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            expected_ids = {auditor_a[0]["record_id"]}
            labels, summary = validate_independent_annotations(
                auditor_a,
                auditor_b,
                read_rows(sample_dir / "adjudication_template.csv"),
                protocol,
                expected_ids,
                blinded_sample_sha256=sha256_file(sample_dir / "audit_blinded.csv"),
                require_bound_protocol=True,
            )
            self.assertTrue(summary["valid"])
            summary["audit_key_commitment_sha256"] = protocol[
                "audit_key_commitment_sha256"
            ]
            summary["label_definition_version"] = protocol[
                "label_definition_version"
            ]
            annotation_dir = root / "annotation"
            write_outputs(
                annotation_dir,
                labels,
                summary,
                {
                    "auditor_a": "a" * 64,
                    "auditor_b": "b" * 64,
                    "adjudication": "c" * 64,
                    "blinded_sample": sha256_file(sample_dir / "audit_blinded.csv"),
                    "protocol_declaration": sha256_file(protocol_path),
                },
            )
            rows, unblinded = unblind(
                annotation_dir,
                sample_dir / "audit_key.csv",
                sample_dir / "sample_summary.json",
            )
            self.assertTrue(unblinded["valid"])
            self.assertEqual(unblinded["strict_sink_semantic"]["tp"], 1)
            self.assertEqual(unblinded["strict_sink_semantic"]["coverage"], 1.0)
            self.assertEqual(rows[0]["strict_projection"], "POSITIVE")
            with (sample_dir / "audit_key.csv").open("a", encoding="utf-8") as fh:
                fh.write("tampered,row\n")
            _, tampered = unblind(
                annotation_dir,
                sample_dir / "audit_key.csv",
                sample_dir / "sample_summary.json",
            )
            self.assertFalse(tampered["valid"])
            self.assertIn(
                "sample_summary_audit_key_sha256_mismatch", tampered["issues"]
            )


if __name__ == "__main__":
    unittest.main()
