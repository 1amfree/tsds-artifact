#!/usr/bin/env python3
"""Tests for the TSDS evidence-closure report generator."""

from __future__ import annotations

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_tsds_evidence_closure_report import build_matrix, build_resource_requests, paper_paragraph


class EvidenceClosureReportTest(unittest.TestCase):
    def test_matrix_preserves_evidence_boundaries(self) -> None:
        aggregate = {
            "analysis_version": "test",
            "status_counts_from_jsonl": {
                "vulnerable": 2,
                "filtered": 1,
                "no_taint_sink": 1,
                "unreachable": 1,
                "timeout": 1,
            },
            "total": {
                "mango_closures": 7,
                "records": 6,
                "unique_pairs": 6,
                "vulnerable_vectors": 20,
                "secure_vectors": 5,
            },
        }
        baseline = {"layers": [{"Layer": "Deduplicated source/sink baseline", "Input": 6}]}
        audit = {"audited_records": 3, "audit_verdict_counts": {"PASS": 3}}
        candidates = {"candidate_pool": 3, "selected": 2}
        repro = {"candidate_count": 2, "pass": 2, "drift": 0, "run_failed": 0}
        harness = {"tasks": 1}
        preflight = {"tasks": 1, "ready": 0, "blocked": 1}

        rootfs_smoke = {"tasks": 1, "pass": 1, "fail": 0}
        loader_smoke = {"tasks": 1, "pass": 1, "fail": 0}
        firmware_inventory = {
            "targets": 2,
            "rootfs_available": 2,
            "rootfs_smoke_pass": 2,
            "dependency_resolution_pass": 2,
            "binary_rootfs_aligned": 1,
        }

        rows = build_matrix(
            aggregate,
            baseline,
            audit,
            candidates,
            repro,
            harness,
            preflight,
            rootfs_smoke,
            loader_smoke,
            firmware_inventory,
        )
        stages = {row["Evidence stage"]: row for row in rows}
        self.assertEqual(stages["Semantic validation"]["Result"], "4/6 semantic verdicts (66.7%)")
        self.assertIn("sink-level evidence", stages["Semantic validation"]["Claim boundary"])
        self.assertEqual(stages["Analyzer reproducibility"]["Claim boundary"], "analyzer-level reproducibility only")
        self.assertEqual(stages["Dynamic preflight"]["Claim boundary"], "dynamic preflight only")
        self.assertEqual(stages["Corpus resource inventory"]["Claim boundary"], "target-rootfs resource evidence")
        self.assertIn("2/2 ABI smoke", stages["Corpus resource inventory"]["Result"])
        self.assertEqual(stages["Target rootfs ABI smoke"]["Result"], "1/1 PASS")
        self.assertIn("canary observation not yet run", stages["Sink-intercept canary scaffold"]["Open gap"])

        paragraph = paper_paragraph(aggregate, repro, preflight, rootfs_smoke, loader_smoke, firmware_inventory)
        self.assertIn("not as device-confirmed exploitation", paragraph)
        self.assertNotIn("device-confirmed validation", paragraph)

    def test_resource_request_rows_are_explicit(self) -> None:
        rows = build_resource_requests(
            [
                {
                    "candidate_id": "poc-01",
                    "target": "Tenda AC18",
                    "qemu_required": "qemu-arm",
                    "qemu_available": "none",
                    "entry_clue_hits": 3,
                    "entry_clue_total": 3,
                    "blockers": "required qemu-user emulator is missing",
                    "resource_request": "install qemu-user for qemu-arm",
                }
            ]
        )
        self.assertEqual(rows[0]["entry_clues"], "3/3")
        self.assertIn("qemu-arm", rows[0]["resource_request"])


if __name__ == "__main__":
    unittest.main()
