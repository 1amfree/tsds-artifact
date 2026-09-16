#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import json

from tsds.summary_synthesis import (
    FunctionSummary,
    SummaryDatabase,
    SummaryEffect,
    SummaryPrecondition,
    summary_from_refinement_candidate,
    synthesize_from_observations,
)


class SummarySynthesisTest(unittest.TestCase):
    def test_database_roundtrip_is_deterministic(self) -> None:
        summary = FunctionSummary(
            target="wrapper_get",
            architecture="MIPS32",
            calling_convention="o32",
            binary_sha256="a" * 64,
            preconditions=(SummaryPrecondition("non_null", 0),),
            effects=(SummaryEffect("return_symbolic_cstring", source_kind="nvram"),),
            confidence="high",
            evidence=("callsite:0x401000",),
        )
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            database = SummaryDatabase((summary,))
            database.write(first)
            loaded = SummaryDatabase.load(first)
            loaded.write(second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertIsNotNone(
                loaded.get(
                    binary_sha256="a" * 64,
                    architecture="MIPS32",
                    calling_convention="o32",
                    target="wrapper_get",
                )
            )
            tampered = json.loads(first.read_text(encoding="utf-8"))
            tampered["summaries"][0]["target"] = "different_target"
            first.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(ValueError):
                SummaryDatabase.load(first)

    def test_refinement_candidate_maps_to_summary_ir(self) -> None:
        summary = summary_from_refinement_candidate(
            {
                "kind": "format_binding_summary",
                "target": "sub_401000",
                "source_kind": "web",
                "source_slot": 1,
                "confidence": "high",
                "preconditions": ["strong_static_source"],
            },
            binary_sha256="b" * 64,
            architecture="ARMEL",
        )
        effect = summary.effects[0]
        self.assertEqual("bind_format_slot", effect.kind)
        self.assertEqual(3, effect.source_arg)

    def test_observation_synthesis_requires_agreement(self) -> None:
        rows = [
            {"behavior": "string_copy", "destination_arg": 0, "source_arg": 1},
            {"behavior": "string_copy", "destination_arg": 0, "source_arg": 1},
        ]
        summary = synthesize_from_observations(
            rows,
            target="copy_wrapper",
            binary_sha256="c" * 64,
            architecture="MIPS32",
        )
        self.assertIsNotNone(summary)
        self.assertEqual("medium", summary.confidence)
        self.assertIsNone(
            synthesize_from_observations(
                rows + [{"behavior": "source_return"}],
                target="ambiguous",
                binary_sha256="c" * 64,
                architecture="MIPS32",
            )
        )


if __name__ == "__main__":
    unittest.main()
