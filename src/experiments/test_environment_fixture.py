#!/usr/bin/env python3
"""Unit tests for TSDS environment fixture modeling."""

from __future__ import annotations

import importlib.util
import json
from argparse import Namespace
from pathlib import Path
import tempfile
import unittest


@unittest.skipIf(importlib.util.find_spec("angr") is None, "advanced evaluator dependencies are unavailable")
class EnvironmentFixtureTest(unittest.TestCase):
    def test_fixture_loader_normalizes_vendor_sections(self) -> None:
        from advanced_sanitizer_evaluator import load_environment_fixture

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.json"
            path.write_text(
                json.dumps({
                    "config_key": {"wan_ipaddr": "192.168.0.1"},
                    "web_params": {"Login": "admin"},
                    "files": {"/tmp/token": {"content": "abc\nnext"}},
                }),
                encoding="utf-8",
            )
            fixture = load_environment_fixture(str(path))

        self.assertEqual(fixture["config"]["wan_ipaddr"], b"192.168.0.1")
        self.assertEqual(fixture["nvram"]["wan_ipaddr"], b"192.168.0.1")
        self.assertEqual(fixture["web"]["login"], b"admin")
        self.assertEqual(fixture["files"]["/tmp/token"], b"abc\nnext")

    def test_fixture_backed_symbolic_bytes_keep_taint(self) -> None:
        import angr
        from advanced_sanitizer_evaluator import (
            _store_fixture_backed_symbolic_string,
            source_kind_for_variable,
        )

        state = angr.SimState(arch="AMD64")
        chars = _store_fixture_backed_symbolic_string(
            state,
            0x100000,
            "nvram_val",
            0,
            "wan_ipaddr",
            b"AB",
            8,
        )
        self.assertEqual(len(chars), 2)
        self.assertTrue(state.solver.symbolic(state.memory.load(0x100000, 1)))
        self.assertEqual(state.solver.eval(state.memory.load(0x100000, 1)), ord("A"))
        variables = set()
        for char in chars:
            variables.update(char.variables)
        self.assertIn("nvram", {source_kind_for_variable(name) for name in variables})

    def test_usage_summary_counts_hits_and_misses(self) -> None:
        from advanced_sanitizer_evaluator import (
            aggregate_environment_fixture_usage,
            summarize_environment_fixture_usage,
        )

        summary = summarize_environment_fixture_usage([
            {"kind": "nvram", "key": "wan_ipaddr", "hit": True, "value_size": 11, "source": "nvram_get"},
            {"kind": "web", "key": "Login", "hit": False, "value_size": 0, "source": "web_get"},
        ])
        self.assertEqual(summary["hits"], 1)
        self.assertEqual(summary["misses"], 1)
        self.assertEqual(summary["by_kind"]["nvram"]["hits"], 1)
        self.assertEqual(summary["by_kind"]["web"]["misses"], 1)
        aggregate = aggregate_environment_fixture_usage([
            {"env_fixture_usage": {
                "hits": 4,
                "misses": 0,
                "by_kind": {"nvram": {"hits": 4, "misses": 0}},
                "keys": [{"kind": "nvram", "key": "lan0_", "hit": True, "value_size": 1, "source": "nvram_get"}],
            }}
        ])
        self.assertEqual(aggregate["hits"], 4)
        self.assertEqual(len(aggregate["keys"]), 1)

    def test_worker_memory_limit_ledger_uses_observed_worker_records(self) -> None:
        from advanced_sanitizer_evaluator import aggregate_worker_limit_enforcement

        ledger = aggregate_worker_limit_enforcement([
            {
                "subprocess_memory_limit_mib": 4096,
                "resource_limit_enforcement": "enforced",
            },
            {
                "memoized": True,
                "subprocess_memory_limit_mib": 4096,
                "resource_limit_enforcement": "not_executed_memoized",
            },
        ], 4096)
        self.assertEqual(1, ledger["executed_records"])
        self.assertEqual(1, ledger["records_with_limit_enforced"])
        self.assertEqual(0, ledger["resource_limit_hits"])
        self.assertEqual(0, ledger["records_with_unavailable_worker_metrics"])
        self.assertTrue(ledger["all_executed_workers_enforced"])

    def test_terminated_worker_preserves_budget_without_fabricating_rss(self) -> None:
        from argparse import Namespace
        from advanced_sanitizer_evaluator import (
            TSDS_ANALYSIS_VERSION,
            isolated_worker_termination_fields,
            make_report_record,
        )
        from tsds.ledger_schema import validate_ledger_record

        class Config:
            mode = "full"
            execution_backend = "forkserver"
            subprocess_memory_limit_mib = 4096

            @staticmethod
            def enabled_features():
                return {"execution_backend": "forkserver"}

        fields = isolated_worker_termination_fields(
            Namespace(subprocess_memory_limit_mib=4096),
            "resource_limit_enforcement': 'enforced'\nMemoryError",
            termination_kind="worker_crash_without_result",
            config=Config(),
        )
        self.assertEqual(TSDS_ANALYSIS_VERSION, fields["analysis_version"])
        self.assertEqual("forkserver", fields["execution_backend"])
        self.assertEqual(4096, fields["subprocess_memory_limit_mib"])
        self.assertEqual("enforced", fields["resource_limit_enforcement"])
        self.assertTrue(fields["resource_limit_hit"])
        self.assertEqual("unavailable_worker_terminated", fields["process_resource_metric_scope"])
        record = make_report_record(
            {"status": "crashed", "error": "StopIteration", **fields},
            closure_idx=0,
        )
        self.assertEqual([], validate_ledger_record(record))

    def test_static_input_prefix_guides_fixture_lookup(self) -> None:
        import angr
        from advanced_sanitizer_evaluator import lookup_environment_fixture

        state = angr.SimState(arch="AMD64")
        state.globals["tsds_env_fixture"] = {
            "config": {"lan0_port_member": b"1"},
            "nvram": {"lan0_port_member": b"1"},
            "web": {},
            "files": {},
            "env": {},
            "argv": {},
        }
        state.globals["tsds_static_inputs_likely"] = ["lan0_port_member"]
        hit = lookup_environment_fixture(state, "nvram", "lan0_")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["key"], "lan0_port_member")
        self.assertEqual(hit["alias_reason"], "static_input_prefix")

    def test_build_closure_command_forwards_fixture_path(self) -> None:
        from advanced_sanitizer_evaluator import build_closure_command

        args = Namespace(
            mode="full",
            engine_timeout=45,
            max_steps=500,
            closure_timeout=90,
            seed_equiv_limit=2,
            no_taint_equiv_limit=3,
            stagnation_limit=10,
            semantic_frontier_min_states=12,
            semantic_frontier_bucket_limit=2,
            semantic_frontier_period=2,
            source_liveness_limit=4,
            source_dead_state_cap=20,
            loop_semantic_min_states=50,
            loop_semantic_min_visits=3,
            loop_semantic_bucket_limit=1,
            loop_semantic_period=1,
            loop_semantic_near_sink_window=0x80,
            loop_semantic_saturation_limit=3,
            weak_evidence_equiv_limit=2,
            no_semantic_frontier=False,
            no_loop_semantic_summary=False,
            loop_semantic_weak_static=False,
            no_reconciliation=False,
            no_evidence_cache=True,
            evidence_cache=None,
            env_fixture_json="fixtures/env.json",
        )
        cmd = build_closure_command(
            "advanced_sanitizer_evaluator.py",
            "firmware/httpd",
            "results/cmdi_results.json",
            1,
            args,
            python_executable="python",
        )
        self.assertIn("--env-fixture-json", cmd)
        self.assertIn("fixtures/env.json", cmd)


if __name__ == "__main__":
    unittest.main()
