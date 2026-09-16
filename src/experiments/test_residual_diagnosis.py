#!/usr/bin/env python3
"""Unit tests for TSDS residual outcome diagnosis."""

from __future__ import annotations

import importlib.util
from argparse import Namespace
import unittest


@unittest.skipIf(importlib.util.find_spec("angr") is None, "advanced evaluator dependencies are unavailable")
class ResidualDiagnosisTest(unittest.TestCase):
    def test_strong_static_unreachable_is_model_gap(self) -> None:
        from advanced_sanitizer_evaluator import residual_diagnosis_for_record

        diagnosis = residual_diagnosis_for_record({
            "status": "unreachable",
            "static_evidence_strength": "strong",
            "path_control_class": "unclassified",
        })
        self.assertEqual(diagnosis["residual_diagnosis_class"], "model_gap_reachability")
        self.assertEqual(diagnosis["residual_diagnosis_severity"], "high")
        self.assertTrue(diagnosis["residual_next_actions"])

    def test_residual_budget_stop_is_path_explosion(self) -> None:
        from advanced_sanitizer_evaluator import (
            residual_diagnosis_for_record,
            residual_recovery_plan_for_record,
        )

        record = {
            "status": "unreachable",
            "path_control_class": "residual_budget_stop",
            "path_control_budget_pressure": "residual_risk",
            "residual_diagnosis_class": "path_explosion_residual",
            "engine_stop_reason": "guided_stagnation_saturated",
        }
        diagnosis = residual_diagnosis_for_record(record)
        self.assertEqual(diagnosis["residual_diagnosis_class"], "path_explosion_residual")
        self.assertIn("residual_path_budget", diagnosis["residual_diagnosis_factors"])
        plan = residual_recovery_plan_for_record({**record, **diagnosis})
        self.assertEqual(plan["residual_plan_strategy"], "semantic_path_refinement")
        self.assertIn("max_steps", plan["residual_plan_config_overrides"])
        self.assertTrue(plan["residual_plan_model_gaps"])

    def test_operational_failure_is_critical(self) -> None:
        from advanced_sanitizer_evaluator import residual_diagnosis_for_record

        diagnosis = residual_diagnosis_for_record({
            "status": "crashed",
            "error": "loader failed",
        })
        self.assertEqual(diagnosis["residual_diagnosis_class"], "operational_failure")
        self.assertEqual(diagnosis["residual_diagnosis_severity"], "critical")

    def test_timeout_plan_extends_budget(self) -> None:
        from advanced_sanitizer_evaluator import (
            residual_diagnosis_for_record,
            residual_recovery_plan_for_record,
        )

        record = {
            "status": "timeout",
            "timeout_kind": "subprocess_timeout",
            "engine_steps": 500,
        }
        diagnosis = residual_diagnosis_for_record(record)
        plan = residual_recovery_plan_for_record({**record, **diagnosis})
        self.assertEqual(plan["residual_plan_strategy"], "budget_extension_rerun")
        self.assertGreaterEqual(plan["residual_plan_config_overrides"]["max_steps"], 1000)

    def test_static_dynamic_disagreement_plan_audits_taint_model(self) -> None:
        from advanced_sanitizer_evaluator import (
            residual_diagnosis_for_record,
            residual_recovery_plan_for_record,
        )

        record = {
            "status": "no_taint_sink",
            "static_evidence_strength": "strong",
            "static_evidence_reasons": ["sink_contains_source_marker"],
            "static_source_markers": ["GetValue("],
            "path_control_class": "direct_no_taint_evidence",
            "no_taint_preview": "fixed helper command",
        }
        diagnosis = residual_diagnosis_for_record(record)
        plan = residual_recovery_plan_for_record({**record, **diagnosis})
        self.assertEqual(plan["residual_plan_strategy"], "taint_model_audit")
        self.assertIn("format_template_binding", plan["residual_plan_model_gaps"])

    def test_weak_resource_no_taint_remains_actionable(self) -> None:
        from advanced_sanitizer_evaluator import (
            evidence_profile_for_record,
            model_gap_requests_for_record,
            residual_diagnosis_for_record,
        )

        record = {
            "closure_idx": 61,
            "status": "no_taint_sink",
            "static_evidence_strength": "weak",
            "static_possible_resource_inputs": ["/proc/mounts"],
            "no_taint_preview": "",
        }
        diagnosis = residual_diagnosis_for_record(record)
        self.assertEqual(diagnosis["residual_diagnosis_class"], "static_dynamic_taint_disagreement")
        profile = evidence_profile_for_record(record)
        self.assertEqual(profile["paper_claim_bucket"], "model_gap_or_taint_disagreement_residual")
        self.assertIn("weak_static_resource_no_dynamic_taint", profile["uncertainty_factors"])
        requests = model_gap_requests_for_record({**record, **diagnosis})
        self.assertTrue(any(request["kind"] == "file" and request["key"] == "/proc/mounts" for request in requests))

    def test_strong_static_no_taint_is_not_false_positive_claim(self) -> None:
        from advanced_sanitizer_evaluator import evidence_profile_for_record

        profile = evidence_profile_for_record({
            "status": "no_taint_sink",
            "static_evidence_strength": "strong",
            "static_evidence_reasons": ["sink_contains_source_marker"],
            "static_source_markers": ["GetValue("],
            "path_control_class": "direct_no_taint_evidence",
            "no_taint_preview": "fixed helper command",
        })
        self.assertEqual(profile["paper_claim_bucket"], "model_gap_or_taint_disagreement_residual")
        self.assertEqual(profile["review_priority"], "high")

    def test_fixed_command_no_taint_is_static_overapproximation(self) -> None:
        from advanced_sanitizer_evaluator import (
            evidence_profile_for_record,
            model_gap_requests_for_record,
            residual_diagnosis_for_record,
            source_obligation_audit_for_record,
        )

        record = {
            "status": "no_taint_sink",
            "static_evidence_strength": "strong",
            "static_evidence_reasons": ["ranked_likely_input"],
            "static_inputs_likely": ["WscVendorPinCode"],
            "no_taint_preview": "ifconfig rai0 down",
        }
        audit = source_obligation_audit_for_record(record)
        self.assertEqual(audit["source_obligation_class"], "static_overapprox_no_taint")
        diagnosis = residual_diagnosis_for_record(record)
        self.assertEqual(diagnosis["residual_diagnosis_class"], "static_overapprox_no_taint")
        profile = evidence_profile_for_record({**record, **diagnosis})
        self.assertEqual(
            profile["paper_claim_bucket"],
            "false_positive_reduction_evidence",
        )
        self.assertEqual(profile["review_priority"], "low")
        self.assertEqual(model_gap_requests_for_record({**record, **diagnosis, **profile}), [])

    def test_mismatched_static_template_no_taint_is_static_overapproximation(self) -> None:
        from advanced_sanitizer_evaluator import (
            residual_diagnosis_for_record,
            source_obligation_audit_for_record,
        )

        record = {
            "status": "no_taint_sink",
            "static_evidence_strength": "strong",
            "static_evidence_reasons": ["static_sink_template"],
            "static_possible_resource_inputs": ["wans.flag", "wl0_ifname"],
            "static_sink_template": "wl -i wl0_ifname >> /tmp/syslog/wl_info.log <source>",
            "no_taint_preview": "date >> /tmp/syslog/sys_info.log",
        }
        audit = source_obligation_audit_for_record(record)
        self.assertEqual(audit["source_obligation_class"], "static_overapprox_no_taint")
        self.assertIn("dynamic_static_command_template_mismatch", audit["source_obligation_factors"])
        diagnosis = residual_diagnosis_for_record(record)
        self.assertEqual(diagnosis["residual_diagnosis_class"], "static_overapprox_no_taint")

    def test_mango_unbound_no_taint_is_not_tsds_model_gap(self) -> None:
        from advanced_sanitizer_evaluator import (
            evidence_profile_for_record,
            model_gap_requests_for_record,
            residual_diagnosis_for_record,
            residual_recovery_plan_for_record,
            source_obligation_audit_for_record,
        )

        record = {
            "status": "no_taint_sink",
            "static_evidence_strength": "absent",
            "static_inputs_likely": [],
            "static_inputs_possible": [],
            "no_taint_preview": "%s >> %s\\n",
        }
        audit = source_obligation_audit_for_record(record)
        self.assertEqual(audit["source_obligation_class"], "mango_unbound_no_taint")
        diagnosis = residual_diagnosis_for_record({**record, **audit})
        self.assertEqual(diagnosis["residual_diagnosis_class"], "mango_unbound_no_taint")
        plan = residual_recovery_plan_for_record({**record, **audit, **diagnosis})
        self.assertEqual(plan["residual_plan_strategy"], "no_rerun_needed")
        profile = evidence_profile_for_record({**record, **audit, **diagnosis})
        self.assertEqual(profile["paper_claim_bucket"], "upstream_unbound_closure_evidence")
        self.assertEqual(model_gap_requests_for_record({**record, **audit, **diagnosis, **profile}), [])

    def test_empty_preview_keeps_no_taint_as_model_gap(self) -> None:
        from advanced_sanitizer_evaluator import (
            evidence_profile_for_record,
            residual_diagnosis_for_record,
            source_obligation_audit_for_record,
        )

        record = {
            "status": "no_taint_sink",
            "static_evidence_strength": "strong",
            "static_evidence_reasons": ["ranked_likely_input"],
            "static_inputs_likely": ["ver_check_config_file"],
            "no_taint_preview": "",
        }
        audit = source_obligation_audit_for_record(record)
        self.assertEqual(audit["source_obligation_class"], "unresolved_source_obligation")
        diagnosis = residual_diagnosis_for_record(record)
        self.assertEqual(diagnosis["residual_diagnosis_class"], "static_dynamic_taint_disagreement")
        profile = evidence_profile_for_record({**record, **diagnosis})
        self.assertEqual(profile["paper_claim_bucket"], "model_gap_or_taint_disagreement_residual")

    def test_possible_source_api_marker_does_not_bind_fixed_command(self) -> None:
        from advanced_sanitizer_evaluator import (
            model_gap_requests_for_record,
            residual_diagnosis_for_record,
            source_obligation_audit_for_record,
        )

        record = {
            "status": "no_taint_sink",
            "static_evidence_strength": "weak",
            "static_evidence_reasons": ["possible_source_marker_only", "possible_resource_input"],
            "static_possible_source_markers": ["fgets("],
            "static_possible_resource_inputs": ["/tmp/usb_mnt_table"],
            "no_taint_preview": "df -h > /tmp/space_info",
        }
        audit = source_obligation_audit_for_record(record)
        self.assertEqual(audit["source_obligation_class"], "static_overapprox_no_taint")
        self.assertIn("possible_source_api_not_bound_to_sink_template", audit["source_obligation_factors"])
        diagnosis = residual_diagnosis_for_record(record)
        self.assertEqual(diagnosis["residual_diagnosis_class"], "static_overapprox_no_taint")
        self.assertEqual(model_gap_requests_for_record({**record, **diagnosis}), [])

    def test_internal_possible_files_are_not_requested(self) -> None:
        from advanced_sanitizer_evaluator import model_gap_requests_for_record

        requests = model_gap_requests_for_record({
            "status": "no_taint_sink",
            "static_evidence_strength": "strong",
            "static_inputs_likely": ["cert_file"],
            "static_inputs_possible": ["/dev/urandom", "/www/UPG_upgrade.htm"],
            "residual_diagnosis_class": "static_dynamic_taint_disagreement",
        })
        keys = {request["key"] for request in requests}
        self.assertIn("cert_file", keys)
        self.assertNotIn("/dev/urandom", keys)
        self.assertNotIn("/www/UPG_upgrade.htm", keys)

    def test_stale_possible_resource_inputs_are_filtered(self) -> None:
        from advanced_sanitizer_evaluator import model_gap_requests_for_record

        requests = model_gap_requests_for_record({
            "status": "no_taint_sink",
            "static_evidence_strength": "weak",
            "static_possible_resource_inputs": ["/dev/urandom", "/www/index.htm", "/proc/mounts"],
            "residual_diagnosis_class": "static_dynamic_taint_disagreement",
        })
        keys = {request["key"] for request in requests}
        self.assertEqual(keys, {"/proc/mounts"})

    def test_residual_refinement_selection_prefers_priority_order(self) -> None:
        from advanced_sanitizer_evaluator import select_residual_refinement_candidates

        records = [
            {"closure_idx": 4, "status": "timeout", "residual_plan_strategy": "budget_extension_rerun", "residual_plan_priority": "high"},
            {"closure_idx": 1, "status": "unreachable", "residual_plan_strategy": "semantic_path_refinement", "residual_plan_priority": "critical"},
            {"closure_idx": 2, "status": "no_taint_sink", "residual_plan_strategy": "taint_model_audit", "residual_plan_priority": "medium"},
        ]
        selected = select_residual_refinement_candidates(records)
        self.assertEqual([record["closure_idx"] for record in selected], [1, 4, 2])

    def test_build_closure_command_applies_refinement_overrides(self) -> None:
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
        )
        cmd = build_closure_command(
            "advanced_sanitizer_evaluator.py",
            "firmware/httpd",
            "results/cmdi_results.json",
            7,
            args,
            overrides={"max_steps": 1200, "loop_semantic_weak_static": True},
            use_evidence_cache=False,
            python_executable="python",
        )
        self.assertIn("--closure-idx", cmd)
        self.assertIn("7", cmd)
        self.assertIn("--max-steps", cmd)
        self.assertIn("1200", cmd)
        self.assertIn("--loop-semantic-weak-static", cmd)
        self.assertIn("--no-evidence-cache", cmd)

    def test_residual_refinement_summary_counts_resolution(self) -> None:
        from advanced_sanitizer_evaluator import summarize_residual_refinement

        summary = summarize_residual_refinement([
            {"old_status": "timeout", "new_status": "filtered", "strategy": "budget_extension_rerun", "priority": "high", "delta": "resolved", "elapsed_sec": 11.2},
            {"old_status": "unreachable", "new_status": "unreachable", "strategy": "semantic_path_refinement", "priority": "high", "delta": "unchanged", "elapsed_sec": 20.0},
        ])
        self.assertEqual(summary["records"], 2)
        self.assertEqual(summary["resolved"], 1)
        self.assertEqual(summary["unchanged"], 1)
        self.assertEqual(summary["new_statuses"]["filtered"], 1)

    def test_model_gap_requests_are_not_emitted_for_plain_resolved_records(self) -> None:
        from advanced_sanitizer_evaluator import model_gap_requests_for_record

        requests = model_gap_requests_for_record({
            "status": "vulnerable",
            "sink_preview": "cmd <sym>",
            "source_kinds": ["web"],
        })
        self.assertEqual(requests, [])

    def test_model_gap_requests_extract_static_inputs(self) -> None:
        from advanced_sanitizer_evaluator import model_gap_requests_for_record

        requests = model_gap_requests_for_record({
            "closure_idx": 3,
            "status": "unreachable",
            "residual_diagnosis_class": "model_gap_reachability",
            "static_evidence_strength": "strong",
            "static_inputs_likely": ["wan_pppoe_user", "/tmp/UDiskname"],
            "trace_summary": "websGetVar -> doSystemCmd",
            "residual_plan_model_gaps": ["loop_or_parser_summary"],
        })
        kinds = {request["kind"] for request in requests}
        keys = {request["key"] for request in requests}
        self.assertIn("config_key", kinds)
        self.assertIn("file", kinds)
        self.assertIn("wan_pppoe_user", keys)
        self.assertIn("/tmp/UDiskname", keys)

    def test_model_gap_request_ledger_counts_kinds(self) -> None:
        from advanced_sanitizer_evaluator import aggregate_model_gap_requests

        ledger = aggregate_model_gap_requests([
            {"model_gap_requests": [{"kind": "config_key", "key": "wan_ip", "reason": "mango_likely_input"}]},
            {"model_gap_requests": [{"kind": "web", "key": "QUERY_STRING", "reason": "trace_expression_token"}]},
        ])
        self.assertEqual(ledger["total"], 2)
        self.assertEqual(ledger["kinds"]["config_key"], 1)
        self.assertEqual(ledger["kinds"]["web"], 1)

    def test_model_gap_token_filter_suppresses_trace_noise(self) -> None:
        from advanced_sanitizer_evaluator import (
            _classify_resource_token,
            _classify_static_input_token,
            _resource_tokens,
            model_gap_requests_for_record,
        )

        tokens = _resource_tokens('sub_40758 stack_base "lan0_ipaddr" "1 apcli0_lan0_"', include_bare=False)
        self.assertEqual(tokens, ["lan0_ipaddr"])
        self.assertEqual(_classify_resource_token("WscVendorPinCode"), "config_key")
        self.assertEqual(_classify_static_input_token("disable_ui"), "config_key")
        requests = model_gap_requests_for_record({
            "status": "no_taint_sink",
            "static_evidence_strength": "strong",
            "static_inputs_likely": ["system", "doSystemCmd", "twsystem", "e", "lan_ipaddr"],
            "residual_diagnosis_class": "static_dynamic_taint_disagreement",
        })
        keys = {request["key"] for request in requests}
        self.assertEqual(keys, {"lan_ipaddr"})

    def test_sink_argument_snapshot_takes_precedence(self) -> None:
        import angr
        import claripy
        from advanced_sanitizer_evaluator import extract_sink_argument_bytes

        state = angr.SimState(arch="AMD64")
        snapshot = [claripy.BVV(ord("i"), 8), claripy.BVV(ord("d"), 8), claripy.BVV(0, 8)]
        state.globals["tsds_sink_arg_bytes_snapshot"] = snapshot
        self.assertEqual(extract_sink_argument_bytes(state, None), snapshot)

    def test_sink_argument_snapshot_recovers_non_first_call_argument(self) -> None:
        import angr
        import claripy
        from advanced_sanitizer_evaluator import _snapshot_sink_argument_bytes, render_model_bytes

        state = angr.SimState(arch="AMD64")
        cmd_addr = 0x500000
        state.memory.store(cmd_addr, b"reboot\x00")

        recovered = _snapshot_sink_argument_bytes(
            state,
            None,
            args=[claripy.BVV(0, 64), claripy.BVV(cmd_addr, 64)],
        )

        self.assertEqual(render_model_bytes(state, recovered), "reboot")
        self.assertEqual(
            state.globals.get("tsds_sink_arg_snapshot_source"),
            "heuristic:call_arg[1]",
        )
        self.assertEqual(
            state.globals.get("tsds_sink_argument_binding_trust"),
            "heuristic",
        )

    def test_target_sink_capture_filters_unrelated_wrapper_calls(self) -> None:
        import angr
        from advanced_sanitizer_evaluator import TraceGuidedEngine

        project = angr.load_shellcode(b"\x90" * 0x200, arch="AMD64", load_address=0x400000)
        engine = TraceGuidedEngine(
            project,
            trace=[{"function": "handler", "ins_addr": "0x400020"}],
            sink_addr=0x400080,
        )
        unrelated = project.factory.blank_state(addr=0x400020)
        unrelated.globals["tsds_sink_target_addr"] = 0x401000
        unrelated.globals["tsds_sink_callsite_addr"] = 0x400040
        unrelated.globals["tsds_sink_return_target"] = 0x400044

        target = project.factory.blank_state(addr=0x400020)
        target.globals["tsds_sink_target_addr"] = 0x401000
        target.globals["tsds_sink_callsite_addr"] = 0x400080
        target.globals["tsds_sink_return_target"] = 0x400088

        accepted, ignored = engine.select_target_sink_captures([unrelated, target])
        self.assertEqual(accepted, [target])
        self.assertEqual(ignored, 1)

    def test_target_sink_capture_accepts_mips_delay_slot_return(self) -> None:
        import angr
        from advanced_sanitizer_evaluator import TraceGuidedEngine

        project = angr.load_shellcode(b"\x00" * 0x200, arch="MIPS32", load_address=0x400000)
        engine = TraceGuidedEngine(
            project,
            trace=[{"function": "handler", "ins_addr": "0x400020"}],
            sink_addr=0x400084,
        )
        captured = project.factory.blank_state(addr=0x400020)
        captured.globals["tsds_sink_target_addr"] = 0x401000
        captured.globals["tsds_sink_callsite_addr"] = 0x400080
        captured.globals["tsds_sink_return_target"] = 0x400088

        self.assertTrue(engine.is_target_sink_capture(captured))

    def test_exact_sink_callsite_preserves_declared_sink_name(self) -> None:
        import angr
        from advanced_sanitizer_evaluator import TraceGuidedEngine

        project = angr.load_shellcode(
            b"\x90" * 0x200, arch="AMD64", load_address=0x400000
        )
        sink_addr = 0x400080
        engine = TraceGuidedEngine(
            project,
            trace=[{"function": "handler", "ins_addr": "0x400020"}],
            sink_addr=sink_addr,
            sink_func="system",
        )

        capture = project.hooked_by(sink_addr)
        self.assertIn(sink_addr, engine.closure_sink_callsite_addrs)
        self.assertEqual(getattr(capture, "tsds_sink_name", ""), "system")
        self.assertEqual(
            getattr(capture, "tsds_sink_name_source", ""),
            "closure_sink_at_exact_callsite",
        )
        reached = project.factory.blank_state(addr=sink_addr)
        self.assertTrue(engine.bind_exact_closure_sink_contract(reached, sink_addr))
        self.assertEqual(
            reached.globals.get("tsds_sink_function_name"),
            "system",
        )
        self.assertEqual(
            reached.globals.get("tsds_sink_function_name_source"),
            "closure_sink_at_exact_callsite",
        )

    def test_generic_trace_wrapper_entries_are_target_sinks(self) -> None:
        import angr
        from advanced_sanitizer_evaluator import TraceGuidedEngine

        project = angr.load_shellcode(b"\x90" * 0x300, arch="AMD64", load_address=0x400000)
        obj = project.loader.main_object
        wrapper_entry = int(obj.min_addr) + 0x100
        sink_addr = wrapper_entry + 0x40
        source_entry = int(obj.min_addr) + 0x20
        wrapper_name = f"sub_{int(obj.mapped_base) + (wrapper_entry - int(obj.min_addr)):x}"
        source_name = f"sub_{int(obj.mapped_base) + (source_entry - int(obj.min_addr)):x}"

        engine = TraceGuidedEngine(
            project,
            trace=[
                {"function": source_name, "ins_addr": hex(source_entry)},
                {"function": wrapper_name, "ins_addr": hex(wrapper_entry)},
            ],
            sink_addr=sink_addr,
            sink_func="system",
        )

        self.assertIn(wrapper_entry, engine.wrapper_sink_entries)
        self.assertIn(wrapper_entry, engine.target_callsite_addrs)
        self.assertNotIn(source_entry, engine.wrapper_sink_entries)
        self.assertEqual(
            getattr(project.hooked_by(sink_addr), "tsds_sink_name", ""),
            "system",
        )
        self.assertEqual(
            getattr(project.hooked_by(wrapper_entry), "tsds_sink_name", ""),
            wrapper_name,
        )
        self.assertEqual(
            getattr(project.hooked_by(wrapper_entry), "tsds_sink_name_source", ""),
            "trace_wrapper_entry",
        )

    def test_possible_resource_inputs_are_weak_static_evidence(self) -> None:
        from advanced_sanitizer_evaluator import closure_static_source_evidence

        evidence = closure_static_source_evidence({
            "sink": {"string": "system(cmd)"},
            "inputs": {"possibly": ["fgets(", "/proc/mounts", "lan_ipaddr"]},
        })
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["static_evidence_strength"], "weak")
        self.assertIn("possible_resource_input", evidence["static_evidence_reasons"])
        self.assertIn("/proc/mounts", evidence["static_possible_resource_inputs"])

    def test_internal_static_files_do_not_create_source_evidence(self) -> None:
        from advanced_sanitizer_evaluator import closure_static_source_evidence

        evidence = closure_static_source_evidence({
            "sink": {"string": "system(cmd)"},
            "inputs": {"possibly": ["/www/UPG_upgrade.htm", "/dev/urandom"]},
        })
        self.assertIsNone(evidence)


if __name__ == "__main__":
    unittest.main()
