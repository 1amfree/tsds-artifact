#!/usr/bin/env python3
"""Unit tests for static sink-template recovery."""

from __future__ import annotations

import importlib.util
import unittest


@unittest.skipIf(importlib.util.find_spec("angr") is None, "advanced evaluator dependencies are unavailable")
class StaticTemplateRecoveryTest(unittest.TestCase):
    def test_extracts_command_template_from_mango_bv_fragment(self) -> None:
        from advanced_sanitizer_evaluator import extract_static_sink_template

        sink = (
            'doSystemCmd(<MultiValues(<BV360 '
            '0x63666d20706f7374206e65746374726c2035313f6f703d312c737472696e675f696e666f3d'
            ' .. fgets(fopen("/tmp/UDiskname", "r+")@0xa0c0c_352_32)@0xa0c34_353_64>)>)'
        )

        self.assertEqual(
            extract_static_sink_template(sink),
            "cfm post netctrl 51?op=1,string_info=",
        )

    def test_extracts_static_template_with_source_slot(self) -> None:
        from advanced_sanitizer_evaluator import (
            closure_static_source_evidence,
            should_static_fallback_evaluate,
        )

        closure = {
            "sink": {
                "string": (
                    'doSystemCmd(<MultiValues(<BV128 0x636174202f70726f632f6d6f756e7473202f '
                    '.. fgets(fopen("/proc/mounts", "r")@0x1000_1_64) '
                    '.. 0x203e202f6465762f6e756c6c>)>)'
                )
            },
            "inputs": {"likely": ["/proc/mounts"], "possibly": []},
        }

        evidence = closure_static_source_evidence(closure)

        self.assertIn("cat /proc/mounts /", evidence["static_sink_template"])
        self.assertIn("<source>", evidence["static_sink_template"])
        self.assertTrue(should_static_fallback_evaluate(evidence))

    def test_dweb_extracted_nvram_template_is_recoverable(self) -> None:
        from advanced_sanitizer_evaluator import (
            closure_static_source_evidence,
            extract_static_sink_template_with_slots,
            should_static_fallback_evaluate,
        )

        sink_text = (
            'doSystemCmd(<MultiValues(<BV2312 '
            '0x6e7672616d20736574206164762e697074762e737462616c6c766c616e733d22 '
            '.. Reverse(dweb_get_extracted@b0458_285_2048) .. 34>)>) @ 0xb026c'
        )
        template = extract_static_sink_template_with_slots(sink_text)
        self.assertIn("nvram set adv.iptv.stballvlans", template)
        self.assertIn("<source>", template)

        evidence = closure_static_source_evidence({
            "sink": {"string": sink_text},
            "inputs": {"likely": [], "possibly": ["wans.flag"]},
            "trace": [{"function": "formSetIptv", "string": "formSetIptv(...)"}],
        })
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["static_evidence_strength"], "strong")
        self.assertTrue(should_static_fallback_evaluate(evidence))

    def test_static_template_promotes_placeholder_recovery_only_with_source_marker(self) -> None:
        from advanced_sanitizer_evaluator import (
            assess_static_dynamic_recovery,
            closure_static_source_evidence,
        )

        closure = {
            "sink": {
                "string": (
                    'doSystemCmd(<MultiValues(<BV360 '
                    '0x63666d20706f7374206e65746374726c2035313f6f703d312c737472696e675f696e666f3d'
                    ' .. fgets(fopen("/tmp/UDiskname", "r+")@0xa0c0c_352_32)@0xa0c34_353_64>)>)'
                )
            },
            "inputs": {"likely": ["/tmp/UDiskname"], "possibly": []},
        }
        evidence = closure_static_source_evidence(closure)
        self.assertEqual(evidence["static_sink_template"], "cfm post netctrl 51?op=1,string_info=<source>")

        assessment = assess_static_dynamic_recovery(evidence, "")
        self.assertTrue(assessment["auto_recover"])
        self.assertEqual(assessment["recovery_confidence"], "static_sink_marker_with_static_template")
        self.assertEqual(assessment["recovered_preview"], "cfm post netctrl 51?op=1,string_info=<source>")

    def test_placeholder_without_template_stays_blocked(self) -> None:
        from advanced_sanitizer_evaluator import assess_static_dynamic_recovery

        assessment = assess_static_dynamic_recovery(
            {
                "static_source_markers": ["GetValue("],
                "static_likely_inputs": ["lan.ip"],
                "static_evidence_strength": "strong",
            },
            "",
        )
        self.assertFalse(assessment["auto_recover"])
        self.assertEqual(assessment["recovery_blocked_reason"], "placeholder_sink_preview")

    def test_direct_getvalue_sink_expression_can_fallback_without_template(self) -> None:
        from advanced_sanitizer_evaluator import (
            closure_static_source_evidence,
            should_static_direct_source_fallback,
            should_static_fallback_evaluate,
        )

        sink_text = (
            'doSystemCmd(<MultiValues(<BV32 Reverse(GetValue("cgi_debug")'
            '@0xc4b08[319:288]) + 0xffff645c>)>) @ 0xc41b4'
        )
        evidence = closure_static_source_evidence({
            "sink": {"string": sink_text},
            "inputs": {"likely": ["cgi_debug"], "possibly": ["TOP", "macfilter.mode"]},
        })

        self.assertEqual(evidence["static_evidence_strength"], "strong")
        self.assertIn("sink_contains_source_marker", evidence["static_evidence_reasons"])
        self.assertFalse(should_static_fallback_evaluate(evidence))
        self.assertTrue(should_static_direct_source_fallback(evidence, sink_text))

    def test_fixed_command_template_predicate_rejects_format_slots(self) -> None:
        from advanced_sanitizer_evaluator import (
            _first_arg_register_name,
            preview_is_fixed_command_template,
        )

        self.assertTrue(
            preview_is_fixed_command_template("dhcp6c -c /tmp/dhcp6c.conf wan_ifname")
        )
        self.assertFalse(
            preview_is_fixed_command_template("dhcp6c -c /tmp/dhcp6c.conf %s")
        )
        self.assertFalse(
            preview_is_fixed_command_template("wl sta_info /tmp/wds_rate > %d")
        )
        class ArmProject:
            arch = type("Arch", (), {"name": "ARMEL", "bits": 32})()

        class MipsProject:
            arch = type("Arch", (), {"name": "MIPS32", "bits": 32})()

        self.assertEqual(_first_arg_register_name(ArmProject()), "r0")
        self.assertEqual(_first_arg_register_name(MipsProject()), "a0")

    def test_static_evidence_source_obligation_blocks_early_shortcut(self) -> None:
        from advanced_sanitizer_evaluator import (
            closure_static_source_evidence,
            static_evidence_has_source_obligation,
        )

        self.assertFalse(static_evidence_has_source_obligation(None))
        evidence = closure_static_source_evidence(
            {
                "sink": {"string": "system(<MultiValues(<BV32 TOP>)>) @ 0x60fe4"},
                "inputs": {"likely": [], "possibly": ["fread("]},
            }
        )
        self.assertTrue(static_evidence_has_source_obligation(evidence))

    def test_resource_format_slot_is_guarded_recovery(self) -> None:
        from advanced_sanitizer_evaluator import assess_static_dynamic_recovery

        evidence = {
            "static_source_markers": [],
            "static_likely_inputs": [],
            "static_possible_inputs": ["sys.mode", "wan1.connecttype"],
            "static_possible_resource_inputs": ["wan1.connecttype"],
            "static_evidence_strength": "weak",
        }

        assessment = assess_static_dynamic_recovery(evidence, "cat /etc/ddns_%s")

        self.assertTrue(assessment["auto_recover"])
        self.assertEqual(assessment["recovery_confidence"], "static_resource_with_format_slot")
        self.assertEqual(assessment["recovered_source_prefix"], "config_val")

    def test_resource_recovery_rejects_fixed_command(self) -> None:
        from advanced_sanitizer_evaluator import assess_static_dynamic_recovery

        evidence = {
            "static_possible_inputs": ["wan1.connecttype"],
            "static_possible_resource_inputs": ["wan1.connecttype"],
            "static_evidence_strength": "weak",
        }

        assessment = assess_static_dynamic_recovery(evidence, "cat /etc/ddns_safe")

        self.assertFalse(assessment["auto_recover"])
        self.assertEqual(assessment["recovery_blocked_reason"], "static_source_not_bound_to_sink_template")

    def test_merge_preserves_binary_recovered_template(self) -> None:
        from advanced_sanitizer_evaluator import (
            closure_static_source_evidence,
            merge_static_evidence,
        )

        closure = {
            "sink": {"string": "system(<MultiValues(<BV32 TOP>)>) @ 0x60fe4"},
            "inputs": {"likely": [], "possibly": ["fread("]},
        }
        raw = closure_static_source_evidence(closure)
        enriched = merge_static_evidence(
            raw,
            {
                "static_sink_template": "rm -rf /tmp/databaseinfo.txt /tmp/tmp_databaseinfo.txt",
                "static_evidence_reasons": ["binary_local_format_template"],
            },
        )

        merged_again = merge_static_evidence(enriched, raw)

        self.assertEqual(
            merged_again["static_sink_template"],
            "rm -rf /tmp/databaseinfo.txt /tmp/tmp_databaseinfo.txt",
        )
        self.assertIn("binary_local_format_template", merged_again["static_evidence_reasons"])
        self.assertIn("possible_resource_input", merged_again["static_evidence_reasons"])

    def test_report_record_merges_enhanced_static_evidence(self) -> None:
        from advanced_sanitizer_evaluator import make_report_record

        closure = {
            "trace": [{"function": "sub_60db8", "ins_addr": "0x60db8", "string": "sub_60db8()"}],
            "sink": {
                "function": "system",
                "ins_addr": "0x60fe4",
                "string": "system(<MultiValues(<BV32 TOP>)>) @ 0x60fe4",
            },
            "inputs": {"likely": [], "possibly": ["fread("]},
        }

        record = make_report_record(
            {
                "status": "no_taint_sink",
                "static_sink_template": "rm -rf /tmp/databaseinfo.txt /tmp/tmp_databaseinfo.txt",
                "static_evidence_reasons": ["binary_local_format_template"],
                "static_evidence_strength": "weak",
            },
            closure_idx=42,
            total_closures=76,
            closure=closure,
        )

        self.assertEqual(
            record["static_evidence"]["static_sink_template"],
            "rm -rf /tmp/databaseinfo.txt /tmp/tmp_databaseinfo.txt",
        )
        self.assertIn("binary_local_format_template", record["static_evidence"]["static_evidence_reasons"])


if __name__ == "__main__":
    unittest.main()
