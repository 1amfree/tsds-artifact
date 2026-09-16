# TSDS Analysis Report

- Generated: 2026-09-15 23:38:28
- Binary: `/home/ubuntu/work/sanitizer/Tenda_AC15/httpd`
- Trace JSON: `/home/ubuntu/work/sanitizer/Tenda_AC15/Tenda_AC15_results/cmdi_results.json`
- Mode: `full`
- Total closures: 65
- Unique pairs expected: 64
- Unique pairs analyzed: 64

## Executive Summary

| Metric | Value |
|---|---:|
| SV-SAT | 3 |
| Modeled-vector filtered | 0 |
| Partially filtered SV-SAT | 1 |
| No-modeled-source sink | 0 |
| Static source inference | 17 |
| Static warning reduction | 0 |
| Residual obligation | 31 |
| Unreachable | 13 |
| Timeout | 0 |
| Crashed | 0 |
| Evaluation errors | 0 |
| SAT shell-vector witnesses | 25 |
| Blocked-vector proofs | 8 |
| Average sanitizer coverage | 0.2424 |
| Wall time seconds | 2802.7470 |
| Average closure time seconds | 43.6802 |
| Average matrix time seconds | 0.8426 |
| Average engine steps | 129.8300 |
| Semantic frontier cuts | 1734 |
| Source-liveness cuts | 2 |
| Delay-slot sink captures | 0 |
| Loop semantic cuts | 0 |
| Seed states tried | 316 |
| Seed states pruned | 96 |
| Memoized closures | 0 |
| Evidence cache hits | 0 |

## Model Gap Requests

| Dimension | Count |
|---|---:|
| kind:config_key | 112 |
| kind:web | 40 |
| kind:file | 8 |
| reason:mango_possible_input | 63 |
| reason:mango_likely_input | 30 |
| reason:trace_expression_token | 29 |
| reason:trace_uses_web_parser | 26 |
| reason:trace_uses_config_api | 12 |

| Closure | Kind | Key | Reason | Confidence | Evidence |
|---:|---|---|---|---|---|
| 1 | config_key | usb.samba.user | mango_likely_input | high | usb.samba.user |
| 1 | config_key | usb.samba.pwd | mango_possible_input | medium | usb.samba.pwd |
| 3 | web | formWriteFacMac | trace_uses_web_parser | medium | formWriteFacMac -> doSystemCmd |
| 4 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 4 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 4 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 4 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 4 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 4 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 4 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 4 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 4 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 5 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 5 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 5 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 5 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 5 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 5 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 5 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 5 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 5 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 6 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 6 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 6 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 6 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 6 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 6 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 6 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 6 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 6 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 7 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 7 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 7 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 7 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 7 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 7 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 7 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 7 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 7 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 8 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 8 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 8 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 8 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 8 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 8 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 8 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 8 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 8 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 9 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 9 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 9 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 9 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 9 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 9 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 9 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 9 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 9 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 10 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 10 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 10 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 10 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 10 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 10 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 10 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 10 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 10 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 11 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 11 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 11 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 11 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 11 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 11 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 11 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 11 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 11 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 12 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 12 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 12 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 12 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 12 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 12 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 12 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 12 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 12 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 13 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 13 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 13 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 13 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 13 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 13 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 13 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 13 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 13 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 14 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 14 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 14 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 14 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 14 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 14 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 14 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 14 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 14 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 15 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 15 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 15 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 15 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 15 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 15 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 15 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac8... |
| 15 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 15 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 16 | web | formexeCommand | trace_uses_web_parser | medium | formexeCommand -> doSystemCmd |
| 17 | web | formexeCommand | trace_uses_web_parser | medium | formexeCommand -> doSystemCmd |
| 18 | web | formexeCommand | trace_uses_web_parser | medium | formexeCommand -> doSystemCmd |
| 19 | web | formexeCommand | trace_uses_web_parser | medium | formexeCommand -> doSystemCmd |
| 20 | web | formexeCommand | trace_uses_web_parser | medium | formexeCommand -> doSystemCmd |
| 22 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 22 | config_key | lan.ip | trace_expression_token | medium | TendaTelnet(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x4fb88 doSy... |
| 25 | web | cgi_debug | mango_likely_input | high | cgi_debug |
| 25 | config_key | macfilter.mode | mango_possible_input | medium | macfilter.mode |
| 25 | web | cgi_debug | trace_expression_token | medium | formAddMacfilterRule(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xc... |
| 25 | web | formAddMacfilterRule | trace_uses_web_parser | medium | formAddMacfilterRule -> doSystemCmd |
| 26 | config_key | usb.samba.enable | mango_possible_input | medium | usb.samba.enable |
| 26 | config_key | usb.samba.guest.user | mango_possible_input | medium | usb.samba.guest.user |
| 26 | web | formSetSambaConf | trace_uses_web_parser | medium | formSetSambaConf -> doSystemCmd |
| 27 | config_key | usb.samba.guest.user | mango_likely_input | high | usb.samba.guest.user |
| 27 | config_key | usb.samba.enable | mango_possible_input | medium | usb.samba.enable |
| 27 | config_key | usb.samba.guest.user | trace_expression_token | medium | formSetSambaConf(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa56c8... |
| 27 | web | formSetSambaConf | trace_uses_web_parser | medium | formSetSambaConf -> doSystemCmd |
| 28 | config_key | wans.flag | mango_possible_input | medium | wans.flag |
| 28 | web | formSetIptv | trace_uses_web_parser | medium | formSetIptv -> doSystemCmd |
| 29 | config_key | wans.flag | mango_possible_input | medium | wans.flag |
| 29 | web | formSetIptv | trace_uses_web_parser | medium | formSetIptv -> doSystemCmd |
| 30 | config_key | wans.flag | mango_possible_input | medium | wans.flag |
| 30 | web | formSetIptv | trace_uses_web_parser | medium | formSetIptv -> doSystemCmd |
| 31 | config_key | wans.flag | mango_possible_input | medium | wans.flag |
| 31 | web | formSetIptv | trace_uses_web_parser | medium | formSetIptv -> doSystemCmd |
| 34 | web | formsetUsbUnload | trace_uses_web_parser | medium | formsetUsbUnload -> doSystemCmd |
| 35 | file | /var/sta_encode_ssid_cache | mango_possible_input | medium | /var/sta_encode_ssid_cache |
| 36 | file | /var/sta_encode_ssid_cache | mango_possible_input | medium | /var/sta_encode_ssid_cache |
| 37 | file | /var/sta_encode_ssid_cache | mango_possible_input | medium | /var/sta_encode_ssid_cache |
| 38 | file | /var/sta_encode_ssid_cache | mango_possible_input | medium | /var/sta_encode_ssid_cache |
| 39 | file | /var/sta_encode_ssid_cache | mango_possible_input | medium | /var/sta_encode_ssid_cache |
| 40 | file | /var/sta_encode_ssid_cache | mango_possible_input | medium | /var/sta_encode_ssid_cache |
| 44 | file | /proc/mounts | mango_likely_input | high | /proc/mounts |
| 44 | file | /proc/mounts | trace_expression_token | medium | sub_69bbc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x69bbc doSystemCmd(<MultiValues(<BV2216 ... |
| 46 | config_key | lan.gst.1.ip | mango_likely_input | high | lan.gst.1.ip |
| 46 | config_key | dhcps.gst.1.en | mango_possible_input | medium | dhcps.gst.1.en |
| 46 | config_key | dhcps.en | mango_possible_input | medium | dhcps.en |
| 46 | config_key | lan.gst.1.ip | trace_expression_token | medium | sub_3a648() @ 0x3a648 doSystemCmd(<MultiValues(<BV2160 0x6966636f6e66696720 .. GetValue("lan.gst.1.ip")@0x3... |
| 48 | config_key | wl5g.public.mode | mango_possible_input | medium | wl5g.public.mode |
| 49 | config_key | wl5g.public.mode | mango_possible_input | medium | wl5g.public.mode |
| 50 | config_key | wl5g.public.mode | mango_possible_input | medium | wl5g.public.mode |
| 62 | config_key | wl0_ifname | mango_possible_input | medium | wl0_ifname |
| 62 | config_key | wans.flag | mango_possible_input | medium | wans.flag |
| 62 | config_key | wl1_ifname | mango_possible_input | medium | wl1_ifname |
| 63 | config_key | wl0_ifname | mango_possible_input | medium | wl0_ifname |
| 63 | config_key | wans.flag | mango_possible_input | medium | wans.flag |
| 63 | config_key | wl1_ifname | mango_possible_input | medium | wl1_ifname |
| 64 | config_key | wan1.connecttype | mango_possible_input | medium | wan1.connecttype |

## Engine Stop Reasons

| Stop reason | Count |
|---|---:|
| `active_empty` | 22 |
| `engine_timeout` | 6 |
| `guided_stagnation_saturated` | 3 |
| `multi_state_settle_budget_exhausted` | 24 |
| `source_liveness_saturated` | 2 |
| `step_budget_exhausted` | 7 |

## Feature Configuration

| Feature | Value |
|---|---|
| `arch_seeding` | `True` |
| `byte_provenance` | `True` |
| `constraint_projection_cache_size` | `2048` |
| `emit_provenance_graph` | `False` |
| `environment_fixture` | `False` |
| `environment_fixture_digest` | `52a76f5de8b7ca65` |
| `evidence_aware_scheduler` | `True` |
| `execution_backend` | `forkserver` |
| `firmware_summaries` | `True` |
| `loop_semantic_bucket_limit` | `1` |
| `loop_semantic_min_states` | `50` |
| `loop_semantic_min_visits` | `3` |
| `loop_semantic_saturation_limit` | `3` |
| `loop_semantic_summary` | `True` |
| `loop_semantic_weak_static` | `False` |
| `multi_state_audit` | `True` |
| `multi_state_settle_steps` | `8` |
| `online_refinement_candidates` | `3` |
| `online_refinement_rounds` | `1` |
| `refinement_bundle` | `False` |
| `resource_limit_enforcement` | `not_requested` |
| `scheduler_active_cap_range` | `[20, 120]` |
| `scheduler_base_active_cap` | `60` |
| `scheduler_constraint_soft_limit` | `800` |
| `scheduler_escape_quota` | `4` |
| `semantic_frontier` | `True` |
| `shell_lexical_gate` | `tsds-shell-lexical-gate-v1` |
| `sink_corridor` | `True` |
| `sink_semantic_plugins` | `True` |
| `solver_query_export` | `False` |
| `source_dead_state_cap` | `20` |
| `source_liveness_limit` | `4` |
| `source_projected_constraints` | `True` |
| `static_dynamic_reconciliation` | `True` |
| `subprocess_memory_limit_mib` | `0` |
| `summary_database` | `False` |
| `threat_matrix` | `True` |
| `weak_evidence_equiv_limit` | `2` |

## Evidence Confidence Overview

| Dimension | Count |
|---|---:|
| confidence:high | 1 |
| confidence:medium | 2 |
| confidence:low | 61 |
| review:critical | 3 |
| review:high | 61 |
| claim:direct_sink_byte_sv_sat_evidence | 3 |
| claim:evidence_contract_residual | 31 |
| claim:residual_unclear_outcome | 13 |
| claim:static_source_slot_inference | 17 |

## Semantic Path-Control Ledger

| Dimension | Count |
|---|---:|
| class:direct_sink_evidence | 3 |
| class:residual_budget_stop | 20 |
| class:semantic_saturation | 2 |
| class:unclassified | 39 |
| pressure:not_applicable | 39 |
| pressure:residual_risk | 20 |
| pressure:resolved | 3 |
| pressure:semantically_bounded | 2 |
| total:path_control_pruned_states | 1907 |
| total:semantic_pruned_states | 1734 |
| total:seed_pruned | 96 |

## Residual Diagnosis

| Dimension | Count |
|---|---:|
| class:bounded_multi_state_no_admissible_primary | 29 |
| class:static_source_inference_unconfirmed | 17 |
| class:path_explosion_residual | 13 |
| class:evidence_contract_residual | 2 |
| severity:high | 61 |
| action:inspect contract violations and vector decisions | 31 |
| action:keep the record outside SV-SAT, M-Filt, and NMS aggregates | 31 |
| action:rerun unknown quote contexts or pruned negative paths conservatively | 31 |
| action:do not aggregate this record as SV-SAT or NMS | 17 |
| action:inspect missing wrapper, parser, and environment summaries | 17 |
| action:replay with a larger reachability budget | 17 |
| action:add a targeted parser or wrapper summary if the trace repeats around one helper | 13 |
| action:increase max steps or closure timeout for this closure | 13 |

## Residual Recovery Plan

| Dimension | Count |
|---|---:|
| strategy:manual_review | 42 |
| strategy:semantic_path_refinement | 13 |
| strategy:budget_extension_rerun | 6 |
| priority:medium | 42 |
| priority:high | 19 |
| model-gap:loop_or_parser_summary | 13 |
| model-gap:sink_distance_model | 13 |
| config:closure_timeout=180 | 19 |
| config:max_steps=1000 | 19 |
| config:loop_semantic_saturation_limit=5 | 13 |
| config:semantic_frontier_bucket_limit=3 | 13 |
| config:engine_timeout=90 | 6 |
| config:subprocess_timeout=240 | 6 |
| config:loop_semantic_weak_static=True | 3 |

## Sanitizer Gap Diagnosis

| Dimension | Count |
|---|---:|
| strength:broadly_bypassable | 2 |
| strength:partial_filter | 1 |
| bypass:Command Substitution | 3 |
| bypass:Variable Expansion | 3 |
| bypass:Background Execution | 2 |
| bypass:Bypass Spaces | 2 |
| bypass:Command Chaining | 2 |
| bypass:Piping | 2 |
| bypass:Redirection | 2 |
| blocked:Background Execution | 1 |
| blocked:Bypass Spaces | 1 |
| blocked:Command Chaining | 1 |
| blocked:Piping | 1 |
| blocked:Redirection | 1 |

## Vulnerable And Partial Findings

| Closure | Status | Vectors V/S | Coverage | Source kinds | Recovery | Preview |
|---:|---|---:|---:|---|---|---|
| 23 | vulnerable | 11/0 | 0.0000 | entry_arg |  | echo "%s" >> /etc/chengyanconfig/</dev/nullAAAAAAAAAAAAAAAAAAAAA |
| 32 | vulnerable | 11/0 | 0.0000 | entry_arg |  | mv :;:;#AAAAAAAAAAAAAAAAAAAAAAAAAA |
| 47 | vulnerable | 3/8 | 0.7273 | file |  | cfm post netctrl 51?op=1,string_info=$AA:AAA |

## Unclear Or Operational Outcomes

| Closure | Status | Diagnosis | Severity | Reason | Time(s) | Static evidence | Preview/Error |
|---:|---|---|---|---|---:|---|---|
| 33 | unreachable | path_explosion_residual | high | active_empty | 3.4309 | absent |  |
| 36 | unreachable | path_explosion_residual | high | guided_stagnation_saturated | 77.4325 | weak |  |
| 37 | unreachable | path_explosion_residual | high | guided_stagnation_saturated | 90.8240 | weak |  |
| 38 | unreachable | path_explosion_residual | high | guided_stagnation_saturated | 91.4945 | weak |  |
| 39 | unreachable | path_explosion_residual | high | active_empty | 45.1487 | weak |  |
| 40 | unreachable | path_explosion_residual | high | active_empty | 45.6928 | weak |  |
| 42 | unreachable | path_explosion_residual | high | step_budget_exhausted | 17.1229 | absent |  |
| 43 | unreachable | path_explosion_residual | high | step_budget_exhausted | 17.2095 | absent |  |
| 48 | unreachable | path_explosion_residual | high | step_budget_exhausted | 15.5199 | weak |  |
| 49 | unreachable | path_explosion_residual | high | step_budget_exhausted | 15.5767 | weak |  |
| 50 | unreachable | path_explosion_residual | high | step_budget_exhausted | 15.2581 | weak |  |
| 61 | unreachable | path_explosion_residual | high | active_empty | 2.1813 | absent |  |
| 65 | unreachable | path_explosion_residual | high | step_budget_exhausted | 31.4623 | absent |  |

## Trace-Level Analysis

### Trace 1: `residual`

- Trace path: `sub_a63ac -> system`
- Source: `sub_a63ac` at `0xa63ac`
- Sink: `system` at `0xa6518`
- Stop/reason: `active_empty`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:usb.samba.user (mango_likely_input); config_key:usb.samba.pwd (mango_possible_input)`
- Result metrics: elapsed=6.0390s, steps=47, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `usb.samba.user`
- Possible inputs: `usb.samba.pwd`
- Source expression: `sub_a63ac() @ 0xa63ac`
- Sink expression: `system(<MultiValues(<BV32 stack_base - 0x410>)>) @ 0xa6518`
- Sink/result preview: `smbpasswd -a admin -s < /tmp/smbpasswd`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a63ac` | `0xa63ac` | `sub_a63ac() @ 0xa63ac` |

### Trace 3: `residual`

- Trace path: `formWriteFacMac -> doSystemCmd`
- Source: `formWriteFacMac` at `0x4550c`
- Sink: `doSystemCmd` at `0x45574`
- Stop/reason: `active_empty`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `web:formWriteFacMac (trace_uses_web_parser)`
- Result metrics: elapsed=28.5827s, steps=247, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `formWriteFacMac(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x4550c`
- Sink expression: `doSystemCmd(<MultiValues(<BV2112 0x63666d206d616320 .. Reverse(dweb_get_extracted@45548_1531_2048)>)>, <MultiValues(<BV32 heap_base>)>) @ 0x45574`
- Sink/result preview: `cfm mac 00:01:02:11:22:33`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formWriteFacMac` | `0x4550c` | `formWriteFacMac(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x4550c` |

### Trace 4: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac818`
- Sink: `doSystemCmd` at `0xad30c`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=42, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=50, density=0.3968
- Path-control events: `semantic_frontier:46, seed_equivalence:4`
- Path-control audit: `50 pruned/omitted states or seeds; 28 frontier rounds, 0 loop rounds; max active 20; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); config_key:security.ddos.map (mango_possible_input); web:lan.webport (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=93.1277s, steps=126, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `security.ddos.map, TOP, lan.webport, firewall.pingwan, security.ipop.map`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV2344 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. GetValue("TOP")@0xad108[1535:0] .. GetValue("TOP")@0xad0f0[255:0] .. 0x202d702069636d70202d6d2069636d70202d2d69...`
- Sink/result preview: `iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac818` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818` |

### Trace 5: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac818`
- Sink: `doSystemCmd` at `0xad1b0`
- Stop/reason: `engine_timeout`
- Static evidence: `strong`
- Evidence confidence: `low` score=34, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, path_budget_residual_risk, strong_static_binding, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=95, density=0.3333
- Path-control events: `semantic_frontier:90, seed_equivalence:5`
- Path-control audit: `95 pruned/omitted states or seeds; 60 frontier rounds, 0 loop rounds; max active 25; stop engine_timeout`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`budget_extension_rerun`, priority=`high`, overrides=`closure_timeout=180, engine_timeout=90, max_steps=1000, subprocess_timeout=240`, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); config_key:security.ddos.map (mango_possible_input); web:lan.webport (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=115.3734s, steps=285, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `security.ddos.map, TOP, lan.webport, firewall.pingwan, security.ipop.map`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. Reverse(GetValue("lan.ip")@0xaa218[1727:1696]) - 0x298 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d7479...`
- Sink/result preview: `iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac818` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818` |

### Trace 6: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac818`
- Sink: `doSystemCmd` at `0xad1e4`
- Stop/reason: `engine_timeout`
- Static evidence: `strong`
- Evidence confidence: `low` score=34, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, path_budget_residual_risk, strong_static_binding, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=93, density=0.3536
- Path-control events: `semantic_frontier:88, seed_equivalence:5`
- Path-control audit: `93 pruned/omitted states or seeds; 50 frontier rounds, 0 loop rounds; max active 25; stop engine_timeout`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`budget_extension_rerun`, priority=`high`, overrides=`closure_timeout=180, engine_timeout=90, max_steps=1000, subprocess_timeout=240`, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); config_key:security.ddos.map (mango_possible_input); web:lan.webport (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=113.6397s, steps=263, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `security.ddos.map, TOP, lan.webport, firewall.pingwan, security.ipop.map`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. Reverse(GetValue("lan.mask")@0xaa23c[1599:1568]) - 0x298 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d74...`
- Sink/result preview: `iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac818` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818` |

### Trace 7: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac818`
- Sink: `doSystemCmd` at `0xad3cc`
- Stop/reason: `engine_timeout`
- Static evidence: `strong`
- Evidence confidence: `low` score=34, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, path_budget_residual_risk, strong_static_binding, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=81, density=0.2682
- Path-control events: `semantic_frontier:70, seed_equivalence:6`
- Path-control audit: `81 pruned/omitted states or seeds; 44 frontier rounds, 0 loop rounds; max active 20; stop engine_timeout`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`budget_extension_rerun`, priority=`high`, overrides=`closure_timeout=180, engine_timeout=90, max_steps=1000, subprocess_timeout=240`, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); config_key:security.ddos.map (mango_possible_input); web:lan.webport (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=90.4183s, steps=302, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `security.ddos.map, TOP, lan.webport, firewall.pingwan, security.ipop.map`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV2344 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. GetValue("TOP")@0xad108[1535:0] .. GetValue("TOP")@0xad0f0[255:0] .. 0x202d702069636d70202d6d2069636d70202d2d69...`
- Sink/result preview: `iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac818` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818` |

### Trace 8: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac818`
- Sink: `doSystemCmd` at `0xad3b4`
- Stop/reason: `engine_timeout`
- Static evidence: `strong`
- Evidence confidence: `low` score=34, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, path_budget_residual_risk, strong_static_binding, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=88, density=0.3667
- Path-control events: `semantic_frontier:77, seed_equivalence:6`
- Path-control audit: `88 pruned/omitted states or seeds; 48 frontier rounds, 0 loop rounds; max active 20; stop engine_timeout`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`budget_extension_rerun`, priority=`high`, overrides=`closure_timeout=180, engine_timeout=90, max_steps=1000, subprocess_timeout=240`, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); config_key:security.ddos.map (mango_possible_input); web:lan.webport (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=90.4432s, steps=240, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `security.ddos.map, TOP, lan.webport, firewall.pingwan, security.ipop.map`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. Reverse(GetValue("lan.ip")@0xaa218[1727:1696]) - 0x298 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d7479...`
- Sink/result preview: `iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac818` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818` |

### Trace 9: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac818`
- Sink: `doSystemCmd` at `0xad2f4`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=42, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=62, density=0.5000
- Path-control events: `semantic_frontier:59, seed_equivalence:3`
- Path-control audit: `62 pruned/omitted states or seeds; 39 frontier rounds, 0 loop rounds; max active 24; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); config_key:security.ddos.map (mango_possible_input); web:lan.webport (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=108.9592s, steps=124, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `security.ddos.map, TOP, lan.webport, firewall.pingwan, security.ipop.map`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV2216 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. GetValue("TOP")@0xad108[1407:0] .. GetValue("TOP")@0xad0f0[255:0] .. 0x202d702069636d70202d6d2069636d70202d2d69...`
- Sink/result preview: `iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac818` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818` |

### Trace 10: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac818`
- Sink: `doSystemCmd` at `0xad398`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=42, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=54, density=0.4320
- Path-control events: `semantic_frontier:51, seed_equivalence:3`
- Path-control audit: `54 pruned/omitted states or seeds; 32 frontier rounds, 0 loop rounds; max active 27; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); config_key:security.ddos.map (mango_possible_input); web:lan.webport (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=105.1351s, steps=125, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `security.ddos.map, TOP, lan.webport, firewall.pingwan, security.ipop.map`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV2216 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. GetValue("TOP")@0xad108[1407:0] .. GetValue("TOP")@0xad0f0[255:0] .. 0x202d702069636d70202d6d2069636d70202d2d69...`
- Sink/result preview: `iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac818` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818` |

### Trace 11: `residual`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac818`
- Sink: `doSystemCmd` at `0xad358`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=22, density=0.2391
- Path-control events: `semantic_frontier:22`
- Path-control audit: `22 pruned/omitted states or seeds; 14 frontier rounds, 0 loop rounds; max active 20; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); config_key:security.ddos.map (mango_possible_input); web:lan.webport (mango_possible_input)`
- Result metrics: elapsed=87.2873s, steps=92, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `security.ddos.map, TOP, lan.webport, firewall.pingwan, security.ipop.map`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. Reverse(GetValue("lan.ip")@0xaa218[1727:1696]) - 0x298 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d7479...`
- Sink/result preview: `iptables -t filter -D INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac818` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818` |

### Trace 12: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac818`
- Sink: `doSystemCmd` at `0xad1c8`
- Stop/reason: `engine_timeout`
- Static evidence: `strong`
- Evidence confidence: `low` score=34, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, path_budget_residual_risk, strong_static_binding, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=98, density=0.2545
- Path-control events: `semantic_frontier:93, seed_equivalence:5`
- Path-control audit: `98 pruned/omitted states or seeds; 52 frontier rounds, 0 loop rounds; max active 25; stop engine_timeout`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`budget_extension_rerun`, priority=`high`, overrides=`closure_timeout=180, engine_timeout=90, max_steps=1000, subprocess_timeout=240`, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); config_key:security.ddos.map (mango_possible_input); web:lan.webport (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=112.1119s, steps=385, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `security.ddos.map, TOP, lan.webport, firewall.pingwan, security.ipop.map`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4920494e505554202d6920 .. Reverse(GetValue("lan.ip")@0xaa218[1727:1696]) - 0x298 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d7479...`
- Sink/result preview: `iptables -t filter -I INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac818` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818` |

### Trace 13: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac818`
- Sink: `doSystemCmd` at `0xad324`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=42, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=42, density=0.3281
- Path-control events: `semantic_frontier:39, seed_equivalence:3`
- Path-control audit: `42 pruned/omitted states or seeds; 30 frontier rounds, 0 loop rounds; max active 26; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); config_key:security.ddos.map (mango_possible_input); web:lan.webport (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=99.5858s, steps=128, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `security.ddos.map, TOP, lan.webport, firewall.pingwan, security.ipop.map`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4920494e505554202d6920 .. Reverse(GetValue("lan.ip")@0xaa218[1727:1696]) - 0x298 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d7479...`
- Sink/result preview: `iptables -t filter -I INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac818` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818` |

### Trace 14: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac818`
- Sink: `doSystemCmd` at `0xad33c`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=42, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=46, density=0.3538
- Path-control events: `semantic_frontier:43, seed_equivalence:3`
- Path-control audit: `46 pruned/omitted states or seeds; 31 frontier rounds, 0 loop rounds; max active 26; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); config_key:security.ddos.map (mango_possible_input); web:lan.webport (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=102.8919s, steps=130, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `security.ddos.map, TOP, lan.webport, firewall.pingwan, security.ipop.map`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4920494e505554202d6920 .. Reverse(GetValue("lan.mask")@0xaa23c[1599:1568]) - 0x2a8 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d74...`
- Sink/result preview: `iptables -t filter -I INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac818` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818` |

### Trace 15: `residual`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac818`
- Sink: `doSystemCmd` at `0xad370`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=22, density=0.2340
- Path-control events: `semantic_frontier:22`
- Path-control audit: `22 pruned/omitted states or seeds; 14 frontier rounds, 0 loop rounds; max active 20; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); config_key:security.ddos.map (mango_possible_input); web:lan.webport (mango_possible_input)`
- Result metrics: elapsed=85.3007s, steps=94, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `security.ddos.map, TOP, lan.webport, firewall.pingwan, security.ipop.map`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4920494e505554202d6920 .. Reverse(GetValue("lan.mask")@0xaa23c[1599:1568]) - 0x298 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d74...`
- Sink/result preview: `iptables -t filter -I INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac818` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac818` |

### Trace 16: `residual`

- Trace path: `formexeCommand -> doSystemCmd`
- Source: `formexeCommand` at `0x7ba84`
- Sink: `doSystemCmd` at `0x7bc0c`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 6; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `web:formexeCommand (trace_uses_web_parser)`
- Result metrics: elapsed=13.4891s, steps=47, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `formexeCommand(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7ba84`
- Sink expression: `doSystemCmd(<MultiValues(<BV216 0x6563686f20 .. TOP .. 0x203e202f746d702f636d64546d702e747874>)>, <MultiValues(<BV32 0x102e84>)>) @ 0x7bc0c`
- Sink/result preview: `echo / > /tmp/cmdTmp.txt`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formexeCommand` | `0x7ba84` | `formexeCommand(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7ba84` |

### Trace 17: `residual`

- Trace path: `formexeCommand -> doSystemCmd`
- Source: `formexeCommand` at `0x7ba84`
- Sink: `doSystemCmd` at `0x7bd34`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 6; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `web:formexeCommand (trace_uses_web_parser)`
- Result metrics: elapsed=15.3122s, steps=48, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `formexeCommand(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7ba84`
- Sink expression: `doSystemCmd(<MultiValues(<BV216 0x6563686f20 .. TOP .. 0x203e202f746d702f636d64546d702e747874>)>, <MultiValues(<BV32 0x102e84>)>) @ 0x7bd34`
- Sink/result preview: `echo %s > /tmp/cmdTmp.txt`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formexeCommand` | `0x7ba84` | `formexeCommand(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7ba84` |

### Trace 18: `residual`

- Trace path: `formexeCommand -> doSystemCmd`
- Source: `formexeCommand` at `0x7ba84`
- Sink: `doSystemCmd` at `0x7bc58`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 7; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `web:formexeCommand (trace_uses_web_parser)`
- Result metrics: elapsed=47.4452s, steps=70, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `formexeCommand(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7ba84`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV176 TOP .. 0x203e202f746d702f636d64546d702e747874>, <BV176 TOP .. 0x203e202f746d702f636d64546d702e747874>}})>, <MultiValues(<BV32 stack_base - 0x220>)>) @ 0x7bc58`
- Sink/result preview: `%s > /tmp/cmdTmp.txt`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formexeCommand` | `0x7ba84` | `formexeCommand(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7ba84` |

### Trace 19: `residual`

- Trace path: `formexeCommand -> doSystemCmd`
- Source: `formexeCommand` at `0x7ba84`
- Sink: `doSystemCmd` at `0x7bca4`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 7; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `web:formexeCommand (trace_uses_web_parser)`
- Result metrics: elapsed=57.9580s, steps=73, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `formexeCommand(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7ba84`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV176 TOP .. 0x203e202f746d702f636d64546d702e747874>, <BV176 TOP .. 0x203e202f746d702f636d64546d702e747874>}})>, <MultiValues(<BV32 stack_base - 0x220>)>) @ 0x7bca4`
- Sink/result preview: `%s > /tmp/cmdTmp.txt`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formexeCommand` | `0x7ba84` | `formexeCommand(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7ba84` |

### Trace 20: `residual`

- Trace path: `formexeCommand -> doSystemCmd`
- Source: `formexeCommand` at `0x7ba84`
- Sink: `doSystemCmd` at `0x7bcf0`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 7; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `web:formexeCommand (trace_uses_web_parser)`
- Result metrics: elapsed=99.6113s, steps=87, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `formexeCommand(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7ba84`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 stack_base - 0x220>)>) @ 0x7bcf0`
- Sink/result preview: `%s`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formexeCommand` | `0x7ba84` | `formexeCommand(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7ba84` |

### Trace 21: `residual`

- Trace path: `sub_62f70 -> doSystemCmd`
- Source: `sub_62f70` at `0x62f70`
- Sink: `doSystemCmd` at `0x6306c`
- Stop/reason: `source_liveness_saturated`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, source_liveness_pruning, unclear_reachability`
- Path control: `semantic_saturation` pressure=`semantically_bounded`, pruned=47, density=0.6024
- Path-control events: `semantic_frontier:45, source_liveness:3, seed_equivalence:2`
- Path-control audit: `47 pruned/omitted states or seeds; 27 frontier rounds, 0 loop rounds; max active 20; stop source_liveness_saturated`
- Semantic classification: `source_dead_frontier`
- Residual diagnosis: `evidence_contract_residual` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=51.4710s, steps=83, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_62f70() @ 0x62f70`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV32 Reverse(TOP) + 0xfffe3c7c>, <BV32 TOP + 0xfffe3c7c>}})>) @ 0x6306c`
- Sink/result preview: `<source_dead_frontier>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_62f70` | `0x62f70` | `sub_62f70() @ 0x62f70` |

### Trace 22: `residual`

- Trace path: `TendaTelnet -> doSystemCmd`
- Source: `TendaTelnet` at `0x4fb88`
- Sink: `doSystemCmd` at `0x4fc60`
- Stop/reason: `active_empty`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:lan.ip (mango_likely_input); config_key:lan.ip (trace_expression_token)`
- Result metrics: elapsed=4.0248s, steps=9, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.ip`
- Possible inputs: ``
- Source expression: `TendaTelnet(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x4fb88`
- Sink expression: `doSystemCmd(<MultiValues(<BV2152 0x74656c6e657464202d6220 .. GetValue("lan.ip")@0x4fc38 .. 0x2026>)>, <MultiValues(<BV32 stack_base - 0x130>)>) @ 0x4fc60`
- Sink/result preview: `telnetd -b %s &`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `TendaTelnet` | `0x4fb88` | `TendaTelnet(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x4fb88` |

### Trace 23: `vulnerable`

- Trace path: `sub_a7e98 -> doSystemCmd`
- Source: `sub_a7e98` at `0xa7e98`
- Sink: `doSystemCmd` at `0xa7f5c`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `medium` score=64, review=`critical`, claim=`direct_sink_byte_sv_sat_evidence`
- Evidence factors: `absent_static_binding, direct_sink_evidence, sanitizer_gap_profile_broad_bypass, sat_payload_evidence`
- Path control: `direct_sink_evidence` pressure=`resolved`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop multi_state_settle_budget_exhausted`
- Result metrics: elapsed=28.8372s, steps=12, vectors=11/0 vulnerable/secure, coverage=0.0000
- Sanitizer gap: `broadly_bypassable` broad sanitizer gap: all decided vectors are bypassable (11 vector(s))
- Gap categories: bypass=`Background Execution, Bypass Spaces, Command Chaining, Command Substitution, Piping, Redirection, Variable Expansion`, blocked=``
- Minimal bypass: `Background Execution` vector=`&` poc=`echo "%s" >> /etc/chengyanconfig/:&:;#AAAAAAAAAAAAAAAAAAAAAAAAAA`
- Repair hints: `Background Execution: reject or quote ampersand job-control operators; Bypass Spaces: normalize and reject alternate whitespace forms such as tabs and ${IFS}; Command Chaining: reject or quote command separators such as semicolon and newline, or avoid shell...`
- Source expression: `sub_a7e98(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa7e98`
- Sink expression: `doSystemCmd(<MultiValues(<BV344 0x6563686f2022 .. TOP .. 0x22203e3e202f6574632f6368656e6779616e636f6e6669672f .. TOP .. 0x2e646174>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa7f5c`
- Sink/result preview: `echo "%s" >> /etc/chengyanconfig/</dev/nullAAAAAAAAAAAAAAAAAAAAA`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a7e98` | `0xa7e98` | `sub_a7e98(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa7e98` |

### Trace 24: `residual`

- Trace path: `sub_31ff8 -> doSystemCmd`
- Source: `sub_31ff8` at `0x31ff8`
- Sink: `doSystemCmd` at `0x32064`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=4.1473s, steps=10, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_31ff8(<MultiValues(<BV32 TOP>)>) @ 0x31ff8`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xfffdddf8>)>) @ 0x32064`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_31ff8` | `0x31ff8` | `sub_31ff8(<MultiValues(<BV32 TOP>)>) @ 0x31ff8` |

### Trace 25: `static_source_inference`

- Trace path: `formAddMacfilterRule -> doSystemCmd`
- Source: `formAddMacfilterRule` at `0xc3890`
- Sink: `doSystemCmd` at `0xc41b4`
- Stop/reason: `active_empty`
- Static evidence: `strong`
- Evidence confidence: `low` score=34, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, static_direct_source_only, strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=4, density=0.0244
- Path-control events: `seed_equivalence:4`
- Path-control audit: `4 pruned/omitted states or seeds; max active 9; stop active_empty`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `web:cgi_debug (mango_likely_input); config_key:macfilter.mode (mango_possible_input); web:cgi_debug (trace_expression_token); web:formAddMacfilterRule (trace_uses_web_parser)`
- Recovery: `static_direct_source_fallback` `static_direct_source_sink_unreached`
- Result metrics: elapsed=55.8017s, steps=164, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `cgi_debug`
- Possible inputs: `TOP, macfilter.mode`
- Source expression: `formAddMacfilterRule(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xc3890`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 Reverse(GetValue("cgi_debug")@0xc4b08[319:288]) + 0xffff645c>)>) @ 0xc41b4`
- Sink/result preview: `<inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formAddMacfilterRule` | `0xc3890` | `formAddMacfilterRule(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xc3890` |

### Trace 26: `residual`

- Trace path: `formSetSambaConf -> doSystemCmd`
- Source: `formSetSambaConf` at `0xa56c8`
- Sink: `doSystemCmd` at `0xa587c`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:usb.samba.enable (mango_possible_input); config_key:usb.samba.guest.user (mango_possible_input); web:formSetSambaConf (trace_uses_web_parser)`
- Result metrics: elapsed=11.8480s, steps=77, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `usb.samba.enable, usb.samba.guest.user`
- Source expression: `formSetSambaConf(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa56c8`
- Sink expression: `doSystemCmd(<MultiValues(<BV2344 0x63666d20706f7374206e65746374726c2035313f6f703d332c737472696e675f696e666f3d .. Reverse(dweb_get_extracted@a57ac_1573_2048)>)>, <MultiValues(<BV32 0x33>)>, <MultiValues(<BV32 0x3>)>, <...`
- Sink/result preview: `cfm post netctrl 51?op=3,string_info=%s`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetSambaConf` | `0xa56c8` | `formSetSambaConf(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa56c8` |

### Trace 27: `static_source_inference`

- Trace path: `formSetSambaConf -> doSystemCmd`
- Source: `formSetSambaConf` at `0xa56c8`
- Sink: `doSystemCmd` at `0xa58f4`
- Stop/reason: `step_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=26, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, path_budget_residual_risk, static_direct_source_only, strong_static_binding, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=4, density=0.0080
- Path-control events: `seed_equivalence:4`
- Path-control audit: `4 pruned/omitted states or seeds; max active 2; stop step_budget_exhausted`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:usb.samba.guest.user (mango_likely_input); config_key:usb.samba.enable (mango_possible_input); config_key:usb.samba.guest.user (trace_expression_token); web:formSetSambaConf (trace_uses_web_parser)`
- Recovery: `static_direct_source_fallback` `static_direct_source_sink_unreached`
- Result metrics: elapsed=40.7740s, steps=500, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `usb.samba.guest.user`
- Possible inputs: `usb.samba.enable`
- Source expression: `formSetSambaConf(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa56c8`
- Sink expression: `doSystemCmd(<MultiValues(<BV2176 0x62757379626f782064656c7573657220 .. GetValue("usb.samba.guest.user")@0xa58cc>)>, <MultiValues(<BV32 stack_base - 0x74>)>) @ 0xa58f4`
- Sink/result preview: `<inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetSambaConf` | `0xa56c8` | `formSetSambaConf(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa56c8` |

### Trace 28: `static_source_inference`

- Trace path: `formSetIptv -> doSystemCmd`
- Source: `formSetIptv` at `0xb0674`
- Sink: `doSystemCmd` at `0xb05b4`
- Stop/reason: `active_empty`
- Static evidence: `strong`
- Evidence confidence: `low` score=42, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=68, density=0.6296
- Path-control events: `semantic_frontier:64, seed_equivalence:4`
- Path-control audit: `68 pruned/omitted states or seeds; 36 frontier rounds, 0 loop rounds; max active 20; stop active_empty`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:wans.flag (mango_possible_input); web:formSetIptv (trace_uses_web_parser)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=73.7932s, steps=108, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `wans.flag, iptv.stb.enable, iptv.city.vlan, adv.iptv.stbpvid, adv.iptv.stballvlans`
- Source expression: `formSetIptv(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xb0674`
- Sink expression: `doSystemCmd(<MultiValues(<BV2312 0x6e7672616d20736574206164762e697074762e737462616c6c766c616e733d22 .. Reverse(dweb_get_extracted@b07a0_1639_2048) .. 34>)>, <MultiValues(<BV32 heap_base + 0x100>)>) @ 0xb05b4`
- Sink/result preview: `nvram set adv.iptv.stballvlans=" <inferred_web>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetIptv` | `0xb0674` | `formSetIptv(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xb0674` |

### Trace 29: `static_source_inference`

- Trace path: `formSetIptv -> doSystemCmd`
- Source: `formSetIptv` at `0xb0674`
- Sink: `doSystemCmd` at `0xb03c8`
- Stop/reason: `active_empty`
- Static evidence: `strong`
- Evidence confidence: `low` score=42, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=92, density=0.8440
- Path-control events: `semantic_frontier:88, seed_equivalence:4`
- Path-control audit: `92 pruned/omitted states or seeds; 36 frontier rounds, 0 loop rounds; max active 20; stop active_empty`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:wans.flag (mango_possible_input); web:formSetIptv (trace_uses_web_parser)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=67.5124s, steps=109, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `wans.flag, iptv.stb.enable, iptv.city.vlan, adv.iptv.stbpvid, adv.iptv.stballvlans`
- Source expression: `formSetIptv(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xb0674`
- Sink expression: `doSystemCmd(<MultiValues(<BV2312 0x6e7672616d20736574206164762e697074762e737462616c6c766c616e733d22 .. Reverse(dweb_get_extracted@b07a0_1639_2048) .. 34>)>, <MultiValues(<BV32 heap_base + 0x100>)>) @ 0xb03c8`
- Sink/result preview: `nvram set adv.iptv.stballvlans=" <inferred_web>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetIptv` | `0xb0674` | `formSetIptv(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xb0674` |

### Trace 30: `static_source_inference`

- Trace path: `formSetIptv -> doSystemCmd`
- Source: `formSetIptv` at `0xb0674`
- Sink: `doSystemCmd` at `0xb05c8`
- Stop/reason: `active_empty`
- Static evidence: `strong`
- Evidence confidence: `low` score=42, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=72, density=0.6667
- Path-control events: `semantic_frontier:68, seed_equivalence:4`
- Path-control audit: `72 pruned/omitted states or seeds; 40 frontier rounds, 0 loop rounds; max active 20; stop active_empty`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:wans.flag (mango_possible_input); web:formSetIptv (trace_uses_web_parser)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=72.1755s, steps=108, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `wans.flag, iptv.stb.enable, iptv.city.vlan, adv.iptv.stbpvid, adv.iptv.stballvlans`
- Source expression: `formSetIptv(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xb0674`
- Sink expression: `doSystemCmd(<MultiValues(<BV2280 0x6e7672616d20736574206164762e697074762e737462707669643d22 .. Reverse(dweb_get_extracted@b07c4_1640_2048) .. 34>)>, <MultiValues(<BV32 heap_base + 0x200>)>) @ 0xb05c8`
- Sink/result preview: `nvram set adv.iptv.stbpvid=" <inferred_web>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetIptv` | `0xb0674` | `formSetIptv(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xb0674` |

### Trace 31: `static_source_inference`

- Trace path: `formSetIptv -> doSystemCmd`
- Source: `formSetIptv` at `0xb0674`
- Sink: `doSystemCmd` at `0xb03dc`
- Stop/reason: `active_empty`
- Static evidence: `strong`
- Evidence confidence: `low` score=42, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=88, density=0.8073
- Path-control events: `semantic_frontier:84, seed_equivalence:4`
- Path-control audit: `88 pruned/omitted states or seeds; 36 frontier rounds, 0 loop rounds; max active 20; stop active_empty`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:wans.flag (mango_possible_input); web:formSetIptv (trace_uses_web_parser)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=67.4590s, steps=109, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `wans.flag, iptv.stb.enable, iptv.city.vlan, adv.iptv.stbpvid, adv.iptv.stballvlans`
- Source expression: `formSetIptv(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xb0674`
- Sink expression: `doSystemCmd(<MultiValues(<BV2280 0x6e7672616d20736574206164762e697074762e737462707669643d22 .. Reverse(dweb_get_extracted@b07c4_1640_2048) .. 34>)>, <MultiValues(<BV32 heap_base + 0x200>)>) @ 0xb03dc`
- Sink/result preview: `nvram set adv.iptv.stbpvid=" <inferred_web>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetIptv` | `0xb0674` | `formSetIptv(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xb0674` |

### Trace 32: `vulnerable`

- Trace path: `sub_316bc -> doSystemCmd`
- Source: `sub_316bc` at `0x316bc`
- Sink: `doSystemCmd` at `0x3171c`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `medium` score=64, review=`critical`, claim=`direct_sink_byte_sv_sat_evidence`
- Evidence factors: `absent_static_binding, direct_sink_evidence, sanitizer_gap_profile_broad_bypass, sat_payload_evidence`
- Path control: `direct_sink_evidence` pressure=`resolved`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop active_empty`
- Result metrics: elapsed=19.8676s, steps=7, vectors=11/0 vulnerable/secure, coverage=0.0000
- Sanitizer gap: `broadly_bypassable` broad sanitizer gap: all decided vectors are bypassable (11 vector(s))
- Gap categories: bypass=`Background Execution, Bypass Spaces, Command Chaining, Command Substitution, Piping, Redirection, Variable Expansion`, blocked=``
- Minimal bypass: `Background Execution` vector=`&` poc=`mv :&:;#AAAAAAAAAAAAAAAAAAAAAAAAAA`
- Repair hints: `Background Execution: reject or quote ampersand job-control operators; Bypass Spaces: normalize and reject alternate whitespace forms such as tabs and ${IFS}; Command Chaining: reject or quote command separators such as semicolon and newline, or avoid shell...`
- Source expression: `sub_316bc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x316bc`
- Sink expression: `doSystemCmd(<MultiValues(<BV152 0x6d7620 .. TOP .. 0x20202f7661722f696d616765>)>, <MultiValues(<BV32 TOP>)>) @ 0x3171c`
- Sink/result preview: `mv :;:;#AAAAAAAAAAAAAAAAAAAAAAAAAA`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_316bc` | `0x316bc` | `sub_316bc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x316bc` |

### Trace 33: `unreachable`

- Trace path: `sub_6b92c -> doSystemCmd`
- Source: `sub_6b92c` at `0x6b92c`
- Sink: `doSystemCmd` at `0x6b9c4`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `absent_static_binding, missing_sink_preview, path_budget_residual_risk, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Result metrics: elapsed=3.4309s, steps=10, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_6b92c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x6b92c`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP>)>) @ 0x6b9c4`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_6b92c` | `0x6b92c` | `sub_6b92c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x6b92c` |

### Trace 34: `residual`

- Trace path: `formsetUsbUnload -> doSystemCmd`
- Source: `formsetUsbUnload` at `0xa6a30`
- Sink: `doSystemCmd` at `0xa6a94`
- Stop/reason: `active_empty`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `web:formsetUsbUnload (trace_uses_web_parser)`
- Result metrics: elapsed=0.8964s, steps=9, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `formsetUsbUnload(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa6a30`
- Sink expression: `doSystemCmd(<MultiValues(<BV2344 0x63666d20706f7374206e65746374726c2035313f6f703d332c737472696e675f696e666f3d .. Reverse(dweb_get_extracted@a6a74_1642_2048)>)>, <MultiValues(<BV32 0x33>)>, <MultiValues(<BV32 0x3>)>, <...`
- Sink/result preview: `cfm post netctrl 51?op=3,string_info=%s`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formsetUsbUnload` | `0xa6a30` | `formsetUsbUnload(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa6a30` |

### Trace 35: `residual`

- Trace path: `sub_a1a00 -> doSystemCmd`
- Source: `sub_a1a00` at `0xa1a00`
- Sink: `doSystemCmd` at `0xa31b4`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `weak`
- Evidence confidence: `low` score=11, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `missing_sink_preview, unclear_reachability, weak_static_binding`
- Path control: `unclassified` pressure=`not_applicable`, pruned=85, density=1.6667
- Path-control events: `semantic_frontier:85`
- Path-control audit: `85 pruned/omitted states or seeds; 20 frontier rounds, 0 loop rounds; max active 20; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `file:/var/sta_encode_ssid_cache (mango_possible_input)`
- Result metrics: elapsed=68.7876s, steps=51, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP, /var/sta_encode_ssid_cache`
- Source expression: `sub_a1a00() @ 0xa1a00`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV32 TOP + 0xffff27ac>, <BV32 TOP + 0xffff27ac>, <BV32 TOP + 0xffff27ac>}})>) @ 0xa31b4`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a1a00` | `0xa1a00` | `sub_a1a00() @ 0xa1a00` |

### Trace 36: `unreachable`

- Trace path: `sub_a1a00 -> doSystemCmd`
- Source: `sub_a1a00` at `0xa1a00`
- Sink: `doSystemCmd` at `0xa31c8`
- Stop/reason: `guided_stagnation_saturated`
- Static evidence: `weak`
- Evidence confidence: `low` score=3, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `missing_sink_preview, path_budget_residual_risk, unclear_reachability, weak_static_binding`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=112, density=1.4177
- Path-control events: `semantic_frontier:75, seed_equivalence:2`
- Path-control audit: `112 pruned/omitted states or seeds; 24 frontier rounds, 0 loop rounds; max active 29; stop guided_stagnation_saturated`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, loop_semantic_weak_static=True, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Model gap requests: `file:/var/sta_encode_ssid_cache (mango_possible_input)`
- Result metrics: elapsed=77.4325s, steps=79, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP, /var/sta_encode_ssid_cache`
- Source expression: `sub_a1a00() @ 0xa1a00`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV32 TOP + 0xffff27c0>, <BV32 TOP + 0xffff27c0>, <BV32 TOP + 0xffff27c0>}})>) @ 0xa31c8`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a1a00` | `0xa1a00` | `sub_a1a00() @ 0xa1a00` |

### Trace 37: `unreachable`

- Trace path: `sub_a1a00 -> doSystemCmd`
- Source: `sub_a1a00` at `0xa1a00`
- Sink: `doSystemCmd` at `0xa31d8`
- Stop/reason: `guided_stagnation_saturated`
- Static evidence: `weak`
- Evidence confidence: `low` score=3, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `missing_sink_preview, path_budget_residual_risk, unclear_reachability, weak_static_binding`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=96, density=1.0667
- Path-control events: `semantic_frontier:84, seed_equivalence:2`
- Path-control audit: `96 pruned/omitted states or seeds; 27 frontier rounds, 0 loop rounds; max active 37; stop guided_stagnation_saturated`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, loop_semantic_weak_static=True, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Model gap requests: `file:/var/sta_encode_ssid_cache (mango_possible_input)`
- Result metrics: elapsed=90.8240s, steps=90, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP, /var/sta_encode_ssid_cache`
- Source expression: `sub_a1a00() @ 0xa1a00`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV32 TOP + 0xffff2808>, <BV32 TOP + 0xffff2808>, <BV32 TOP + 0xffff2808>}})>) @ 0xa31d8`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a1a00` | `0xa1a00` | `sub_a1a00() @ 0xa1a00` |

### Trace 38: `unreachable`

- Trace path: `sub_a1a00 -> doSystemCmd`
- Source: `sub_a1a00` at `0xa1a00`
- Sink: `doSystemCmd` at `0xa31e8`
- Stop/reason: `guided_stagnation_saturated`
- Static evidence: `weak`
- Evidence confidence: `low` score=3, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `missing_sink_preview, path_budget_residual_risk, unclear_reachability, weak_static_binding`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=97, density=1.0659
- Path-control events: `semantic_frontier:87, seed_equivalence:2`
- Path-control audit: `97 pruned/omitted states or seeds; 30 frontier rounds, 0 loop rounds; max active 37; stop guided_stagnation_saturated`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, loop_semantic_weak_static=True, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Model gap requests: `file:/var/sta_encode_ssid_cache (mango_possible_input)`
- Result metrics: elapsed=91.4945s, steps=91, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP, /var/sta_encode_ssid_cache`
- Source expression: `sub_a1a00() @ 0xa1a00`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV32 TOP + 0xffff2850>, <BV32 TOP + 0xffff2850>, <BV32 TOP + 0xffff2850>}})>) @ 0xa31e8`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a1a00` | `0xa1a00` | `sub_a1a00() @ 0xa1a00` |

### Trace 39: `unreachable`

- Trace path: `sub_a1a00 -> doSystemCmd`
- Source: `sub_a1a00` at `0xa1a00`
- Sink: `doSystemCmd` at `0xa3474`
- Stop/reason: `active_empty`
- Static evidence: `weak`
- Evidence confidence: `low` score=3, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `missing_sink_preview, path_budget_residual_risk, unclear_reachability, weak_static_binding`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=86, density=1.2647
- Path-control events: `semantic_frontier:84, seed_equivalence:2`
- Path-control audit: `86 pruned/omitted states or seeds; 24 frontier rounds, 0 loop rounds; max active 20; stop active_empty`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Model gap requests: `file:/var/sta_encode_ssid_cache (mango_possible_input)`
- Result metrics: elapsed=45.1487s, steps=68, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP, /var/sta_encode_ssid_cache`
- Source expression: `sub_a1a00() @ 0xa1a00`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV32 TOP + 0xffff25e4>, <BV32 TOP + 0xffff25e4>, <BV32 TOP + 0xffff25e4>}})>) @ 0xa3474`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a1a00` | `0xa1a00` | `sub_a1a00() @ 0xa1a00` |

### Trace 40: `unreachable`

- Trace path: `sub_a1a00 -> doSystemCmd`
- Source: `sub_a1a00` at `0xa1a00`
- Sink: `doSystemCmd` at `0xa34a0`
- Stop/reason: `active_empty`
- Static evidence: `weak`
- Evidence confidence: `low` score=3, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `missing_sink_preview, path_budget_residual_risk, unclear_reachability, weak_static_binding`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=86, density=1.2647
- Path-control events: `semantic_frontier:84, seed_equivalence:2`
- Path-control audit: `86 pruned/omitted states or seeds; 24 frontier rounds, 0 loop rounds; max active 20; stop active_empty`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Model gap requests: `file:/var/sta_encode_ssid_cache (mango_possible_input)`
- Result metrics: elapsed=45.6928s, steps=68, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP, /var/sta_encode_ssid_cache`
- Source expression: `sub_a1a00() @ 0xa1a00`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV32 TOP + 0xffff260c>, <BV32 TOP + 0xffff260c>, <BV32 TOP + 0xffff260c>}})>) @ 0xa34a0`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a1a00` | `0xa1a00` | `sub_a1a00() @ 0xa1a00` |

### Trace 41: `residual`

- Trace path: `sub_71e8c -> doSystemCmd`
- Source: `sub_71e8c` at `0x71e8c`
- Sink: `doSystemCmd` at `0x71ed0`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=4.5126s, steps=32, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_71e8c() @ 0x71e8c`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xfffe5e9c>)>) @ 0x71ed0`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_71e8c` | `0x71e8c` | `sub_71e8c() @ 0x71e8c` |

### Trace 42: `unreachable`

- Trace path: `sub_a00c0 -> doSystemCmd`
- Source: `sub_a00c0` at `0xa00c0`
- Sink: `doSystemCmd` at `0xa0174`
- Stop/reason: `step_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `absent_static_binding, missing_sink_preview, path_budget_residual_risk, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=2, density=0.0040
- Path-control events: `seed_equivalence:2`
- Path-control audit: `2 pruned/omitted states or seeds; max active 1; stop step_budget_exhausted`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Result metrics: elapsed=17.1229s, steps=500, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP`
- Source expression: `sub_a00c0() @ 0xa00c0`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV32 TOP + 0xffff250c>, <BV32 Reverse(TOP) + 0xffff250c>}})>) @ 0xa0174`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a00c0` | `0xa00c0` | `sub_a00c0() @ 0xa00c0` |

### Trace 43: `unreachable`

- Trace path: `sub_a00c0 -> doSystemCmd`
- Source: `sub_a00c0` at `0xa00c0`
- Sink: `doSystemCmd` at `0xa023c`
- Stop/reason: `step_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `absent_static_binding, missing_sink_preview, path_budget_residual_risk, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=2, density=0.0040
- Path-control events: `seed_equivalence:2`
- Path-control audit: `2 pruned/omitted states or seeds; max active 1; stop step_budget_exhausted`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Result metrics: elapsed=17.2095s, steps=500, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP`
- Source expression: `sub_a00c0() @ 0xa00c0`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV32 Reverse(TOP) + 0xffff0ea8>, <BV32 TOP + 0xffff0ea8>}})>) @ 0xa023c`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a00c0` | `0xa00c0` | `sub_a00c0() @ 0xa00c0` |

### Trace 44: `static_source_inference`

- Trace path: `sub_69bbc -> doSystemCmd`
- Source: `sub_69bbc` at `0x69bbc`
- Sink: `doSystemCmd` at `0x69f20`
- Stop/reason: `engine_timeout`
- Static evidence: `strong`
- Evidence confidence: `low` score=34, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, path_budget_residual_risk, strong_static_binding, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=13, density=0.0565
- Path-control events: `semantic_frontier:8, seed_equivalence:5`
- Path-control audit: `13 pruned/omitted states or seeds; 8 frontier rounds, 0 loop rounds; max active 17; stop engine_timeout`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`budget_extension_rerun`, priority=`high`, overrides=`closure_timeout=180, engine_timeout=90, max_steps=1000, subprocess_timeout=240`, gaps=``
- Model gap requests: `file:/proc/mounts (mango_likely_input); file:/proc/mounts (trace_expression_token)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=90.3534s, steps=230, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `/proc/mounts`
- Possible inputs: `/sys/bus/usb/devices/usb1/idProduct`
- Source expression: `sub_69bbc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x69bbc`
- Sink expression: `doSystemCmd(<MultiValues(<BV2216 0x63617420 .. fgets(fopen("/proc/mounts", "r")@0x69c94_1679_32)@0x69de0_1682_2048 .. 47 .. TOP .. 0x203e202f6465762f6e756c6c>)>, <MultiValues(<BV32 stack_base - 0x224>)>) @ 0x69f20`
- Sink/result preview: `cat > /dev/null <inferred_file>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_69bbc` | `0x69bbc` | `sub_69bbc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x69bbc` |

### Trace 45: `residual`

- Trace path: `sub_b73dc -> doSystemCmd`
- Source: `sub_b73dc` at `0xb73dc`
- Sink: `doSystemCmd` at `0xb7468`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=3.4454s, steps=13, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_b73dc(<MultiValues(<BV32 0x0>)>) @ 0xb73dc`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 stack_base - 0x3f8>)>) @ 0xb7468`
- Sink/result preview: `echo -gro 1610612736 >> proc/net/vlan/1`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_b73dc` | `0xb73dc` | `sub_b73dc(<MultiValues(<BV32 0x0>)>) @ 0xb73dc` |

### Trace 46: `residual`

- Trace path: `sub_3a648 -> doSystemCmd`
- Source: `sub_3a648` at `0x3a648`
- Sink: `doSystemCmd` at `0x3a854`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=14, density=0.1687
- Path-control audit: `14 pruned/omitted states or seeds; max active 20; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:lan.gst.1.ip (mango_likely_input); config_key:dhcps.gst.1.en (mango_possible_input); config_key:dhcps.en (mango_possible_input); config_key:lan.gst.1.ip (trace_expression_token)`
- Result metrics: elapsed=70.6677s, steps=83, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.gst.1.ip`
- Possible inputs: `dhcps.gst.1.en, dhcps.en`
- Source expression: `sub_3a648() @ 0x3a648`
- Sink expression: `doSystemCmd(<MultiValues(<BV2160 0x6966636f6e66696720 .. GetValue("lan.gst.1.ip")@0x3a7d8[2047:1280] .. Reverse(TOP) .. GetValue("lan.gst.1.ip")@0x3a7d8[1247:0] .. 32 .. TOP>)>, <MultiValues(<BV32 stack_base - 0x74>)>...`
- Sink/result preview: `ifconfig %s `

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_3a648` | `0x3a648` | `sub_3a648() @ 0x3a648` |

### Trace 47: `vulnerable`

- Trace path: `sub_a0f14 -> doSystemCmd`
- Source: `sub_a0f14` at `0xa0f14`
- Sink: `doSystemCmd` at `0xa0fa8`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `high` score=90, review=`critical`, claim=`direct_sink_byte_sv_sat_evidence`
- Evidence factors: `direct_sink_evidence, partial_sanitizer_profile, sanitizer_gap_profile_partial, sat_payload_evidence, strong_static_binding`
- Path control: `direct_sink_evidence` pressure=`resolved`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop multi_state_settle_budget_exhausted`
- Result metrics: elapsed=9.7690s, steps=20, vectors=3/8 vulnerable/secure, coverage=0.7273
- Sanitizer gap: `partial_filter` partial sanitizer: 3 bypass vector(s) across 2 category/categories; 8 vector(s) blocked
- Gap categories: bypass=`Command Substitution, Variable Expansion`, blocked=`Background Execution, Bypass Spaces, Command Chaining, Piping, Redirection`
- Minimal bypass: `Command Substitution` vector=`$(` poc=`cfm post netctrl 51?op=1,string_info=A$(:)AA`
- Repair hints: `Command Substitution: reject backtick and $() substitution syntax or execute without a shell; Variable Expansion: reject dollar expansion syntax or force strict single-argument quoting`
- Likely inputs: `/tmp/UDiskname`
- Possible inputs: ``
- Source expression: `sub_a0f14() @ 0xa0f14`
- Sink expression: `doSystemCmd(<MultiValues(<BV360 0x63666d20706f7374206e65746374726c2035313f6f703d312c737472696e675f696e666f3d .. fgets(fopen("/tmp/UDiskname", "r+")@0xa0f54_1726_32)@0xa0f7c_1727_64>)>, <MultiValues(<BV32 0x33>)>, <Mul...`
- Sink/result preview: `cfm post netctrl 51?op=1,string_info=$AA:AAA`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a0f14` | `0xa0f14` | `sub_a0f14() @ 0xa0f14` |

### Trace 48: `unreachable`

- Trace path: `sub_92794 -> doSystemCmd`
- Source: `sub_92794` at `0x92794`
- Sink: `doSystemCmd` at `0x92c84`
- Stop/reason: `step_budget_exhausted`
- Static evidence: `weak`
- Evidence confidence: `low` score=3, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `missing_sink_preview, path_budget_residual_risk, unclear_reachability, weak_static_binding`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=2, density=0.0040
- Path-control events: `seed_equivalence:2`
- Path-control audit: `2 pruned/omitted states or seeds; max active 1; stop step_budget_exhausted`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Model gap requests: `config_key:wl5g.public.mode (mango_possible_input)`
- Result metrics: elapsed=15.5199s, steps=500, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP, wl5g.public.mode, /webroot/default.cfg`
- Source expression: `sub_92794() @ 0x92794`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV32 TOP + 0xffff0e00>, <BV32 TOP + 0xffff0e00>}})>) @ 0x92c84`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_92794` | `0x92794` | `sub_92794() @ 0x92794` |

### Trace 49: `unreachable`

- Trace path: `sub_92794 -> doSystemCmd`
- Source: `sub_92794` at `0x92794`
- Sink: `doSystemCmd` at `0x92c98`
- Stop/reason: `step_budget_exhausted`
- Static evidence: `weak`
- Evidence confidence: `low` score=3, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `missing_sink_preview, path_budget_residual_risk, unclear_reachability, weak_static_binding`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=2, density=0.0040
- Path-control events: `seed_equivalence:2`
- Path-control audit: `2 pruned/omitted states or seeds; max active 1; stop step_budget_exhausted`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Model gap requests: `config_key:wl5g.public.mode (mango_possible_input)`
- Result metrics: elapsed=15.5767s, steps=500, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP, wl5g.public.mode, /webroot/default.cfg`
- Source expression: `sub_92794() @ 0x92794`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV32 TOP + 0xffff0e28>, <BV32 TOP + 0xffff0e28>}})>) @ 0x92c98`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_92794` | `0x92794` | `sub_92794() @ 0x92794` |

### Trace 50: `unreachable`

- Trace path: `sub_92794 -> doSystemCmd`
- Source: `sub_92794` at `0x92794`
- Sink: `doSystemCmd` at `0x92d98`
- Stop/reason: `step_budget_exhausted`
- Static evidence: `weak`
- Evidence confidence: `low` score=3, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `missing_sink_preview, path_budget_residual_risk, unclear_reachability, weak_static_binding`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=2, density=0.0040
- Path-control events: `seed_equivalence:2`
- Path-control audit: `2 pruned/omitted states or seeds; max active 1; stop step_budget_exhausted`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Model gap requests: `config_key:wl5g.public.mode (mango_possible_input)`
- Result metrics: elapsed=15.2581s, steps=500, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP, wl5g.public.mode, /webroot/default.cfg`
- Source expression: `sub_92794() @ 0x92794`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xffff0ea8>)>) @ 0x92d98`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_92794` | `0x92794` | `sub_92794() @ 0x92794` |

### Trace 51: `residual`

- Trace path: `sub_a1850 -> doSystemCmd`
- Source: `sub_a1850` at `0xa1850`
- Sink: `doSystemCmd` at `0xa34fc`
- Stop/reason: `source_liveness_saturated`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, source_liveness_pruning, unclear_reachability`
- Path control: `semantic_saturation` pressure=`semantically_bounded`, pruned=95, density=2.9697
- Path-control events: `semantic_frontier:93, source_liveness:3, seed_equivalence:2`
- Path-control audit: `95 pruned/omitted states or seeds; 21 frontier rounds, 0 loop rounds; max active 20; stop source_liveness_saturated`
- Semantic classification: `source_dead_frontier`
- Residual diagnosis: `evidence_contract_residual` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=26.8702s, steps=33, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP`
- Source expression: `sub_a1850() @ 0xa1850`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xffff28f0>)>) @ 0xa34fc`
- Sink/result preview: `<source_dead_frontier>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a1850` | `0xa1850` | `sub_a1850() @ 0xa1850` |

### Trace 52: `residual`

- Trace path: `sub_a8c38 -> doSystemCmd`
- Source: `sub_a8c38` at `0xa8c38`
- Sink: `doSystemCmd` at `0xa8ce8`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 8; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=6.8117s, steps=15, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_a8c38() @ 0xa8c38`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xffff345c>)>) @ 0xa8ce8`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a8c38` | `0xa8c38` | `sub_a8c38() @ 0xa8c38` |

### Trace 53: `residual`

- Trace path: `sub_a8c38 -> doSystemCmd`
- Source: `sub_a8c38` at `0xa8c38`
- Sink: `doSystemCmd` at `0xa8d00`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 7; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=6.6061s, steps=15, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_a8c38() @ 0xa8c38`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xffff3488>)>) @ 0xa8d00`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a8c38` | `0xa8c38` | `sub_a8c38() @ 0xa8c38` |

### Trace 54: `residual`

- Trace path: `sub_a8c38 -> doSystemCmd`
- Source: `sub_a8c38` at `0xa8c38`
- Sink: `doSystemCmd` at `0xa8d38`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=10, density=0.5000
- Path-control events: `semantic_frontier:10`
- Path-control audit: `10 pruned/omitted states or seeds; 10 frontier rounds, 0 loop rounds; max active 16; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=15.3195s, steps=20, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_a8c38() @ 0xa8c38`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xffff34b4>)>) @ 0xa8d38`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a8c38` | `0xa8c38` | `sub_a8c38() @ 0xa8c38` |

### Trace 55: `residual`

- Trace path: `sub_a8c38 -> doSystemCmd`
- Source: `sub_a8c38` at `0xa8c38`
- Sink: `doSystemCmd` at `0xa8d74`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=75, density=3.2609
- Path-control events: `semantic_frontier:75`
- Path-control audit: `75 pruned/omitted states or seeds; 15 frontier rounds, 0 loop rounds; max active 20; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=22.8130s, steps=23, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_a8c38() @ 0xa8c38`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xffff34d0>)>) @ 0xa8d74`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a8c38` | `0xa8c38` | `sub_a8c38() @ 0xa8c38` |

### Trace 56: `residual`

- Trace path: `sub_70460 -> doSystemCmd`
- Source: `sub_70460` at `0x70460`
- Sink: `doSystemCmd` at `0x7047c`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=2.1959s, steps=5, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_70460() @ 0x70460`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xfffe5c7c>)>) @ 0x7047c`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_70460` | `0x70460` | `sub_70460() @ 0x70460` |

### Trace 57: `residual`

- Trace path: `sub_70460 -> doSystemCmd`
- Source: `sub_70460` at `0x70460`
- Sink: `doSystemCmd` at `0x704a4`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=3.1953s, steps=21, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_70460() @ 0x70460`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xfffe5ca8>)>) @ 0x704a4`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_70460` | `0x70460` | `sub_70460() @ 0x70460` |

### Trace 58: `residual`

- Trace path: `sub_b03ec -> doSystemCmd`
- Source: `sub_b03ec` at `0xb03ec`
- Sink: `doSystemCmd` at `0xb0428`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=2.4098s, steps=8, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_b03ec() @ 0xb03ec`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xffff4524>)>) @ 0xb0428`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_b03ec` | `0xb03ec` | `sub_b03ec() @ 0xb03ec` |

### Trace 59: `residual`

- Trace path: `sub_b03ec -> doSystemCmd`
- Source: `sub_b03ec` at `0xb03ec`
- Sink: `doSystemCmd` at `0xb0438`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=2.5016s, steps=10, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_b03ec() @ 0xb03ec`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xffff4548>)>) @ 0xb0438`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_b03ec` | `0xb03ec` | `sub_b03ec() @ 0xb03ec` |

### Trace 60: `residual`

- Trace path: `sub_6ba0c -> doShell`
- Source: `sub_6ba0c` at `0x6ba0c`
- Sink: `doShell` at `0x6ba68`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=2.8642s, steps=5, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_6ba0c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x6ba0c`
- Sink expression: `doShell(<MultiValues(<BV32 TOP>)>) @ 0x6ba68`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_6ba0c` | `0x6ba0c` | `sub_6ba0c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x6ba0c` |

### Trace 61: `unreachable`

- Trace path: `sub_38c28 -> sub_38a24 -> doSystemCmd`
- Source: `sub_38c28` at `0x38c28`
- Sink: `doSystemCmd` at `0x38ab8`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `absent_static_binding, missing_sink_preview, path_budget_residual_risk, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Result metrics: elapsed=2.1813s, steps=24, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `<BV32 TOP>`
- Source expression: `sub_38c28(<MultiValues(<BV32 TOP>)>) @ 0x38c28`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 stack_base - 0x250>)>) @ 0x38ab8`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_38c28` | `0x38c28` | `sub_38c28(<MultiValues(<BV32 TOP>)>) @ 0x38c28` |
| 1 | `sub_38a24` | `0x38fc4` | `sub_38a24(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP + 0x2>)>, <MultiValues(<BV32 TOP - 0x2 - (TOP + 0x2)>)>) @ 0x38fc4` |

### Trace 62: `residual`

- Trace path: `sub_3d3a8 -> sub_3ce9c -> doSystemCmd`
- Source: `sub_3d3a8` at `0x3d3a8`
- Sink: `doSystemCmd` at `0x3ca74`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:wl0_ifname (mango_possible_input); config_key:wans.flag (mango_possible_input); config_key:wl1_ifname (mango_possible_input)`
- Result metrics: elapsed=7.0429s, steps=28, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `wl0_ifname, wans.flag, wl1_ifname`
- Source expression: `sub_3d3a8(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x3d3a8`
- Sink expression: `doSystemCmd(<MultiValues(<BV448 0x6563686f2022776c202d6920776c305f69666e616d6520 .. TOP .. 0x3a22203e3e202f746d702f7379736c6f672f776c5f696e666f2e6c6f67>)>, <MultiValues(<BV32 stack_base - 0x66c>)>, <MultiValues(<BV32 ...`
- Sink/result preview: `echo "date:" >> /tmp/syslog/sys_info.log`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_3d3a8` | `0x3d3a8` | `sub_3d3a8(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x3d3a8` |
| 1 | `sub_3ce9c` | `0x3d464` | `sub_3ce9c(<MultiValues(<BV32 stack_base - 0x440>)>) @ 0x3d464` |

### Trace 63: `residual`

- Trace path: `sub_3d3a8 -> sub_3ce9c -> doSystemCmd`
- Source: `sub_3d3a8` at `0x3d3a8`
- Sink: `doSystemCmd` at `0x3caa0`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:wl0_ifname (mango_possible_input); config_key:wans.flag (mango_possible_input); config_key:wl1_ifname (mango_possible_input)`
- Result metrics: elapsed=7.8969s, steps=32, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `wl0_ifname, wans.flag, wl1_ifname`
- Source expression: `sub_3d3a8(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x3d3a8`
- Sink expression: `doSystemCmd(<MultiValues(<BV264 TOP .. 0x203e3e202f746d702f7379736c6f672f7379735f696e666f2e6c6f670a>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 0xdea90>)>) @ 0x3caa0`
- Sink/result preview: `date >> /tmp/syslog/sys_info.log\x0a`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_3d3a8` | `0x3d3a8` | `sub_3d3a8(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x3d3a8` |
| 1 | `sub_3ce9c` | `0x3d464` | `sub_3ce9c(<MultiValues(<BV32 stack_base - 0x440>)>) @ 0x3d464` |

### Trace 64: `residual`

- Trace path: `sub_77e08 -> sub_77d28 -> popen`
- Source: `sub_77e08` at `0x77e08`
- Sink: `popen` at `0x77d88`
- Stop/reason: `active_empty`
- Static evidence: `weak`
- Evidence confidence: `low` score=16, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `unclear_reachability, weak_static_binding`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:wan1.connecttype (mango_possible_input)`
- Result metrics: elapsed=1.7937s, steps=17, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `sys.mode, wan1.connecttype`
- Source expression: `sub_77e08() @ 0x77e08`
- Sink expression: `popen(<MultiValues(<BV32 stack_base - 0x54>)>, <MultiValues(<BV32 0xe5e58>)>) @ 0x77d88`
- Sink/result preview: `cat /etc/ddns_%s`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_77e08` | `0x77e08` | `sub_77e08() @ 0x77e08` |
| 1 | `sub_77d28` | `0x77f88` | `sub_77d28(<MultiValues(<BV32 stack_base - 0x54>)>, <MultiValues(<BV32 stack_base - 0x58>)>) @ 0x77f88` |

### Trace 65: `unreachable`

- Trace path: `sub_10fb0 -> sub_30b28 -> execve`
- Source: `sub_10fb0` at `0x10fb0`
- Sink: `execve` at `0x30c40`
- Stop/reason: `step_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `absent_static_binding, missing_sink_preview, path_budget_residual_risk, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop step_budget_exhausted`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Result metrics: elapsed=31.4623s, steps=500, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_10fb0(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x10fb0`
- Sink expression: `execve(<MultiValues({0: {<BV32 0x40>, <BV32 Reverse(TOP) + 0x40>, <BV32 0x0>, <BV32 0x13e>}})>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x30c40`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_10fb0` | `0x10fb0` | `sub_10fb0(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x1...` |
| 1 | `sub_30b28` | `0x115c8` | `sub_30b28(<MultiValues({0: {<BV32 0x13e>, <BV32 0x0>, <BV32 Reverse(TOP) + 0x40>, <BV32 0x40>}})>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)...` |

## Per-Closure Results

| Closure | Status | Confidence | Review | Path control | Stop/reason | Time(s) | Steps | V/S | Coverage | Static | Classification | Preview |
|---:|---|---|---|---|---|---:|---:|---:|---:|---|---|---|
| 1 | residual | low | high | unclassified | active_empty | 6.0390 | 47 |  |  | strong |  | smbpasswd -a admin -s < /tmp/smbpasswd |
| 3 | residual | low | high | unclassified | active_empty | 28.5827 | 247 |  |  | strong |  | cfm mac 00:01:02:11:22:33 |
| 4 | static_source_inference | low | high | unclassified | multi_state_settle_budget_exhausted | 93.1277 | 126 |  |  | strong | static_sink_template_fallback | iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 5 | static_source_inference | low | high | residual_budget_stop | engine_timeout | 115.3734 | 285 |  |  | strong | static_sink_template_fallback | iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 6 | static_source_inference | low | high | residual_budget_stop | engine_timeout | 113.6397 | 263 |  |  | strong | static_sink_template_fallback | iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 7 | static_source_inference | low | high | residual_budget_stop | engine_timeout | 90.4183 | 302 |  |  | strong | static_sink_template_fallback | iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 8 | static_source_inference | low | high | residual_budget_stop | engine_timeout | 90.4432 | 240 |  |  | strong | static_sink_template_fallback | iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 9 | static_source_inference | low | high | unclassified | multi_state_settle_budget_exhausted | 108.9592 | 124 |  |  | strong | static_sink_template_fallback | iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 10 | static_source_inference | low | high | unclassified | multi_state_settle_budget_exhausted | 105.1351 | 125 |  |  | strong | static_sink_template_fallback | iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 11 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 87.2873 | 92 |  |  | strong |  | iptables -t filter -D INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP |
| 12 | static_source_inference | low | high | residual_budget_stop | engine_timeout | 112.1119 | 385 |  |  | strong | static_sink_template_fallback | iptables -t filter -I INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 13 | static_source_inference | low | high | unclassified | multi_state_settle_budget_exhausted | 99.5858 | 128 |  |  | strong | static_sink_template_fallback | iptables -t filter -I INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 14 | static_source_inference | low | high | unclassified | multi_state_settle_budget_exhausted | 102.8919 | 130 |  |  | strong | static_sink_template_fallback | iptables -t filter -I INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 15 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 85.3007 | 94 |  |  | strong |  | iptables -t filter -I INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP |
| 16 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 13.4891 | 47 |  |  | absent |  | echo / > /tmp/cmdTmp.txt |
| 17 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 15.3122 | 48 |  |  | absent |  | echo %s > /tmp/cmdTmp.txt |
| 18 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 47.4452 | 70 |  |  | absent |  | %s > /tmp/cmdTmp.txt |
| 19 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 57.9580 | 73 |  |  | absent |  | %s > /tmp/cmdTmp.txt |
| 20 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 99.6113 | 87 |  |  | absent |  | %s |
| 21 | residual | low | high | semantic_saturation | source_liveness_saturated | 51.4710 | 83 |  |  | absent | source_dead_frontier | <source_dead_frontier> |
| 22 | residual | low | high | unclassified | active_empty | 4.0248 | 9 |  |  | strong |  | telnetd -b %s & |
| 23 | vulnerable | medium | critical | direct_sink_evidence | multi_state_settle_budget_exhausted | 28.8372 | 12 | 11/0 | 0.0000 | absent |  | echo "%s" >> /etc/chengyanconfig/</dev/nullAAAAAAAAAAAAAAAAAAAAA |
| 24 | residual | low | high | unclassified | active_empty | 4.1473 | 10 |  |  | absent |  |  |
| 25 | static_source_inference | low | high | unclassified | active_empty | 55.8017 | 164 |  |  | strong | static_direct_source_fallback | <inferred_config> |
| 26 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 11.8480 | 77 |  |  | strong |  | cfm post netctrl 51?op=3,string_info=%s |
| 27 | static_source_inference | low | high | residual_budget_stop | step_budget_exhausted | 40.7740 | 500 |  |  | strong | static_direct_source_fallback | <inferred_config> |
| 28 | static_source_inference | low | high | unclassified | active_empty | 73.7932 | 108 |  |  | strong | static_sink_template_fallback | nvram set adv.iptv.stballvlans=" <inferred_web> |
| 29 | static_source_inference | low | high | unclassified | active_empty | 67.5124 | 109 |  |  | strong | static_sink_template_fallback | nvram set adv.iptv.stballvlans=" <inferred_web> |
| 30 | static_source_inference | low | high | unclassified | active_empty | 72.1755 | 108 |  |  | strong | static_sink_template_fallback | nvram set adv.iptv.stbpvid=" <inferred_web> |
| 31 | static_source_inference | low | high | unclassified | active_empty | 67.4590 | 109 |  |  | strong | static_sink_template_fallback | nvram set adv.iptv.stbpvid=" <inferred_web> |
| 32 | vulnerable | medium | critical | direct_sink_evidence | active_empty | 19.8676 | 7 | 11/0 | 0.0000 | absent |  | mv :;:;#AAAAAAAAAAAAAAAAAAAAAAAAAA |
| 33 | unreachable | low | high | residual_budget_stop | active_empty | 3.4309 | 10 |  |  | absent |  |  |
| 34 | residual | low | high | unclassified | active_empty | 0.8964 | 9 |  |  | strong |  | cfm post netctrl 51?op=3,string_info=%s |
| 35 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 68.7876 | 51 |  |  | weak |  |  |
| 36 | unreachable | low | high | residual_budget_stop | guided_stagnation_saturated | 77.4325 | 79 |  |  | weak |  |  |
| 37 | unreachable | low | high | residual_budget_stop | guided_stagnation_saturated | 90.8240 | 90 |  |  | weak |  |  |
| 38 | unreachable | low | high | residual_budget_stop | guided_stagnation_saturated | 91.4945 | 91 |  |  | weak |  |  |
| 39 | unreachable | low | high | residual_budget_stop | active_empty | 45.1487 | 68 |  |  | weak |  |  |
| 40 | unreachable | low | high | residual_budget_stop | active_empty | 45.6928 | 68 |  |  | weak |  |  |
| 41 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 4.5126 | 32 |  |  | absent |  |  |
| 42 | unreachable | low | high | residual_budget_stop | step_budget_exhausted | 17.1229 | 500 |  |  | absent |  |  |
| 43 | unreachable | low | high | residual_budget_stop | step_budget_exhausted | 17.2095 | 500 |  |  | absent |  |  |
| 44 | static_source_inference | low | high | residual_budget_stop | engine_timeout | 90.3534 | 230 |  |  | strong | static_sink_template_fallback | cat > /dev/null <inferred_file> |
| 45 | residual | low | high | unclassified | active_empty | 3.4454 | 13 |  |  | absent |  | echo -gro 1610612736 >> proc/net/vlan/1 |
| 46 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 70.6677 | 83 |  |  | strong |  | ifconfig %s  |
| 47 | vulnerable | high | critical | direct_sink_evidence | multi_state_settle_budget_exhausted | 9.7690 | 20 | 3/8 | 0.7273 | strong |  | cfm post netctrl 51?op=1,string_info=$AA:AAA |
| 48 | unreachable | low | high | residual_budget_stop | step_budget_exhausted | 15.5199 | 500 |  |  | weak |  |  |
| 49 | unreachable | low | high | residual_budget_stop | step_budget_exhausted | 15.5767 | 500 |  |  | weak |  |  |
| 50 | unreachable | low | high | residual_budget_stop | step_budget_exhausted | 15.2581 | 500 |  |  | weak |  |  |
| 51 | residual | low | high | semantic_saturation | source_liveness_saturated | 26.8702 | 33 |  |  | absent | source_dead_frontier | <source_dead_frontier> |
| 52 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 6.8117 | 15 |  |  | absent |  |  |
| 53 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 6.6061 | 15 |  |  | absent |  |  |
| 54 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 15.3195 | 20 |  |  | absent |  |  |
| 55 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 22.8130 | 23 |  |  | absent |  |  |
| 56 | residual | low | high | unclassified | active_empty | 2.1959 | 5 |  |  | absent |  |  |
| 57 | residual | low | high | unclassified | active_empty | 3.1953 | 21 |  |  | absent |  |  |
| 58 | residual | low | high | unclassified | active_empty | 2.4098 | 8 |  |  | absent |  |  |
| 59 | residual | low | high | unclassified | active_empty | 2.5016 | 10 |  |  | absent |  |  |
| 60 | residual | low | high | unclassified | active_empty | 2.8642 | 5 |  |  | absent |  |  |
| 61 | unreachable | low | high | residual_budget_stop | active_empty | 2.1813 | 24 |  |  | absent |  |  |
| 62 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 7.0429 | 28 |  |  | strong |  | echo "date:" >> /tmp/syslog/sys_info.log |
| 63 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 7.8969 | 32 |  |  | strong |  | date >> /tmp/syslog/sys_info.log\x0a |
| 64 | residual | low | high | unclassified | active_empty | 1.7937 | 17 |  |  | weak |  | cat /etc/ddns_%s |
| 65 | unreachable | low | high | residual_budget_stop | step_budget_exhausted | 31.4623 | 500 |  |  | absent |  |  |

## Output Artifacts

- Summary JSON: `/home/ubuntu/work/sanitizer/experiment_reports/full_firmware_campaign_current_tsds_multistate_full_20260916/tenda_ac15.summary.json`
- Per-closure JSONL: `/home/ubuntu/work/sanitizer/experiment_reports/full_firmware_campaign_current_tsds_multistate_full_20260916/tenda_ac15.results.jsonl`
