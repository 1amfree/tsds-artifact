# TSDS Analysis Report

- Generated: 2026-09-16 00:13:35
- Binary: `/home/ubuntu/work/sanitizer/Tenda_AC18/httpd`
- Trace JSON: `/home/ubuntu/work/sanitizer/Tenda_AC18/results/cmdi_results.json`
- Mode: `full`
- Total closures: 56
- Unique pairs expected: 54
- Unique pairs analyzed: 54

## Executive Summary

| Metric | Value |
|---|---:|
| SV-SAT | 3 |
| Modeled-vector filtered | 0 |
| Partially filtered SV-SAT | 1 |
| No-modeled-source sink | 0 |
| Static source inference | 14 |
| Static warning reduction | 0 |
| Residual obligation | 32 |
| Unreachable | 4 |
| Timeout | 1 |
| Crashed | 0 |
| Evaluation errors | 0 |
| SAT shell-vector witnesses | 25 |
| Blocked-vector proofs | 8 |
| Average sanitizer coverage | 0.2424 |
| Wall time seconds | 2105.8017 |
| Average closure time seconds | 38.8900 |
| Average matrix time seconds | 0.7243 |
| Average engine steps | 113.4400 |
| Semantic frontier cuts | 932 |
| Source-liveness cuts | 0 |
| Delay-slot sink captures | 0 |
| Loop semantic cuts | 0 |
| Seed states tried | 280 |
| Seed states pruned | 63 |
| Memoized closures | 0 |
| Evidence cache hits | 0 |

## Model Gap Requests

| Dimension | Count |
|---|---:|
| kind:config_key | 107 |
| kind:web | 33 |
| kind:file | 2 |
| reason:mango_possible_input | 52 |
| reason:mango_likely_input | 30 |
| reason:trace_expression_token | 29 |
| reason:trace_uses_web_parser | 19 |
| reason:trace_uses_config_api | 12 |

| Closure | Kind | Key | Reason | Confidence | Evidence |
|---:|---|---|---|---|---|
| 1 | config_key | usb.samba.user | mango_likely_input | high | usb.samba.user |
| 1 | config_key | usb.samba.pwd | mango_possible_input | medium | usb.samba.pwd |
| 3 | config_key | usb.samba.guest.user | mango_possible_input | medium | usb.samba.guest.user |
| 3 | config_key | usb.samba.enable | mango_possible_input | medium | usb.samba.enable |
| 3 | web | formSetSambaConf | trace_uses_web_parser | medium | formSetSambaConf -> doSystemCmd |
| 4 | config_key | usb.samba.guest.user | mango_likely_input | high | usb.samba.guest.user |
| 4 | config_key | usb.samba.enable | mango_possible_input | medium | usb.samba.enable |
| 4 | config_key | usb.samba.guest.user | trace_expression_token | medium | formSetSambaConf(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa5380... |
| 4 | web | formSetSambaConf | trace_uses_web_parser | medium | formSetSambaConf -> doSystemCmd |
| 6 | web | formsetUsbUnload | trace_uses_web_parser | medium | formsetUsbUnload -> doSystemCmd |
| 7 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 7 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 7 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 7 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 7 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 7 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 7 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 7 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 7 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 8 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 8 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 8 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 8 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 8 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 8 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 8 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 8 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 8 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 9 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 9 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 9 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 9 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 9 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 9 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 9 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 9 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 9 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 10 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 10 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 10 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 10 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 10 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 10 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 10 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 10 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 10 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 11 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 11 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 11 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 11 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 11 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 11 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 11 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 11 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 11 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 12 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 12 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 12 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 12 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 12 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 12 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 12 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 12 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 12 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 13 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 13 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 13 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 13 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 13 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 13 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 13 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 13 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 13 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 14 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 14 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 14 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 14 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 14 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 14 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 14 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 14 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 14 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 15 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 15 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 15 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 15 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 15 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 15 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 15 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 15 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 15 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 16 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 16 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 16 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 16 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 16 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 16 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 16 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 16 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 16 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 17 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 17 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 17 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 17 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 17 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 17 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 17 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 17 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 17 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 18 | config_key | lan.mask | mango_likely_input | high | lan.mask |
| 18 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 18 | web | lan.webport | mango_possible_input | medium | lan.webport |
| 18 | config_key | security.ddos.map | mango_possible_input | medium | security.ddos.map |
| 18 | config_key | security.ipop.map | mango_possible_input | medium | security.ipop.map |
| 18 | config_key | lan.ip | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 18 | config_key | lan.mask | trace_expression_token | medium | formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4... |
| 18 | web | formSetFirewallCfg | trace_uses_web_parser | medium | formSetFirewallCfg -> doSystemCmd |
| 18 | config_key | formSetFirewallCfg | trace_uses_config_api | medium | formSetFirewallCfg -> doSystemCmd |
| 20 | config_key | lan.ip | mango_likely_input | high | lan.ip |
| 20 | config_key | lan.ip | trace_expression_token | medium | TendaTelnet(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x4f6c4 doSy... |
| 21 | config_key | wans.flag | mango_possible_input | medium | wans.flag |
| 21 | web | formSetIptv | trace_uses_web_parser | medium | formSetIptv -> doSystemCmd |
| 22 | config_key | wans.flag | mango_possible_input | medium | wans.flag |
| 22 | web | formSetIptv | trace_uses_web_parser | medium | formSetIptv -> doSystemCmd |
| 28 | web | formWriteFacMac | trace_uses_web_parser | medium | formWriteFacMac -> doSystemCmd |
| 35 | web | cgi_debug | mango_likely_input | high | cgi_debug |
| 35 | config_key | macfilter.mode | mango_possible_input | medium | macfilter.mode |
| 35 | web | cgi_debug | trace_expression_token | medium | formAddMacfilterRule(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xc... |
| 35 | web | formAddMacfilterRule | trace_uses_web_parser | medium | formAddMacfilterRule -> doSystemCmd |
| 37 | config_key | lan.gst.1.ip | mango_likely_input | high | lan.gst.1.ip |
| 37 | config_key | dhcps.gst.1.en | mango_possible_input | medium | dhcps.gst.1.en |
| 37 | config_key | dhcps.en | mango_possible_input | medium | dhcps.en |
| 37 | config_key | lan.gst.1.ip | trace_expression_token | medium | sub_3a1a4() @ 0x3a1a4 doSystemCmd(<MultiValues(<BV2160 0x6966636f6e66696720 .. GetValue("lan.gst.1.ip")@0x3... |
| 45 | file | /proc/mounts | mango_likely_input | high | /proc/mounts |
| 45 | file | /proc/mounts | trace_expression_token | medium | sub_69d24(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x69d24 doSystemCmd(<MultiValues({0: {<BV... |
| 49 | config_key | wans.flag | mango_possible_input | medium | wans.flag |
| 49 | config_key | wl0_ifname | mango_possible_input | medium | wl0_ifname |
| 49 | config_key | wl1_ifname | mango_possible_input | medium | wl1_ifname |
| 50 | config_key | wans.flag | mango_possible_input | medium | wans.flag |
| 50 | config_key | wl0_ifname | mango_possible_input | medium | wl0_ifname |
| 50 | config_key | wl1_ifname | mango_possible_input | medium | wl1_ifname |
| 55 | config_key | wan1.connecttype | mango_possible_input | medium | wan1.connecttype |

## Engine Stop Reasons

| Stop reason | Count |
|---|---:|
| `active_empty` | 24 |
| `engine_timeout` | 6 |
| `multi_state_settle_budget_exhausted` | 21 |
| `step_budget_exhausted` | 3 |

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
| confidence:low | 51 |
| review:critical | 3 |
| review:high | 51 |
| claim:direct_sink_byte_sv_sat_evidence | 3 |
| claim:evidence_contract_residual | 32 |
| claim:residual_unclear_outcome | 5 |
| claim:static_source_slot_inference | 14 |

## Semantic Path-Control Ledger

| Dimension | Count |
|---|---:|
| class:direct_sink_evidence | 3 |
| class:residual_budget_stop | 11 |
| class:unclassified | 40 |
| pressure:not_applicable | 40 |
| pressure:residual_risk | 11 |
| pressure:resolved | 3 |
| total:path_control_pruned_states | 1019 |
| total:semantic_pruned_states | 932 |
| total:seed_pruned | 63 |

## Residual Diagnosis

| Dimension | Count |
|---|---:|
| class:bounded_multi_state_no_admissible_primary | 32 |
| class:static_source_inference_unconfirmed | 14 |
| class:path_explosion_residual | 4 |
| class:time_budget_exhaustion | 1 |
| severity:high | 51 |
| action:inspect contract violations and vector decisions | 32 |
| action:keep the record outside SV-SAT, M-Filt, and NMS aggregates | 32 |
| action:rerun unknown quote contexts or pruned negative paths conservatively | 32 |
| action:do not aggregate this record as SV-SAT or NMS | 14 |
| action:inspect missing wrapper, parser, and environment summaries | 14 |
| action:replay with a larger reachability budget | 14 |
| action:add a targeted parser or wrapper summary if the trace repeats around one helper | 4 |
| action:increase max steps or closure timeout for this closure | 4 |

## Residual Recovery Plan

| Dimension | Count |
|---|---:|
| strategy:manual_review | 41 |
| strategy:budget_extension_rerun | 6 |
| strategy:semantic_path_refinement | 4 |
| priority:medium | 41 |
| priority:high | 10 |
| model-gap:loop_or_parser_summary | 4 |
| model-gap:sink_distance_model | 4 |
| config:closure_timeout=180 | 10 |
| config:max_steps=1000 | 10 |
| config:engine_timeout=90 | 6 |
| config:subprocess_timeout=240 | 6 |
| config:loop_semantic_saturation_limit=5 | 4 |
| config:semantic_frontier_bucket_limit=3 | 4 |

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
| 5 | vulnerable | 11/0 | 0.0000 | entry_arg |  | echo "%s" >> /etc/chengyanconfig/</dev/nullAAAAAAAAAAAAAAAAAAAAA |
| 19 | vulnerable | 11/0 | 0.0000 | entry_arg |  | mv </dev/nullAAAAAAAAAAAAAAAAAAAAA |
| 39 | vulnerable | 3/8 | 0.7273 | file |  | cfm post netctrl 51?op=1,string_info=AA(:)"A |

## Unclear Or Operational Outcomes

| Closure | Status | Diagnosis | Severity | Reason | Time(s) | Static evidence | Preview/Error |
|---:|---|---|---|---|---:|---|---|
| 2 | unreachable | path_explosion_residual | high | active_empty | 4.6176 | absent |  |
| 27 | unreachable | path_explosion_residual | high | step_budget_exhausted | 15.6757 | absent |  |
| 42 | timeout | time_budget_exhaustion | high | engine_timeout | 91.9617 | absent |  |
| 46 | unreachable | path_explosion_residual | high | active_empty | 2.2125 | absent |  |
| 56 | unreachable | path_explosion_residual | high | step_budget_exhausted | 31.7278 | absent |  |

## Trace-Level Analysis

### Trace 1: `residual`

- Trace path: `sub_a6064 -> system`
- Source: `sub_a6064` at `0xa6064`
- Sink: `system` at `0xa61d0`
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
- Result metrics: elapsed=4.6988s, steps=47, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `usb.samba.user`
- Possible inputs: `usb.samba.pwd`
- Source expression: `sub_a6064() @ 0xa6064`
- Sink expression: `system(<MultiValues(<BV32 stack_base - 0x410>)>) @ 0xa61d0`
- Sink/result preview: `smbpasswd -a admin -s < /tmp/smbpasswd`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a6064` | `0xa6064` | `sub_a6064() @ 0xa6064` |

### Trace 2: `unreachable`

- Trace path: `sub_6b59c -> doSystemCmd`
- Source: `sub_6b59c` at `0x6b59c`
- Sink: `doSystemCmd` at `0x6b658`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `absent_static_binding, missing_sink_preview, path_budget_residual_risk, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=0, density=0.0000
- Path-control audit: `max active 3; stop active_empty`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Result metrics: elapsed=4.6176s, steps=12, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_6b59c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x6b59c`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP>)>) @ 0x6b658`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_6b59c` | `0x6b59c` | `sub_6b59c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x6b59c` |

### Trace 3: `residual`

- Trace path: `formSetSambaConf -> doSystemCmd`
- Source: `formSetSambaConf` at `0xa5380`
- Sink: `doSystemCmd` at `0xa5534`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:usb.samba.guest.user (mango_possible_input); config_key:usb.samba.enable (mango_possible_input); web:formSetSambaConf (trace_uses_web_parser)`
- Result metrics: elapsed=10.2472s, steps=77, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `usb.samba.guest.user, usb.samba.enable`
- Source expression: `formSetSambaConf(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa5380`
- Sink expression: `doSystemCmd(<MultiValues(<BV2344 0x63666d20706f7374206e65746374726c2035313f6f703d332c737472696e675f696e666f3d .. Reverse(dweb_get_extracted@a5464_185_2048)>)>, <MultiValues(<BV32 0x33>)>, <MultiValues(<BV32 0x3>)>, <M...`
- Sink/result preview: `cfm post netctrl 51?op=3,string_info=%s`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetSambaConf` | `0xa5380` | `formSetSambaConf(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa5380` |

### Trace 4: `static_source_inference`

- Trace path: `formSetSambaConf -> doSystemCmd`
- Source: `formSetSambaConf` at `0xa5380`
- Sink: `doSystemCmd` at `0xa55ac`
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
- Result metrics: elapsed=36.9801s, steps=500, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `usb.samba.guest.user`
- Possible inputs: `usb.samba.enable`
- Source expression: `formSetSambaConf(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa5380`
- Sink expression: `doSystemCmd(<MultiValues(<BV2176 0x62757379626f782064656c7573657220 .. GetValue("usb.samba.guest.user")@0xa5584>)>, <MultiValues(<BV32 stack_base - 0x74>)>) @ 0xa55ac`
- Sink/result preview: `<inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetSambaConf` | `0xa5380` | `formSetSambaConf(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa5380` |

### Trace 5: `vulnerable`

- Trace path: `sub_a7b50 -> doSystemCmd`
- Source: `sub_a7b50` at `0xa7b50`
- Sink: `doSystemCmd` at `0xa7c14`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `medium` score=64, review=`critical`, claim=`direct_sink_byte_sv_sat_evidence`
- Evidence factors: `absent_static_binding, direct_sink_evidence, sanitizer_gap_profile_broad_bypass, sat_payload_evidence`
- Path control: `direct_sink_evidence` pressure=`resolved`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop multi_state_settle_budget_exhausted`
- Result metrics: elapsed=26.1150s, steps=12, vectors=11/0 vulnerable/secure, coverage=0.0000
- Sanitizer gap: `broadly_bypassable` broad sanitizer gap: all decided vectors are bypassable (11 vector(s))
- Gap categories: bypass=`Background Execution, Bypass Spaces, Command Chaining, Command Substitution, Piping, Redirection, Variable Expansion`, blocked=``
- Minimal bypass: `Background Execution` vector=`&` poc=`echo "%s" >> /etc/chengyanconfig/:&:;#AAAAAAAAAAAAAAAAAAAAAAAAAA`
- Repair hints: `Background Execution: reject or quote ampersand job-control operators; Bypass Spaces: normalize and reject alternate whitespace forms such as tabs and ${IFS}; Command Chaining: reject or quote command separators such as semicolon and newline, or avoid shell...`
- Source expression: `sub_a7b50(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa7b50`
- Sink expression: `doSystemCmd(<MultiValues(<BV344 0x6563686f2022 .. TOP .. 0x22203e3e202f6574632f6368656e6779616e636f6e6669672f .. TOP .. 0x2e646174>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa7c14`
- Sink/result preview: `echo "%s" >> /etc/chengyanconfig/</dev/nullAAAAAAAAAAAAAAAAAAAAA`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a7b50` | `0xa7b50` | `sub_a7b50(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa7b50` |

### Trace 6: `residual`

- Trace path: `formsetUsbUnload -> doSystemCmd`
- Source: `formsetUsbUnload` at `0xa66e8`
- Sink: `doSystemCmd` at `0xa674c`
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
- Result metrics: elapsed=0.8998s, steps=9, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `formsetUsbUnload(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa66e8`
- Sink expression: `doSystemCmd(<MultiValues(<BV2344 0x63666d20706f7374206e65746374726c2035313f6f703d332c737472696e675f696e666f3d .. Reverse(dweb_get_extracted@a672c_197_2048)>)>, <MultiValues(<BV32 0x33>)>, <MultiValues(<BV32 0x3>)>, <M...`
- Sink/result preview: `cfm post netctrl 51?op=3,string_info=%s`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formsetUsbUnload` | `0xa66e8` | `formsetUsbUnload(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa66e8` |

### Trace 7: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac4d0`
- Sink: `doSystemCmd` at `0xace68`
- Stop/reason: `engine_timeout`
- Static evidence: `strong`
- Evidence confidence: `low` score=34, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, path_budget_residual_risk, strong_static_binding, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=95, density=0.2278
- Path-control events: `semantic_frontier:90, seed_equivalence:5`
- Path-control audit: `95 pruned/omitted states or seeds; 60 frontier rounds, 0 loop rounds; max active 25; stop engine_timeout`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`budget_extension_rerun`, priority=`high`, overrides=`closure_timeout=180, engine_timeout=90, max_steps=1000, subprocess_timeout=240`, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); web:lan.webport (mango_possible_input); config_key:security.ddos.map (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=110.1344s, steps=417, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `lan.webport, security.ddos.map, security.ipop.map, firewall.pingwan, TOP`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. TOP .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d747970652038202d6a2044524f50>, <BV584 0x69707461626c657...`
- Sink/result preview: `iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac4d0` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0` |

### Trace 8: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac4d0`
- Sink: `doSystemCmd` at `0xace9c`
- Stop/reason: `engine_timeout`
- Static evidence: `strong`
- Evidence confidence: `low` score=34, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, path_budget_residual_risk, strong_static_binding, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=93, density=0.2263
- Path-control events: `semantic_frontier:88, seed_equivalence:5`
- Path-control audit: `93 pruned/omitted states or seeds; 50 frontier rounds, 0 loop rounds; max active 25; stop engine_timeout`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`budget_extension_rerun`, priority=`high`, overrides=`closure_timeout=180, engine_timeout=90, max_steps=1000, subprocess_timeout=240`, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); web:lan.webport (mango_possible_input); config_key:security.ddos.map (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=110.1076s, steps=411, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `lan.webport, security.ddos.map, security.ipop.map, firewall.pingwan, TOP`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. TOP .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d747970652038202d6a2044524f50>, <BV584 0x69707461626c657...`
- Sink/result preview: `iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac4d0` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0` |

### Trace 9: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac4d0`
- Sink: `doSystemCmd` at `0xad084`
- Stop/reason: `engine_timeout`
- Static evidence: `strong`
- Evidence confidence: `low` score=34, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, path_budget_residual_risk, strong_static_binding, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=81, density=0.1990
- Path-control events: `semantic_frontier:70, seed_equivalence:6`
- Path-control audit: `81 pruned/omitted states or seeds; 44 frontier rounds, 0 loop rounds; max active 20; stop engine_timeout`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`budget_extension_rerun`, priority=`high`, overrides=`closure_timeout=180, engine_timeout=90, max_steps=1000, subprocess_timeout=240`, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); web:lan.webport (mango_possible_input); config_key:security.ddos.map (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=90.3000s, steps=407, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `lan.webport, security.ddos.map, security.ipop.map, firewall.pingwan, TOP`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. Reverse(GetValue("lan.ip")@0xa9ed0[1727:1696]) - 0x2a8 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d7479...`
- Sink/result preview: `iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac4d0` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0` |

### Trace 10: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac4d0`
- Sink: `doSystemCmd` at `0xacfac`
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
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); web:lan.webport (mango_possible_input); config_key:security.ddos.map (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=90.7041s, steps=124, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `lan.webport, security.ddos.map, security.ipop.map, firewall.pingwan, TOP`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. Reverse(GetValue("lan.mask")@0xa9ef4[1599:1568]) - 0x298 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d74...`
- Sink/result preview: `iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac4d0` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0` |

### Trace 11: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac4d0`
- Sink: `doSystemCmd` at `0xad06c`
- Stop/reason: `engine_timeout`
- Static evidence: `strong`
- Evidence confidence: `low` score=34, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, path_budget_residual_risk, strong_static_binding, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=90, density=0.2821
- Path-control events: `semantic_frontier:79, seed_equivalence:6`
- Path-control audit: `90 pruned/omitted states or seeds; 49 frontier rounds, 0 loop rounds; max active 20; stop engine_timeout`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`budget_extension_rerun`, priority=`high`, overrides=`closure_timeout=180, engine_timeout=90, max_steps=1000, subprocess_timeout=240`, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); web:lan.webport (mango_possible_input); config_key:security.ddos.map (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=90.3200s, steps=319, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `lan.webport, security.ddos.map, security.ipop.map, firewall.pingwan, TOP`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. Reverse(GetValue("lan.mask")@0xa9ef4[1599:1568]) - 0x298 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d74...`
- Sink/result preview: `iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac4d0` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0` |

### Trace 12: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac4d0`
- Sink: `doSystemCmd` at `0xad050`
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
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); web:lan.webport (mango_possible_input); config_key:security.ddos.map (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=93.2642s, steps=125, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `lan.webport, security.ddos.map, security.ipop.map, firewall.pingwan, TOP`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. Reverse(GetValue("lan.ip")@0xa9ed0[1727:1696]) - 0x298 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d7479...`
- Sink/result preview: `iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac4d0` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0` |

### Trace 13: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac4d0`
- Sink: `doSystemCmd` at `0xacfc4`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=42, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=57, density=0.4524
- Path-control events: `semantic_frontier:54, seed_equivalence:3`
- Path-control audit: `57 pruned/omitted states or seeds; 34 frontier rounds, 0 loop rounds; max active 26; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); web:lan.webport (mango_possible_input); config_key:security.ddos.map (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=94.3411s, steps=126, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `lan.webport, security.ddos.map, security.ipop.map, firewall.pingwan, TOP`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. Reverse(GetValue("lan.mask")@0xa9ef4[1599:1568]) - 0x2a8 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d74...`
- Sink/result preview: `iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac4d0` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0` |

### Trace 14: `residual`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac4d0`
- Sink: `doSystemCmd` at `0xad010`
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
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); web:lan.webport (mango_possible_input); config_key:security.ddos.map (mango_possible_input)`
- Result metrics: elapsed=76.8946s, steps=92, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `lan.webport, security.ddos.map, security.ipop.map, firewall.pingwan, TOP`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4420494e505554202d6920 .. Reverse(GetValue("lan.ip")@0xa9ed0[1727:1696]) - 0x298 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d7479...`
- Sink/result preview: `iptables -t filter -D INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac4d0` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0` |

### Trace 15: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac4d0`
- Sink: `doSystemCmd` at `0xacfdc`
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
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); web:lan.webport (mango_possible_input); config_key:security.ddos.map (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=98.1125s, steps=128, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `lan.webport, security.ddos.map, security.ipop.map, firewall.pingwan, TOP`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4920494e505554202d6920 .. Reverse(GetValue("lan.mask")@0xa9ef4[1599:1568]) - 0x298 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d74...`
- Sink/result preview: `iptables -t filter -I INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac4d0` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0` |

### Trace 16: `residual`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac4d0`
- Sink: `doSystemCmd` at `0xad028`
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
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); web:lan.webport (mango_possible_input); config_key:security.ddos.map (mango_possible_input)`
- Result metrics: elapsed=84.3529s, steps=94, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `lan.webport, security.ddos.map, security.ipop.map, firewall.pingwan, TOP`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4920494e505554202d6920 .. Reverse(GetValue("lan.mask")@0xa9ef4[1599:1568]) - 0x298 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d74...`
- Sink/result preview: `iptables -t filter -I INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac4d0` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0` |

### Trace 17: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac4d0`
- Sink: `doSystemCmd` at `0xace80`
- Stop/reason: `engine_timeout`
- Static evidence: `strong`
- Evidence confidence: `low` score=34, review=`high`, claim=`static_source_slot_inference`
- Evidence factors: `guarded_static_dynamic_recovery, path_budget_residual_risk, strong_static_binding, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=98, density=0.2462
- Path-control events: `semantic_frontier:93, seed_equivalence:5`
- Path-control audit: `98 pruned/omitted states or seeds; 52 frontier rounds, 0 loop rounds; max active 25; stop engine_timeout`
- Residual diagnosis: `static_source_inference_unconfirmed` severity=`high` Static evidence binds a source slot, but no target-sink state was observed.
- Residual next actions: `replay with a larger reachability budget; inspect missing wrapper, parser, and environment summaries; do not aggregate this record as SV-SAT or NMS`
- Recovery plan: strategy=`budget_extension_rerun`, priority=`high`, overrides=`closure_timeout=180, engine_timeout=90, max_steps=1000, subprocess_timeout=240`, gaps=``
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); web:lan.webport (mango_possible_input); config_key:security.ddos.map (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=110.9215s, steps=398, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `lan.webport, security.ddos.map, security.ipop.map, firewall.pingwan, TOP`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV584 0x69707461626c6573202d742066696c746572202d4920494e505554202d6920 .. Reverse(GetValue("lan.ip")@0xa9ed0[1727:1696]) - 0x298 .. 0x202d702069636d70202d6d2069636d70202d2d69636d702d7479...`
- Sink/result preview: `iptables -t filter -I INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac4d0` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0` |

### Trace 18: `static_source_inference`

- Trace path: `formSetFirewallCfg -> doSystemCmd`
- Source: `formSetFirewallCfg` at `0xac4d0`
- Sink: `doSystemCmd` at `0xacff4`
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
- Model gap requests: `config_key:lan.mask (mango_likely_input); config_key:lan.ip (mango_likely_input); web:lan.webport (mango_possible_input); config_key:security.ddos.map (mango_possible_input)`
- Recovery: `static_sink_template_fallback` `static_source_template_unreached`
- Result metrics: elapsed=103.9984s, steps=130, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.mask, lan.ip`
- Possible inputs: `lan.webport, security.ddos.map, security.ipop.map, firewall.pingwan, TOP`
- Source expression: `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV2344 0x69707461626c6573202d742066696c746572202d4920494e505554202d6920 .. GetValue("TOP")@0xacdc0[1535:0] .. GetValue("TOP")@0xacda8[255:0] .. 0x202d702069636d70202d6d2069636d70202d2d69...`
- Sink/result preview: `iptables -t filter -I INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetFirewallCfg` | `0xac4d0` | `formSetFirewallCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xac4d0` |

### Trace 19: `vulnerable`

- Trace path: `sub_31218 -> doSystemCmd`
- Source: `sub_31218` at `0x31218`
- Sink: `doSystemCmd` at `0x31278`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `medium` score=64, review=`critical`, claim=`direct_sink_byte_sv_sat_evidence`
- Evidence factors: `absent_static_binding, direct_sink_evidence, sanitizer_gap_profile_broad_bypass, sat_payload_evidence`
- Path control: `direct_sink_evidence` pressure=`resolved`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop active_empty`
- Result metrics: elapsed=19.9497s, steps=7, vectors=11/0 vulnerable/secure, coverage=0.0000
- Sanitizer gap: `broadly_bypassable` broad sanitizer gap: all decided vectors are bypassable (11 vector(s))
- Gap categories: bypass=`Background Execution, Bypass Spaces, Command Chaining, Command Substitution, Piping, Redirection, Variable Expansion`, blocked=``
- Minimal bypass: `Background Execution` vector=`&` poc=`mv :&:;#AAAAAAAAAAAAAAAAAAAAAAAAAA`
- Repair hints: `Background Execution: reject or quote ampersand job-control operators; Bypass Spaces: normalize and reject alternate whitespace forms such as tabs and ${IFS}; Command Chaining: reject or quote command separators such as semicolon and newline, or avoid shell...`
- Source expression: `sub_31218(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x31218`
- Sink expression: `doSystemCmd(<MultiValues(<BV152 0x6d7620 .. TOP .. 0x20202f7661722f696d616765>)>, <MultiValues(<BV32 TOP>)>) @ 0x31278`
- Sink/result preview: `mv </dev/nullAAAAAAAAAAAAAAAAAAAAA`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_31218` | `0x31218` | `sub_31218(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x31218` |

### Trace 20: `residual`

- Trace path: `TendaTelnet -> doSystemCmd`
- Source: `TendaTelnet` at `0x4f6c4`
- Sink: `doSystemCmd` at `0x4f79c`
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
- Result metrics: elapsed=3.4508s, steps=9, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.ip`
- Possible inputs: ``
- Source expression: `TendaTelnet(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x4f6c4`
- Sink expression: `doSystemCmd(<MultiValues(<BV2152 0x74656c6e657464202d6220 .. GetValue("lan.ip")@0x4f774 .. 0x2026>)>, <MultiValues(<BV32 stack_base - 0x130>)>) @ 0x4f79c`
- Sink/result preview: `telnetd -b %s &`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `TendaTelnet` | `0x4f6c4` | `TendaTelnet(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x4f6c4` |

### Trace 21: `static_source_inference`

- Trace path: `formSetIptv -> doSystemCmd`
- Source: `formSetIptv` at `0xb032c`
- Sink: `doSystemCmd` at `0xb026c`
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
- Result metrics: elapsed=70.2109s, steps=108, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `iptv.stb.enable, adv.iptv.stbpvid, adv.iptv.stballvlans, iptv.city.vlan, wans.flag`
- Source expression: `formSetIptv(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xb032c`
- Sink expression: `doSystemCmd(<MultiValues(<BV2312 0x6e7672616d20736574206164762e697074762e737462616c6c766c616e733d22 .. Reverse(dweb_get_extracted@b0458_285_2048) .. 34>)>, <MultiValues(<BV32 heap_base + 0x100>)>) @ 0xb026c`
- Sink/result preview: `nvram set adv.iptv.stballvlans=" <inferred_web>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetIptv` | `0xb032c` | `formSetIptv(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xb032c` |

### Trace 22: `static_source_inference`

- Trace path: `formSetIptv -> doSystemCmd`
- Source: `formSetIptv` at `0xb032c`
- Sink: `doSystemCmd` at `0xb0280`
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
- Result metrics: elapsed=70.7454s, steps=108, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `iptv.stb.enable, adv.iptv.stbpvid, adv.iptv.stballvlans, iptv.city.vlan, wans.flag`
- Source expression: `formSetIptv(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xb032c`
- Sink expression: `doSystemCmd(<MultiValues(<BV2280 0x6e7672616d20736574206164762e697074762e737462707669643d22 .. Reverse(dweb_get_extracted@b047c_286_2048) .. 34>)>, <MultiValues(<BV32 heap_base + 0x200>)>) @ 0xb0280`
- Sink/result preview: `nvram set adv.iptv.stbpvid=" <inferred_web>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetIptv` | `0xb032c` | `formSetIptv(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xb032c` |

### Trace 23: `residual`

- Trace path: `sub_affe0 -> doSystemCmd`
- Source: `sub_affe0` at `0xaffe0`
- Sink: `doSystemCmd` at `0xb0080`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=3.9574s, steps=19, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_affe0() @ 0xaffe0`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xffff462c>)>) @ 0xb0080`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_affe0` | `0xaffe0` | `sub_affe0() @ 0xaffe0` |

### Trace 24: `residual`

- Trace path: `sub_affe0 -> doSystemCmd`
- Source: `sub_affe0` at `0xaffe0`
- Sink: `doSystemCmd` at `0xb00e0`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=3.9568s, steps=20, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_affe0() @ 0xaffe0`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xffff4674>)>) @ 0xb00e0`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_affe0` | `0xaffe0` | `sub_affe0() @ 0xaffe0` |

### Trace 25: `residual`

- Trace path: `sub_affe0 -> doSystemCmd`
- Source: `sub_affe0` at `0xaffe0`
- Sink: `doSystemCmd` at `0xb0094`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=4.0127s, steps=19, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_affe0() @ 0xaffe0`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xffff4650>)>) @ 0xb0094`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_affe0` | `0xaffe0` | `sub_affe0() @ 0xaffe0` |

### Trace 26: `residual`

- Trace path: `sub_affe0 -> doSystemCmd`
- Source: `sub_affe0` at `0xaffe0`
- Sink: `doSystemCmd` at `0xb00f0`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=4.3960s, steps=20, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_affe0() @ 0xaffe0`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xffff4698>)>) @ 0xb00f0`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_affe0` | `0xaffe0` | `sub_affe0() @ 0xaffe0` |

### Trace 27: `unreachable`

- Trace path: `sub_61484 -> doSystemCmd`
- Source: `sub_61484` at `0x61484`
- Sink: `doSystemCmd` at `0x614d0`
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
- Result metrics: elapsed=15.6757s, steps=500, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_61484() @ 0x61484`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xfffe3d70>)>) @ 0x614d0`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_61484` | `0x61484` | `sub_61484() @ 0x61484` |

### Trace 28: `residual`

- Trace path: `formWriteFacMac -> doSystemCmd`
- Source: `formWriteFacMac` at `0x45040`
- Sink: `doSystemCmd` at `0x450a8`
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
- Result metrics: elapsed=21.5362s, steps=247, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `formWriteFacMac(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x45040`
- Sink expression: `doSystemCmd(<MultiValues(<BV2112 0x63666d206d616320 .. Reverse(dweb_get_extracted@4507c_289_2048)>)>, <MultiValues(<BV32 heap_base>)>) @ 0x450a8`
- Sink/result preview: `cfm mac 00:01:02:11:22:33`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formWriteFacMac` | `0x45040` | `formWriteFacMac(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x45040` |

### Trace 29: `residual`

- Trace path: `sub_7b73c -> doSystemCmd`
- Source: `sub_7b73c` at `0x7b73c`
- Sink: `doSystemCmd` at `0x7b8c4`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 6; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=13.5274s, steps=47, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_7b73c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7b73c`
- Sink expression: `doSystemCmd(<MultiValues(<BV216 0x6563686f20 .. TOP .. 0x203e202f746d702f636d64546d702e747874>)>, <MultiValues(<BV32 0x102994>)>) @ 0x7b8c4`
- Sink/result preview: `echo / > /tmp/cmdTmp.txt`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_7b73c` | `0x7b73c` | `sub_7b73c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7b73c` |

### Trace 30: `residual`

- Trace path: `sub_7b73c -> doSystemCmd`
- Source: `sub_7b73c` at `0x7b73c`
- Sink: `doSystemCmd` at `0x7b9ec`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 6; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=14.7029s, steps=48, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_7b73c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7b73c`
- Sink expression: `doSystemCmd(<MultiValues(<BV216 0x6563686f20 .. TOP .. 0x203e202f746d702f636d64546d702e747874>)>, <MultiValues(<BV32 0x102994>)>) @ 0x7b9ec`
- Sink/result preview: `echo %s > /tmp/cmdTmp.txt`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_7b73c` | `0x7b73c` | `sub_7b73c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7b73c` |

### Trace 31: `residual`

- Trace path: `sub_a86fc -> doSystemCmd`
- Source: `sub_a86fc` at `0xa86fc`
- Sink: `doSystemCmd` at `0xa89a0`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 10; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=18.7347s, steps=49, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_a86fc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa86fc`
- Sink expression: `doSystemCmd(<MultiValues(<BV2376 0x6563686f202231300a .. Reverse(dweb_get_extracted@a883c_300_2048) .. 0x22203e202f6574632f6368656e6779616e636f6e6669672f64656d6f2e636667>)>, <MultiValues(<BV32 heap_base + 0x200>)>) @ ...`
- Sink/result preview: `echo "10\x0a%s" > /etc/chengyanconfig/demo.cfg`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a86fc` | `0xa86fc` | `sub_a86fc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa86fc` |

### Trace 32: `residual`

- Trace path: `sub_a86fc -> doSystemCmd`
- Source: `sub_a86fc` at `0xa86fc`
- Sink: `doSystemCmd` at `0xa89b8`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 9; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=17.9398s, steps=49, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_a86fc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa86fc`
- Sink expression: `doSystemCmd(<MultiValues(<BV2352 0x6563686f2022 .. Reverse(dweb_get_extracted@a883c_300_2048) .. 0x22203e202f6574632f6368656e6779616e636f6e6669672f64656d6f2e636667>)>, <MultiValues(<BV32 heap_base + 0x200>)>) @ 0xa89b8`
- Sink/result preview: `echo "%s" > /etc/chengyanconfig/demo.cfg`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a86fc` | `0xa86fc` | `sub_a86fc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa86fc` |

### Trace 33: `residual`

- Trace path: `sub_a86fc -> doSystemCmd`
- Source: `sub_a86fc` at `0xa86fc`
- Sink: `doSystemCmd` at `0xa89f0`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=6, density=0.1111
- Path-control events: `semantic_frontier:6`
- Path-control audit: `6 pruned/omitted states or seeds; 6 frontier rounds, 0 loop rounds; max active 18; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=35.8088s, steps=54, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_a86fc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa86fc`
- Sink expression: `doSystemCmd(<MultiValues(<BV4264 0x6265686176696f725f6d616e6167657220 .. Reverse(dweb_get_extracted@a87f4_298_2048) .. 0x202d2d .. Reverse(dweb_get_extracted@a8818_299_2048) .. 32>)>, <MultiValues(<BV32 heap_base>)>, ...`
- Sink/result preview: `behavior_manager %s --%s `

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a86fc` | `0xa86fc` | `sub_a86fc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa86fc` |

### Trace 34: `residual`

- Trace path: `sub_a86fc -> doSystemCmd`
- Source: `sub_a86fc` at `0xa86fc`
- Sink: `doSystemCmd` at `0xa8a2c`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=40, density=0.7018
- Path-control events: `semantic_frontier:40`
- Path-control audit: `40 pruned/omitted states or seeds; 12 frontier rounds, 0 loop rounds; max active 28; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=54.1491s, steps=57, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_a86fc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa86fc`
- Sink expression: `doSystemCmd(<MultiValues(<BV4488 0x6265686176696f725f6d616e6167657220 .. Reverse(dweb_get_extracted@a87f4_298_2048) .. 0x202d2d .. Reverse(dweb_get_extracted@a8818_299_2048) .. 0x202f6574632f6368656e6779616e636f6e6669...`
- Sink/result preview: `behavior_manager %s --%s /etc/chengyanconfig/demo.cfg`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a86fc` | `0xa86fc` | `sub_a86fc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa86fc` |

### Trace 35: `static_source_inference`

- Trace path: `formAddMacfilterRule -> doSystemCmd`
- Source: `formAddMacfilterRule` at `0xc3548`
- Sink: `doSystemCmd` at `0xc3e6c`
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
- Result metrics: elapsed=48.2596s, steps=164, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `cgi_debug`
- Possible inputs: `macfilter.mode, TOP`
- Source expression: `formAddMacfilterRule(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xc3548`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 Reverse(GetValue("cgi_debug")@0xc4ae0[191:160]) + 0xffff65ac>)>) @ 0xc3e6c`
- Sink/result preview: `<inferred_config>`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formAddMacfilterRule` | `0xc3548` | `formAddMacfilterRule(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xc3548` |

### Trace 36: `residual`

- Trace path: `sub_3d8b8 -> doSystemCmd`
- Source: `sub_3d8b8` at `0x3d8b8`
- Sink: `doSystemCmd` at `0x3d8bc`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.1666s, steps=2, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_3d8b8() @ 0x3d8b8`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP>)>) @ 0x3d8bc`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_3d8b8` | `0x3d8b8` | `sub_3d8b8() @ 0x3d8b8` |

### Trace 37: `residual`

- Trace path: `sub_3a1a4 -> doSystemCmd`
- Source: `sub_3a1a4` at `0x3a1a4`
- Sink: `doSystemCmd` at `0x3a3b0`
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
- Result metrics: elapsed=72.9932s, steps=83, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `lan.gst.1.ip`
- Possible inputs: `dhcps.gst.1.en, dhcps.en`
- Source expression: `sub_3a1a4() @ 0x3a1a4`
- Sink expression: `doSystemCmd(<MultiValues(<BV2160 0x6966636f6e66696720 .. GetValue("lan.gst.1.ip")@0x3a334[2047:1280] .. Reverse(TOP) .. GetValue("lan.gst.1.ip")@0x3a334[1247:0] .. 32 .. TOP>)>, <MultiValues(<BV32 stack_base - 0x74>)>...`
- Sink/result preview: `ifconfig %s `

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_3a1a4` | `0x3a1a4` | `sub_3a1a4() @ 0x3a1a4` |

### Trace 38: `residual`

- Trace path: `sub_b7094 -> doSystemCmd`
- Source: `sub_b7094` at `0xb7094`
- Sink: `doSystemCmd` at `0xb7120`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=3.5791s, steps=13, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_b7094(<MultiValues(<BV32 0x0>)>) @ 0xb7094`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 stack_base - 0x110>)>) @ 0xb7120`
- Sink/result preview: `echo -gro 1610612736 >> proc/net/vlan/1`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_b7094` | `0xb7094` | `sub_b7094(<MultiValues(<BV32 0x0>)>) @ 0xb7094` |

### Trace 39: `vulnerable`

- Trace path: `sub_a0bcc -> doSystemCmd`
- Source: `sub_a0bcc` at `0xa0bcc`
- Sink: `doSystemCmd` at `0xa0c60`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `high` score=90, review=`critical`, claim=`direct_sink_byte_sv_sat_evidence`
- Evidence factors: `direct_sink_evidence, partial_sanitizer_profile, sanitizer_gap_profile_partial, sat_payload_evidence, strong_static_binding`
- Path control: `direct_sink_evidence` pressure=`resolved`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop multi_state_settle_budget_exhausted`
- Result metrics: elapsed=10.0641s, steps=20, vectors=3/8 vulnerable/secure, coverage=0.7273
- Sanitizer gap: `partial_filter` partial sanitizer: 3 bypass vector(s) across 2 category/categories; 8 vector(s) blocked
- Gap categories: bypass=`Command Substitution, Variable Expansion`, blocked=`Background Execution, Bypass Spaces, Command Chaining, Piping, Redirection`
- Minimal bypass: `Command Substitution` vector=`$(` poc=`cfm post netctrl 51?op=1,string_info=A$(:)AA`
- Repair hints: `Command Substitution: reject backtick and $() substitution syntax or execute without a shell; Variable Expansion: reject dollar expansion syntax or force strict single-argument quoting`
- Likely inputs: `/tmp/UDiskname`
- Possible inputs: ``
- Source expression: `sub_a0bcc() @ 0xa0bcc`
- Sink expression: `doSystemCmd(<MultiValues(<BV360 0x63666d20706f7374206e65746374726c2035313f6f703d312c737472696e675f696e666f3d .. fgets(fopen("/tmp/UDiskname", "r+")@0xa0c0c_352_32)@0xa0c34_353_64>)>, <MultiValues(<BV32 0x33>)>, <Multi...`
- Sink/result preview: `cfm post netctrl 51?op=1,string_info=AA(:)"A`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a0bcc` | `0xa0bcc` | `sub_a0bcc() @ 0xa0bcc` |

### Trace 40: `residual`

- Trace path: `sub_9283c -> doSystemCmd`
- Source: `sub_9283c` at `0x9283c`
- Sink: `doSystemCmd` at `0x9293c`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=15, density=0.1128
- Path-control events: `semantic_frontier:15`
- Path-control audit: `15 pruned/omitted states or seeds; 10 frontier rounds, 0 loop rounds; max active 12; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=98.0834s, steps=133, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP, /webroot/default.cfg`
- Source expression: `sub_9283c() @ 0x9283c`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV32 TOP + 0xffff0f48>, <BV32 TOP + 0xffff0f48>}})>) @ 0x9293c`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_9283c` | `0x9283c` | `sub_9283c() @ 0x9283c` |

### Trace 41: `residual`

- Trace path: `sub_9283c -> doSystemCmd`
- Source: `sub_9283c` at `0x9283c`
- Sink: `doSystemCmd` at `0x92950`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=15, density=0.1111
- Path-control events: `semantic_frontier:15`
- Path-control audit: `15 pruned/omitted states or seeds; 10 frontier rounds, 0 loop rounds; max active 12; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=105.1647s, steps=135, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP, /webroot/default.cfg`
- Source expression: `sub_9283c() @ 0x9283c`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV32 TOP + 0xffff0f70>, <BV32 TOP + 0xffff0f70>}})>) @ 0x92950`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_9283c` | `0x9283c` | `sub_9283c() @ 0x9283c` |

### Trace 42: `timeout`

- Trace path: `sub_9283c -> doSystemCmd`
- Source: `sub_9283c` at `0x9283c`
- Sink: `doSystemCmd` at `0x92a50`
- Stop/reason: `engine_timeout`
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `absent_static_binding, missing_sink_preview, path_budget_residual_risk, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=17, density=0.1069
- Path-control events: `semantic_frontier:14, seed_equivalence:3`
- Path-control audit: `17 pruned/omitted states or seeds; 12 frontier rounds, 0 loop rounds; max active 27; stop engine_timeout`
- Residual diagnosis: `time_budget_exhaustion` severity=`high` The analysis consumed its time budget before reaching a resolved sink or no-taint explanation.
- Residual next actions: `rerun with a larger closure/subprocess timeout; enable evidence cache and same-run memoization; inspect path-control events for repeated frontier classes`
- Recovery plan: strategy=`budget_extension_rerun`, priority=`high`, overrides=`closure_timeout=180, engine_timeout=90, max_steps=1000, subprocess_timeout=240`, gaps=``
- Result metrics: elapsed=91.9617s, steps=159, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP, /webroot/default.cfg`
- Source expression: `sub_9283c() @ 0x9283c`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xffff0ff0>)>) @ 0x92a50`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_9283c` | `0x9283c` | `sub_9283c() @ 0x9283c` |

### Trace 43: `residual`

- Trace path: `sub_6fe24 -> doSystemCmd`
- Source: `sub_6fe24` at `0x6fe24`
- Sink: `doSystemCmd` at `0x6fe54`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=2.2704s, steps=7, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_6fe24() @ 0x6fe24`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP + 0xfffe5dc0>)>) @ 0x6fe54`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_6fe24` | `0x6fe24` | `sub_6fe24() @ 0x6fe24` |

### Trace 44: `residual`

- Trace path: `sub_6b6a0 -> doShell`
- Source: `sub_6b6a0` at `0x6b6a0`
- Sink: `doShell` at `0x6b720`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 3; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=3.9324s, steps=8, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_6b6a0(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x6b6a0`
- Sink expression: `doShell(<MultiValues(<BV32 TOP>)>) @ 0x6b720`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_6b6a0` | `0x6b6a0` | `sub_6b6a0(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x6b6a0` |

### Trace 45: `residual`

- Trace path: `sub_69d24 -> sub_6986c -> doSystemCmd`
- Source: `sub_69d24` at `0x69d24`
- Sink: `doSystemCmd` at `0x69bd0`
- Stop/reason: `active_empty`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `file:/proc/mounts (mango_likely_input); file:/proc/mounts (trace_expression_token)`
- Result metrics: elapsed=2.2736s, steps=4, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: `/proc/mounts`
- Possible inputs: `/sys/bus/usb/devices/usb1/idProduct, /sys/bus/usb/devices/usb1/idVendor`
- Source expression: `sub_69d24(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x69d24`
- Sink expression: `doSystemCmd(<MultiValues({0: {<BV2216 0x63617420 .. fgets(fopen("/proc/mounts", "r")@0x69944_316_32)@0x69a90_322_2048 .. 47 .. TOP .. 0x203e202f6465762f6e756c6c>, <BV2216 0x63617420 .. fgets(fopen("/proc/mounts", "r")...`
- Sink/result preview: ` \x09  \x09  \x09   \x09\x09 \x09 \x09\x09 \x09\x09\x09\x09\x09    @\x09 `

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_69d24` | `0x69d24` | `sub_69d24(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x69d24` |
| 1 | `sub_6986c` | `0x69d68` | `sub_6986c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x69d68` |

### Trace 46: `unreachable`

- Trace path: `sub_38784 -> sub_38580 -> doSystemCmd`
- Source: `sub_38784` at `0x38784`
- Sink: `doSystemCmd` at `0x38614`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `absent_static_binding, missing_sink_preview, path_budget_residual_risk, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Result metrics: elapsed=2.2125s, steps=24, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `<BV32 TOP>`
- Source expression: `sub_38784(<MultiValues(<BV32 TOP>)>) @ 0x38784`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 stack_base - 0x250>)>) @ 0x38614`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_38784` | `0x38784` | `sub_38784(<MultiValues(<BV32 TOP>)>) @ 0x38784` |
| 1 | `sub_38580` | `0x38b20` | `sub_38580(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP + 0x2>)>, <MultiValues(<BV32 TOP - 0x2 - (TOP + 0x2)>)>) @ 0x38b20` |

### Trace 49: `residual`

- Trace path: `sub_3cf04 -> sub_3c9f8 -> doSystemCmd`
- Source: `sub_3cf04` at `0x3cf04`
- Sink: `doSystemCmd` at `0x3c5d0`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:wans.flag (mango_possible_input); config_key:wl0_ifname (mango_possible_input); config_key:wl1_ifname (mango_possible_input)`
- Result metrics: elapsed=7.2693s, steps=28, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `wans.flag, wl0_ifname, wl1_ifname`
- Source expression: `sub_3cf04(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x3cf04`
- Sink expression: `doSystemCmd(<MultiValues(<BV448 0x6563686f2022776c202d6920776c305f69666e616d6520 .. TOP .. 0x3a22203e3e202f746d702f7379736c6f672f776c5f696e666f2e6c6f67>)>, <MultiValues(<BV32 stack_base - 0x66c>)>, <MultiValues(<BV32 ...`
- Sink/result preview: `echo "date:" >> /tmp/syslog/sys_info.log`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_3cf04` | `0x3cf04` | `sub_3cf04(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x3cf04` |
| 1 | `sub_3c9f8` | `0x3cfc0` | `sub_3c9f8(<MultiValues(<BV32 stack_base - 0x440>)>) @ 0x3cfc0` |

### Trace 50: `residual`

- Trace path: `sub_3cf04 -> sub_3c9f8 -> doSystemCmd`
- Source: `sub_3cf04` at `0x3cf04`
- Sink: `doSystemCmd` at `0x3c5fc`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `strong`
- Evidence confidence: `low` score=36, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `strong_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:wans.flag (mango_possible_input); config_key:wl0_ifname (mango_possible_input); config_key:wl1_ifname (mango_possible_input)`
- Result metrics: elapsed=8.0548s, steps=32, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `wans.flag, wl0_ifname, wl1_ifname`
- Source expression: `sub_3cf04(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x3cf04`
- Sink expression: `doSystemCmd(<MultiValues(<BV392 0x776c202d6920776c305f69666e616d6520 .. TOP .. 0x203e3e202f746d702f7379736c6f672f776c5f696e666f2e6c6f670a>)>, <MultiValues(<BV32 stack_base - 0x66c>)>, <MultiValues(<BV32 0xde71c>)>) @ ...`
- Sink/result preview: `date >> /tmp/syslog/sys_info.log\x0a`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_3cf04` | `0x3cf04` | `sub_3cf04(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x3cf04` |
| 1 | `sub_3c9f8` | `0x3cfc0` | `sub_3c9f8(<MultiValues(<BV32 stack_base - 0x440>)>) @ 0x3cfc0` |

### Trace 51: `residual`

- Trace path: `sub_3cb98 -> sub_3c5a0 -> doSystemCmd`
- Source: `sub_3cb98` at `0x3cb98`
- Sink: `doSystemCmd` at `0x3c5d0`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.1272s, steps=2, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_3cb98() @ 0x3cb98`
- Sink expression: `doSystemCmd(<MultiValues(<BV160 0x6563686f2022 .. TOP .. 0x3a22203e3e20 .. TOP>)>, <MultiValues(<BV32 TOP + (TOP << 0x5)>)>, <MultiValues(<BV32 TOP + 0xfffdf7d8>)>) @ 0x3c5d0`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_3cb98` | `0x3cb98` | `sub_3cb98() @ 0x3cb98` |
| 1 | `sub_3c5a0` | `0x3cbc0` | `sub_3c5a0(<MultiValues(<BV32 TOP + (TOP << 0x5)>)>, <MultiValues(<BV32 TOP + 0xfffdf7d8>)>) @ 0x3cbc0` |

### Trace 52: `residual`

- Trace path: `sub_3cb98 -> sub_3c5a0 -> doSystemCmd`
- Source: `sub_3cb98` at `0x3cb98`
- Sink: `doSystemCmd` at `0x3c5e4`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.1181s, steps=2, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_3cb98() @ 0x3cb98`
- Sink expression: `doSystemCmd(<MultiValues(<BV536 0x6563686f20222a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a22203e3e20 .. TOP>)>, <MultiValues(<BV32 TOP + 0xfffdf7d8>)>) @ 0x3...`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_3cb98` | `0x3cb98` | `sub_3cb98() @ 0x3cb98` |
| 1 | `sub_3c5a0` | `0x3cbc0` | `sub_3c5a0(<MultiValues(<BV32 TOP + (TOP << 0x5)>)>, <MultiValues(<BV32 TOP + 0xfffdf7d8>)>) @ 0x3cbc0` |

### Trace 53: `residual`

- Trace path: `sub_3cb98 -> sub_3c5a0 -> doSystemCmd`
- Source: `sub_3cb98` at `0x3cb98`
- Sink: `doSystemCmd` at `0x3c5fc`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.1190s, steps=2, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_3cb98() @ 0x3cb98`
- Sink expression: `doSystemCmd(<MultiValues(<BV104 TOP .. 0x203e3e20 .. TOP .. 10>)>, <MultiValues(<BV32 TOP + (TOP << 0x5)>)>, <MultiValues(<BV32 TOP + 0xfffdf7d8>)>) @ 0x3c5fc`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_3cb98` | `0x3cb98` | `sub_3cb98() @ 0x3cb98` |
| 1 | `sub_3c5a0` | `0x3cbc0` | `sub_3c5a0(<MultiValues(<BV32 TOP + (TOP << 0x5)>)>, <MultiValues(<BV32 TOP + 0xfffdf7d8>)>) @ 0x3cbc0` |

### Trace 54: `residual`

- Trace path: `sub_3cb98 -> sub_3c5a0 -> doSystemCmd`
- Source: `sub_3cb98` at `0x3cb98`
- Sink: `doSystemCmd` at `0x3c610`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.1180s, steps=2, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_3cb98() @ 0x3cb98`
- Sink expression: `doSystemCmd(<MultiValues(<BV544 0x6563686f20222a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a0a22203e3e20 .. TOP>)>, <MultiValues(<BV32 TOP + 0xfffdf7d8>)>) @ 0...`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_3cb98` | `0x3cb98` | `sub_3cb98() @ 0x3cb98` |
| 1 | `sub_3c5a0` | `0x3cbc0` | `sub_3c5a0(<MultiValues(<BV32 TOP + (TOP << 0x5)>)>, <MultiValues(<BV32 TOP + 0xfffdf7d8>)>) @ 0x3cbc0` |

### Trace 55: `residual`

- Trace path: `sub_77ac0 -> sub_779e0 -> popen`
- Source: `sub_77ac0` at `0x77ac0`
- Sink: `popen` at `0x77a40`
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
- Result metrics: elapsed=1.8014s, steps=17, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `sys.mode, wan1.connecttype`
- Source expression: `sub_77ac0() @ 0x77ac0`
- Sink expression: `popen(<MultiValues(<BV32 stack_base - 0x54>)>, <MultiValues(<BV32 0xe5aac>)>) @ 0x77a40`
- Sink/result preview: `cat /etc/ddns_%s`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_77ac0` | `0x77ac0` | `sub_77ac0() @ 0x77ac0` |
| 1 | `sub_779e0` | `0x77c40` | `sub_779e0(<MultiValues(<BV32 stack_base - 0x54>)>, <MultiValues(<BV32 stack_base - 0x58>)>) @ 0x77c40` |

### Trace 56: `unreachable`

- Trace path: `sub_10f80 -> sub_30684 -> execve`
- Source: `sub_10f80` at `0x10f80`
- Sink: `execve` at `0x3079c`
- Stop/reason: `step_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `absent_static_binding, missing_sink_preview, path_budget_residual_risk, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop step_budget_exhausted`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Result metrics: elapsed=31.7278s, steps=500, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_10f80(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x10f80`
- Sink expression: `execve(<MultiValues({0: {<BV32 0x13e>, <BV32 0x0>, <BV32 Reverse(TOP) + 0x40>, <BV32 0x40>}})>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x3079c`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_10f80` | `0x10f80` | `sub_10f80(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x1...` |
| 1 | `sub_30684` | `0x11598` | `sub_30684(<MultiValues({0: {<BV32 0x40>, <BV32 Reverse(TOP) + 0x40>, <BV32 0x13e>, <BV32 0x0>}})>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)...` |

## Per-Closure Results

| Closure | Status | Confidence | Review | Path control | Stop/reason | Time(s) | Steps | V/S | Coverage | Static | Classification | Preview |
|---:|---|---|---|---|---|---:|---:|---:|---:|---|---|---|
| 1 | residual | low | high | unclassified | active_empty | 4.6988 | 47 |  |  | strong |  | smbpasswd -a admin -s < /tmp/smbpasswd |
| 2 | unreachable | low | high | residual_budget_stop | active_empty | 4.6176 | 12 |  |  | absent |  |  |
| 3 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 10.2472 | 77 |  |  | strong |  | cfm post netctrl 51?op=3,string_info=%s |
| 4 | static_source_inference | low | high | residual_budget_stop | step_budget_exhausted | 36.9801 | 500 |  |  | strong | static_direct_source_fallback | <inferred_config> |
| 5 | vulnerable | medium | critical | direct_sink_evidence | multi_state_settle_budget_exhausted | 26.1150 | 12 | 11/0 | 0.0000 | absent |  | echo "%s" >> /etc/chengyanconfig/</dev/nullAAAAAAAAAAAAAAAAAAAAA |
| 6 | residual | low | high | unclassified | active_empty | 0.8998 | 9 |  |  | strong |  | cfm post netctrl 51?op=3,string_info=%s |
| 7 | static_source_inference | low | high | residual_budget_stop | engine_timeout | 110.1344 | 417 |  |  | strong | static_sink_template_fallback | iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 8 | static_source_inference | low | high | residual_budget_stop | engine_timeout | 110.1076 | 411 |  |  | strong | static_sink_template_fallback | iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 9 | static_source_inference | low | high | residual_budget_stop | engine_timeout | 90.3000 | 407 |  |  | strong | static_sink_template_fallback | iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 10 | static_source_inference | low | high | unclassified | multi_state_settle_budget_exhausted | 90.7041 | 124 |  |  | strong | static_sink_template_fallback | iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 11 | static_source_inference | low | high | residual_budget_stop | engine_timeout | 90.3200 | 319 |  |  | strong | static_sink_template_fallback | iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 12 | static_source_inference | low | high | unclassified | multi_state_settle_budget_exhausted | 93.2642 | 125 |  |  | strong | static_sink_template_fallback | iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 13 | static_source_inference | low | high | unclassified | multi_state_settle_budget_exhausted | 94.3411 | 126 |  |  | strong | static_sink_template_fallback | iptables -t filter -D INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 14 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 76.8946 | 92 |  |  | strong |  | iptables -t filter -D INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP |
| 15 | static_source_inference | low | high | unclassified | multi_state_settle_budget_exhausted | 98.1125 | 128 |  |  | strong | static_sink_template_fallback | iptables -t filter -I INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 16 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 84.3529 | 94 |  |  | strong |  | iptables -t filter -I INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP |
| 17 | static_source_inference | low | high | residual_budget_stop | engine_timeout | 110.9215 | 398 |  |  | strong | static_sink_template_fallback | iptables -t filter -I INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 18 | static_source_inference | low | high | unclassified | multi_state_settle_budget_exhausted | 103.9984 | 130 |  |  | strong | static_sink_template_fallback | iptables -t filter -I INPUT -i -p icmp -m icmp --icmp-type 8 -j DROP <inferred_config> |
| 19 | vulnerable | medium | critical | direct_sink_evidence | active_empty | 19.9497 | 7 | 11/0 | 0.0000 | absent |  | mv </dev/nullAAAAAAAAAAAAAAAAAAAAA |
| 20 | residual | low | high | unclassified | active_empty | 3.4508 | 9 |  |  | strong |  | telnetd -b %s & |
| 21 | static_source_inference | low | high | unclassified | active_empty | 70.2109 | 108 |  |  | strong | static_sink_template_fallback | nvram set adv.iptv.stballvlans=" <inferred_web> |
| 22 | static_source_inference | low | high | unclassified | active_empty | 70.7454 | 108 |  |  | strong | static_sink_template_fallback | nvram set adv.iptv.stbpvid=" <inferred_web> |
| 23 | residual | low | high | unclassified | active_empty | 3.9574 | 19 |  |  | absent |  |  |
| 24 | residual | low | high | unclassified | active_empty | 3.9568 | 20 |  |  | absent |  |  |
| 25 | residual | low | high | unclassified | active_empty | 4.0127 | 19 |  |  | absent |  |  |
| 26 | residual | low | high | unclassified | active_empty | 4.3960 | 20 |  |  | absent |  |  |
| 27 | unreachable | low | high | residual_budget_stop | step_budget_exhausted | 15.6757 | 500 |  |  | absent |  |  |
| 28 | residual | low | high | unclassified | active_empty | 21.5362 | 247 |  |  | strong |  | cfm mac 00:01:02:11:22:33 |
| 29 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 13.5274 | 47 |  |  | absent |  | echo / > /tmp/cmdTmp.txt |
| 30 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 14.7029 | 48 |  |  | absent |  | echo %s > /tmp/cmdTmp.txt |
| 31 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 18.7347 | 49 |  |  | strong |  | echo "10\x0a%s" > /etc/chengyanconfig/demo.cfg |
| 32 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 17.9398 | 49 |  |  | strong |  | echo "%s" > /etc/chengyanconfig/demo.cfg |
| 33 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 35.8088 | 54 |  |  | strong |  | behavior_manager %s --%s  |
| 34 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 54.1491 | 57 |  |  | strong |  | behavior_manager %s --%s /etc/chengyanconfig/demo.cfg |
| 35 | static_source_inference | low | high | unclassified | active_empty | 48.2596 | 164 |  |  | strong | static_direct_source_fallback | <inferred_config> |
| 36 | residual | low | high | unclassified | active_empty | 0.1666 | 2 |  |  | absent |  |  |
| 37 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 72.9932 | 83 |  |  | strong |  | ifconfig %s  |
| 38 | residual | low | high | unclassified | active_empty | 3.5791 | 13 |  |  | absent |  | echo -gro 1610612736 >> proc/net/vlan/1 |
| 39 | vulnerable | high | critical | direct_sink_evidence | multi_state_settle_budget_exhausted | 10.0641 | 20 | 3/8 | 0.7273 | strong |  | cfm post netctrl 51?op=1,string_info=AA(:)"A |
| 40 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 98.0834 | 133 |  |  | absent |  |  |
| 41 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 105.1647 | 135 |  |  | absent |  |  |
| 42 | timeout | low | high | residual_budget_stop | engine_timeout | 91.9617 | 159 |  |  | absent |  |  |
| 43 | residual | low | high | unclassified | active_empty | 2.2704 | 7 |  |  | absent |  |  |
| 44 | residual | low | high | unclassified | active_empty | 3.9324 | 8 |  |  | absent |  |  |
| 45 | residual | low | high | unclassified | active_empty | 2.2736 | 4 |  |  | strong |  |  \x09  \x09  \x09   \x09\x09 \x09 \x09\x09 \x09\x09\x09\x09\x09    @\x09  |
| 46 | unreachable | low | high | residual_budget_stop | active_empty | 2.2125 | 24 |  |  | absent |  |  |
| 49 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 7.2693 | 28 |  |  | strong |  | echo "date:" >> /tmp/syslog/sys_info.log |
| 50 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 8.0548 | 32 |  |  | strong |  | date >> /tmp/syslog/sys_info.log\x0a |
| 51 | residual | low | high | unclassified | active_empty | 0.1272 | 2 |  |  | absent |  |  |
| 52 | residual | low | high | unclassified | active_empty | 0.1181 | 2 |  |  | absent |  |  |
| 53 | residual | low | high | unclassified | active_empty | 0.1190 | 2 |  |  | absent |  |  |
| 54 | residual | low | high | unclassified | active_empty | 0.1180 | 2 |  |  | absent |  |  |
| 55 | residual | low | high | unclassified | active_empty | 1.8014 | 17 |  |  | weak |  | cat /etc/ddns_%s |
| 56 | unreachable | low | high | residual_budget_stop | step_budget_exhausted | 31.7278 | 500 |  |  | absent |  |  |

## Output Artifacts

- Summary JSON: `/home/ubuntu/work/sanitizer/experiment_reports/full_firmware_campaign_current_tsds_multistate_full_20260916/tenda_ac18.summary.json`
- Per-closure JSONL: `/home/ubuntu/work/sanitizer/experiment_reports/full_firmware_campaign_current_tsds_multistate_full_20260916/tenda_ac18.results.jsonl`
