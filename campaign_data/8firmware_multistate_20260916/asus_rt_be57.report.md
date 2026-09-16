# TSDS Analysis Report

- Generated: 2026-09-15 19:42:30
- Binary: `/home/ubuntu/work/sanitizer/ASUS_RT-BE57/httpd`
- Trace JSON: `/home/ubuntu/work/sanitizer/ASUS_RT-BE57/result/cmdi_results.json`
- Mode: `full`
- Total closures: 32
- Unique pairs expected: 19
- Unique pairs analyzed: 19

## Executive Summary

| Metric | Value |
|---|---:|
| SV-SAT | 3 |
| Modeled-vector filtered | 0 |
| Partially filtered SV-SAT | 0 |
| No-modeled-source sink | 0 |
| Static source inference | 0 |
| Static warning reduction | 0 |
| Residual obligation | 11 |
| Unreachable | 5 |
| Timeout | 0 |
| Crashed | 0 |
| Evaluation errors | 0 |
| SAT shell-vector witnesses | 33 |
| Blocked-vector proofs | 11 |
| Average sanitizer coverage | 0.1429 |
| Wall time seconds | 502.4755 |
| Average closure time seconds | 26.3243 |
| Average matrix time seconds | 0.8988 |
| Average engine steps | 44.7900 |
| Semantic frontier cuts | 4 |
| Source-liveness cuts | 1 |
| Delay-slot sink captures | 0 |
| Loop semantic cuts | 0 |
| Seed states tried | 96 |
| Seed states pruned | 3 |
| Memoized closures | 0 |
| Evidence cache hits | 0 |

## Model Gap Requests

| Dimension | Count |
|---|---:|
| kind:config_key | 4 |
| reason:mango_possible_input | 4 |

| Closure | Kind | Key | Reason | Confidence | Evidence |
|---:|---|---|---|---|---|
| 7 | config_key | lan_ifname | mango_possible_input | medium | lan_ifname |
| 17 | config_key | apg0_ssid | mango_possible_input | medium | apg0_ssid |
| 27 | config_key | lan_ipaddr | mango_possible_input | medium | lan_ipaddr |
| 27 | config_key | wl_unit | mango_possible_input | medium | wl_unit |

## Engine Stop Reasons

| Stop reason | Count |
|---|---:|
| `active_empty` | 17 |
| `guided_stagnation_saturated` | 1 |
| `source_liveness_saturated` | 1 |

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
| confidence:medium | 3 |
| confidence:low | 16 |
| review:critical | 3 |
| review:high | 16 |
| claim:direct_sink_byte_sv_sat_evidence | 3 |
| claim:evidence_contract_residual | 11 |
| claim:residual_unclear_outcome | 5 |

## Semantic Path-Control Ledger

| Dimension | Count |
|---|---:|
| class:direct_sink_evidence | 3 |
| class:residual_budget_stop | 4 |
| class:semantic_saturation | 1 |
| class:unclassified | 11 |
| pressure:not_applicable | 11 |
| pressure:residual_risk | 4 |
| pressure:resolved | 3 |
| pressure:semantically_bounded | 1 |
| total:path_control_pruned_states | 36 |
| total:semantic_pruned_states | 4 |
| total:seed_pruned | 3 |

## Residual Diagnosis

| Dimension | Count |
|---|---:|
| class:bounded_multi_state_no_admissible_primary | 7 |
| class:path_explosion_residual | 4 |
| class:evidence_contract_residual | 3 |
| class:bounded_multi_state_collection_incomplete | 1 |
| class:weak_candidate_unreached | 1 |
| severity:high | 15 |
| severity:medium | 1 |
| action:inspect contract violations and vector decisions | 11 |
| action:keep the record outside SV-SAT, M-Filt, and NMS aggregates | 11 |
| action:rerun unknown quote contexts or pruned negative paths conservatively | 11 |
| action:add a targeted parser or wrapper summary if the trace repeats around one helper | 4 |
| action:increase max steps or closure timeout for this closure | 4 |
| action:inspect loop-semantic and frontier-pruning events | 4 |
| action:manually inspect the static closure before increasing symbolic budget | 1 |
| action:prioritize lower than strong-source unreachable closures | 1 |

## Residual Recovery Plan

| Dimension | Count |
|---|---:|
| strategy:manual_review | 11 |
| strategy:semantic_path_refinement | 4 |
| strategy:static_candidate_triage | 1 |
| priority:medium | 11 |
| priority:high | 4 |
| priority:low | 1 |
| model-gap:loop_or_parser_summary | 4 |
| model-gap:sink_distance_model | 4 |
| config:closure_timeout=180 | 4 |
| config:loop_semantic_saturation_limit=5 | 4 |
| config:max_steps=1000 | 4 |
| config:semantic_frontier_bucket_limit=3 | 4 |
| config:loop_semantic_weak_static=True | 1 |

## Sanitizer Gap Diagnosis

| Dimension | Count |
|---|---:|
| strength:broadly_bypassable | 3 |
| strength:fully_filtered | 1 |
| strength:unresolved_filter | 3 |
| bypass:Background Execution | 3 |
| bypass:Bypass Spaces | 3 |
| bypass:Command Chaining | 3 |
| bypass:Command Substitution | 3 |
| bypass:Piping | 3 |
| bypass:Redirection | 3 |
| bypass:Variable Expansion | 3 |
| blocked:Background Execution | 1 |
| blocked:Bypass Spaces | 1 |
| blocked:Command Chaining | 1 |
| blocked:Command Substitution | 1 |
| blocked:Piping | 1 |
| blocked:Redirection | 1 |
| blocked:Variable Expansion | 1 |

## Vulnerable And Partial Findings

| Closure | Status | Vectors V/S | Coverage | Source kinds | Recovery | Preview |
|---:|---|---:|---:|---|---|---|
| 3 | vulnerable | 11/0 | 0.0000 | entry_arg |  | :;:;#AAAAAAAAAAAAAAAAAAAAAAAAA  |
| 4 | vulnerable | 11/0 | 0.0000 | entry_arg |  | </dev/nullAAAAAAAAAAAAAAAAAAAAA |
| 8 | vulnerable | 11/0 | 0.0000 | entry_arg |  | hostapd_cli -i:;:;#AAAAAAAAAAAAAAAAAAAAAAAAAA |

## Unclear Or Operational Outcomes

| Closure | Status | Diagnosis | Severity | Reason | Time(s) | Static evidence | Preview/Error |
|---:|---|---|---|---|---:|---|---|
| 17 | unreachable | path_explosion_residual | high | active_empty | 27.4501 | weak |  |
| 20 | unreachable | path_explosion_residual | high | active_empty | 4.7255 | absent |  |
| 24 | unreachable | weak_candidate_unreached | medium | source_liveness_saturated | 89.0922 | weak |  |
| 27 | unreachable | path_explosion_residual | high | active_empty | 15.7136 | weak |  |
| 28 | unreachable | path_explosion_residual | high | guided_stagnation_saturated | 56.6687 | absent |  |

## Trace-Level Analysis

### Trace 1: `residual`

- Trace path: `sub_4fae4 -> system`
- Source: `sub_4fae4` at `0x4fae4`
- Sink: `system` at `0x4fafc`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.3483s, steps=4, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_4fae4() @ 0x4fae4`
- Sink expression: `system(<MultiValues(<BV32 stack_base + 0x4>)>) @ 0x4fafc`
- Sink/result preview: `\xc0\x1d\xff\xeb\x04`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_4fae4` | `0x4fae4` | `sub_4fae4() @ 0x4fae4` |

### Trace 2: `residual`

- Trace path: `sub_6bfec -> system`
- Source: `sub_6bfec` at `0x6bfec`
- Sink: `system` at `0x6c028`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `evidence_contract_residual` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.4991s, steps=6, vectors=0/0 vulnerable/secure, coverage=0.0000
- Sanitizer gap: `unresolved_filter` solver gaps prevent sanitizer diagnosis for 11 vector(s)
- Repair hints: `Background Execution: reject or quote ampersand job-control operators; Bypass Spaces: normalize and reject alternate whitespace forms such as tabs and ${IFS}; Command Chaining: reject or quote command separators such as semicolon and newline, or avoid shell...`
- Source expression: `sub_6bfec() @ 0x6bfec`
- Sink expression: `system(<MultiValues(<BV32 TOP>)>) @ 0x6c028`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_6bfec` | `0x6bfec` | `sub_6bfec() @ 0x6bfec` |

### Trace 3: `vulnerable`

- Trace path: `sub_40758 -> system`
- Source: `sub_40758` at `0x40758`
- Sink: `system` at `0x407cc`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `medium` score=64, review=`critical`, claim=`direct_sink_byte_sv_sat_evidence`
- Evidence factors: `absent_static_binding, direct_sink_evidence, sanitizer_gap_profile_broad_bypass, sat_payload_evidence`
- Path control: `direct_sink_evidence` pressure=`resolved`, pruned=0, density=0.0000
- Path-control audit: `max active 3; stop active_empty`
- Result metrics: elapsed=23.2165s, steps=19, vectors=11/0 vulnerable/secure, coverage=0.0000
- Sanitizer gap: `broadly_bypassable` broad sanitizer gap: all decided vectors are bypassable (11 vector(s))
- Gap categories: bypass=`Background Execution, Bypass Spaces, Command Chaining, Command Substitution, Piping, Redirection, Variable Expansion`, blocked=``
- Minimal bypass: `Background Execution` vector=`&` poc=`:&:;#AAAAAAAAAAAAAAAAAAAAAAAAA`
- Repair hints: `Background Execution: reject or quote ampersand job-control operators; Bypass Spaces: normalize and reject alternate whitespace forms such as tabs and ${IFS}; Command Chaining: reject or quote command separators such as semicolon and newline, or avoid shell...`
- Source expression: `sub_40758(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x40758`
- Sink expression: `system(<MultiValues(<BV32 TOP>)>) @ 0x407cc`
- Sink/result preview: `:;:;#AAAAAAAAAAAAAAAAAAAAAAAAA `

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_40758` | `0x40758` | `sub_40758(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x40758` |

### Trace 4: `vulnerable`

- Trace path: `sub_406b4 -> system`
- Source: `sub_406b4` at `0x406b4`
- Sink: `system` at `0x406d4`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `medium` score=64, review=`critical`, claim=`direct_sink_byte_sv_sat_evidence`
- Evidence factors: `absent_static_binding, direct_sink_evidence, sanitizer_gap_profile_broad_bypass, sat_payload_evidence`
- Path control: `direct_sink_evidence` pressure=`resolved`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Result metrics: elapsed=4.0641s, steps=4, vectors=11/0 vulnerable/secure, coverage=0.0000
- Sanitizer gap: `broadly_bypassable` broad sanitizer gap: all decided vectors are bypassable (11 vector(s))
- Gap categories: bypass=`Background Execution, Bypass Spaces, Command Chaining, Command Substitution, Piping, Redirection, Variable Expansion`, blocked=``
- Minimal bypass: `Background Execution` vector=`&` poc=`:&:;#AAAAAAAAAAAAAAAAAAAAAAAAAA`
- Repair hints: `Background Execution: reject or quote ampersand job-control operators; Bypass Spaces: normalize and reject alternate whitespace forms such as tabs and ${IFS}; Command Chaining: reject or quote command separators such as semicolon and newline, or avoid shell...`
- Source expression: `sub_406b4() @ 0x406b4`
- Sink expression: `system(<MultiValues(<BV32 stack_base + 0x4c>)>) @ 0x406d4`
- Sink/result preview: `</dev/nullAAAAAAAAAAAAAAAAAAAAA`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_406b4` | `0x406b4` | `sub_406b4() @ 0x406b4` |

### Trace 5: `residual`

- Trace path: `sub_3119c -> system`
- Source: `sub_3119c` at `0x3119c`
- Sink: `system` at `0x31224`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `evidence_contract_residual` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.7677s, steps=11, vectors=0/0 vulnerable/secure, coverage=0.0000
- Sanitizer gap: `unresolved_filter` solver gaps prevent sanitizer diagnosis for 11 vector(s)
- Repair hints: `Background Execution: reject or quote ampersand job-control operators; Bypass Spaces: normalize and reject alternate whitespace forms such as tabs and ${IFS}; Command Chaining: reject or quote command separators such as semicolon and newline, or avoid shell...`
- Source expression: `sub_3119c() @ 0x3119c`
- Sink expression: `system(<MultiValues(<BV32 TOP>)>) @ 0x31224`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_3119c` | `0x3119c` | `sub_3119c() @ 0x3119c` |

### Trace 6: `residual`

- Trace path: `sub_7329c -> popen`
- Source: `sub_7329c` at `0x7329c`
- Sink: `popen` at `0x733b4`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=10.3177s, steps=8, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_7329c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7329c`
- Sink expression: `popen(<MultiValues(<BV32 stack_base - 0x178>)>, <MultiValues(<BV32 0x88ecb>)>) @ 0x733b4`
- Sink/result preview: `iw %s station dump`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_7329c` | `0x7329c` | `sub_7329c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x7329c` |

### Trace 7: `residual`

- Trace path: `sub_3f040 -> popen`
- Source: `sub_3f040` at `0x3f040`
- Sink: `popen` at `0x3f110`
- Stop/reason: `active_empty`
- Static evidence: `weak`
- Evidence confidence: `low` score=16, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `sanitizer_gap_profile_fully_filtered, unclear_reachability, weak_static_binding`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop active_empty`
- Residual diagnosis: `bounded_multi_state_collection_incomplete` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Model gap requests: `config_key:lan_ifname (mango_possible_input)`
- Result metrics: elapsed=53.1870s, steps=45, vectors=0/11 vulnerable/secure, coverage=1.0000
- Sanitizer gap: `fully_filtered` all modeled shell vectors are blocked (11 secure vector(s))
- Gap categories: bypass=``, blocked=`Background Execution, Bypass Spaces, Command Chaining, Command Substitution, Piping, Redirection, Variable Expansion`
- Likely inputs: ``
- Possible inputs: `login_timestamp, login_ip, lan_ifname`
- Source expression: `sub_3f040() @ 0x3f040`
- Sink expression: `popen(<MultiValues(<BV32 stack_base + 0x13c>)>, <MultiValues(<BV32 0x88ecb>)>) @ 0x3f110`
- Sink/result preview: `ip neigh show to %s dev `

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_3f040` | `0x3f040` | `sub_3f040() @ 0x3f040` |

### Trace 8: `vulnerable`

- Trace path: `sub_75e40 -> popen`
- Source: `sub_75e40` at `0x75e40`
- Sink: `popen` at `0x75e9c`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `medium` score=64, review=`critical`, claim=`direct_sink_byte_sv_sat_evidence`
- Evidence factors: `absent_static_binding, direct_sink_evidence, sanitizer_gap_profile_broad_bypass, sat_payload_evidence`
- Path control: `direct_sink_evidence` pressure=`resolved`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Result metrics: elapsed=16.7680s, steps=4, vectors=11/0 vulnerable/secure, coverage=0.0000
- Sanitizer gap: `broadly_bypassable` broad sanitizer gap: all decided vectors are bypassable (11 vector(s))
- Gap categories: bypass=`Background Execution, Bypass Spaces, Command Chaining, Command Substitution, Piping, Redirection, Variable Expansion`, blocked=``
- Minimal bypass: `Background Execution` vector=`&` poc=`hostapd_cli -i:&:;#AAAAAAAAAAAAAAAAAAAAAAAAAA`
- Repair hints: `Background Execution: reject or quote ampersand job-control operators; Bypass Spaces: normalize and reject alternate whitespace forms such as tabs and ${IFS}; Command Chaining: reject or quote command separators such as semicolon and newline, or avoid shell...`
- Source expression: `sub_75e40(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x75e40`
- Sink expression: `popen(<MultiValues(<BV32 stack_base - 0x201c>)>, <MultiValues(<BV32 0x88ecb>)>) @ 0x75e9c`
- Sink/result preview: `hostapd_cli -i:;:;#AAAAAAAAAAAAAAAAAAAAAAAAAA`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_75e40` | `0x75e40` | `sub_75e40(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x75e40` |

### Trace 17: `unreachable`

- Trace path: `sub_487e0 -> popen`
- Source: `sub_487e0` at `0x487e0`
- Sink: `popen` at `0x48df0`
- Stop/reason: `active_empty`
- Static evidence: `weak`
- Evidence confidence: `low` score=3, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `missing_sink_preview, path_budget_residual_risk, unclear_reachability, weak_static_binding`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=2, density=0.0444
- Path-control events: `seed_equivalence:2`
- Path-control audit: `2 pruned/omitted states or seeds; max active 9; stop active_empty`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Model gap requests: `config_key:apg0_ssid (mango_possible_input)`
- Result metrics: elapsed=27.4501s, steps=45, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `apg0_ssid`
- Source expression: `sub_487e0() @ 0x487e0`
- Sink expression: `popen(<MultiValues(<BV32 stack_base + 0x130>)>, <MultiValues(<BV32 0x88ecb>)>) @ 0x48df0`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_487e0` | `0x487e0` | `sub_487e0() @ 0x487e0` |

### Trace 18: `residual`

- Trace path: `sub_772e8 -> popen`
- Source: `sub_772e8` at `0x772e8`
- Sink: `popen` at `0x774e0`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=7.0288s, steps=40, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `TOP`
- Source expression: `sub_772e8(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x772e8`
- Sink expression: `popen(<MultiValues(<BV32 stack_base - 0xac>)>, <MultiValues(<BV32 0x88ecb>)>) @ 0x774e0`
- Sink/result preview: `hostapd_cli -iwl0 get_config`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_772e8` | `0x772e8` | `sub_772e8(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x772e8` |

### Trace 19: `residual`

- Trace path: `sub_3c2bc -> popen`
- Source: `sub_3c2bc` at `0x3c2bc`
- Sink: `popen` at `0x3c530`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `evidence_contract_residual` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=4.5299s, steps=23, vectors=0/0 vulnerable/secure, coverage=0.0000
- Sanitizer gap: `unresolved_filter` solver gaps prevent sanitizer diagnosis for 11 vector(s)
- Repair hints: `Background Execution: reject or quote ampersand job-control operators; Bypass Spaces: normalize and reject alternate whitespace forms such as tabs and ${IFS}; Command Chaining: reject or quote command separators such as semicolon and newline, or avoid shell...`
- Source expression: `sub_3c2bc() @ 0x3c2bc`
- Sink expression: `popen(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 0x88ecb>)>) @ 0x3c530`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_3c2bc` | `0x3c2bc` | `sub_3c2bc() @ 0x3c2bc` |

### Trace 20: `unreachable`

- Trace path: `sub_652e8 -> sub_65188 -> popen`
- Source: `sub_652e8` at `0x652e8`
- Sink: `popen` at `0x65208`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `absent_static_binding, missing_sink_preview, path_budget_residual_risk, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=0, density=0.0000
- Path-control audit: `max active 5; stop active_empty`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Result metrics: elapsed=4.7255s, steps=42, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_652e8() @ 0x652e8`
- Sink expression: `popen(<MultiValues(<BV32 stack_base - 0x1c0>)>, <MultiValues(<BV32 0x88ecb>)>) @ 0x65208`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_652e8` | `0x652e8` | `sub_652e8() @ 0x652e8` |
| 1 | `sub_65188` | `0x65460` | `sub_65188(<MultiValues(<BV32 stack_base - 0xbc>)>, <MultiValues(<BV32 stack_base - 0x120>)>, <MultiValues(<BV32 0x21>)>) @ 0x65460` |

### Trace 21: `residual`

- Trace path: `sub_1ae24 -> sub_65188 -> popen`
- Source: `sub_1ae24` at `0x1ae24`
- Sink: `popen` at `0x65208`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=7.1887s, steps=21, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_1ae24(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x1ae24`
- Sink expression: `popen(<MultiValues(<BV32 stack_base - 0x148>)>, <MultiValues(<BV32 0x88ecb>)>) @ 0x65208`
- Sink/result preview: ` \x09     \x09   \x09\x09 \x09\x09\x09\x09 \x09\x09\x09\x0a      \x09 `

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_1ae24` | `0x1ae24` | `sub_1ae24(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <Mult...` |
| 1 | `sub_65188` | `0x1af68` | `sub_65188(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 stack_base - 0xb4>)>, <MultiValues(<BV32 0x23>)>) @ 0x1af68` |

### Trace 22: `residual`

- Trace path: `sub_745e0 -> sub_7442c -> sub_7442c -> popen`
- Source: `sub_745e0` at `0x745e0`
- Sink: `popen` at `0x74504`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=68.7337s, steps=15, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_745e0(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x745e0`
- Sink expression: `popen(<MultiValues(<BV32 stack_base - 0x24bc>)>, <MultiValues(<BV32 0x88ecb>)>) @ 0x74504`
- Sink/result preview: ` \x0a \x0aI  \x09\x0a\x0a \x0a! \x09\x0a\x0a  \x0a`\x0a\x0a\x09\x0a \x0a\x0a  \x0a`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_745e0` | `0x745e0` | `sub_745e0(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x745e0` |
| 1 | `sub_7442c` | `0x74a3c` | `sub_7442c(<MultiValues(<BV32 TOP>)>, <MultiValues({0: {<BV32 TOP>, <BV32 stack_base - 0x218>}})>) @ 0x74a3c` |
| 2 | `sub_7442c` | `0x75aa0` | `sub_7442c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 stack_base - 0x390>)>) @ 0x75aa0` |

### Trace 24: `unreachable`

- Trace path: `sub_745e0 -> sub_72c9c -> sub_72c9c -> popen`
- Source: `sub_745e0` at `0x745e0`
- Sink: `popen` at `0x72d68`
- Stop/reason: `source_liveness_saturated`
- Static evidence: `weak`
- Evidence confidence: `low` score=11, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `missing_sink_preview, source_liveness_pruning, unclear_reachability, weak_static_binding`
- Path control: `semantic_saturation` pressure=`semantically_bounded`, pruned=16, density=0.0939
- Path-control events: `source_liveness:4, seed_equivalence:1`
- Path-control audit: `16 pruned/omitted states or seeds; max active 21; stop source_liveness_saturated`
- Residual diagnosis: `weak_candidate_unreached` severity=`medium` The sink was not reached and the static source binding is weak or absent.
- Residual next actions: `prioritize lower than strong-source unreachable closures; manually inspect the static closure before increasing symbolic budget`
- Recovery plan: strategy=`static_candidate_triage`, priority=`low`, overrides=``, gaps=``
- Result metrics: elapsed=89.0922s, steps=213, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `fread(`
- Source expression: `sub_745e0(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x745e0`
- Sink expression: `popen(<MultiValues(<BV32 stack_base - 0x5d8>)>, <MultiValues(<BV32 0x88ecb>)>) @ 0x72d68`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_745e0` | `0x745e0` | `sub_745e0(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x745e0` |
| 1 | `sub_72c9c` | `0x756e4` | `sub_72c9c(<MultiValues({0: {<BV32 stack_base - 0x218>, <BV32 TOP>}})>, <MultiValues(<BV32 stack_base - 0x330>)>) @ 0x756e4` |
| 2 | `sub_72c9c` | `0x74d3c` | `sub_72c9c(<MultiValues(<BV32 stack_base - 0x380>)>, <MultiValues(<BV32 stack_base - 0x310>)>) @ 0x74d3c` |

### Trace 25: `residual`

- Trace path: `sub_75fa4 -> sub_7442c -> sub_7442c -> popen`
- Source: `sub_75fa4` at `0x75fa4`
- Sink: `popen` at `0x74504`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 8; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=90.9638s, steps=84, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_75fa4(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x75fa4`
- Sink expression: `popen(<MultiValues(<BV32 stack_base - 0x22c4>)>, <MultiValues(<BV32 0x88ecb>)>) @ 0x74504`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_75fa4` | `0x75fa4` | `sub_75fa4(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x75fa4` |
| 1 | `sub_7442c` | `0x762e0` | `sub_7442c(<MultiValues(<BV32 0x0>)>, <MultiValues(<BV32 stack_base - 0x1ac>)>) @ 0x762e0` |
| 2 | `sub_7442c` | `0x760a8` | `sub_7442c(<MultiValues(<BV32 0x0>)>, <MultiValues(<BV32 stack_base - 0x1ac>)>) @ 0x760a8` |

### Trace 27: `unreachable`

- Trace path: `sub_1bcc8 -> sub_1ae24 -> sub_65188 -> popen`
- Source: `sub_1bcc8` at `0x1bcc8`
- Sink: `popen` at `0x65208`
- Stop/reason: `active_empty`
- Static evidence: `weak`
- Evidence confidence: `low` score=3, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `missing_sink_preview, path_budget_residual_risk, unclear_reachability, weak_static_binding`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=0, density=0.0000
- Path-control audit: `max active 3; stop active_empty`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Model gap requests: `config_key:lan_ipaddr (mango_possible_input); config_key:wl_unit (mango_possible_input)`
- Result metrics: elapsed=15.7136s, steps=110, vectors=0/0 vulnerable/secure, coverage=
- Likely inputs: ``
- Possible inputs: `x_Setting, re_mode, lan_ipaddr, smart_connect_x, disable_ui, wl_unit, fgets(`
- Source expression: `sub_1bcc8() @ 0x1bcc8`
- Sink expression: `popen(<MultiValues(<BV32 stack_base - 0x2b80>)>, <MultiValues(<BV32 0x88ecb>)>) @ 0x65208`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_1bcc8` | `0x1bcc8` | `sub_1bcc8() @ 0x1bcc8` |
| 1 | `sub_1ae24` | `0x1d6a0` | `sub_1ae24(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 0xaa001>)>, <MultiValues(<BV32 0x0>)>, <MultiValues(<BV32 stack_base - 0x297c>)>, <MultiValues(<BV32 0x40>)>, <MultiValue...` |
| 2 | `sub_65188` | `0x1af68` | `sub_65188(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 stack_base - 0x2aec>)>, <MultiValues(<BV32 0x23>)>) @ 0x1af68` |

### Trace 28: `unreachable`

- Trace path: `sub_6b858 -> sub_76c4c -> sub_75fa4 -> sub_7442c -> sub_7442c -> sub_7442c -> popen`
- Source: `sub_6b858` at `0x6b858`
- Sink: `popen` at `0x74504`
- Stop/reason: `guided_stagnation_saturated`
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `absent_static_binding, missing_sink_preview, path_budget_residual_risk, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=18, density=0.2857
- Path-control events: `semantic_frontier:4`
- Path-control audit: `18 pruned/omitted states or seeds; 4 frontier rounds, 0 loop rounds; max active 20; stop guided_stagnation_saturated`
- Residual diagnosis: `path_explosion_residual` severity=`high` The sink was not reached before residual path-control budget pressure remained.
- Residual next actions: `increase max steps or closure timeout for this closure; inspect loop-semantic and frontier-pruning events; add a targeted parser or wrapper summary if the trace repeats around one helper`
- Recovery plan: strategy=`semantic_path_refinement`, priority=`high`, overrides=`closure_timeout=180, loop_semantic_saturation_limit=5, loop_semantic_weak_static=True, max_steps=1000, semantic_frontier_bucket_limit=3`, gaps=`loop_or_parser_summary, sink_distance_model`
- Result metrics: elapsed=56.6687s, steps=63, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_6b858(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x6b858`
- Sink expression: `popen(<MultiValues(<BV32 stack_base - 0x5354>)>, <MultiValues(<BV32 0x88ecb>)>) @ 0x74504`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_6b858` | `0x6b858` | `sub_6b858(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x6b858` |
| 1 | `sub_76c4c` | `0x6b96c` | `sub_76c4c(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues({0: {<BV32 0x1>, <BV32 0xffffffff>, <BV32 0x0>}})>) @ 0x6b96c` |
| 2 | `sub_75fa4` | `0x76c58` | `sub_75fa4(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x76c58` |
| 3 | `sub_7442c` | `0x762e0` | `sub_7442c(<MultiValues(<BV32 0x0>)>, <MultiValues(<BV32 stack_base - 0x323c>)>) @ 0x762e0` |
| 4 | `sub_7442c` | `0x762e0` | `sub_7442c(<MultiValues(<BV32 0x0>)>, <MultiValues(<BV32 stack_base - 0x323c>)>) @ 0x762e0` |
| 5 | `sub_7442c` | `0x760a8` | `sub_7442c(<MultiValues(<BV32 0x0>)>, <MultiValues(<BV32 stack_base - 0x323c>)>) @ 0x760a8` |

### Trace 30: `residual`

- Trace path: `sub_61a6c -> sub_76c4c -> sub_75fa4 -> sub_7442c -> sub_7442c -> sub_7442c -> popen`
- Source: `sub_61a6c` at `0x61a6c`
- Sink: `popen` at `0x74504`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 8; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=18.8979s, steps=94, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_61a6c() @ 0x61a6c`
- Sink expression: `popen(<MultiValues(<BV32 stack_base - 0x22ec>)>, <MultiValues(<BV32 0x88ecb>)>) @ 0x74504`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_61a6c` | `0x61a6c` | `sub_61a6c() @ 0x61a6c` |
| 1 | `sub_76c4c` | `0x61ac8` | `sub_76c4c(<MultiValues(<BV32 0x0>)>, <MultiValues(<BV32 0x3>)>, <MultiValues(<BV32 0x0>)>) @ 0x61ac8` |
| 2 | `sub_75fa4` | `0x76c58` | `sub_75fa4(<MultiValues(<BV32 0x0>)>, <MultiValues(<BV32 0x3>)>) @ 0x76c58` |
| 3 | `sub_7442c` | `0x762e0` | `sub_7442c(<MultiValues(<BV32 0x0>)>, <MultiValues(<BV32 stack_base - 0x1d4>)>) @ 0x762e0` |
| 4 | `sub_7442c` | `0x762e0` | `sub_7442c(<MultiValues(<BV32 0x0>)>, <MultiValues(<BV32 stack_base - 0x1d4>)>) @ 0x762e0` |
| 5 | `sub_7442c` | `0x760a8` | `sub_7442c(<MultiValues(<BV32 0x0>)>, <MultiValues(<BV32 stack_base - 0x1d4>)>) @ 0x760a8` |

## Per-Closure Results

| Closure | Status | Confidence | Review | Path control | Stop/reason | Time(s) | Steps | V/S | Coverage | Static | Classification | Preview |
|---:|---|---|---|---|---|---:|---:|---:|---:|---|---|---|
| 1 | residual | low | high | unclassified | active_empty | 0.3483 | 4 |  |  | absent |  | \xc0\x1d\xff\xeb\x04 |
| 2 | residual | low | high | unclassified | active_empty | 0.4991 | 6 | 0/0 | 0.0000 | absent |  |  |
| 3 | vulnerable | medium | critical | direct_sink_evidence | active_empty | 23.2165 | 19 | 11/0 | 0.0000 | absent |  | :;:;#AAAAAAAAAAAAAAAAAAAAAAAAA  |
| 4 | vulnerable | medium | critical | direct_sink_evidence | active_empty | 4.0641 | 4 | 11/0 | 0.0000 | absent |  | </dev/nullAAAAAAAAAAAAAAAAAAAAA |
| 5 | residual | low | high | unclassified | active_empty | 0.7677 | 11 | 0/0 | 0.0000 | absent |  |  |
| 6 | residual | low | high | unclassified | active_empty | 10.3177 | 8 |  |  | absent |  | iw %s station dump |
| 7 | residual | low | high | unclassified | active_empty | 53.1870 | 45 | 0/11 | 1.0000 | weak |  | ip neigh show to %s dev  |
| 8 | vulnerable | medium | critical | direct_sink_evidence | active_empty | 16.7680 | 4 | 11/0 | 0.0000 | absent |  | hostapd_cli -i:;:;#AAAAAAAAAAAAAAAAAAAAAAAAAA |
| 17 | unreachable | low | high | residual_budget_stop | active_empty | 27.4501 | 45 |  |  | weak |  |  |
| 18 | residual | low | high | unclassified | active_empty | 7.0288 | 40 |  |  | absent |  | hostapd_cli -iwl0 get_config |
| 19 | residual | low | high | unclassified | active_empty | 4.5299 | 23 | 0/0 | 0.0000 | absent |  |  |
| 20 | unreachable | low | high | residual_budget_stop | active_empty | 4.7255 | 42 |  |  | absent |  |  |
| 21 | residual | low | high | unclassified | active_empty | 7.1887 | 21 |  |  | absent |  |  \x09     \x09   \x09\x09 \x09\x09\x09\x09 \x09\x09\x09\x0a      \x09  |
| 22 | residual | low | high | unclassified | active_empty | 68.7337 | 15 |  |  | absent |  |  \x0a \x0aI  \x09\x0a\x0a \x0a! \x09\x0a\x0a  \x0a`\x0a\x0a\x09\x0a \x0a\x0a  \x0a |
| 24 | unreachable | low | high | semantic_saturation | source_liveness_saturated | 89.0922 | 213 |  |  | weak |  |  |
| 25 | residual | low | high | unclassified | active_empty | 90.9638 | 84 |  |  | absent |  |  |
| 27 | unreachable | low | high | residual_budget_stop | active_empty | 15.7136 | 110 |  |  | weak |  |  |
| 28 | unreachable | low | high | residual_budget_stop | guided_stagnation_saturated | 56.6687 | 63 |  |  | absent |  |  |
| 30 | residual | low | high | unclassified | active_empty | 18.8979 | 94 |  |  | absent |  |  |

## Output Artifacts

- Summary JSON: `/home/ubuntu/work/sanitizer/experiment_reports/full_firmware_campaign_current_tsds_multistate_full_20260916/asus_rt_be57.summary.json`
- Per-closure JSONL: `/home/ubuntu/work/sanitizer/experiment_reports/full_firmware_campaign_current_tsds_multistate_full_20260916/asus_rt_be57.results.jsonl`
