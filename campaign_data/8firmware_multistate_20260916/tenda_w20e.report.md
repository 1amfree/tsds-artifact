# TSDS Analysis Report

- Generated: 2026-09-16 00:16:58
- Binary: `/home/ubuntu/work/sanitizer/Tenda_W20E/httpd`
- Trace JSON: `/home/ubuntu/work/sanitizer/Tenda_W20E/results/cmdi_results.json`
- Mode: `full`
- Total closures: 21
- Unique pairs expected: 21
- Unique pairs analyzed: 21

## Executive Summary

| Metric | Value |
|---|---:|
| SV-SAT | 1 |
| Modeled-vector filtered | 0 |
| Partially filtered SV-SAT | 0 |
| No-modeled-source sink | 0 |
| Static source inference | 0 |
| Static warning reduction | 0 |
| Residual obligation | 19 |
| Unreachable | 0 |
| Timeout | 1 |
| Crashed | 3 |
| Evaluation errors | 0 |
| SAT shell-vector witnesses | 11 |
| Blocked-vector proofs | 0 |
| Average sanitizer coverage | 0.0000 |
| Wall time seconds | 201.7702 |
| Average closure time seconds | 2.3673 |
| Average matrix time seconds | 0.9947 |
| Average engine steps | 8.1800 |
| Semantic frontier cuts | 0 |
| Source-liveness cuts | 0 |
| Delay-slot sink captures | 0 |
| Loop semantic cuts | 0 |
| Seed states tried | 87 |
| Seed states pruned | 0 |
| Memoized closures | 0 |
| Evidence cache hits | 0 |

## Model Gap Requests

| Dimension | Count |
|---|---:|
| kind:config_key | 1 |
| kind:web | 1 |
| reason:trace_uses_config_api | 1 |
| reason:trace_uses_web_parser | 1 |

| Closure | Kind | Key | Reason | Confidence | Evidence |
|---:|---|---|---|---|---|
| 4 | web | formSetDebugCfg | trace_uses_web_parser | medium | formSetDebugCfg -> system |
| 4 | config_key | formSetDebugCfg | trace_uses_config_api | medium | formSetDebugCfg -> system |

## Engine Stop Reasons

| Stop reason | Count |
|---|---:|
| `active_empty` | 16 |
| `multi_state_settle_budget_exhausted` | 1 |

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
| confidence:medium | 1 |
| confidence:low | 20 |
| review:critical | 1 |
| review:high | 20 |
| claim:direct_sink_byte_sv_sat_evidence | 1 |
| claim:evidence_contract_residual | 16 |
| claim:operational_residual_risk | 3 |
| claim:residual_unclear_outcome | 1 |

## Semantic Path-Control Ledger

| Dimension | Count |
|---|---:|
| class:direct_sink_evidence | 1 |
| class:operational_stop | 3 |
| class:residual_budget_stop | 1 |
| class:unclassified | 16 |
| pressure:not_applicable | 16 |
| pressure:residual_risk | 4 |
| pressure:resolved | 1 |
| total:path_control_pruned_states | 0 |
| total:semantic_pruned_states | 0 |
| total:seed_pruned | 0 |

## Residual Diagnosis

| Dimension | Count |
|---|---:|
| class:bounded_multi_state_no_admissible_primary | 16 |
| class:operational_failure | 3 |
| class:time_budget_exhaustion | 1 |
| severity:high | 17 |
| severity:critical | 3 |
| action:inspect contract violations and vector decisions | 16 |
| action:keep the record outside SV-SAT, M-Filt, and NMS aggregates | 16 |
| action:rerun unknown quote contexts or pruned negative paths conservatively | 16 |
| action:inspect loader/subprocess error text | 3 |
| action:rerun this closure after fixing the operational precondition | 3 |
| action:verify binary and closure JSON paths | 3 |
| action:enable evidence cache and same-run memoization | 1 |
| action:inspect path-control events for repeated frontier classes | 1 |

## Residual Recovery Plan

| Dimension | Count |
|---|---:|
| strategy:manual_review | 16 |
| strategy:operational_fix | 3 |
| strategy:budget_extension_rerun | 1 |
| priority:medium | 16 |
| priority:critical | 3 |
| priority:high | 1 |
| model-gap:loader_or_input_precondition | 3 |
| config:closure_timeout=180 | 1 |
| config:engine_timeout=90 | 1 |
| config:max_steps=1000 | 1 |
| config:subprocess_timeout=240 | 1 |

## Sanitizer Gap Diagnosis

| Dimension | Count |
|---|---:|
| strength:broadly_bypassable | 1 |
| bypass:Background Execution | 1 |
| bypass:Bypass Spaces | 1 |
| bypass:Command Chaining | 1 |
| bypass:Command Substitution | 1 |
| bypass:Piping | 1 |
| bypass:Redirection | 1 |
| bypass:Variable Expansion | 1 |

## Vulnerable And Partial Findings

| Closure | Status | Vectors V/S | Coverage | Source kinds | Recovery | Preview |
|---:|---|---:|---:|---|---|---|
| 19 | vulnerable | 11/0 | 0.0000 | entry_arg |  | traceroute :;:;#AAAAAAAAAAAAAAAAAAAAAAAAAA |

## Unclear Or Operational Outcomes

| Closure | Status | Diagnosis | Severity | Reason | Time(s) | Static evidence | Preview/Error |
|---:|---|---|---|---|---:|---|---|
| 4 | timeout | time_budget_exhaustion | high | fork_worker_timeout |  | absent |  |
| 6 | crashed | operational_failure | critical |  |  | absent | StopIteration:  |
| 11 | crashed | operational_failure | critical |  |  | absent | StopIteration:  |
| 17 | crashed | operational_failure | critical |  |  | absent | StopIteration:  |

## Trace-Level Analysis

### Trace 1: `residual`

- Trace path: `sub_5ae64 -> system_wan_get_link_status`
- Source: `sub_5ae64` at `0x5ae64`
- Sink: `system_wan_get_link_status` at `0x5ae84`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=3.1339s, steps=8, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_5ae64() @ 0x5ae64`
- Sink expression: `system_wan_get_link_status(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x5ae84`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_5ae64` | `0x5ae64` | `sub_5ae64() @ 0x5ae64` |

### Trace 2: `residual`

- Trace path: `sub_b8d54 -> system_get_code_format`
- Source: `sub_b8d54` at `0xb8d54`
- Sink: `system_get_code_format` at `0xb8f28`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=4.1685s, steps=21, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_b8d54() @ 0xb8d54`
- Sink expression: `system_get_code_format(<MultiValues(<BV32 TOP + 0x21>)>) @ 0xb8f28`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_b8d54` | `0xb8d54` | `sub_b8d54() @ 0xb8d54` |

### Trace 3: `residual`

- Trace path: `sub_b8d54 -> system_get_code_format`
- Source: `sub_b8d54` at `0xb8d54`
- Sink: `system_get_code_format` at `0xb8fa4`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 4; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=6.0825s, steps=30, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_b8d54() @ 0xb8d54`
- Sink expression: `system_get_code_format(<MultiValues(<BV32 TOP + (TOP << 0x5) + TOP + 0x4b>)>) @ 0xb8fa4`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_b8d54` | `0xb8d54` | `sub_b8d54() @ 0xb8d54` |

### Trace 4: `timeout`

- Trace path: `formSetDebugCfg -> system`
- Source: `formSetDebugCfg` at `0x3fc58`
- Sink: `system` at `0x3fd38`
- Stop/reason: `fork_worker_timeout`
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`residual_unclear_outcome`
- Evidence factors: `absent_static_binding, missing_sink_preview, path_budget_residual_risk, unclear_reachability`
- Path control: `residual_budget_stop` pressure=`residual_risk`, pruned=0, density=0.0000
- Path-control audit: `stop fork_worker_timeout`
- Residual diagnosis: `time_budget_exhaustion` severity=`high` The analysis consumed its time budget before reaching a resolved sink or no-taint explanation.
- Residual next actions: `rerun with a larger closure/subprocess timeout; enable evidence cache and same-run memoization; inspect path-control events for repeated frontier classes`
- Recovery plan: strategy=`budget_extension_rerun`, priority=`high`, overrides=`closure_timeout=180, engine_timeout=90, max_steps=1000, subprocess_timeout=240`, gaps=``
- Model gap requests: `web:formSetDebugCfg (trace_uses_web_parser); config_key:formSetDebugCfg (trace_uses_config_api)`
- Result metrics: elapsed=s, steps=, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `formSetDebugCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x3fc58`
- Sink expression: `system(<MultiValues(<BV32 stack_base - 0x94>)>) @ 0x3fd38`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `formSetDebugCfg` | `0x3fc58` | `formSetDebugCfg(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x3fc58` |

### Trace 5: `residual`

- Trace path: `sub_977f8 -> doSystemCmd`
- Source: `sub_977f8` at `0x977f8`
- Sink: `doSystemCmd` at `0x97800`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.2634s, steps=2, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_977f8() @ 0x977f8`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP - 0x228>)>) @ 0x97800`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_977f8` | `0x977f8` | `sub_977f8() @ 0x977f8` |

### Trace 6: `crashed`

- Trace path: `sub_4a684 -> doSystemCmd`
- Source: `sub_4a684` at `0x4a684`
- Sink: `doSystemCmd` at `0x4a6e4`
- Stop/reason: ``
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`operational_residual_risk`
- Evidence factors: `absent_static_binding, operational_failure, path_budget_residual_risk`
- Path control: `operational_stop` pressure=`residual_risk`, pruned=0, density=0.0000
- Path-control audit: `operational_stop`
- Residual diagnosis: `operational_failure` severity=`critical` The closure was not semantically evaluated because the analysis failed operationally.
- Residual next actions: `verify binary and closure JSON paths; inspect loader/subprocess error text; rerun this closure after fixing the operational precondition`
- Recovery plan: strategy=`operational_fix`, priority=`critical`, overrides=``, gaps=`loader_or_input_precondition`
- Result metrics: elapsed=s, steps=, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_4a684() @ 0x4a684`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP - 0x8>)>) @ 0x4a6e4`
- Sink/result preview: `StopIteration: `

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_4a684` | `0x4a684` | `sub_4a684() @ 0x4a684` |

### Trace 7: `residual`

- Trace path: `sub_a9a58 -> doSystemCmd`
- Source: `sub_a9a58` at `0xa9a58`
- Sink: `doSystemCmd` at `0xa9a5c`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.4264s, steps=2, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_a9a58(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa9a58`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP>)>) @ 0xa9a5c`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a9a58` | `0xa9a58` | `sub_a9a58(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0xa9a58` |

### Trace 8: `residual`

- Trace path: `sub_970dc -> doSystemCmd`
- Source: `sub_970dc` at `0x970dc`
- Sink: `doSystemCmd` at `0x971a4`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=2.9103s, steps=16, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_970dc() @ 0x970dc`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP - 0x314>)>) @ 0x971a4`
- Sink/result preview: `mv /var/wewifi/mv %s %s.jpg /webroot/images/webpush/`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_970dc` | `0x970dc` | `sub_970dc() @ 0x970dc` |

### Trace 9: `residual`

- Trace path: `sub_976b4 -> doSystemCmd`
- Source: `sub_976b4` at `0x976b4`
- Sink: `doSystemCmd` at `0x976dc`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.4067s, steps=4, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_976b4() @ 0x976b4`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP - 0x228>)>) @ 0x976dc`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_976b4` | `0x976b4` | `sub_976b4() @ 0x976b4` |

### Trace 10: `residual`

- Trace path: `sub_976b4 -> doSystemCmd`
- Source: `sub_976b4` at `0x976b4`
- Sink: `doSystemCmd` at `0x97744`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.6730s, steps=8, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_976b4() @ 0x976b4`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP - 0x228>)>) @ 0x97744`
- Sink/result preview: `crop %s crop %s %s %ld %ld %ld %ld 0 0 0 0`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_976b4` | `0x976b4` | `sub_976b4() @ 0x976b4` |

### Trace 11: `crashed`

- Trace path: `sub_976b4 -> doSystemCmd`
- Source: `sub_976b4` at `0x976b4`
- Sink: `doSystemCmd` at `0x977c0`
- Stop/reason: ``
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`operational_residual_risk`
- Evidence factors: `absent_static_binding, operational_failure, path_budget_residual_risk`
- Path control: `operational_stop` pressure=`residual_risk`, pruned=0, density=0.0000
- Path-control audit: `operational_stop`
- Residual diagnosis: `operational_failure` severity=`critical` The closure was not semantically evaluated because the analysis failed operationally.
- Residual next actions: `verify binary and closure JSON paths; inspect loader/subprocess error text; rerun this closure after fixing the operational precondition`
- Recovery plan: strategy=`operational_fix`, priority=`critical`, overrides=``, gaps=`loader_or_input_precondition`
- Result metrics: elapsed=s, steps=, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_976b4() @ 0x976b4`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP - 0x228>)>) @ 0x977c0`
- Sink/result preview: `StopIteration: `

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_976b4` | `0x976b4` | `sub_976b4() @ 0x976b4` |

### Trace 12: `residual`

- Trace path: `sub_4ad5c -> doSystemCmd`
- Source: `sub_4ad5c` at `0x4ad5c`
- Sink: `doSystemCmd` at `0x4ada8`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.4180s, steps=4, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_4ad5c() @ 0x4ad5c`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP - 0x424>)>) @ 0x4ada8`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_4ad5c` | `0x4ad5c` | `sub_4ad5c() @ 0x4ad5c` |

### Trace 13: `residual`

- Trace path: `sub_4ad5c -> doSystemCmd`
- Source: `sub_4ad5c` at `0x4ad5c`
- Sink: `doSystemCmd` at `0x4ae14`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.6968s, steps=8, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_4ad5c() @ 0x4ad5c`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP - 0x424>)>) @ 0x4ae14`
- Sink/result preview: `crop %s crop %s %s %ld %ld %ld %ld 0 0 0 0`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_4ad5c` | `0x4ad5c` | `sub_4ad5c() @ 0x4ad5c` |

### Trace 14: `residual`

- Trace path: `sub_4626c -> doSystemCmd`
- Source: `sub_4626c` at `0x4626c`
- Sink: `doSystemCmd` at `0x46274`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.2820s, steps=2, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_4626c() @ 0x4626c`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 0x46274 + TOP>)>) @ 0x46274`
- Sink/result preview: `\xe6#\xff\xeb\1\x9f\xe5\x030\x8f\xe0\x03`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_4626c` | `0x4626c` | `sub_4626c() @ 0x4626c` |

### Trace 15: `residual`

- Trace path: `sub_4ae84 -> doSystemCmd`
- Source: `sub_4ae84` at `0x4ae84`
- Sink: `doSystemCmd` at `0x4ae8c`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.2659s, steps=2, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_4ae84() @ 0x4ae84`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP - 0x4>)>) @ 0x4ae8c`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_4ae84` | `0x4ae84` | `sub_4ae84() @ 0x4ae84` |

### Trace 16: `residual`

- Trace path: `sub_4ae84 -> doSystemCmd`
- Source: `sub_4ae84` at `0x4ae84`
- Sink: `doSystemCmd` at `0x4aed0`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.5214s, steps=6, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_4ae84() @ 0x4ae84`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP - 0x424>)>) @ 0x4aed0`
- Sink/result preview: `rm -rf /webroot/images/webpush/%s`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_4ae84` | `0x4ae84` | `sub_4ae84() @ 0x4ae84` |

### Trace 17: `crashed`

- Trace path: `sub_4ae84 -> doSystemCmd`
- Source: `sub_4ae84` at `0x4ae84`
- Sink: `doSystemCmd` at `0x4af60`
- Stop/reason: ``
- Static evidence: `absent`
- Evidence confidence: `low` score=0, review=`high`, claim=`operational_residual_risk`
- Evidence factors: `absent_static_binding, operational_failure, path_budget_residual_risk`
- Path control: `operational_stop` pressure=`residual_risk`, pruned=0, density=0.0000
- Path-control audit: `operational_stop`
- Residual diagnosis: `operational_failure` severity=`critical` The closure was not semantically evaluated because the analysis failed operationally.
- Residual next actions: `verify binary and closure JSON paths; inspect loader/subprocess error text; rerun this closure after fixing the operational precondition`
- Recovery plan: strategy=`operational_fix`, priority=`critical`, overrides=``, gaps=`loader_or_input_precondition`
- Result metrics: elapsed=s, steps=, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_4ae84() @ 0x4ae84`
- Sink expression: `doSystemCmd(<MultiValues(<BV32 TOP - 0x424>)>) @ 0x4af60`
- Sink/result preview: `StopIteration: `

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_4ae84` | `0x4ae84` | `sub_4ae84() @ 0x4ae84` |

### Trace 18: `residual`

- Trace path: `sub_a9018 -> popen`
- Source: `sub_a9018` at `0xa9018`
- Sink: `popen` at `0xa902c`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=0.2613s, steps=2, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_a9018() @ 0xa9018`
- Sink expression: `popen(<MultiValues(<BV32 TOP - 0x10c>)>, <MultiValues(<BV32 0xeacac>)>) @ 0xa902c`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a9018` | `0xa9018` | `sub_a9018() @ 0xa9018` |

### Trace 19: `vulnerable`

- Trace path: `traceroute_handle_thread -> popen`
- Source: `traceroute_handle_thread` at `0xa90a8`
- Sink: `popen` at `0xa9154`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `medium` score=64, review=`critical`, claim=`direct_sink_byte_sv_sat_evidence`
- Evidence factors: `absent_static_binding, direct_sink_evidence, sanitizer_gap_profile_broad_bypass, sat_payload_evidence`
- Path control: `direct_sink_evidence` pressure=`resolved`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Result metrics: elapsed=15.5858s, steps=9, vectors=11/0 vulnerable/secure, coverage=0.0000
- Sanitizer gap: `broadly_bypassable` broad sanitizer gap: all decided vectors are bypassable (11 vector(s))
- Gap categories: bypass=`Background Execution, Bypass Spaces, Command Chaining, Command Substitution, Piping, Redirection, Variable Expansion`, blocked=``
- Minimal bypass: `Background Execution` vector=`&` poc=`traceroute :&:;#AAAAAAAAAAAAAAAAAAAAAAAAAA`
- Repair hints: `Background Execution: reject or quote ampersand job-control operators; Bypass Spaces: normalize and reject alternate whitespace forms such as tabs and ${IFS}; Command Chaining: reject or quote command separators such as semicolon and newline, or avoid shell...`
- Source expression: `traceroute_handle_thread(<MultiValues(<BV32 TOP>)>) @ 0xa90a8`
- Sink expression: `popen(<MultiValues(<BV32 stack_base - 0x514>)>, <MultiValues(<BV32 0xeacac>)>) @ 0xa9154`
- Sink/result preview: `traceroute :;:;#AAAAAAAAAAAAAAAAAAAAAAAAAA`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `traceroute_handle_thread` | `0xa90a8` | `traceroute_handle_thread(<MultiValues(<BV32 TOP>)>) @ 0xa90a8` |

### Trace 20: `residual`

- Trace path: `sub_403e0 -> execve`
- Source: `sub_403e0` at `0x403e0`
- Sink: `execve` at `0x40414`
- Stop/reason: `multi_state_settle_budget_exhausted`
- Static evidence: `absent`
- Evidence confidence: `low` score=5, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, missing_sink_preview, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop multi_state_settle_budget_exhausted`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=2.7895s, steps=13, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_403e0() @ 0x403e0`
- Sink expression: `execve(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x40414`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_403e0` | `0x403e0` | `sub_403e0() @ 0x403e0` |

### Trace 21: `residual`

- Trace path: `sub_12768 -> launchCgi -> execve`
- Source: `sub_12768` at `0x12768`
- Sink: `execve` at `0x1358c`
- Stop/reason: `active_empty`
- Static evidence: `absent`
- Evidence confidence: `low` score=10, review=`high`, claim=`evidence_contract_residual`
- Evidence factors: `absent_static_binding, unclear_reachability`
- Path control: `unclassified` pressure=`not_applicable`, pruned=0, density=0.0000
- Path-control audit: `max active 1; stop active_empty`
- Residual diagnosis: `bounded_multi_state_no_admissible_primary` severity=`high` The analysis retained an explicit residual because no admissible positive or negative claim was complete.
- Residual next actions: `inspect contract violations and vector decisions; rerun unknown quote contexts or pruned negative paths conservatively; keep the record outside SV-SAT, M-Filt, and NMS aggregates`
- Recovery plan: strategy=`manual_review`, priority=`medium`, overrides=``, gaps=``
- Result metrics: elapsed=1.3579s, steps=2, vectors=0/0 vulnerable/secure, coverage=
- Source expression: `sub_12768() @ 0x12768`
- Sink expression: `execve(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x1358c`
- Sink/result preview: `x\x0a?6C      \x0a\x09?4@<C#\x09  \x0a\x09     @ `

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_12768` | `0x12768` | `sub_12768() @ 0x12768` |
| 1 | `launchCgi` | `0x12784` | `launchCgi(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x12784` |

## Per-Closure Results

| Closure | Status | Confidence | Review | Path control | Stop/reason | Time(s) | Steps | V/S | Coverage | Static | Classification | Preview |
|---:|---|---|---|---|---|---:|---:|---:|---:|---|---|---|
| 1 | residual | low | high | unclassified | active_empty | 3.1339 | 8 |  |  | absent |  |  |
| 2 | residual | low | high | unclassified | active_empty | 4.1685 | 21 |  |  | absent |  |  |
| 3 | residual | low | high | unclassified | active_empty | 6.0825 | 30 |  |  | absent |  |  |
| 4 | timeout | low | high | residual_budget_stop | fork_worker_timeout |  |  |  |  | absent |  |  |
| 5 | residual | low | high | unclassified | active_empty | 0.2634 | 2 |  |  | absent |  |  |
| 6 | crashed | low | high | operational_stop |  |  |  |  |  | absent |  | StopIteration:  |
| 7 | residual | low | high | unclassified | active_empty | 0.4264 | 2 |  |  | absent |  |  |
| 8 | residual | low | high | unclassified | active_empty | 2.9103 | 16 |  |  | absent |  | mv /var/wewifi/mv %s %s.jpg /webroot/images/webpush/ |
| 9 | residual | low | high | unclassified | active_empty | 0.4067 | 4 |  |  | absent |  |  |
| 10 | residual | low | high | unclassified | active_empty | 0.6730 | 8 |  |  | absent |  | crop %s crop %s %s %ld %ld %ld %ld 0 0 0 0 |
| 11 | crashed | low | high | operational_stop |  |  |  |  |  | absent |  | StopIteration:  |
| 12 | residual | low | high | unclassified | active_empty | 0.4180 | 4 |  |  | absent |  |  |
| 13 | residual | low | high | unclassified | active_empty | 0.6968 | 8 |  |  | absent |  | crop %s crop %s %s %ld %ld %ld %ld 0 0 0 0 |
| 14 | residual | low | high | unclassified | active_empty | 0.2820 | 2 |  |  | absent |  | \xe6#\xff\xeb\1\x9f\xe5\x030\x8f\xe0\x03 |
| 15 | residual | low | high | unclassified | active_empty | 0.2659 | 2 |  |  | absent |  |  |
| 16 | residual | low | high | unclassified | active_empty | 0.5214 | 6 |  |  | absent |  | rm -rf /webroot/images/webpush/%s |
| 17 | crashed | low | high | operational_stop |  |  |  |  |  | absent |  | StopIteration:  |
| 18 | residual | low | high | unclassified | active_empty | 0.2613 | 2 |  |  | absent |  |  |
| 19 | vulnerable | medium | critical | direct_sink_evidence | active_empty | 15.5858 | 9 | 11/0 | 0.0000 | absent |  | traceroute :;:;#AAAAAAAAAAAAAAAAAAAAAAAAAA |
| 20 | residual | low | high | unclassified | multi_state_settle_budget_exhausted | 2.7895 | 13 |  |  | absent |  |  |
| 21 | residual | low | high | unclassified | active_empty | 1.3579 | 2 |  |  | absent |  | x\x0a?6C      \x0a\x09?4@<C#\x09  \x0a\x09     @  |

## Output Artifacts

- Summary JSON: `/home/ubuntu/work/sanitizer/experiment_reports/full_firmware_campaign_current_tsds_multistate_full_20260916/tenda_w20e.summary.json`
- Per-closure JSONL: `/home/ubuntu/work/sanitizer/experiment_reports/full_firmware_campaign_current_tsds_multistate_full_20260916/tenda_w20e.results.jsonl`
