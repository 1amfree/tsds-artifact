# TSDS Analysis Report

- Generated: 2026-09-16 04:26:57
- Binary: `/home/ubuntu/work/sanitizer/Tenda_W20E/httpd`
- Trace JSON: `/home/ubuntu/work/sanitizer/Tenda_W20E/results/cmdi_results.json`
- Mode: `full`
- Total closures: 
- Unique pairs expected: 
- Unique pairs analyzed: 1

## Executive Summary

| Metric | Value |
|---|---:|
| SV-SAT | 1 |
| Modeled-vector filtered | 0 |
| Partially filtered SV-SAT | 0 |
| No-modeled-source sink | 0 |
| Static source inference | 0 |
| Static warning reduction | 0 |
| Residual obligation | 0 |
| Unreachable | 0 |
| Timeout | 0 |
| Crashed | 0 |
| Evaluation errors | 0 |
| SAT shell-vector witnesses | 11 |
| Blocked-vector proofs | 0 |
| Average sanitizer coverage | 0.0000 |
| Wall time seconds | 17.2712 |
| Average closure time seconds | 17.2712 |
| Average matrix time seconds | 1.0134 |
| Average engine steps | 9.0000 |
| Semantic frontier cuts | 0 |
| Source-liveness cuts | 0 |
| Delay-slot sink captures | 0 |
| Loop semantic cuts | 0 |
| Seed states tried | 6 |
| Seed states pruned | 0 |
| Memoized closures | 0 |
| Evidence cache hits | 0 |

## Engine Stop Reasons

| Stop reason | Count |
|---|---:|
| `active_empty` | 1 |

## Feature Configuration

| Feature | Value |
|---|---|
| `arch_seeding` | `True` |
| `byte_provenance` | `True` |
| `constraint_projection_cache_size` | `4096` |
| `emit_provenance_graph` | `False` |
| `environment_fixture` | `False` |
| `environment_fixture_digest` | `52a76f5de8b7ca65` |
| `evidence_aware_scheduler` | `False` |
| `execution_backend` | `forkserver` |
| `firmware_summaries` | `True` |
| `loop_semantic_bucket_limit` | `1` |
| `loop_semantic_min_states` | `50` |
| `loop_semantic_min_visits` | `3` |
| `loop_semantic_saturation_limit` | `3` |
| `loop_semantic_summary` | `False` |
| `loop_semantic_weak_static` | `False` |
| `multi_state_audit` | `True` |
| `multi_state_settle_steps` | `96` |
| `online_refinement_candidates` | `3` |
| `online_refinement_rounds` | `1` |
| `refinement_bundle` | `False` |
| `resource_limit_enforcement` | `not_requested` |
| `scheduler_active_cap_range` | `[500, 500]` |
| `scheduler_base_active_cap` | `500` |
| `scheduler_constraint_soft_limit` | `4000` |
| `scheduler_escape_quota` | `32` |
| `semantic_frontier` | `False` |
| `shell_lexical_gate` | `tsds-shell-lexical-gate-v1` |
| `sink_corridor` | `True` |
| `sink_semantic_plugins` | `True` |
| `solver_query_export` | `False` |
| `source_dead_state_cap` | `500` |
| `source_liveness_limit` | `0` |
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
| review:critical | 1 |
| claim:direct_sink_byte_sv_sat_evidence | 1 |

## Semantic Path-Control Ledger

| Dimension | Count |
|---|---:|
| class:direct_sink_evidence | 1 |
| pressure:resolved | 1 |
| total:path_control_pruned_states | 0 |
| total:semantic_pruned_states | 0 |
| total:seed_pruned | 0 |

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

## Trace-Level Analysis

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
- Result metrics: elapsed=17.2712s, steps=9, vectors=11/0 vulnerable/secure, coverage=0.0000
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

## Per-Closure Results

| Closure | Status | Confidence | Review | Path control | Stop/reason | Time(s) | Steps | V/S | Coverage | Static | Classification | Preview |
|---:|---|---|---|---|---|---:|---:|---:|---:|---|---|---|
| 19 | vulnerable | medium | critical | direct_sink_evidence | active_empty | 17.2712 | 9 | 11/0 | 0.0000 | absent |  | traceroute :;:;#AAAAAAAAAAAAAAAAAAAAAAAAAA |

## Output Artifacts

- Summary JSON: `/home/ubuntu/work/sanitizer/experiment_reports/iceccs_high_budget_positive_full_20260916/tenda_w20e_idx18/summary.json`
- Per-closure JSONL: `/home/ubuntu/work/sanitizer/experiment_reports/iceccs_high_budget_positive_full_20260916/tenda_w20e_idx18/results.jsonl`
