# TSDS Analysis Report

- Generated: 2026-09-16 04:24:46
- Binary: `/home/ubuntu/work/sanitizer/Tenda_AC15/httpd`
- Trace JSON: `/home/ubuntu/work/sanitizer/Tenda_AC15/Tenda_AC15_results/cmdi_results.json`
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
| Wall time seconds | 21.3835 |
| Average closure time seconds | 21.3835 |
| Average matrix time seconds | 0.9453 |
| Average engine steps | 7.0000 |
| Semantic frontier cuts | 0 |
| Source-liveness cuts | 0 |
| Delay-slot sink captures | 0 |
| Loop semantic cuts | 0 |
| Seed states tried | 8 |
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
| 32 | vulnerable | 11/0 | 0.0000 | entry_arg |  | mv </dev/nullAAAAAAAAAAAAAAAAAAAAA |

## Trace-Level Analysis

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
- Result metrics: elapsed=21.3835s, steps=7, vectors=11/0 vulnerable/secure, coverage=0.0000
- Sanitizer gap: `broadly_bypassable` broad sanitizer gap: all decided vectors are bypassable (11 vector(s))
- Gap categories: bypass=`Background Execution, Bypass Spaces, Command Chaining, Command Substitution, Piping, Redirection, Variable Expansion`, blocked=``
- Minimal bypass: `Background Execution` vector=`&` poc=`mv :&:;#AAAAAAAAAAAAAAAAAAAAAAAAAA`
- Repair hints: `Background Execution: reject or quote ampersand job-control operators; Bypass Spaces: normalize and reject alternate whitespace forms such as tabs and ${IFS}; Command Chaining: reject or quote command separators such as semicolon and newline, or avoid shell...`
- Source expression: `sub_316bc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x316bc`
- Sink expression: `doSystemCmd(<MultiValues(<BV152 0x6d7620 .. TOP .. 0x20202f7661722f696d616765>)>, <MultiValues(<BV32 TOP>)>) @ 0x3171c`
- Sink/result preview: `mv </dev/nullAAAAAAAAAAAAAAAAAAAAA`

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_316bc` | `0x316bc` | `sub_316bc(<MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>, <MultiValues(<BV32 TOP>)>) @ 0x316bc` |

## Per-Closure Results

| Closure | Status | Confidence | Review | Path control | Stop/reason | Time(s) | Steps | V/S | Coverage | Static | Classification | Preview |
|---:|---|---|---|---|---|---:|---:|---:|---:|---|---|---|
| 32 | vulnerable | medium | critical | direct_sink_evidence | active_empty | 21.3835 | 7 | 11/0 | 0.0000 | absent |  | mv </dev/nullAAAAAAAAAAAAAAAAAAAAA |

## Output Artifacts

- Summary JSON: `/home/ubuntu/work/sanitizer/experiment_reports/iceccs_high_budget_positive_full_20260916/tenda_ac15_idx31/summary.json`
- Per-closure JSONL: `/home/ubuntu/work/sanitizer/experiment_reports/iceccs_high_budget_positive_full_20260916/tenda_ac15_idx31/results.jsonl`
