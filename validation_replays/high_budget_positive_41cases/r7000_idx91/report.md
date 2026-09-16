# TSDS Analysis Report

- Generated: 2026-09-16 04:14:23
- Binary: `/home/ubuntu/work/sanitizer/R7000/httpd`
- Trace JSON: `/home/ubuntu/work/sanitizer/R7000/R7000_result/cmdi_results.json`
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
| SAT shell-vector witnesses | 3 |
| Blocked-vector proofs | 0 |
| Average sanitizer coverage | 0.0000 |
| Wall time seconds | 94.2840 |
| Average closure time seconds | 94.2840 |
| Average matrix time seconds | 6.2160 |
| Average engine steps | 21.0000 |
| Semantic frontier cuts | 0 |
| Source-liveness cuts | 0 |
| Delay-slot sink captures | 0 |
| Loop semantic cuts | 0 |
| Seed states tried | 5 |
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
| claim:direct_observed_prefix_sv_sat_evidence | 1 |

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
| bypass:Command Substitution | 1 |
| bypass:Variable Expansion | 1 |

## Vulnerable And Partial Findings

| Closure | Status | Vectors V/S | Coverage | Source kinds | Recovery | Preview |
|---:|---|---:|---:|---|---|---|
| 92 | vulnerable | 3/0 | 0.0000 | file |  | kill -9 %$(:`@- @-A=(A@,"@@A.@A/A-AAAA@.(AA@@-AA(@A@@@A*(A-@-(AA@(@.-(@;rm -f /var/run/ftpc.pid  |

## Trace-Level Analysis

### Trace 92: `vulnerable`

- Trace path: `sub_a345c -> system`
- Source: `sub_a345c` at `0xa345c`
- Sink: `system` at `0xa3538`
- Stop/reason: `active_empty`
- Static evidence: `weak`
- Evidence confidence: `medium` score=60, review=`critical`, claim=`direct_observed_prefix_sv_sat_evidence`
- Evidence factors: `direct_sink_evidence, observed_prefix_without_cstring_terminator, sanitizer_gap_profile_broad_bypass, sat_payload_evidence, weak_static_binding`
- Path control: `direct_sink_evidence` pressure=`resolved`, pruned=0, density=0.0000
- Path-control audit: `max active 2; stop active_empty`
- Result metrics: elapsed=94.2840s, steps=21, vectors=3/0 vulnerable/secure, coverage=0.0000
- Sanitizer gap: `broadly_bypassable` broad sanitizer gap: all decided vectors are bypassable (3 vector(s))
- Gap categories: bypass=`Command Substitution, Variable Expansion`, blocked=``
- Minimal bypass: `Command Substitution` vector=`$(` poc=`kill -9 A$(:)AA AAA=AAA,AAAAAAA/AAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;rm -f /var/run/ftpc.pid`
- Repair hints: `Command Substitution: reject backtick and $() substitution syntax or execute without a shell; Variable Expansion: reject dollar expansion syntax or force strict single-argument quoting`
- Likely inputs: ``
- Possible inputs: `fgets(`
- Source expression: `sub_a345c() @ 0xa345c`
- Sink expression: `system(<MultiValues(<BV32 TOP>)>) @ 0xa3538`
- Sink/result preview: `kill -9 %$(:`@- @-A=(A@,"@@A.@A/A-AAAA@.(AA@@-AA(@A@@@A*(A-@-(AA@(@.-(@;rm -f /var/run/ftpc.pid `

| Step | Function | Address | Expression |
|---:|---|---|---|
| 0 | `sub_a345c` | `0xa345c` | `sub_a345c() @ 0xa345c` |

## Per-Closure Results

| Closure | Status | Confidence | Review | Path control | Stop/reason | Time(s) | Steps | V/S | Coverage | Static | Classification | Preview |
|---:|---|---|---|---|---|---:|---:|---:|---:|---|---|---|
| 92 | vulnerable | medium | critical | direct_sink_evidence | active_empty | 94.2840 | 21 | 3/0 | 0.0000 | weak |  | kill -9 %$(:`@- @-A=(A@,"@@A.@A/A-AAAA@.(AA@@-AA(@A@@@A*(A-@-(AA@(@.-(@;rm -f /var/run/ftpc.pid  |

## Output Artifacts

- Summary JSON: `/home/ubuntu/work/sanitizer/experiment_reports/iceccs_high_budget_positive_full_20260916/r7000_idx91/summary.json`
- Per-closure JSONL: `/home/ubuntu/work/sanitizer/experiment_reports/iceccs_high_budget_positive_full_20260916/r7000_idx91/results.jsonl`
