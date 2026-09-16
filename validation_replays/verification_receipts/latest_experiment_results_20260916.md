# Latest TSDS Evidence Results

This document is an evidence-only result summary. It is not manuscript text.
No paper source or Overleaf project was modified during these runs.

## Current campaign

- Scope: 8 firmware targets, 546 input closures, and 518 deduplicated records.
- All 8 target processes returned successfully.
- The current serialized multi-state audit covers 193 sink-reached records and
  1,862 bounded sink profiles. It records 124 complete and 69 incomplete
  collections, with zero candidate-wide-negative flags.
- The current ledger contains 41 direct sink-byte positive records. Other
  records remain in their declared static, residual, timeout, unreachable, or
  crash categories; no category was changed for presentation purposes.

## Higher-budget positive replay

The suite `iceccs_high_budget_positive_full_20260916` replayed every one of the
41 current direct-positive records using a higher bounded budget and the exact
remote runner receipt.

- 41/41 cases produced receipts and returned with code 0.
- 41/41 retained `VECTOR_SAT`, direct provenance, and the core source/sink
  identity.
- 35 collections completed within the bound; 6 are explicit incompleteness
  warnings.
- 0 identity mismatches, result mismatches, or candidate-wide-negative flags
  were observed.
- The package contains 302 hash-checked artifacts, including raw case outputs,
  run configuration, normalized receipt metadata, the exact executed runner,
  and the audit source and tests.

The replay result is existential over the collected bounded sink instances. An
incomplete collection is not evidence of exhaustive sink-state coverage and
does not support a candidate-wide negative conclusion.

## Witness interface replay

The current-campaign witness package contains 275 vector-satisfying ledger
entries and 177 unique rendered witnesses.

- Bash syntax checks: 177/177 passed.
- Dash syntax checks: 177/177 passed.
- Strict inert execution was admitted for 22 witnesses and passed for 10;
  155 were intentionally not executed.
- Full firmware-generated commands were not executed. This is shell-interface
  calibration and record/offset checking, not firmware source realizability,
  closed-world precision/recall, or device exploitability.

## Incomplete-record recovery

The package `iceccs_high_budget_incomplete_full_20260916` replayed all 69
current records whose bounded multi-state collection was incomplete.

- 68/69 cases produced receipts; 13 collections completed under the higher
  bound and 56 remained incomplete.
- The observed outcomes were 62 residuals and 6 existing `VECTOR_SAT` rows;
  one case timed out before producing a receipt.
- No available aggregate emitted a candidate-wide negative flag. Missing or
  incomplete receipts remain non-claimable.

A targeted higher-timeout recovery then retried the four non-claimable cases
in `iceccs_targeted_multistate_timeout_recovery_full_20260916_v2`.

- 3/4 cases produced receipts, of which 2 contained usable multi-state
  aggregates; 0 collections became complete and 0 candidate-wide negatives
  were emitted.
- In that four-case run, `DIR-878` remained non-claimable after the outer
  timeout, while the `Tenda-AC15` unreachable result had no multi-state
  aggregate. Both remain retained as explicit v2 boundary cases.
- The v1/v2 raw outputs, exact executed runners, audit summaries, and package
  manifests are hash checked. These runs do not establish exhaustive coverage,
  solver soundness, source realizability, firmware ground truth, or device
  exploitability.

A separate fresh Linux recovery then revisited only the `DIR-878` closure at
index 2 with a 1,500-second outer watchdog and higher internal bounds.

- The source/sink identity matched the frozen current-campaign row.
- The receipt completed 10 engine runs and collected 160 bounded profiles;
  aggregation was `exists_positive` with 20 positive profiles and no
  candidate-wide-negative flag.
- The selected receipt retained direct `DIRECT_SINK_BYTE` provenance,
  `VECTOR_SAT`, four SAT vectors, and seven matrix-UNSAT vectors.
- This recovery is stored separately and does not rewrite the original
  campaign ledger or manuscript. It is a target-local bounded observation,
  not firmware ground truth or device-level exploitability.

As a targeted check on the historical conditioned stratum, three historical
`SINK_RECONCILED` positive rows were replayed on the same Linux evaluator under
the same higher-budget policy.

- All three source/sink identities matched their historical rows.
- None admitted a current direct or conditioned promotion; all three remained
  residual, and no candidate-wide-negative flag was emitted.
- Two collections completed with no modeled source; the third remained
  explicitly incomplete. This is non-promotion and scope evidence, not a
  historical source-link validation or refutation.

## Existing independent checks

- Exported-query replay: 62,618 query replays with 37,343 SAT and 25,275 UNSAT
  declaration matches; all 37,343 requested SAT model bindings matched.
- Cross-solver replay: 7 query-bearing targets and zero observed
  disagreements, missing rows, or expected-status disagreements.
- Finite semantic calibration: 1,056/1,056 native-oracle rows matched.
- Fresh current-code aggregation calibration: 5,602 short profile sequences
  and 10 duplicate/permutation relations were checked against an independent
  finite oracle; all 5,612 cases passed with zero failures.
- Fresh Linux-evaluator reviewer-gap calibration: 176/176 matrix construction
  labels and 154/154 applicable Z3 replays passed; the same-callsite ELF
  produced 4 distinct profiles across 2 engine runs, completed collection,
  `exists_positive` aggregation, and no candidate-wide-negative flag.
- Conditioned-link calibration: 18 native, 31 adversarial, and 744 randomized
  boundary cases passed without false admission or false rejection. Historical
  conditioned rows remain non-promoted because their serialized source links
  are absent.
- Remote threat-matrix boundary suite: 15/15 finite evaluator cases passed,
  covering all 11 implemented vector predicates plus four filtering,
  fixed-syntax, NUL-termination, and quote-breakout boundary cases. The suite
  used the locked Linux evaluator and executed no firmware service or shell;
  it is matrix-boundary calibration, not firmware ground truth or device
  validation.
- Historical conditioned replay sample: 3/3 identity-bound replays preserved
  the fail-closed boundary, with 0 direct promotions, 0 conditioned
  promotions, and 0 candidate-wide-negative flags.
- Reviewer-gap closure audit: 30/30 evidence gates pass; the latest v44 audit
  was generated against an index containing 390 artifact entries, including
  the DIR-878, historical-conditioned, dynamic-validation, and threat-matrix
  boundaries. The current index contains 393 artifacts after adding the v44
  outputs. Five stronger
  claims remain explicitly open: historical exhaustive state coverage,
  historical conditioned source linkage, independent blinded human labels,
  firmware closed-world precision/recall, and device-level exploitability.

## Dynamic validation boundary preflight

The package `iceccs_dynamic_validation_boundary_20260916_v1` records a
read-only substrate check for three selected targets. All 3/3 preflight tasks
were ready, all 3/3 inert target-rootfs ABI smokes passed, and 2/3 loader
smokes passed. Only Tenda AC18 had an exact analysis-binary/rootfs-binary
hash match and a passing loader smoke. Tenda AC15 and D-Link DIR-878 were
explicitly retained as binary-mismatch boundaries. No firmware main routine,
service, handler, command sink, shell, generated witness, or network/device
workflow was executed; these results do not establish source realizability,
firmware ground truth, precision/recall, or device-level exploitability.

## Locations

- High-budget package: `paper_work/iceccs_high_budget_positive_full_20260916/`
- Incomplete-record package: `paper_work/iceccs_high_budget_incomplete_full_20260916/`
- Targeted recovery package: `paper_work/iceccs_targeted_multistate_timeout_recovery_full_20260916_v2/`
- Witness package: `paper_work/iceccs_current_campaign_witness_replay_20260916_v1/`
- Fresh aggregation calibration: `paper_work/iceccs_multistate_exhaustive_property_calibration_20260916_v4/`
- Linux evaluator calibration: `paper_work/iceccs_reviewer_gap_calibration_20260916_remote_v1/`
- DIR-878 bounded recovery: `paper_work/iceccs_dir878_timeout_recovery_20260916_v3/`
- Historical conditioned replay sample: `paper_work/iceccs_historical_conditioned_recovery_20260916_v1/`
- Dynamic validation boundary preflight: `paper_work/iceccs_dynamic_validation_boundary_20260916_v1/`
- Threat-matrix boundary suite: `paper_work/iceccs_threat_matrix_boundary_20260916_v1/`
- Latest closure audit: `paper_work/iceccs_reviewer_gap_closure_audit_20260916_v44/`
- Total evidence index: `paper_work/iceccs_evidence_completion_20260915/manifest.json`

The manuscript projects remain frozen. The latest manuscript source is still
the separate `TSDS_upload` project; these newest experiment results have not
been inserted into its LaTeX source or PDF.
