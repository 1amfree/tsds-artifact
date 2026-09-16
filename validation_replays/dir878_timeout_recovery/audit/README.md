# Multi-state recovery suite audit

Valid: **False**
Cases: **1**
Core call-site identities equal: **0**
Recovery collections explicitly incomplete: **0**
Candidate-wide negative flags: **0**
Profile-count delta sum: **100**

Snapshot digests are reported separately from core call-site identity because bounded replays may materialize different concrete constraints.

This artifact compares a finite set of identity-bound, single-closure bounded replays.  It supports recovery and negative-gate accounting only; it does not prove exhaustive sink-state coverage, solver soundness, source realizability, firmware precision/recall, or device exploitability.

| Target | Closure | Baseline profiles | Recovery profiles | Delta | Recovery class | Complete | Issues |
|---|---:|---:|---:|---:|---|---|---|
| dir878 | 2 | 60 | 160 | 100 | exists_positive | True | core_callsite_identity_changed |
