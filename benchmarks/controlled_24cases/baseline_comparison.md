# Controlled baseline comparison

This is a same-input calibration, not firmware ground truth.

- Cases: `24`; independent positive labels: `14`.
- B0 treats every reached `system` call as positive.
- B1 requires the exact input to survive in the final command and contain a shell meta character.
- B2 scans the full command for shell meta characters and ignores source ownership.
- TSDS uses the actual evaluator result; residuals would be unknown, not negative.

| Validator | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| B0_original_source_to_sink | 14 | 10 | 0 | 0 | 0.5833 | 1.0 | 0.7368 |
| B1_source_owned_meta | 14 | 0 | 10 | 0 | 1.0 | 1.0 | 1.0 |
| B2_full_string_meta | 14 | 5 | 5 | 0 | 0.7368 | 1.0 | 0.8485 |
| TSDS | 14 | 0 | 10 | 0 | 1.0 | 1.0 | 1.0 |

Same-input controlled counterfactual comparison. Labels come from the independently specified native benchmark semantics. B0/B1/B2 are simple validators, not independent firmware accuracy baselines.
