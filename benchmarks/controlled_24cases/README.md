# SANER 2027 controlled benchmark

This artifact is an Ubuntu-only implementation calibration, not a firmware ground-truth study.

- Cases: `24` (14 independently labelled positive, 10 negative).
- Native marker observations: `14`.
- TSDS: `24` matches, `0` unresolved, `0` mismatches.
- Native commands are logged by an interposer and executed only with fixed benign marker inputs through `/bin/dash`; no generated TSDS witness is executed.
- An unresolved TSDS result is not counted as a negative label.

All source, binary, closure, command, effect, evaluator logs, and hashes are retained below this directory.
