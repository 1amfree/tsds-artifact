# Full Firmware Campaign Aggregate

Candidate closures are the front-end inputs; Eval is the selected, de-duplicated record count actually analyzed in this run.
Paper-facing columns below are derived from `evidence_contract_ledger.verdicts`; legacy status fields are not used.

| Target | Candidates | Selected | Eval | SV-SAT | Partial | M-Filt | NMS | Static-src | Static-red. | Contract residual | Contract invalid | Witnesses | Avg(s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| asus_rt_be57 | 32 | 19 | 19 | 3 | 0 | 0 | 0 | 0 | 0 | 16 | 0 | 33 | 26.3243 |
| dir878 | 52 | 49 | 49 | 0 | 0 | 0 | 0 | 0 | 2 | 47 | 0 | 0 | 68.383 |
| r6400v2 | 76 | 75 | 75 | 4 | 0 | 0 | 0 | 0 | 36 | 35 | 0 | 44 | 28.6079 |
| r7000 | 161 | 157 | 157 | 15 | 6 | 0 | 0 | 0 | 71 | 71 | 0 | 97 | 34.1475 |
| tenda_ac15 | 65 | 64 | 64 | 3 | 1 | 0 | 0 | 17 | 0 | 44 | 0 | 25 | 43.6802 |
| tenda_ac18 | 56 | 54 | 54 | 3 | 1 | 0 | 0 | 14 | 0 | 37 | 0 | 25 | 38.89 |
| tenda_w20e | 21 | 21 | 21 | 1 | 0 | 0 | 0 | 0 | 0 | 20 | 0 | 11 | 2.3673 |
| xr300 | 83 | 79 | 79 | 12 | 10 | 0 | 0 | 0 | 11 | 56 | 0 | 40 | 53.7238 |
| TOTAL | 546 | 518 | 518 | 41 | 18 | 0 | 0 | 31 | 120 | 326 | 0 | 275 |  |

## Resource profile

Peak RSS is the maximum resident set reported by GNU time for each target process tree.

| Target | Peak RSS (MiB) | User CPU (s) | System CPU (s) | CPU (%) | Major faults | Minor faults |
|---|---:|---:|---:|---:|---:|---:|
| asus_rt_be57 | 2419.23 | 474.98 | 32.86 | 100.0 | 17 | 2525404 |
| dir878 | 3977.19 | 3302.38 | 64.56 | 100.0 | 0 | 9965154 |
| r6400v2 | 3374.77 | 2064.32 | 97.75 | 100.0 | 0 | 14566291 |
| r7000 | 3568.41 | 5639.63 | 220.43 | 100.0 | 3 | 31231437 |
| tenda_ac15 | 1474.39 | 2713.89 | 101.9 | 100.0 | 0 | 8182775 |
| tenda_ac18 | 1371.24 | 2040.16 | 73.8 | 100.0 | 0 | 6541485 |
| tenda_w20e | 2926.18 | 192.74 | 12.11 | 100.0 | 0 | 1642484 |
| xr300 | 7733.99 | 4459.02 | 213.29 | 100.0 | 0 | 28469370 |
| TOTAL | 7733.99 | 20887.12 | 816.7 | -- | 20 | 103124400 |

## Operational stop breakdown

These counters explain contract residuals; they are not negative verdicts.

| Target | Explicit residual | Unreachable | Timeout | Crash | Eval error | State error |
|---|---:|---:|---:|---:|---:|---:|
| asus_rt_be57 | 11 | 5 | 0 | 0 | 0 | 0 |
| dir878 | 16 | 5 | 26 | 0 | 0 | 0 |
| r6400v2 | 14 | 13 | 8 | 0 | 0 | 0 |
| r7000 | 20 | 15 | 36 | 0 | 0 | 0 |
| tenda_ac15 | 31 | 13 | 0 | 0 | 0 | 0 |
| tenda_ac18 | 32 | 4 | 1 | 0 | 0 | 0 |
| tenda_w20e | 19 | 0 | 1 | 3 | 0 | 0 |
| xr300 | 17 | 23 | 16 | 0 | 0 | 0 |
| TOTAL | 160 | 78 | 88 | 3 | 0 | 0 |
