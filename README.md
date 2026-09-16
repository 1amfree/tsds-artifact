# TSDS Artifact & Reproducibility Package (IEEE CSCloud 2026)

This repository contains the complete source code, experimental campaign datasets, controlled benchmark suites, execution traces, cryptographic verification receipts, and the camera-ready manuscript for the research paper:

> **TSDS: Auditable Final-Byte Evidence for Command-Injection Triage in Edge Firmware**  
> *IEEE CSCloud 2026 (13th IEEE International Conference on Cyber Security and Cloud Computing)*

---

## 1. Quick Verification (Zero External Dependencies)

To independently verify all empirical claims, table values, matrix cell counts, and cryptographic receipts reported in the manuscript, run the automated verification script using standard Python (Python 3.8+):

```bash
python scripts/verify_all_receipts.py
```

### Expected Output
```text
===========================================================================
  1. Validating 8-Firmware Multi-State Campaign Accounting (Table I)
===========================================================================
  Direct Complete-String SV-SAT :   36
  Direct Observed-Prefix P-SAT  :    5
  Static Source-Slot Obligation :   31
  Static Template Reduction     :  120
  Typed Residual Obligations    :  326
  -------------------------------------
  Total Accounted Records       :  518 (Expected: 518)
  [PASS] Exact candidate accounting invariant conserved: 36 + 5 + 31 + 120 + 326 = 518.
  ...
===========================================================================
  OVERALL AUDIT RESULT: [ALL PASS] (100% Verified)
  All empirical claims in the CSCloud 2026 paper are fully supported by
  independently verifiable evidence in this package.
===========================================================================
```

---

## 2. Directory Structure

The package is organized into modular directories matching the methodology and evaluation sections of the paper:

```text
experiment_upload/
├── README.md                      # This file (artifact guide and claim-to-evidence mapping)
├── REPRODUCTION.md                # Step-by-step reproduction instructions
├── SHA256SUMS                     # Cryptographic SHA-256 manifest of all files
├── paper/
│   ├── CSCloud_2026_CameraReady.pdf   # Complete 12-page camera-ready PDF (IEEE format)
│   └── source/                    # Complete LaTeX source tree and build files
├── src/
│   ├── tsds/                      # Core TSDS engine modules (27 Python modules)
│   │   ├── candidate_contract.py  # Final-byte candidate contract & ledger schema
│   │   ├── constraint_projection.py# Backward SMT path condition projecter
│   │   ├── shell_matrix_spec.py   # 11-vector quote-aware shell effect matrix
│   │   ├── multi_state_aggregation.py # Multi-state obligation aggregator
│   │   ├── evidence_scope.py      # Scope ladder (SV-SAT, P-SAT, Residuals)
│   │   └── ...                    # Sink corridor, forkserver, provenance graph, etc.
│   └── experiments/               # Experimentation runners, verification & audit tools
├── benchmarks/
│   └── controlled_24cases/        # 24-case controlled ground-truth benchmark suite
│       ├── controlled_benchmark.c # C source code covering 24 syntactic/quote patterns
│       ├── controlled_benchmark   # Compiled Linux ELF binary
│       ├── cases.csv              # Ground-truth labels & metadata for all 24 cases
│       ├── baseline_comparison.json # Exact metric comparison (TSDS vs B0, B1, B2)
│       ├── baseline/              # Detailed per-case baseline outputs (B0, B1, B2)
│       └── tsds/                  # Per-case TSDS execution outputs (1..24)
├── campaign_data/
│   ├── 8firmware_multistate_20260916/ # Raw campaign results across 8 commercial firmwares
│   │   ├── asus_rt_be57/          # ASUS RT-BE57 raw .results.jsonl, logs & configs
│   │   ├── dir878/                # D-Link DIR-878 raw .results.jsonl, logs & configs
│   │   ├── r6400v2/               # Netgear R6400v2 raw .results.jsonl, logs & configs
│   │   ├── r7000/                 # Netgear R7000 raw .results.jsonl, logs & configs
│   │   ├── tenda_ac15/            # Tenda AC15 raw .results.jsonl, logs & configs
│   │   ├── tenda_ac18/            # Tenda AC18 raw .results.jsonl, logs & configs
│   │   ├── tenda_w20e/            # Tenda W20E raw .results.jsonl, logs & configs
│   │   └── xr300/                 # Netgear XR300 raw .results.jsonl, logs & configs
│   └── multistate_audit_summary/  # Campaign audit and selection coverage summaries
├── validation_replays/
│   ├── high_budget_positive_41cases/ # 41 positive candidate dynamic replay packages
│   ├── witness_syntax_177cases/   # 177 unique rendered witnesses verified on Bash/Dash
│   ├── dir878_timeout_recovery/   # 1,500s deep watchdog recovery validation records
│   └── verification_receipts/     # Cryptographic receipts (393 verified SHA-256 checks)
└── scripts/
    ├── verify_all_receipts.py     # Self-contained zero-dependency audit verifier
    └── check_environment.py       # Environment diagnostic tool
```

---

## 3. Mapping Paper Claims to Empirical Artifacts

Every quantitative claim, table, and evaluation metric in the manuscript is backed by an explicit, auditable file in this artifact package:

### 3.1 Table I: Multi-State Candidate Accounting across 8 Firmwares
- **Paper Claim**: Across 8 production firmware images, TSDS triaged 518 total sink candidates into:
  - **36** Complete-String Direct SV-SAT
  - **5** Observed-Prefix Direct P-SAT
  - **31** Static Source-Slot Obligations
  - **120** Static Template Reductions
  - **326** Typed Residual Obligations
- **Evidence Files**:
  - Raw JSONL logs: `campaign_data/8firmware_multistate_20260916/<target>/multistate_run.results.jsonl`
  - Target-by-target summary: `campaign_data/multistate_audit_summary/current_multistate_campaign_audit.json`
  - Automated Verifier: Step 1 in `scripts/verify_all_receipts.py` reads all raw lines directly and verifies conservation:
    $$\sum (\text{Complete} + \text{Prefix} + \text{Source} + \text{Template} + \text{Residuals}) = 518$$

### 3.2 Table II: Controlled 24-Case Ground Truth Benchmark
- **Paper Claim**: On 24 synthetic patterns covering complex quoting, escaping, formatting, and numeric projections:
  - **TSDS (Ours)**: Precision = 1.0000, Recall = 1.0000, F1 = 1.0000, False Positives = 0
  - **B0 (Reachability-Only)**: Precision = 0.5833, Recall = 1.0000, F1 = 0.7368, False Positives = 10
  - **B1 (Byte-Owned)**: Precision = 1.0000, Recall = 1.0000, F1 = 1.0000, False Positives = 0
  - **B2 (Full-String Blind)**: Precision = 0.7368, Recall = 1.0000, F1 = 0.8485, False Positives = 5
- **Evidence Files**:
  - Ground-truth definitions: `benchmarks/controlled_24cases/cases.csv`
  - Metric summary: `benchmarks/controlled_24cases/baseline_comparison.json`
  - Complete C source: `benchmarks/controlled_24cases/controlled_benchmark.c`
  - Individual run traces: `benchmarks/controlled_24cases/tsds/` and `benchmarks/controlled_24cases/baseline/`
  - Automated Verifier: Step 3 in `scripts/verify_all_receipts.py`

### 3.3 Section V-B: Quote-Aware Shell Effect Matrix
- **Paper Claim**: The shell effect matrix models 64 distinct syntactic profiles across 11 canonical injection vectors ($64 \times 11 = 704$ total cell decisions), yielding:
  - **275** `VECTOR_SAT`
  - **150** `MATRIX_UNSAT`
  - **279** `INCONCLUSIVE`
- **Evidence Files**:
  - Matrix specification: `src/tsds/shell_matrix_spec.py`
  - Matrix receipt audit: `validation_replays/verification_receipts/verification_20260916_final.json`
  - Automated Verifier: Step 2 in `scripts/verify_all_receipts.py`

### 3.4 Section V-C: Dynamic Replay & Syntax Witness Audit
- **Paper Claim**:
  - 41 positive candidates were replayed under high-budget dynamic instrumentation to observe concrete process forks.
  - 177 unique rendered witnesses were tested against strict POSIX shell parsers (`bash` and `dash`), achieving 100% syntax compliance without unquoted malformations.
  - Cryptographic integrity audit contains 393 verified SHA-256 receipts.
- **Evidence Files**:
  - 41 Replay cases: `validation_replays/high_budget_positive_41cases/`
  - 177 Witness syntax logs: `validation_replays/witness_syntax_177cases/audit.json`
  - 393 Cryptographic receipts: `validation_replays/verification_receipts/verification_20260916_final.json`
  - Automated Verifier: Step 4 in `scripts/verify_all_receipts.py`

---

## 4. Hardware & Software Requirements

### To Run Standalone Verification Script (`scripts/verify_all_receipts.py`)
- Standard Python 3.8 or higher.
- No external packages required (uses only built-in `hashlib`, `json`, `pathlib`, `os`, `sys`).
- Supported on Windows, Linux, and macOS.

### To Re-execute SMT Solvers and Symbolic Engine (Optional)
- Linux x86_64 or Windows 10/11 with Python 3.10+
- `z3-solver` >= 4.12.0
- Optional: `angr` >= 9.2.0 (for full binary lifting and symbolic tracing)
- Optional: QEMU user-mode emulators (`qemu-arm`, `qemu-mips`, `qemu-mipsel`) for firmware execution

---

## 5. Paper Information & Citation

```bibtex
@inproceedings{tsds2026cscloud,
  author    = {Zuozheng Zhou and Jian Lin and Shuai Ren and Haoran Liu and Jintao Bao and Ruimin Wang},
  title     = {TSDS: Auditable Final-Byte Evidence for Command-Injection Triage in Edge Firmware},
  booktitle = {Proceedings of the 13th IEEE International Conference on Cyber Security and Cloud Computing (CSCloud 2026)},
  year      = {2026},
  publisher = {IEEE}
}
```
