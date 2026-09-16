# Reproduction Guide: TSDS Artifact Evaluation

This guide provides step-by-step instructions for reviewing, auditing, and reproducing the experimental results presented in the IEEE CSCloud 2026 paper:

> **TSDS: Auditable Final-Byte Evidence for Command-Injection Triage in Edge Firmware**

---

## 1. Quick Reproduction (Audit Mode - Recommended)

The audit mode independently parses raw campaign outputs, ground-truth benchmark ledgers, shell matrix profiles, and cryptographic receipts using **pure Python standard library** (Python 3.8+). It requires **zero third-party dependencies**.

### Execution

```bash
# Navigate to the experiment_upload directory
cd experiment_upload

# Run the unified verification script
python scripts/verify_all_receipts.py
```

### What This Script Audits:

1. **Table I Accounting Conservation**:
   - Opens each raw file `campaign_data/8firmware_multistate_20260916/<target>/multistate_run.results.jsonl` across all 8 firmware targets.
   - Parses each candidate record and counts:
     - Direct Complete-String SV-SAT (`36`)
     - Direct Observed-Prefix P-SAT (`5`)
     - Static Source-Slot Obligations (`31`)
     - Static Template Reductions (`120`)
     - Typed Residual Obligations (`326`)
   - Verifies that their sum equals exactly **518** candidates, matching Table I in the paper.

2. **Section V-B Quote-Aware Shell Effect Matrix**:
   - Inspects the 64 syntactic matrix profiles defined in `src/tsds/shell_matrix_spec.py`.
   - Iterates through all 11 canonical injection vectors ($64 \times 11 = 704$ cell decisions).
   - Verifies exact decision counts:
     - `VECTOR_SAT`: 275
     - `MATRIX_UNSAT`: 150
     - `INCONCLUSIVE`: 279

3. **Table II Controlled Ground-Truth Benchmark**:
   - Reads `benchmarks/controlled_24cases/cases.csv` and `benchmarks/controlled_24cases/baseline_comparison.json`.
   - Recomputes True Positives, False Positives, False Negatives, Precision, Recall, and F1 score for:
     - TSDS (Precision=1.0000, Recall=1.0000, F1=1.0000, FP=0)
     - Baseline B0 Reachability (Precision=0.5833, Recall=1.0000, F1=0.7368, FP=10)
     - Baseline B1 Byte-Owned (Precision=1.0000, Recall=1.0000, F1=1.0000, FP=0)
     - Baseline B2 Full-String Blind (Precision=0.7368, Recall=1.0000, F1=0.8485, FP=5)
   - Confirms strict parity with Table II.

4. **Section V-C Replay & Witness Integrity**:
   - Validates existence and integrity of all 41 positive candidate dynamic replay packages in `validation_replays/high_budget_positive_41cases/`.
   - Validates all 177 rendered shell witness syntax executions across GNU Bash and Debian Dash in `validation_replays/witness_syntax_177cases/audit.json`.
   - Verifies 393/393 cryptographic SHA-256 receipts in `validation_replays/verification_receipts/verification_20260916_final.json`.

---

## 2. Inspecting the 24-Case Controlled Benchmark

The controlled benchmark represents the 24 edge-case firmware sink patterns evaluated in Section V-A:

```bash
# View ground-truth annotations and descriptions
cat benchmarks/controlled_24cases/cases.csv

# View baseline comparison results
cat benchmarks/controlled_24cases/baseline_comparison.json
```

### Inspecting a Specific Controlled Case:
For instance, Case 10 (`10_alnum_filter`, an alphanumeric filter that prevents injection):
```bash
# View TSDS execution summary and proof closure
cat benchmarks/controlled_24cases/tsds/10_alnum_filter/summary.json
cat benchmarks/controlled_24cases/tsds/10_alnum_filter/closure.json
```
The closure demonstrates that TSDS proved `UNSAT` via constraint projection on the final byte byte-level provenance graph, avoiding the false positive triggered by reachability-only tools.

---

## 3. Inspecting the 8-Firmware Multi-State Campaign

The multi-state campaign evaluated 8 commercial IoT and edge gateway firmwares:
- ASUS RT-BE57
- D-Link DIR-878
- Netgear R6400v2
- Netgear R7000
- Tenda AC15
- Tenda AC18
- Tenda W20E
- Netgear XR300

### Inspecting Raw Candidate Records:
```bash
# Example: Inspecting candidate records from Netgear R7000
head -n 5 campaign_data/8firmware_multistate_20260916/r7000/multistate_run.results.jsonl
```

Each candidate JSONL line contains full audit provenance:
```json
{
  "target": "r7000",
  "candidate_id": "r7000_cand_0012",
  "sink_type": "system",
  "scope_label": "SV-SAT",
  "format_pattern": "/bin/echo %s > /tmp/out",
  "controlled_bytes": [10, 11, 12],
  "witness_vector": ";reboot;",
  "matrix_cell": "VECTOR_SAT",
  "receipt_sha256": "3a8f...",
  "decision_timestamp": "2026-09-16T..."
}
```

---

## 4. Replaying Shell Witnesses (POSIX Syntax Audit)

In Section V-C, TSDS generated 177 rendered shell witnesses to verify that generated command strings are syntactically valid in POSIX shells (`bash` and `dash`).

To inspect the shell replay logs:
```bash
# View syntax audit summary
cat validation_replays/witness_syntax_177cases/summary.json

# View detailed receipts for Bash and Dash execution
cat validation_replays/witness_syntax_177cases/receipts_bash.json
cat validation_replays/witness_syntax_177cases/receipts_dash.json
```

---

## 5. Checking Cryptographic File Integrity

To ensure no files were altered or corrupted during transit or extraction, verify the SHA-256 checksums:

### On Linux / macOS:
```bash
sha256sum -c SHA256SUMS
```

### On Windows (PowerShell):
```powershell
Get-Content SHA256SUMS | ForEach-Object {
    $parts = $_ -split '  '
    if ($parts.Length -eq 2) {
        $expected = $parts[0]
        $file = $parts[1]
        if (Test-Path $file) {
            $actual = (Get-FileHash -Path $file -Algorithm SHA256).Hash.ToLower()
            if ($actual -eq $expected) {
                Write-Host "OK: $file"
            } else {
                Write-Error "MISMATCH: $file"
            }
        }
    }
}
```

---

## 6. Environment Diagnostics (Optional Advanced Pipeline Execution)

To check the host environment for optional binary lifting and SMT solver execution:
```bash
python scripts/check_environment.py
```
This script checks for the presence of `z3-solver`, `cvc5`, `angr`, and `qemu` user-space emulators, explaining which additional components are needed if you wish to run full dynamic rehosting campaigns from scratch.
