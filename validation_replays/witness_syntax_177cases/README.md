# Current campaign witness replay

Finite replay of serialized grammar-complete witnesses from the current eight-target TSDS ledger. Commands are restricted to the existing inert template allowlist, run under empty environment and isolated temporary directories. This calibrates shell syntax and interface return behavior; it does not establish original-program source realizability, firmware precision/recall, human ground truth, or device-level exploitability.

- Current records: `518`.
- Direct positive records: `41`.
- Grammar-complete VECTOR_SAT entries: `275`.
- Unique witnesses: `177`.
- Controlled-offset subset failures: `0`.

| Shell | Safety-gate pass | Syntax pass | Execution admitted | Zero-return replay | Execution not run | Unexpected files |
|---|---:|---:|---:|---:|---:|---:|
| `/usr/bin/bash` | 22 | 177 | 22 | 10 | 155 | 0 |
| `/usr/bin/dash` | 22 | 177 | 22 | 10 | 155 | 0 |

The replay never invokes a target firmware process and does not execute any generated witness on a device.
