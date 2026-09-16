"""Small, dependency-light building blocks for TSDS experiment artifacts.

The symbolic evaluator intentionally remains the canonical execution engine.
This package contains pure-Python components that can independently validate
its ledgers, plan residual replays, and generate reproducibility artifacts.
Keeping these components free of angr makes the evidence protocol auditable in
minimal artifact environments.
"""

from __future__ import annotations

__all__ = [
    "evidence_certificates",
    "evidence_scheduler",
    "candidate_contract",
    "constraint_projection",
    "evidence_scope",
    "exploitability_calibration",
    "forkserver",
    "independent_certificate_verifier",
    "performance_diagnostics",
    "model_refinement",
    "online_refinement",
    "provenance_graph",
    "reconciliation_link",
    "source_realizability",
    "residual_refinement",
    "residual_root_causes",
    "resource_envelopes",
    "sanitizer_repair",
    "shell_dialects",
    "shell_matrix_spec",
    "sink_corridor",
    "sink_semantics",
    "statistical_evidence",
    "summary_synthesis",
    "ledger_schema",
]
