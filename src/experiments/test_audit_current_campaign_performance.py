#!/usr/bin/env python3
"""Tests for the current-campaign performance ledger."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from experiments.audit_current_campaign_performance import build_ledger, write_outputs


def _write_fixture(root: Path) -> None:
    target_dir = root / "nested"
    target_dir.mkdir()
    summary = {
        "total_closures": 3,
        "unique_pairs_expected": 2,
        "unique_pairs_analyzed": 2,
        "wall_time_sec": 5.0,
        "resource_limit_enforcement_ledger": {
            "configured_limit_mib": 8192,
            "executed_records": 2,
            "records_with_limit_requested": 2,
            "records_with_limit_enforced": 2,
            "records_with_unavailable_worker_metrics": 0,
            "resource_limit_hits": 0,
            "all_executed_workers_enforced": True,
        },
    }
    rows = [
        {
            "closure_idx": 0,
            "status": "residual",
            "verdict": "RESIDUAL",
            "elapsed_sec": 2.0,
            "process_peak_rss_mib": 100.0,
            "process_resource_metric_scope": "worker_recorded",
            "subprocess_memory_limit_mib": 8192,
            "resource_limit_enforcement": "enforced",
            "resource_limit_hit": False,
            "engine_steps_total": 10,
        },
        {
            "closure_idx": 1,
            "status": "vulnerable",
            "verdict": "VECTOR_SAT",
            "elapsed_sec": 3.0,
            "process_peak_rss_mib": 120.0,
            "process_resource_metric_scope": "worker_recorded",
            "subprocess_memory_limit_mib": 8192,
            "resource_limit_enforcement": "enforced",
            "resource_limit_hit": False,
            "engine_steps_total": 20,
            "solver_query_bundle_count": 2,
        },
    ]
    (target_dir / "fixture.results.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )
    (target_dir / "fixture.summary.json").write_text(
        json.dumps(summary), encoding="utf-8"
    )


def test_recursive_ledger_and_outputs() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        _write_fixture(root)
        ledger, rows, issues = build_ledger(root)
        assert not issues
        assert ledger["valid"] is True
        assert ledger["campaign"]["records"] == 2
        assert ledger["campaign"]["input_closures"] == 3
        assert ledger["campaign"]["matrix_query_manifest_count"] == 2
        assert len(rows) == 2
        out = root / "out"
        write_outputs(out, ledger, rows)
        assert (out / "current_campaign_performance.json").is_file()
        assert (out / "current_campaign_resource_records.csv").read_text(encoding="utf-8").count("\n") == 3
