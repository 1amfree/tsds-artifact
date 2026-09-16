from __future__ import annotations

from pathlib import Path

import experiments.audit_smt_model_binding_parallel as parallel


def test_parallel_collection_preserves_manifest_order(monkeypatch) -> None:
    paths = [Path("a.manifest.json"), Path("b.manifest.json")]

    monkeypatch.setattr(parallel, "_manifest_paths", lambda _campaign: paths)
    monkeypatch.setattr(
        parallel,
        "select_manifests",
        lambda available, _campaign, _limit: list(available),
    )

    def fake_audit(path, **_kwargs):
        return [{"manifest": str(path), "observed": "SAT", "declared": "SAT", "valid": True}]

    monkeypatch.setattr(parallel, "audit_manifest", fake_audit)
    summary, rows = parallel.collect_campaign(
        Path("campaign"), solver="z3", timeout=1, limit=0, workers=2
    )

    assert [row["manifest"] for row in rows] == [str(path) for path in paths]
    assert summary["selected_manifest_count"] == 2
    assert summary["query_count"] == 2
    assert summary["valid"] is True


def test_parallel_collection_records_worker_errors(monkeypatch) -> None:
    path = Path("broken.manifest.json")
    monkeypatch.setattr(parallel, "_manifest_paths", lambda _campaign: [path])
    monkeypatch.setattr(
        parallel,
        "select_manifests",
        lambda available, _campaign, _limit: list(available),
    )

    def fake_audit(_path, **_kwargs):
        raise ValueError("malformed")

    monkeypatch.setattr(parallel, "audit_manifest", fake_audit)
    summary, rows = parallel.collect_campaign(
        Path("campaign"), solver="z3", timeout=1, limit=0, workers=2
    )

    assert rows == []
    assert summary["valid"] is False
    assert len(summary["manifest_errors"]) == 1
