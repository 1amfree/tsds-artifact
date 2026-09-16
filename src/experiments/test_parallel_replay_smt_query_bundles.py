from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from experiments.parallel_replay_smt_query_bundles import main


def _manifest(root: Path, name: str, marker: str, expected: str) -> None:
    query = root / f"{name}.full.smt2"
    query.write_text(f"; {marker}\n(check-sat)\n", encoding="utf-8")
    payload = {
        "schema": "tsds-solver-query-bundle-v1",
        "query_id": name,
        "files": {"full": query.name, "projected": None},
        "sha256": {
            "full_smt2": hashlib.sha256(query.read_bytes()).hexdigest(),
            "projected_smt2": None,
        },
        "producer": {
            "decision": expected,
            "full_result": expected,
            "projected_result": "NOT_RUN",
            "full_validation": "performed",
        },
    }
    (root / f"{name}.manifest.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )


def test_parallel_replay_publishes_complete_ordered_receipts(tmp_path: Path, monkeypatch) -> None:
    _manifest(tmp_path, "a", "emit-sat", "SAT")
    _manifest(tmp_path, "b", "emit-unsat", "UNSAT")
    solver = tmp_path / "reference_solver.py"
    solver.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "text = Path(sys.argv[1]).read_text(encoding='utf-8')\n"
        "print('sat' if 'emit-sat' in text else 'unsat')\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "parallel_replay_smt_query_bundles.py",
            "--bundle-dir",
            str(tmp_path),
            "--out-dir",
            str(out_dir),
            "--solver-argv",
            f'"{sys.executable}" "{solver}"',
            "--workers",
            "2",
            "--start-method",
            "spawn",
            "--fail-on-mismatch",
            "--fail-if-unavailable",
        ],
    )
    assert main() == 0
    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["manifest_count"] == 2
    assert summary["replay_count"] == 2
    assert summary["comparison_counts"] == {
        "MATCH": 2,
        "MISMATCH": 0,
        "UNKNOWN": 0,
        "NOT_APPLICABLE": 0,
    }
    assert not (out_dir / "replay_receipts.jsonl.partial").exists()
    receipts = [
        json.loads(line)
        for line in (out_dir / "replay_receipts.jsonl").read_text().splitlines()
    ]
    assert [Path(item["manifest"]).name for item in receipts] == [
        "a.manifest.json",
        "b.manifest.json",
    ]
    assert [item["replays"][0]["comparison"] for item in receipts] == [
        "MATCH",
        "MATCH",
    ]
