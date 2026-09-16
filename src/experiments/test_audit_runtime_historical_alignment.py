from __future__ import annotations

import json
from pathlib import Path

from experiments.audit_runtime_historical_alignment import audit


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def test_audit_keeps_exact_near_and_missing_callsite_boundaries(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    campaign = workspace / "campaign"
    campaign.mkdir(parents=True)
    config = {
        "targets": [
            {
                "name": "demo",
                "label": "Demo Device",
                "binary": "demo/httpd",
                "binary_sha256": "b" * 64,
            }
        ]
    }
    config_path = workspace / "campaign_configuration.json"
    write_json(config_path, config)
    result_path = campaign / "demo.results.jsonl"
    result_path.write_text(
        json.dumps(
            {
                "closure_idx": 0,
                "closure_ordinal": 1,
                "source_addr": "0x1000",
                "sink_addr": "0x2000",
                "source_function": "source",
                "sink_function": "system",
                "status": "vulnerable",
                "verdict": "VECTOR_SAT",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    evidence = workspace / "evidence"
    write_json(evidence / "canary_summary.json", {"target": "Demo Device"})
    import hashlib

    summary_digest = hashlib.sha256((evidence / "canary_summary.json").read_bytes()).hexdigest()
    runtime_csv = workspace / "runtime.csv"
    runtime_csv.write_text(
        "id,target,sink,callsite,token,attempt_class,observed_command,handler_or_entry,evidence_dir,summary_sha256\n"
        f"exact,Demo Device,system@plt,0x2000,T,positive_token_to_sink,T,,evidence,{summary_digest}\n"
        f"near,Demo Device,system@plt,0x2004,T,positive_token_to_sink,T,source entry at 0x1000,evidence,{summary_digest}\n"
        f"missing,Demo Device,system@plt,,T,boundary_sink_hit_no_token,,,evidence,{summary_digest}\n",
        encoding="utf-8",
    )
    runtime_summary = workspace / "runtime_summary.json"
    write_json(
        runtime_summary,
        {
            "runtime_attempts": 3,
            "campaign_identity": {
                "result_files": 1,
                "results_identity_sha256": "placeholder",
            },
        },
    )

    result = audit(
        workspace_root=workspace,
        runtime_csv=runtime_csv,
        runtime_summary_path=runtime_summary,
        campaign_dir=campaign,
        campaign_config_path=config_path,
    )
    assert result["summary"]["valid"] is False
    assert result["summary"]["match_kinds"] == {
        "exact_sink_callsite": 1,
        "source_entry_sink_address_mismatch": 1,
        "target_only_missing_callsite": 1,
    }
    assert result["rows"][0]["analysis_relation"] == "runtime_positive_with_vector_sat_record"
    assert result["rows"][1]["analysis_relation"] == "not_joined"


def test_audit_accepts_matching_campaign_identity(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    campaign = workspace / "campaign"
    campaign.mkdir(parents=True)
    config_path = workspace / "config.json"
    write_json(config_path, {"targets": [{"name": "demo", "label": "Demo"}]})
    (campaign / "demo.results.jsonl").write_text("{}\n", encoding="utf-8")
    from experiments.audit_runtime_historical_alignment import campaign_identity

    identity = campaign_identity(campaign)
    evidence = workspace / "evidence"
    write_json(evidence / "canary_summary.json", {})
    import hashlib

    digest = hashlib.sha256((evidence / "canary_summary.json").read_bytes()).hexdigest()
    runtime_csv = workspace / "runtime.csv"
    runtime_csv.write_text(
        "id,target,sink,callsite,token,attempt_class,observed_command,evidence_dir,summary_sha256\n"
        f"row,Demo,,,,boundary_no_sink_hit,,evidence,{digest}\n",
        encoding="utf-8",
    )
    runtime_summary = workspace / "runtime_summary.json"
    write_json(
        runtime_summary,
        {"runtime_attempts": 1, "campaign_identity": identity},
    )
    result = audit(
        workspace_root=workspace,
        runtime_csv=runtime_csv,
        runtime_summary_path=runtime_summary,
        campaign_dir=campaign,
        campaign_config_path=config_path,
    )
    assert result["summary"]["valid"] is True
    assert result["summary"]["campaign_identity_match"] is True
