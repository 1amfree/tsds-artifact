#!/usr/bin/env python3
"""Run an independent release-readiness audit over one TSDS pipeline run.

The pipeline performs stage-local checks while it is running.  This audit is
intentionally post-hoc and read-only: it rechecks the accepted manifest,
recomputes declared artifact identities, and cross-checks the paper export
against conservation, contract, schema, resource, and repeatability reports.
It is a release gate for evidence packaging, not a validator of exploitability.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.build_deterministic_artifact_archive import CONTENTS_NAME  # noqa: E402
from experiments.verify_deterministic_artifact_archive import verify_archive  # noqa: E402


SCHEMA = "tsds-release-readiness-v2"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_VERDICTS = {
    "VECTOR_SAT",
    "MATRIX_UNSAT",
    "NO_MODELED_SOURCE",
    "STATIC_SOURCE_INFERENCE",
    "STATIC_WARNING_REDUCTION",
    "RESIDUAL",
}
BASE_REQUIRED_STAGE_ORDER = (
    "01_full_campaign",
    "02_campaign_conservation",
    "03_evidence_contract",
    "04_vector_decision_integrity",
    "05_shell_witness_syntax",
    "06_threat_matrix_boundary",
    "08_evidence_certificates",
    "09_resource_envelope",
    "10_ledger_schema",
    "11_shell_dialect_profiles",
    "12_counterfactual_repair_pack",
    "13_residual_refinement_plan",
    "14_busybox_calibration",
)
FINAL_REQUIRED_STAGE_ORDER = (
    "99_run_identity_drift_gate",
    "16_paper_tables",
)
REPORT_PATHS = {
    "campaign_conservation": "campaign_conservation/campaign_conservation_audit.json",
    "evidence_contract": "evidence_contract/evidence_contract_audit.json",
    "ledger_schema": "ledger_schema/ledger_schema_audit.json",
    "vector_decision_integrity": "vector_decision_integrity/vector_decision_integrity_audit.json",
    "shell_witness_syntax": "shell_witness_syntax/shell_witness_syntax_summary.json",
    "evidence_certificates": "evidence_certificates/evidence_certificate_audit.json",
    "resource_envelope": "resource_envelope/resource_envelope_audit.json",
    "busybox_calibration": "busybox_calibration/busybox_calibration_summary.json",
    "threat_matrix_boundary": "threat_matrix_boundary/threat_matrix_executable_summary.json",
    "shell_dialect_profiles": "shell_dialect_profiles/shell_dialect_profile_audit.json",
    "paper_tables": "paper_tables/paper_data_summary.json",
    "source_snapshot_self_test": "source_snapshot_self_test/source_snapshot_self_test.json",
}
REPORT_SCHEMAS = {
    "campaign_conservation": "tsds-campaign-conservation-audit-v1",
    "evidence_contract": "tsds-evidence-contract-audit-v1",
    "ledger_schema": "tsds-ledger-schema-v1",
    "vector_decision_integrity": "tsds-vector-decision-integrity-audit-v1",
    "shell_witness_syntax": "tsds-shell-witness-syntax-audit-v1",
    "evidence_certificates": "tsds-evidence-certificate-audit-v1",
    "resource_envelope": "tsds-resource-envelope-v1",
    "busybox_calibration": "tsds-busybox-shell-vector-calibration-v2",
    "threat_matrix_boundary": "tsds-threat-matrix-boundary-v1",
    "shell_dialect_profiles": "tsds-shell-dialect-profile-v1",
    "paper_tables": "tsds-paper-table-export-v2",
    "source_snapshot_self_test": "tsds-source-snapshot-self-test-v1",
}


def report_schema_for_pipeline(name: str, pipeline_schema: str) -> str:
    """Return the report schema emitted by the declared pipeline generation."""

    if name == "evidence_certificates" and pipeline_schema == "tsds-v18-pipeline-v7":
        return "tsds-evidence-certificate-audit-v2"
    return REPORT_SCHEMAS[name]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """拒绝会在不同 JSON 解析器中产生歧义的重复对象键。"""

        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key {key!r}: {path}")
            value[key] = item
        return value

    value = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
    )
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def issue(issues: list[str], condition: bool, name: str) -> None:
    if not condition:
        issues.append(name)


def canonical_relative_path(value: Any) -> PurePosixPath | None:
    """将 manifest 路径约束为无歧义的相对 POSIX 路径。"""

    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        return None
    if any(part in {"", "."} for part in path.parts):
        return None
    return path


def path_has_symlink(root: Path, relative: PurePosixPath) -> bool:
    """检查从发布根目录到目标文件的任一路径分量是否为符号链接。"""

    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def stage_succeeded(stage: dict[str, Any]) -> bool:
    if "returncode" not in stage or isinstance(stage.get("returncode"), bool):
        return False
    try:
        return int(stage.get("returncode")) == 0
    except (TypeError, ValueError):
        return False


def read_stage(manifest: dict[str, Any], name: str) -> dict[str, Any] | None:
    for stage in manifest.get("stages") or []:
        if stage.get("name") == name:
            return stage
    return None


def verify_artifacts(
    manifest: dict[str, Any], artifact_root: Path, issues: list[str]
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """重新计算声明产物的身份，并返回可用于交叉绑定的路径索引。"""

    raw_entries = manifest.get("artifacts")
    if not isinstance(raw_entries, list):
        issues.append("artifact_entries_not_list")
        raw_entries = []
    entries = raw_entries
    if not entries:
        issues.append("no_declared_artifacts")
    paths: set[str] = set()
    identities: dict[str, dict[str, Any]] = {}
    checked = 0
    mismatches = 0
    invalid_entries = 0
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            invalid_entries += 1
            issues.append(f"artifact_entry_not_object:{index}")
            continue
        raw_relative = entry.get("path")
        relative_path = canonical_relative_path(raw_relative)
        if relative_path is None:
            invalid_entries += 1
            issues.append(f"unsafe_artifact_path:{raw_relative}")
            continue
        relative = relative_path.as_posix()
        if relative in paths:
            invalid_entries += 1
            issues.append("duplicate_or_empty_artifact_path")
            continue
        paths.add(relative)
        path = artifact_root.joinpath(*relative_path.parts)
        if path_has_symlink(artifact_root, relative_path):
            invalid_entries += 1
            issues.append(f"symlink_artifact_path:{relative}")
            continue
        path = path.resolve()
        if artifact_root != path and artifact_root not in path.parents:
            invalid_entries += 1
            issues.append(f"artifact_path_escapes_root:{relative}")
            continue
        if not path.is_file():
            invalid_entries += 1
            issues.append(f"missing_artifact:{relative}")
            continue
        declared_size = entry.get("size")
        declared_sha256 = entry.get("sha256")
        if (
            isinstance(declared_size, bool)
            or not isinstance(declared_size, int)
            or declared_size < 0
        ):
            invalid_entries += 1
            issues.append(f"invalid_artifact_size:{relative}")
            continue
        if not isinstance(declared_sha256, str) or SHA256_RE.fullmatch(declared_sha256) is None:
            invalid_entries += 1
            issues.append(f"invalid_artifact_sha256:{relative}")
            continue
        checked += 1
        observed_size = path.stat().st_size
        observed_sha256 = sha256_file(path)
        if observed_size != declared_size:
            mismatches += 1
            issues.append(f"artifact_size_mismatch:{relative}")
        if observed_sha256 != declared_sha256:
            mismatches += 1
            issues.append(f"artifact_sha256_mismatch:{relative}")
        identities[relative] = {
            "size": observed_size,
            "sha256": observed_sha256,
        }
    summary = {
        "declared": len(entries),
        "checked": checked,
        "mismatches": mismatches,
        "invalid_entries": invalid_entries,
        "unique_paths": len(paths),
        "valid": bool(entries) and checked == len(entries) and not mismatches and not invalid_entries,
    }
    return summary, identities


def validate_stage_contract(
    manifest: dict[str, Any],
    issues: list[str],
    *,
    require_repeatability: bool,
    require_negative_confirmation: bool,
    require_source_snapshot_self_test: bool,
) -> tuple[list[str], list[str]]:
    """验证 v17 发布流水线的必需 stage、唯一性和证据生成顺序。"""

    raw_stages = manifest.get("stages")
    if not isinstance(raw_stages, list) or not raw_stages:
        issues.append("no_pipeline_stages")
        return [], []
    names: list[str] = []
    failed: list[str] = []
    for index, stage in enumerate(raw_stages):
        if not isinstance(stage, dict):
            failed.append(f"invalid_stage_{index}")
            continue
        name = str(stage.get("name") or f"unnamed_stage_{index}")
        names.append(name)
        if not stage_succeeded(stage):
            failed.append(name)
    if len(names) != len(set(names)):
        issues.append("duplicate_pipeline_stage")
    required = list(BASE_REQUIRED_STAGE_ORDER)
    if require_source_snapshot_self_test:
        required.insert(required.index("08_evidence_certificates"), "07_source_snapshot_self_test")
    if require_negative_confirmation:
        required.append("15_negative_confirmation")
    if require_repeatability:
        required.append("15b_repeatability_consensus")
    required.extend(FINAL_REQUIRED_STAGE_ORDER)
    missing = [name for name in required if name not in names]
    if missing:
        issues.append("missing_required_stage:" + ",".join(missing))
    observed_required = [name for name in names if name in required]
    if not missing and observed_required != required:
        issues.append("required_stage_order_mismatch")
    if failed:
        issues.append("failed_stage:" + ",".join(failed))
    return failed, required


def verify_archive_binding(
    archive_path: Path,
    archive_manifest_path: Path,
    pipeline_manifest_path: Path,
    artifact_identities: dict[str, dict[str, Any]],
    *,
    archive_prefix: str,
    issues: list[str],
) -> dict[str, Any]:
    """验证归档内部身份，并将其逐文件绑定到当前 pipeline manifest。"""

    prefix = canonical_relative_path(archive_prefix)
    result: dict[str, Any] = {
        "required": True,
        "archive": str(archive_path.resolve()),
        "manifest": str(archive_manifest_path.resolve()),
        "prefix": archive_prefix,
        "verified": False,
        "bound": False,
        "checked_pipeline_artifacts": 0,
    }
    if prefix is None:
        issues.append("invalid_archive_prefix")
        return result
    try:
        verification = verify_archive(archive_path.resolve(), archive_manifest_path.resolve())
        result["verification"] = verification
        if not verification.get("verified"):
            issues.append("artifact_archive_verification_failed")
            return result
        result["verified"] = True
        with tarfile.open(archive_path.resolve(), "r:gz") as archive:
            embedded = archive.extractfile(CONTENTS_NAME)
            contents = json.loads(embedded.read() if embedded else b"")
        rows = contents.get("files") or []
        archived = {
            str(row.get("path")): row
            for row in rows
            if isinstance(row, dict) and isinstance(row.get("path"), str)
        }
        pipeline_manifest_member = (prefix / "pipeline_manifest.json").as_posix()
        manifest_row = archived.get(pipeline_manifest_member)
        manifest_bound = False
        if not isinstance(manifest_row, dict):
            issues.append("archive_missing_pipeline_manifest")
        else:
            manifest_bound = (
                manifest_row.get("size") == pipeline_manifest_path.stat().st_size
                and manifest_row.get("sha256") == sha256_file(pipeline_manifest_path)
            )
            issue(
                issues,
                manifest_bound,
                "archive_pipeline_manifest_identity_mismatch",
            )
        binding_mismatches = 0
        for relative, identity in sorted(artifact_identities.items()):
            member_name = (prefix / PurePosixPath(relative)).as_posix()
            row = archived.get(member_name)
            if not isinstance(row, dict) or row.get("size") != identity["size"] or row.get("sha256") != identity["sha256"]:
                binding_mismatches += 1
        result["checked_pipeline_artifacts"] = len(artifact_identities)
        result["binding_mismatches"] = binding_mismatches
        if binding_mismatches:
            issues.append(f"archive_pipeline_artifact_mismatch:{binding_mismatches}")
        result["bound"] = manifest_bound and binding_mismatches == 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, tarfile.TarError) as exc:
        result["error"] = f"{type(exc).__name__}:{exc}"
        issues.append("artifact_archive_binding_unreadable")
    return result


def audit_release(
    manifest_path: Path,
    *,
    artifact_root: Path | None = None,
    expected_schema: str = "tsds-v17-pipeline-v6",
    require_repeatability: bool = False,
    require_negative_confirmation: bool = False,
    minimum_negative_records: int = 1,
    verification_path: Path | None = None,
    archive_path: Path | None = None,
    archive_manifest_path: Path | None = None,
    archive_prefix: str = "pipeline",
) -> dict[str, Any]:
    """对一个不可变 pipeline 目录执行独立、只读、失败关闭的发布审计。"""

    manifest_path = manifest_path.resolve()
    manifest = load_json(manifest_path)
    root = (artifact_root or manifest_path.parent).resolve()
    issues: list[str] = []
    invocation = {str(value) for value in (manifest.get("invocation") or [])}
    # manifest 自带的执行意图优先，避免独立审计时漏传严格门禁参数。
    require_repeatability = require_repeatability or "--repeatability-baseline" in invocation
    require_negative_confirmation = (
        require_negative_confirmation or "--run-negative-confirmation" in invocation
    )
    if minimum_negative_records < 0:
        raise ValueError("minimum_negative_records must be non-negative")

    issue(issues, manifest.get("schema") == expected_schema, "pipeline_schema_mismatch")
    issue(issues, manifest.get("success") is True, "pipeline_not_accepted")
    drift = manifest.get("identity_drift") or {}
    issue(issues, drift.get("stable") is True, "run_identity_not_stable")
    lock = manifest.get("exclusive_run_lock") or {}
    issue(issues, lock.get("schema") == "tsds-exclusive-run-lock-v1", "run_lock_missing")
    issue(
        issues,
        str(lock.get("mode") or "").endswith("exclusive_nonblocking"),
        "run_lock_not_exclusive",
    )
    reproducibility = manifest.get("reproducibility") or {}
    issue(
        issues,
        reproducibility.get("schema") == "tsds-reproducibility-v2",
        "reproducibility_schema_mismatch",
    )
    issue(issues, not reproducibility.get("missing_sources"), "missing_declared_sources")
    issue(issues, not reproducibility.get("missing_inputs"), "missing_declared_inputs")
    failed_stages, required_stages = validate_stage_contract(
        manifest,
        issues,
        require_repeatability=require_repeatability,
        require_negative_confirmation=require_negative_confirmation,
        require_source_snapshot_self_test=expected_schema == "tsds-v17-pipeline-v6",
    )

    checks: dict[str, Any] = {}
    required_reports = {
        "campaign_conservation": (
            "campaign_conservation_audit.json",
            lambda data: data.get("valid") is True,
        ),
        "evidence_contract": (
            "evidence_contract_audit.json",
            lambda data: int(data.get("records_with_contract_issues") or 0) == 0,
        ),
        "ledger_schema": (
            "ledger_schema_audit.json",
            lambda data: int(data.get("records_with_issues") or 0) == 0,
        ),
        "vector_decision_integrity": (
            "vector_decision_integrity_audit.json",
            lambda data: (
                data.get("records_with_integrity_issues") == 0
                and not data.get("integrity_issue_counts")
            ),
        ),
        "shell_witness_syntax": (
            "shell_witness_syntax_summary.json",
            lambda data: int((data.get("record_outcomes") or {}).get("records_all_witnesses_invalid") or 0) == 0,
        ),
        "evidence_certificates": (
            "evidence_certificate_audit.json",
            lambda data: int(data.get("records_with_issues") or 0) == 0,
        ),
        "resource_envelope": (
            "resource_envelope_audit.json",
            lambda data: (
                isinstance(data.get("issues"), list)
                and not data.get("issues")
                and int(data.get("records") or 0) > 0
                and int(data.get("records_missing_required_rss") or 0) == 0
                and int(data.get("records_with_unavailable_worker_metrics") or 0) == 0
                and int(data.get("resource_limit_hits") or 0) == 0
            ),
        ),
        "busybox_calibration": (
            "busybox_calibration_summary.json",
            lambda data: (
                data.get("calibration_pass") is True
                and int(data.get("v2_witness_parse_ok") or 0)
                == int(data.get("v2_witness_cases") or -1)
                and int(data.get("complete_effect_observed") or 0)
                == int(data.get("complete_effect_cases") or -1)
            ),
        ),
        "threat_matrix_boundary": (
            "threat_matrix_executable_summary.json",
            lambda data: (
                int(data.get("total_cases") or 0) > 0
                and int(data.get("passed_cases") or 0)
                == int(data.get("total_cases") or -1)
            ),
        ),
        "shell_dialect_profiles": (
            "shell_dialect_profile_audit.json",
            lambda data: not data.get("issue_counts"),
        ),
        "paper_tables": (
            "paper_data_summary.json",
            lambda data: data.get("all_contract_valid") is True,
        ),
    }
    if expected_schema == "tsds-v17-pipeline-v6":
        required_reports["source_snapshot_self_test"] = (
            "source_snapshot_self_test.json",
            lambda data: (
                data.get("valid") is True
                and data.get("source_identity_stable") is True
                and int((data.get("counts") or {}).get("tests") or 0) > 0
                and int((data.get("counts") or {}).get("failures") or 0) == 0
                and int((data.get("counts") or {}).get("errors") or 0) == 0
                and int(data.get("returncode") or 0) == 0
            ),
        )
    loaded_reports: dict[str, dict[str, Any]] = {}
    for name, (_filename, predicate) in required_reports.items():
        relative = REPORT_PATHS[name]
        path = root.joinpath(*PurePosixPath(relative).parts)
        row: dict[str, Any] = {"path": str(path), "present": path.is_file()}
        if not path.is_file():
            issues.append(f"missing_report:{name}")
        else:
            try:
                data = load_json(path)
                loaded_reports[name] = data
                row["schema"] = data.get("schema")
                expected_report_schema = report_schema_for_pipeline(name, expected_schema)
                # v5 的 threat-matrix 报告尚未写入 schema；v6 起强制精确绑定。
                schema_valid = data.get("schema") == expected_report_schema
                if name == "threat_matrix_boundary" and expected_schema == "tsds-v17-pipeline-v5":
                    schema_valid = data.get("schema") in {None, expected_report_schema}
                if name == "paper_tables" and expected_schema == "tsds-v17-pipeline-v5":
                    schema_valid = data.get("schema") in {
                        "tsds-paper-table-export-v1",
                        expected_report_schema,
                    }
                row["expected_schema"] = expected_report_schema
                row["schema_valid"] = schema_valid
                row["valid"] = bool(schema_valid and predicate(data))
                if not row["valid"]:
                    issues.append(f"report_failed:{name}")
            except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
                row["error"] = f"{type(exc).__name__}:{exc}"
                issues.append(f"report_unreadable:{name}")
        checks[name] = row

    if "paper_tables" in loaded_reports and "campaign_conservation" in loaded_reports:
        # 交叉计数只使用已成功解析的对象，损坏报告必须形成 issue 而不是异常退出。
        try:
            paper = loaded_reports["paper_tables"]
            conservation = loaded_reports["campaign_conservation"]
            paper_records = int(paper.get("records") or 0)
            conserved_records = int(
                (conservation.get("total") or {}).get("selected_closures") or 0
            )
            issue(
                issues,
                paper_records == conserved_records,
                "paper_conservation_count_mismatch",
            )
            verdicts = paper.get("verdicts") or {}
            issue(
                issues,
                isinstance(verdicts, dict)
                and set(verdicts).issubset(EXPECTED_VERDICTS)
                and sum(int(value or 0) for value in verdicts.values()) == paper_records,
                "paper_verdict_count_mismatch",
            )
            for name in (
                "evidence_contract",
                "ledger_schema",
                "vector_decision_integrity",
                "evidence_certificates",
                "resource_envelope",
            ):
                if name in loaded_reports:
                    report_records = int(loaded_reports[name].get("records") or 0)
                    issue(
                        issues,
                        report_records == paper_records,
                        f"paper_{name}_record_count_mismatch",
                    )
        except (TypeError, ValueError):
            issues.append("cross_report_count_unreadable")

    repeatability: dict[str, Any] = {"required": require_repeatability, "present": False}
    repeatability_report: dict[str, Any] | None = None
    repeatability_path = root / "repeatability_consensus" / "repeatability_summary.json"
    if repeatability_path.is_file():
        repeatability["present"] = True
        try:
            data = load_json(repeatability_path)
            repeatability_report = data
            repeatability["schema"] = data.get("schema")
            core = data.get("sink_semantic_core") or {}
            repeatability["sink_semantic_core"] = {
                "baseline_records": core.get("baseline_records"),
                "stable_records": core.get("stable_records"),
                "semantic_drift": core.get("semantic_drift"),
                "baseline_only": core.get("baseline_only"),
                "baseline_reproduced": core.get("baseline_reproduced"),
            }
            if require_repeatability:
                issue(
                    issues,
                    data.get("schema") == "tsds-repeatability-audit-v4",
                    "repeatability_schema_mismatch",
                )
                baseline_records = int(core.get("baseline_records") or 0)
                stable_records = int(core.get("stable_records") or 0)
                paper_records = int(
                    (loaded_reports.get("paper_tables") or {}).get("records") or 0
                )
                issue(
                    issues,
                    int(data.get("baseline_records") or 0) == paper_records
                    and int(data.get("replay_records") or 0) == paper_records
                    and int(data.get("baseline_only") or 0) == 0
                    and int(data.get("replay_only") or 0) == 0,
                    "repeatability_record_set_mismatch",
                )
                issue(issues, baseline_records > 0, "sink_semantic_repeatability_empty")
                issue(issues, core.get("baseline_reproduced") is True, "sink_semantic_repeatability_failed")
                issue(issues, int(core.get("semantic_drift") or 0) == 0, "sink_semantic_drift")
                issue(issues, int(core.get("baseline_only") or 0) == 0, "sink_semantic_missing_records")
                issue(
                    issues,
                    stable_records == baseline_records,
                    "sink_semantic_stable_count_mismatch",
                )
                for side in ("baseline", "replay"):
                    identity = ((data.get("inputs") or {}).get(side) or {})
                    issue(
                        issues,
                        int(identity.get("result_files") or 0) > 0
                        and SHA256_RE.fullmatch(str(identity.get("results_identity_sha256") or "")) is not None,
                        f"repeatability_{side}_identity_invalid",
                    )
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            repeatability["error"] = f"{type(exc).__name__}:{exc}"
            issues.append("repeatability_report_unreadable")
    elif require_repeatability:
        issues.append("missing_repeatability_report")

    if (
        expected_schema == "tsds-v17-pipeline-v6"
        and require_repeatability
        and repeatability_report is not None
        and "paper_tables" in loaded_reports
    ):
        # paper-facing consensus 必须逐字段绑定到已审计的重复性报告。
        paper = loaded_reports["paper_tables"]
        expected_consensus = repeatability_report.get("conservative_consensus") or {}
        issue(
            issues,
            paper.get("repeatability_consensus") == expected_consensus,
            "paper_repeatability_consensus_mismatch",
        )
        issue(
            issues,
            paper.get("repeatability_audit_sha256") == sha256_file(repeatability_path),
            "paper_repeatability_identity_mismatch",
        )

    repeatability_gate_names = {
        "missing_repeatability_report",
        "repeatability_report_unreadable",
        "repeatability_schema_mismatch",
        "sink_semantic_repeatability_empty",
        "sink_semantic_repeatability_failed",
        "sink_semantic_drift",
        "sink_semantic_missing_records",
        "sink_semantic_stable_count_mismatch",
        "repeatability_baseline_identity_invalid",
        "repeatability_replay_identity_invalid",
        "repeatability_record_set_mismatch",
    }
    repeatability["valid"] = not require_repeatability or not any(
        name in issues for name in repeatability_gate_names
    )

    negative_confirmation: dict[str, Any] = {
        "required": require_negative_confirmation,
        "present": False,
        "minimum_records": minimum_negative_records,
    }
    negative_path = root / "negative_confirmation" / "negative_confirmation_summary.json"
    if negative_path.is_file():
        negative_confirmation["present"] = True
        try:
            data = load_json(negative_path)
            negative_confirmation["schema"] = data.get("schema")
            negative_confirmation["records"] = int(data.get("records") or 0)
            negative_confirmation["outcomes"] = data.get("outcomes") or {}
            if require_negative_confirmation:
                outcomes = data.get("outcomes") or {}
                issue(
                    issues,
                    data.get("schema") == "tsds-negative-confirmation-v1",
                    "negative_confirmation_schema_mismatch",
                )
                issue(
                    issues,
                    int(data.get("records") or 0) >= minimum_negative_records,
                    "negative_confirmation_insufficient_records",
                )
                issue(
                    issues,
                    sum(int(value or 0) for value in outcomes.values())
                    == int(data.get("records") or 0),
                    "negative_confirmation_outcome_count_mismatch",
                )
                issue(
                    issues,
                    not data.get("gate_issues")
                    and int(outcomes.get("replay_error") or 0) == 0
                    and int(outcomes.get("target_manifest_missing") or 0) == 0
                    and int(outcomes.get("changed_to_vector_sat") or 0) == 0,
                    "negative_confirmation_gate_failed",
                )
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            negative_confirmation["error"] = f"{type(exc).__name__}:{exc}"
            issues.append("negative_confirmation_report_unreadable")
    elif require_negative_confirmation:
        issues.append("missing_negative_confirmation_report")

    negative_confirmation["valid"] = not require_negative_confirmation or not any(
        name.startswith("negative_confirmation_") for name in issues
    )

    verification: dict[str, Any] = {"required": verification_path is not None, "present": False}
    if verification_path is not None:
        verification_path = verification_path.resolve()
        verification["present"] = verification_path.is_file()
        if not verification_path.is_file():
            issues.append("missing_artifact_verification")
        else:
            try:
                data = load_json(verification_path)
                verification["schema"] = data.get("schema")
                verification["verified"] = (
                    data.get("schema") == "tsds-deterministic-artifact-verification-v1"
                    and data.get("verified") is True
                    and not data.get("issues")
                )
                if not verification["verified"]:
                    issues.append("artifact_verification_failed")
            except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
                verification["error"] = f"{type(exc).__name__}:{exc}"
                issues.append("artifact_verification_unreadable")

    artifacts, artifact_identities = verify_artifacts(manifest, root, issues)
    critical_paths = {REPORT_PATHS[name] for name in required_reports} | {
        "campaign/full_campaign_aggregate.json",
        "reproducibility_drift.json",
        "source_snapshot/Taint_demo/sanitizer_demo/advanced_sanitizer_evaluator.py",
        "source_snapshot/experiments/audit_release_readiness.py",
    }
    if expected_schema == "tsds-v17-pipeline-v6":
        critical_paths.update(
            {
                "source_snapshot/pytest.ini",
                "source_snapshot/experiments/test_release_readiness.py",
                "source_snapshot/operation-mango-public/pyproject.toml",
            }
        )
    if require_repeatability:
        critical_paths.add("repeatability_consensus/repeatability_summary.json")
    if require_negative_confirmation:
        critical_paths.add("negative_confirmation/negative_confirmation_summary.json")
    missing_critical = sorted(critical_paths - set(artifact_identities))
    if missing_critical:
        issues.append("undeclared_critical_artifact:" + ",".join(missing_critical))
    issue(
        issues,
        any(
            name.startswith("campaign/") and name.endswith(".results.jsonl")
            for name in artifact_identities
        ),
        "no_declared_campaign_result_ledger",
    )

    archive_requested = archive_path is not None or archive_manifest_path is not None
    archive_binding: dict[str, Any] = {"required": archive_requested, "present": False}
    if archive_requested:
        if archive_path is None or archive_manifest_path is None:
            issues.append("incomplete_archive_binding_arguments")
        elif not archive_path.is_file() or not archive_manifest_path.is_file():
            issues.append("missing_archive_binding_input")
        else:
            archive_binding = verify_archive_binding(
                archive_path,
                archive_manifest_path,
                manifest_path,
                artifact_identities,
                archive_prefix=archive_prefix,
                issues=issues,
            )
            archive_binding["present"] = True
    summary = {
        "schema": SCHEMA,
        "pipeline_manifest": str(manifest_path),
        "artifact_root": str(root),
        "pipeline_schema": manifest.get("schema"),
        "pipeline_success": manifest.get("success") is True,
        "failed_stages": failed_stages,
        "required_stages": required_stages,
        "checks": checks,
        "repeatability": repeatability,
        "negative_confirmation": negative_confirmation,
        "artifact_verification": verification,
        "archive_binding": archive_binding,
        "artifacts": artifacts,
        "issues": sorted(set(issues)),
        "valid": not issues,
        "claim_boundary": (
            "Release readiness verifies cross-artifact identity and declared "
            "evidence gates. It does not establish device reachability, command "
            "execution, exploitability, or superiority over another tool."
        ),
    }
    return summary


def write_outputs(out_dir: Path, summary: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "release_readiness.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    rows = [
        {
            "check": "pipeline",
            "valid": summary["pipeline_success"] and not summary["failed_stages"],
            "detail": ",".join(summary["failed_stages"]),
        },
        {
            "check": "artifacts",
            "valid": summary["artifacts"]["valid"],
            "detail": summary["artifacts"]["checked"],
        },
    ]
    rows.extend(
        {
            "check": name,
            "valid": details.get("valid", details.get("present", False)),
            "detail": details.get("schema", details.get("path", "")),
        }
        for name, details in summary["checks"].items()
    )
    for name in ("repeatability", "negative_confirmation", "artifact_verification", "archive_binding"):
        details = summary[name]
        valid = details.get("valid") is True
        if name == "artifact_verification":
            valid = details.get("verified") is True
        if not details.get("required"):
            valid = True
        if name == "archive_binding" and details.get("required"):
            valid = details.get("bound") is True
        rows.append(
            {
                "check": name,
                "valid": valid,
                "detail": details.get("schema", details.get("archive", "")),
            }
        )
    with (out_dir / "release_readiness_checks.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=["check", "valid", "detail"], lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    latex = [
        r"\begin{tabular}{lr}",
        r"\toprule",
        r"Release gate & Result \\",
        r"\midrule",
        f"Pipeline and stages & {'PASS' if summary['pipeline_success'] and not summary['failed_stages'] else 'FAIL'} \\\\",
        f"Declared artifacts & {'PASS' if summary['artifacts']['valid'] else 'FAIL'} \\\\",
        f"Repeatability gate & {'PASS' if summary['repeatability'].get('valid') is True else 'FAIL'} \\\\",
        f"Negative confirmation & {'PASS' if summary['negative_confirmation'].get('valid') is True else 'FAIL'} \\\\",
        f"Archive binding & {'PASS' if (not summary['archive_binding']['required'] or summary['archive_binding'].get('bound') is True) else 'FAIL'} \\\\",
        f"All cross-artifact checks & {'PASS' if summary['valid'] else 'FAIL'} \\\\",
        r"\bottomrule",
        r"\end{tabular}",
        "",
    ]
    (out_dir / "release_readiness_table.tex").write_text("\n".join(latex), encoding="utf-8")
    (out_dir / "README.md").write_text(
        "# TSDS release-readiness audit\n\n"
        f"Valid: **{summary['valid']}**; declared artifacts: **{summary['artifacts']['declared']}**; "
        f"issues: **{len(summary['issues'])}**.\n\n"
        + summary["claim_boundary"]
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pipeline-manifest", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--expected-schema", default="tsds-v17-pipeline-v6")
    parser.add_argument("--require-repeatability", action="store_true")
    parser.add_argument("--require-negative-confirmation", action="store_true")
    parser.add_argument("--minimum-negative-records", type=int, default=1)
    parser.add_argument("--artifact-verification", type=Path)
    parser.add_argument("--artifact-archive", type=Path)
    parser.add_argument("--artifact-archive-manifest", type=Path)
    parser.add_argument("--archive-prefix", default="pipeline")
    parser.add_argument("--fail-on-issues", action="store_true")
    args = parser.parse_args()
    summary = audit_release(
        args.pipeline_manifest,
        artifact_root=args.artifact_root,
        expected_schema=args.expected_schema,
        require_repeatability=args.require_repeatability,
        require_negative_confirmation=args.require_negative_confirmation,
        minimum_negative_records=args.minimum_negative_records,
        verification_path=args.artifact_verification,
        archive_path=args.artifact_archive,
        archive_manifest_path=args.artifact_archive_manifest,
        archive_prefix=args.archive_prefix,
    )
    write_outputs(args.out_dir, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["valid"] or not args.fail_on_issues else 2


if __name__ == "__main__":
    raise SystemExit(main())
