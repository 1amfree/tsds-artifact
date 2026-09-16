#!/usr/bin/env python3
"""Independently verify a TSDS v18/v7 evidence-extension directory.

The extension builder records stage-local success and file identities.  This
module deliberately does not import the builder.  It re-parses the manifest
with duplicate-key rejection, recomputes the complete artifact closure, binds
the extension to the accepted pipeline manifest, and cross-checks the reports
that support the P0--P2 claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any


VERIFICATION_SCHEMA = "tsds-v18-evidence-extension-verification-v1"
EXTENSION_SCHEMA = "tsds-v18-evidence-extension-v7"
EXPECTED_STAGES = (
    "01_source_snapshot_self_test",
    "02_evidence_certificates_v2",
    "03_independent_certificate_verifier",
    "04_residual_root_causes",
    "05_performance_diagnostics",
    "06_shell_matrix_profiles",
    "07_external_calibration_pack",
    "08_blinded_ground_truth_sample",
    "09_satc_fixture_conversion",
    "10_candidate_contract",
    "11_reproduction_sbom",
    "12_paper_tables",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REPORT_PATHS = {
    "source_self_test": "source_snapshot_self_test/source_snapshot_self_test.json",
    "certificate_audit": "evidence_certificates_v2/evidence_certificate_audit.json",
    "independent_verifier": (
        "independent_certificate_verifier/independent_certificate_verification.json"
    ),
    "residual_taxonomy": "residual_root_causes/residual_root_cause_summary.json",
    "performance": "performance_diagnostics/performance_diagnostics.json",
    "matrix_profiles": "shell_matrix_profiles/shell_dialect_profile_audit.json",
    "calibration": "external_calibration_pack/calibration_pack_summary.json",
    "ground_truth_sample": "blinded_ground_truth_sample/sample_summary.json",
    "candidate_contract": "candidate_contract/candidate_contract_audit.json",
    "environment_lock": "reproduction_sbom/environment_lock.json",
    "cyclonedx": "reproduction_sbom/tsds.cyclonedx.json",
    "paper_tables": "paper_tables/paper_data_summary.json",
}


class DuplicateKeyError(ValueError):
    """Raised when a JSON object contains an ambiguous duplicate key."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json_strict(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise DuplicateKeyError(f"duplicate JSON key {key!r}: {path}")
            value[key] = item
        return value

    value = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates
    )
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def canonical_relative_path(value: Any) -> PurePosixPath | None:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return None
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or ".." in path.parts
        or any(part in {"", "."} for part in path.parts)
        or path.as_posix() != value
    ):
        return None
    return path


def path_has_symlink(root: Path, relative: PurePosixPath) -> bool:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def integer(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def issue(issues: list[str], condition: bool, name: str) -> None:
    if not condition:
        issues.append(name)


def verify_identity_rows(
    root: Path,
    rows: Any,
    issues: list[str],
    *,
    prefix: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
    identities: dict[str, dict[str, Any]] = {}
    checked = 0
    mismatches = 0
    invalid = 0
    if not isinstance(rows, list):
        issues.append(f"{prefix}_rows_not_list")
        rows = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            issues.append(f"{prefix}_row_not_object:{index}")
            invalid += 1
            continue
        relative = canonical_relative_path(row.get("path"))
        if relative is None:
            issues.append(f"{prefix}_unsafe_path:{row.get('path')}")
            invalid += 1
            continue
        name = relative.as_posix()
        if name in identities:
            issues.append(f"{prefix}_duplicate_path:{name}")
            invalid += 1
            continue
        if path_has_symlink(root, relative):
            issues.append(f"{prefix}_symlink_path:{name}")
            invalid += 1
            continue
        path = root.joinpath(*relative.parts)
        if not path.is_file():
            issues.append(f"{prefix}_missing_file:{name}")
            invalid += 1
            continue
        declared_size = integer(row.get("size"))
        declared_digest = row.get("sha256")
        if declared_size is None or declared_size < 0:
            issues.append(f"{prefix}_invalid_size:{name}")
            invalid += 1
            continue
        if not isinstance(declared_digest, str) or not SHA256_RE.fullmatch(
            declared_digest
        ):
            issues.append(f"{prefix}_invalid_sha256:{name}")
            invalid += 1
            continue
        observed_size = path.stat().st_size
        observed_digest = sha256_file(path)
        checked += 1
        if observed_size != declared_size:
            issues.append(f"{prefix}_size_mismatch:{name}")
            mismatches += 1
        if observed_digest != declared_digest:
            issues.append(f"{prefix}_sha256_mismatch:{name}")
            mismatches += 1
        identities[name] = {"size": observed_size, "sha256": observed_digest}
    return identities, {
        "declared": len(rows),
        "checked": checked,
        "invalid": invalid,
        "mismatches": mismatches,
    }


def read_report(
    root: Path,
    relative: str,
    identities: dict[str, dict[str, Any]],
    issues: list[str],
) -> dict[str, Any]:
    if relative not in identities:
        issues.append(f"report_not_artifact_bound:{relative}")
    path = root / Path(relative)
    try:
        return load_json_strict(path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        issues.append(f"report_unreadable:{relative}:{type(exc).__name__}")
        return {}


def verify_reports(
    root: Path,
    manifest: dict[str, Any],
    identities: dict[str, dict[str, Any]],
    issues: list[str],
) -> dict[str, Any]:
    reports = {
        name: read_report(root, path, identities, issues)
        for name, path in REPORT_PATHS.items()
    }
    input_facts = manifest.get("input") if isinstance(manifest.get("input"), dict) else {}
    records = integer(input_facts.get("records"))
    residuals = integer(input_facts.get("residuals"))
    pipeline_digest = input_facts.get("pipeline_manifest_sha256")

    source_test = reports["source_self_test"]
    counts = source_test.get("counts") if isinstance(source_test.get("counts"), dict) else {}
    issue(issues, source_test.get("schema") == "tsds-source-snapshot-self-test-v1", "source_self_test_schema")
    issue(issues, source_test.get("valid") is True, "source_self_test_invalid")
    issue(issues, source_test.get("returncode") == 0, "source_self_test_returncode")
    issue(issues, source_test.get("timed_out") is False, "source_self_test_timed_out")
    issue(issues, source_test.get("source_identity_stable") is True, "source_identity_drift")
    issue(issues, counts.get("failures") == 0 and counts.get("errors") == 0, "source_test_failures")

    certificates = reports["certificate_audit"]
    issue(issues, certificates.get("schema") == "tsds-evidence-certificate-audit-v2", "certificate_audit_schema")
    issue(issues, records is not None and certificates.get("records") == records, "certificate_record_count")
    issue(issues, certificates.get("valid_certificates") == records, "certificate_valid_count")
    issue(issues, certificates.get("records_with_issues") == 0, "certificate_issues")
    issue(issues, not certificates.get("issue_counts"), "certificate_issue_counts")

    verifier = reports["independent_verifier"]
    issue(issues, verifier.get("schema") == "tsds-independent-certificate-verifier-v1", "independent_verifier_schema")
    issue(issues, verifier.get("valid") is True, "independent_verifier_invalid")
    issue(issues, records is not None and verifier.get("records") == records, "independent_verifier_records")
    issue(issues, verifier.get("valid_records") == records, "independent_verifier_valid_records")
    issue(issues, verifier.get("source_records") == records, "independent_verifier_source_records")
    issue(issues, verifier.get("records_with_issues") == 0, "independent_verifier_issues")
    preflight = verifier.get("parser_preflight")
    issue(
        issues,
        isinstance(preflight, list)
        and len(preflight) >= 2
        and all(row.get("returncode") == 0 and row.get("no_execution") is True for row in preflight if isinstance(row, dict))
        and all(isinstance(row, dict) for row in preflight),
        "parser_preflight_invalid",
    )

    residual = reports["residual_taxonomy"]
    binding = residual.get("pipeline_binding") if isinstance(residual.get("pipeline_binding"), dict) else {}
    issue(issues, residual.get("schema") == "tsds-residual-root-cause-audit-v1", "residual_schema")
    issue(issues, residual.get("valid") is True and residual.get("classification_complete") is True, "residual_incomplete")
    issue(issues, residuals is not None and residual.get("records") == residuals, "residual_record_count")
    issue(issues, residual.get("classified_records") == residuals, "residual_classified_count")
    issue(issues, not residual.get("issues"), "residual_issues")
    issue(issues, binding.get("verified") is True and not binding.get("issues"), "residual_pipeline_binding")
    issue(issues, binding.get("manifest_sha256") == pipeline_digest, "residual_pipeline_digest")

    performance = reports["performance"]
    issue(issues, performance.get("schema") == "tsds-performance-diagnostics-v1", "performance_schema")
    issue(issues, performance.get("valid") is True and not performance.get("issues"), "performance_invalid")
    issue(issues, records is not None and performance.get("records") == records, "performance_record_count")

    matrix = reports["matrix_profiles"]
    issue(issues, matrix.get("schema") == "tsds-shell-dialect-profile-v1", "matrix_profile_schema")
    issue(issues, not matrix.get("issue_counts"), "matrix_profile_issues")
    issue(issues, isinstance(matrix.get("matrix_spec_sha256"), str) and SHA256_RE.fullmatch(matrix["matrix_spec_sha256"]) is not None, "matrix_spec_digest")

    calibration = reports["calibration"]
    calibration_binding = calibration.get("pipeline_binding") if isinstance(calibration.get("pipeline_binding"), dict) else {}
    issue(issues, calibration.get("schema") == "tsds-exploitability-calibration-pack-v1", "calibration_schema")
    issue(issues, records is not None and calibration.get("campaign_records") == records, "calibration_population")
    issue(issues, integer(calibration.get("selected_records")) is not None and calibration.get("selected_records", 0) > 0, "calibration_empty")
    issue(issues, calibration_binding.get("verified") is True and not calibration_binding.get("issues"), "calibration_pipeline_binding")
    issue(issues, calibration.get("pipeline_manifest_sha256") == pipeline_digest, "calibration_pipeline_digest")

    sample = reports["ground_truth_sample"]
    issue(issues, sample.get("schema") == "tsds-blinded-ground-truth-sample-v4", "ground_truth_schema")
    issue(issues, records is not None and sample.get("campaign_records") == records, "ground_truth_population")
    issue(issues, integer(sample.get("sample_records")) is not None and sample.get("sample_records", 0) > 0, "ground_truth_empty")
    issue(issues, sample.get("pipeline_manifest_sha256") == pipeline_digest, "ground_truth_pipeline_digest")

    contract = reports["candidate_contract"]
    issue(issues, contract.get("schema") == "tsds-candidate-contract-v1", "candidate_contract_schema")
    issue(issues, contract.get("valid") is True and not contract.get("issues"), "candidate_contract_invalid")
    issue(issues, integer(contract.get("records")) is not None and contract.get("records", 0) > 0, "candidate_contract_empty")

    environment = reports["environment_lock"]
    issue(issues, environment.get("schema") == "tsds-reproduction-environment-lock-v1", "environment_lock_schema")
    issue(issues, integer(environment.get("source_files")) is not None and environment.get("source_files", 0) > 0, "environment_source_inventory_empty")
    issue(issues, isinstance(environment.get("python_packages"), list) and len(environment.get("python_packages")) > 0, "environment_packages_empty")
    issue(issues, isinstance(environment.get("source_aggregate_sha256"), str) and SHA256_RE.fullmatch(environment["source_aggregate_sha256"]) is not None, "environment_source_digest")

    cyclonedx = reports["cyclonedx"]
    issue(issues, cyclonedx.get("bomFormat") == "CycloneDX", "cyclonedx_format")
    issue(issues, str(cyclonedx.get("specVersion")) == "1.5", "cyclonedx_version")

    paper = reports["paper_tables"]
    issue(issues, paper.get("schema") == "tsds-paper-table-export-v2", "paper_table_schema")
    issue(issues, paper.get("all_contract_valid") is True, "paper_contract_invalid")
    issue(issues, records is not None and paper.get("records") == records, "paper_record_count")
    verdicts = paper.get("verdicts") if isinstance(paper.get("verdicts"), dict) else {}
    issue(issues, records is not None and sum(value for value in verdicts.values() if isinstance(value, int) and not isinstance(value, bool)) == records, "paper_verdict_conservation")

    return {
        "reports_checked": len(reports),
        "records": records,
        "residuals": residuals,
        "certificate_records": certificates.get("records"),
        "independent_verifier_valid_records": verifier.get("valid_records"),
        "calibration_records": calibration.get("selected_records"),
        "ground_truth_sample_records": sample.get("sample_records"),
        "candidate_records": contract.get("records"),
    }


def verify_extension(
    extension_root: Path,
    *,
    accepted_run: Path | None = None,
) -> dict[str, Any]:
    root = extension_root.resolve()
    issues: list[str] = []
    manifest_path = root / "extension_manifest.json"
    try:
        manifest = load_json_strict(manifest_path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "schema": VERIFICATION_SCHEMA,
            "valid": False,
            "extension_root": str(root),
            "issues": [f"manifest_unreadable:{type(exc).__name__}"],
        }

    issue(issues, manifest.get("schema") == EXTENSION_SCHEMA, "extension_schema")
    issue(issues, manifest.get("success") is True, "extension_not_successful")
    stages = manifest.get("stages")
    if not isinstance(stages, list):
        stages = []
        issues.append("stages_not_list")
    names = [stage.get("name") for stage in stages if isinstance(stage, dict)]
    issue(issues, tuple(names) == EXPECTED_STAGES, "stage_order_or_membership")
    issue(issues, len(stages) == len(EXPECTED_STAGES), "stage_count")
    for index, stage in enumerate(stages):
        if not isinstance(stage, dict):
            issues.append(f"stage_not_object:{index}")
            continue
        issue(issues, integer(stage.get("returncode")) == 0, f"stage_failed:{stage.get('name')}")

    identities, artifact_summary = verify_identity_rows(
        root, manifest.get("artifacts"), issues, prefix="artifact"
    )
    observed_files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path != manifest_path
    }
    declared_files = set(identities)
    for name in sorted(observed_files - declared_files):
        issues.append(f"undeclared_artifact:{name}")
    for name in sorted(declared_files - observed_files):
        issues.append(f"declared_artifact_not_observed:{name}")
    for stage in stages:
        if isinstance(stage, dict):
            issue(issues, stage.get("log") in identities, f"stage_log_not_bound:{stage.get('name')}")

    snapshot_root = root / "source_snapshot"
    snapshot_identities, snapshot_summary = verify_identity_rows(
        snapshot_root, manifest.get("source_snapshot"), issues, prefix="source_snapshot"
    )
    issue(issues, manifest.get("source_snapshot_files") == len(snapshot_identities), "source_snapshot_count")
    observed_snapshot = {
        path.relative_to(snapshot_root).as_posix()
        for path in snapshot_root.rglob("*")
        if path.is_file()
    } if snapshot_root.is_dir() else set()
    issue(issues, observed_snapshot == set(snapshot_identities), "source_snapshot_closure")

    input_facts = manifest.get("input") if isinstance(manifest.get("input"), dict) else {}
    accepted_path = accepted_run.resolve() if accepted_run is not None else Path(str(input_facts.get("accepted_run", ""))).resolve()
    pipeline_path = accepted_path / "pipeline_manifest.json"
    try:
        pipeline = load_json_strict(pipeline_path)
        observed_pipeline_digest = sha256_file(pipeline_path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        pipeline = {}
        observed_pipeline_digest = None
        issues.append(f"input_pipeline_unreadable:{type(exc).__name__}")
    issue(issues, pipeline.get("success") is True, "input_pipeline_not_successful")
    issue(issues, pipeline.get("schema") == input_facts.get("pipeline_schema"), "input_pipeline_schema")
    issue(issues, observed_pipeline_digest == input_facts.get("pipeline_manifest_sha256"), "input_pipeline_digest")

    report_summary = verify_reports(root, manifest, identities, issues)
    unique_issues = sorted(set(issues))
    return {
        "schema": VERIFICATION_SCHEMA,
        "valid": not unique_issues,
        "extension_root": str(root),
        "extension_manifest": str(manifest_path),
        "extension_manifest_sha256": sha256_file(manifest_path),
        "input_pipeline_manifest": str(pipeline_path),
        "input_pipeline_manifest_sha256": observed_pipeline_digest,
        "stages": {"expected": len(EXPECTED_STAGES), "observed": len(stages)},
        "artifacts": {
            **artifact_summary,
            "observed": len(observed_files),
            "closure_complete": observed_files == declared_files,
        },
        "source_snapshot": {
            **snapshot_summary,
            "observed": len(observed_snapshot),
            "closure_complete": observed_snapshot == set(snapshot_identities),
        },
        "reports": report_summary,
        "issues": unique_issues,
        "claim_boundary": (
            "This verification checks release identities and evidence-report "
            "invariants; it does not establish analyzer completeness or device-level effects."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--extension-root", type=Path, required=True)
    parser.add_argument("--accepted-run", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-valid", action="store_true")
    args = parser.parse_args()
    root = args.extension_root.resolve()
    output = args.output.resolve()
    if output == root or root in output.parents:
        print("verification output must be outside the immutable extension root", file=sys.stderr)
        return 3
    report = verify_extension(root, accepted_run=args.accepted_run)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2 if args.require_valid and not report.get("valid") else 0


if __name__ == "__main__":
    raise SystemExit(main())
