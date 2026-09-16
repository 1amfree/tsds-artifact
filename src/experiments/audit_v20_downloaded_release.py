#!/usr/bin/env python3
"""Independently audit a downloaded TSDS v20 paper-evidence release."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.build_v20_manuscript_binding import build_binding, latex_counts
from experiments.build_deterministic_artifact_archive import CONTENTS_NAME
from experiments.fetch_v20_release import release_names
from experiments.verify_deterministic_artifact_archive import verify_archive


SCHEMA = "tsds-v20-downloaded-release-audit-v1"
EXPECTED_CLAIMS = {f"C{index}" for index in range(1, 10)}
EXPECTED_EVIDENCE = {
    "accepted_manifest",
    "paper_tables",
    "repeatability",
    "matrix",
    "confirmatory",
    "record_transitions",
    "confirmatory_transitions",
    "extension_verification",
    "runtime",
    "satc",
}
EXPECTED_CLAIM_EVIDENCE = {
    "C1": ("accepted_manifest", "paper_tables"),
    "C2": ("matrix", "record_transitions"),
    "C3": ("matrix", "record_transitions"),
    "C4": ("matrix", "record_transitions"),
    "C5": ("extension_verification",),
    "C6": ("repeatability",),
    "C7": ("runtime",),
    "C8": ("satc",),
    "C9": ("confirmatory", "confirmatory_transitions"),
}
EXPECTED_ARCHIVE_ONLY_PREFIXES = {"liveness_probe"}
FORBIDDEN_RELEASE_TOKENS = ("20260717_r4", "tsds_v20_full_20260717_r4")
TEXT_AUDIT_SUFFIXES = {
    "",
    ".csv",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".stderr",
    ".stdout",
    ".tex",
    ".txt",
}
CONTAMINATION_SCAN_EXCLUDED_PARTS = {
    "reproduction_sbom",
    "source_snapshot",
    "source_snapshot_self_test",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def strict_json(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key {key!r}: {path}")
            value[key] = item
        return value

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def add_check(
    checks: list[dict[str, Any]], issues: list[str], name: str, passed: bool, detail: Any
) -> None:
    checks.append({"check": name, "passed": bool(passed), "detail": str(detail)})
    if not passed:
        issues.append(name)


def locate_one(root: Path, filename: str) -> Path:
    values = sorted(root.rglob(filename))
    if len(values) != 1:
        raise ValueError(f"expected exactly one {filename} under {root}, found {len(values)}")
    return values[0]


def identity_matches(document: dict[str, Any], path: Path) -> bool:
    return bool(
        document.get("size") == path.stat().st_size
        and document.get("sha256") == sha256_file(path)
    )


def valid_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(callable(is_junction) and is_junction())


def safe_relative_path(value: Any) -> PurePosixPath | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        return None
    return path


def verify_download_manifest(
    root: Path,
    fetch: dict[str, Any],
    expected_names: set[str],
    tag: str,
) -> tuple[list[str], dict[tuple[str, str], dict[str, Any]], int]:
    violations: list[str] = []
    identities: dict[tuple[str, str], dict[str, Any]] = {}
    downloads = fetch.get("downloads")
    if not isinstance(downloads, dict):
        return ["downloads is not an object"], identities, 0

    observed_files = 0
    for name in sorted(expected_names):
        directory = root / name
        rows = downloads.get(name)
        if not isinstance(rows, list):
            violations.append(f"{name}: manifest rows are not a list")
            continue
        declared: set[str] = set()
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                violations.append(f"{name}[{index}]: row is not an object")
                continue
            relative = safe_relative_path(row.get("path"))
            if relative is None:
                violations.append(f"{name}[{index}]: unsafe relative path")
                continue
            key = relative.as_posix()
            if key in declared:
                violations.append(f"{name}: duplicate manifest path {key}")
                continue
            declared.add(key)
            candidate = directory.joinpath(*relative.parts)
            if not candidate.is_file() or is_link_like(candidate):
                violations.append(f"{name}/{key}: missing, non-regular, or linked file")
                continue
            size = row.get("size")
            sha256 = row.get("sha256")
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                violations.append(f"{name}/{key}: invalid manifest size")
                continue
            if not valid_sha256(sha256):
                violations.append(f"{name}/{key}: invalid manifest SHA-256")
                continue
            actual_size = candidate.stat().st_size
            actual_sha256 = sha256_file(candidate)
            if actual_size != size:
                violations.append(f"{name}/{key}: size mismatch")
            if actual_sha256 != sha256:
                violations.append(f"{name}/{key}: SHA-256 mismatch")
            identities[(name, key)] = {
                "path": candidate,
                "size": actual_size,
                "sha256": actual_sha256,
            }
            observed_files += 1

        actual: set[str] = set()
        if directory.is_dir() and not is_link_like(directory):
            for current_root, directory_names, filenames in os.walk(directory, followlinks=False):
                current = Path(current_root)
                for member in list(directory_names):
                    child = current / member
                    if is_link_like(child):
                        violations.append(f"{name}: linked directory {child.relative_to(directory).as_posix()}")
                        directory_names.remove(member)
                for member in filenames:
                    child = current / member
                    relative = child.relative_to(directory).as_posix()
                    if is_link_like(child) or not child.is_file():
                        violations.append(f"{name}: non-regular member {relative}")
                    else:
                        actual.add(relative)
        if actual != declared:
            missing = sorted(declared - actual)
            extra = sorted(actual - declared)
            violations.append(
                f"{name}: file-set mismatch missing={missing[:10]} extra={extra[:10]}"
            )

    declared_count = fetch.get("files")
    if isinstance(declared_count, bool) or not isinstance(declared_count, int):
        violations.append("fetch file count is not an integer")
    elif declared_count != observed_files:
        violations.append(
            f"fetch file count mismatch declared={declared_count} observed={observed_files}"
        )

    marker_name = f"tsds_v20_experiment_queue_{tag}.complete"
    marker = root / marker_name
    marker_identity = fetch.get("queue_marker")
    if not isinstance(marker_identity, dict):
        violations.append("queue marker identity is missing")
    elif (
        not marker.is_file()
        or is_link_like(marker)
        or marker_identity.get("path") != marker_name
        or not identity_matches(marker_identity, marker)
    ):
        violations.append("queue marker identity mismatch")

    return violations, identities, observed_files


def resolve_claim_evidence_path(
    root: Path,
    entry: Any,
    expected_names: set[str],
) -> tuple[Path | None, str | None, str | None]:
    if not isinstance(entry, dict):
        return None, None, "evidence identity is not an object"
    remote_value = entry.get("path")
    if not isinstance(remote_value, str) or not remote_value or "\\" in remote_value:
        return None, None, "evidence identity has no path"
    remote = PurePosixPath(remote_value)
    if (
        not remote.is_absolute()
        or remote.as_posix() != remote_value
        or any(part in {"", ".", ".."} for part in remote.parts)
    ):
        return None, None, "evidence path is not a canonical absolute POSIX path"
    matches = [index for index, part in enumerate(remote.parts) if part in expected_names]
    if len(matches) != 1:
        return None, None, "evidence path does not identify exactly one registered release directory"
    index = matches[0]
    name = remote.parts[index]
    relative_parts = remote.parts[index + 1 :]
    if not relative_parts or any(part in {"", ".", ".."} for part in relative_parts):
        return None, None, "evidence path has an unsafe release-relative component"
    relative = PurePosixPath(*relative_parts).as_posix()
    return root.joinpath(name, *relative_parts), f"{name}/{relative}", None


def verify_claim_evidence(
    root: Path,
    claim: dict[str, Any],
    expected_names: set[str],
    downloaded: dict[tuple[str, str], dict[str, Any]],
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    violations: list[str] = []
    verified: dict[str, dict[str, Any]] = {}
    evidence = claim.get("evidence")
    if not isinstance(evidence, dict):
        return ["claim matrix evidence map is missing"], verified
    if set(evidence) != EXPECTED_EVIDENCE:
        violations.append(
            f"claim evidence keys mismatch expected={sorted(EXPECTED_EVIDENCE)} observed={sorted(evidence)}"
        )
    for name in sorted(EXPECTED_EVIDENCE):
        entry = evidence.get(name)
        path, display, error = resolve_claim_evidence_path(root, entry, expected_names)
        if error or path is None or display is None:
            violations.append(f"{name}: {error}")
            continue
        if not path.is_file() or is_link_like(path):
            violations.append(f"{name}: evidence file is missing or linked: {display}")
            continue
        assert isinstance(entry, dict)
        size = entry.get("size")
        sha256 = entry.get("sha256")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            violations.append(f"{name}: invalid evidence size")
            continue
        if not valid_sha256(sha256):
            violations.append(f"{name}: invalid evidence SHA-256")
            continue
        actual = {"path": path, "size": path.stat().st_size, "sha256": sha256_file(path)}
        if actual["size"] != size or actual["sha256"] != sha256:
            violations.append(f"{name}: evidence identity mismatch")
            continue
        release_name, relative = display.split("/", 1)
        manifest_identity = downloaded.get((release_name, relative))
        if manifest_identity is None:
            violations.append(f"{name}: evidence is absent from the fetch manifest")
            continue
        if (
            manifest_identity["size"] != actual["size"]
            or manifest_identity["sha256"] != actual["sha256"]
        ):
            violations.append(f"{name}: evidence and fetch-manifest identities disagree")
            continue
        verified[name] = {
            "path": display,
            "size": actual["size"],
            "sha256": actual["sha256"],
        }
    return violations, verified


def scan_forbidden_tokens(paths: list[Path]) -> list[str]:
    contamination: list[str] = []
    tokens = tuple(token.encode("ascii") for token in FORBIDDEN_RELEASE_TOKENS)
    overlap = max(len(token) for token in tokens) - 1
    for path in paths:
        if (
            path.suffix.lower() not in TEXT_AUDIT_SUFFIXES
            or any(part in CONTAMINATION_SCAN_EXCLUDED_PARTS for part in path.parts)
        ):
            continue
        previous = b""
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                data = previous + block
                for text, token in zip(FORBIDDEN_RELEASE_TOKENS, tokens):
                    if token in data:
                        contamination.append(f"{path.name}:{text}")
                previous = data[-overlap:] if overlap else b""
    return sorted(set(contamination))


def archive_prefix_locations(
    root: Path, tag: str, suffix: str
) -> dict[str, Path]:
    post = root / f"tsds_v20_post_release_{tag}_{suffix}"
    return {
        "pipeline": root / f"tsds_v20_accepted_repeat_{tag}",
        "full_campaign": root / f"tsds_v20_full_{tag}",
        "full_audits": root / f"tsds_v20_full_audits_{tag}",
        "matrix": root / f"tsds_v20_matrix_{tag}",
        "matrix_analysis": root / f"tsds_v20_matrix_analysis_{tag}",
        "matrix_transitions": root / f"tsds_v20_matrix_transitions_{tag}",
        "confirm": root / f"tsds_v20_confirmatory_{tag}",
        "confirm_analysis": root / f"tsds_v20_confirmatory_analysis_{tag}",
        "confirm_transitions": root / f"tsds_v20_confirmatory_transitions_{tag}",
        "resource_calibration": root / f"tsds_v20_resource_calibration_{tag}",
        "runtime_repeatability": root / f"tsds_v20_runtime_repeatability_{tag}",
        "runtime_pack": root / f"tsds_v20_runtime_validation_expansion_{tag}",
        "shell_syntax": root / f"tsds_v20_shell_syntax_{tag}",
        "boundary_suite": root / f"tsds_v20_boundary_suite_{tag}",
        "extension": root / f"tsds_v20_evidence_extension_{tag}",
        "extension_verification": root
        / f"tsds_v20_evidence_extension_verification_{tag}",
        "blinded_roles": root / f"tsds_v20_blinded_role_packages_{tag}",
        "satc_parser": post / "satc_js_parser_environment",
        "satc_keyword_extraction": post / "satc_keyword_extraction",
        "satc_keyword_slice": post / "satc_keyword_slice",
        "satc_keyword_workload_identity": post / "satc_keyword_workload_identity",
        "satc": post / "satc_ingestion",
        "claims": post / "claim_evidence",
    }


def verify_archive_release_bindings(
    archive_path: Path,
    locations: dict[str, Path],
) -> tuple[list[str], dict[str, int]]:
    violations: list[str] = []
    bound_counts: dict[str, int] = {}
    with tarfile.open(archive_path, "r:gz") as archive:
        extracted = archive.extractfile(CONTENTS_NAME)
        if extracted is None:
            return ["archive has no embedded contents manifest"], bound_counts
        contents = json.loads(extracted.read().decode("utf-8"))
    raw_rows = contents.get("files") if isinstance(contents, dict) else None
    if not isinstance(raw_rows, list):
        return ["archive embedded file list is missing"], bound_counts

    rows_by_prefix: dict[str, dict[str, dict[str, Any]]] = {
        prefix: {} for prefix in locations
    }
    prefix_counts: dict[str, int] = {}
    for row in raw_rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            continue
        path = PurePosixPath(row["path"])
        if not path.parts:
            continue
        prefix = path.parts[0]
        prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1
        if prefix not in locations:
            continue
        relative = PurePosixPath(*path.parts[1:]).as_posix()
        if not relative or relative in rows_by_prefix[prefix]:
            violations.append(f"{prefix}: invalid or duplicate archive-relative path")
            continue
        rows_by_prefix[prefix][relative] = row

    expected_prefixes = set(locations) | EXPECTED_ARCHIVE_ONLY_PREFIXES
    if set(prefix_counts) != expected_prefixes:
        violations.append(
            "archive prefix set mismatch "
            f"missing={sorted(expected_prefixes - set(prefix_counts))} "
            f"extra={sorted(set(prefix_counts) - expected_prefixes)}"
        )
    for prefix in EXPECTED_ARCHIVE_ONLY_PREFIXES:
        if prefix_counts.get(prefix, 0) <= 0:
            violations.append(f"{prefix}: archive-only prefix is empty")

    for prefix, directory in locations.items():
        expected = rows_by_prefix[prefix]
        if not expected:
            violations.append(f"{prefix}: archive prefix is missing or empty")
            continue
        actual: dict[str, Path] = {}
        if not directory.is_dir() or is_link_like(directory):
            violations.append(f"{prefix}: downloaded binding directory is missing or linked")
            continue
        for current_root, directory_names, filenames in os.walk(directory, followlinks=False):
            current = Path(current_root)
            for member in list(directory_names):
                child = current / member
                if is_link_like(child):
                    violations.append(
                        f"{prefix}: linked directory {child.relative_to(directory).as_posix()}"
                    )
                    directory_names.remove(member)
            for member in filenames:
                child = current / member
                relative = child.relative_to(directory).as_posix()
                if is_link_like(child) or not child.is_file():
                    violations.append(f"{prefix}: non-regular member {relative}")
                else:
                    actual[relative] = child
        if set(actual) != set(expected):
            violations.append(
                f"{prefix}: archive/download file-set mismatch "
                f"missing={sorted(set(expected) - set(actual))[:10]} "
                f"extra={sorted(set(actual) - set(expected))[:10]}"
            )
        for relative in sorted(set(actual) & set(expected)):
            row = expected[relative]
            path = actual[relative]
            if path.stat().st_size != row.get("size") or sha256_file(path) != row.get(
                "sha256"
            ):
                violations.append(f"{prefix}/{relative}: archive/download identity mismatch")
        bound_counts[prefix] = len(expected)
    for prefix in EXPECTED_ARCHIVE_ONLY_PREFIXES:
        bound_counts[prefix] = prefix_counts.get(prefix, 0)
    return violations, bound_counts


def audit_release(root: Path, tag: str, suffix: str) -> dict[str, Any]:
    root = root.resolve()
    issues: list[str] = []
    checks: list[dict[str, Any]] = []
    fetch_path = root / "fetch_manifest.json"
    if not fetch_path.is_file():
        raise ValueError(f"missing fetch manifest: {fetch_path}")
    fetch = strict_json(fetch_path)
    expected_names = set(release_names(tag, suffix))
    raw_downloads = fetch.get("downloads")
    downloaded_names = set(raw_downloads) if isinstance(raw_downloads, dict) else set()
    add_check(checks, issues, "fetch_schema", fetch.get("schema") == "tsds-v20-release-fetch-v1", fetch.get("schema"))
    add_check(checks, issues, "fetch_tag", fetch.get("tag") == tag, fetch.get("tag"))
    add_check(
        checks,
        issues,
        "fetch_post_release_suffix",
        fetch.get("post_release_suffix") == suffix,
        fetch.get("post_release_suffix"),
    )
    add_check(
        checks,
        issues,
        "download_directory_set",
        downloaded_names == expected_names,
        f"expected={len(expected_names)} observed={len(downloaded_names)}",
    )
    missing_directories = sorted(name for name in expected_names if not (root / name).is_dir())
    add_check(checks, issues, "download_directories_present", not missing_directories, missing_directories)
    manifest_issues, downloaded_identities, downloaded_files = verify_download_manifest(
        root, fetch, expected_names, tag
    )
    add_check(
        checks,
        issues,
        "download_manifest_integrity",
        not manifest_issues,
        manifest_issues,
    )
    expected_top_level = expected_names | {
        "fetch_manifest.json",
        "manuscript_binding",
        f"tsds_v20_experiment_queue_{tag}.complete",
    }
    actual_top_level = {path.name for path in root.iterdir()}
    add_check(
        checks,
        issues,
        "release_root_file_set",
        actual_top_level == expected_top_level,
        {
            "missing": sorted(expected_top_level - actual_top_level),
            "extra": sorted(actual_top_level - expected_top_level),
        },
    )

    post_root = root / f"tsds_v20_post_release_{tag}_{suffix}"
    accepted = root / f"tsds_v20_accepted_repeat_{tag}"
    post_summary_path = post_root / "post_release_summary.json"
    claim_path = post_root / "claim_evidence" / "claim_evidence_matrix.json"
    release_path = post_root / "release_readiness" / "release_readiness.json"
    remote_archive_verification_path = post_root / "evidence_archive_verification.json"
    archive_path = post_root / f"tsds_v20_{tag}_evidence.tar.gz"
    archive_manifest_path = post_root / f"tsds_v20_{tag}_evidence_manifest.json"
    binding_path = root / "manuscript_binding" / "manuscript_binding.json"
    counts_path = root / "manuscript_binding" / "manuscript_counts.tex"
    binding_readme_path = root / "manuscript_binding" / "README.md"
    required_files = (
        post_summary_path,
        claim_path,
        release_path,
        remote_archive_verification_path,
        archive_path,
        archive_manifest_path,
        binding_path,
        counts_path,
        binding_readme_path,
        accepted / "pipeline_manifest.json",
        accepted / "paper_tables" / "paper_data_summary.json",
    )
    missing_files = [str(path) for path in required_files if not path.is_file()]
    add_check(checks, issues, "required_release_files", not missing_files, missing_files)
    if missing_files:
        return {
            "schema": SCHEMA,
            "tag": tag,
            "valid": False,
            "checks": checks,
            "issues": sorted(set(issues)),
        }

    post = strict_json(post_summary_path)
    claim = strict_json(claim_path)
    release = strict_json(release_path)
    remote_archive = strict_json(remote_archive_verification_path)
    binding = strict_json(binding_path)

    statuses = post.get("claim_statuses") or {}
    add_check(checks, issues, "post_summary_schema", post.get("schema") == "tsds-v20-post-release-summary-v1", post.get("schema"))
    add_check(checks, issues, "post_summary_paper_ready", post.get("ready_for_full_paper_writing") is True, post.get("ready_for_full_paper_writing"))
    add_check(checks, issues, "post_summary_release_ready", post.get("release_readiness_valid") is True, post.get("release_readiness_valid"))
    add_check(checks, issues, "post_summary_archive_verified", post.get("evidence_archive_verified") is True, post.get("evidence_archive_verified"))
    add_check(
        checks,
        issues,
        "post_summary_claims",
        set(statuses) == EXPECTED_CLAIMS and all(value == "supported" for value in statuses.values()),
        statuses,
    )

    claim_rows = claim.get("claims") or []
    claim_ids = [
        str(row.get("claim_id"))
        for row in claim_rows
        if isinstance(row, dict) and row.get("claim_id")
    ]
    claim_statuses = {
        str(row.get("claim_id")): row.get("status")
        for row in claim_rows
        if isinstance(row, dict) and row.get("claim_id")
    }
    add_check(checks, issues, "claim_matrix_schema", claim.get("schema") == "tsds-v20-claim-evidence-matrix-v1", claim.get("schema"))
    add_check(checks, issues, "claim_matrix_ready", claim.get("ready_for_full_paper_writing") is True, claim.get("ready_for_full_paper_writing"))
    add_check(
        checks,
        issues,
        "claim_matrix_statuses",
        set(claim_statuses) == EXPECTED_CLAIMS
        and all(value == "supported" for value in claim_statuses.values()),
        claim_statuses,
    )
    add_check(
        checks,
        issues,
        "claim_matrix_row_set",
        isinstance(claim_rows, list)
        and len(claim_rows) == len(EXPECTED_CLAIMS)
        and len(claim_ids) == len(EXPECTED_CLAIMS)
        and set(claim_ids) == EXPECTED_CLAIMS,
        claim_ids,
    )
    incomplete_claim_metadata = [
        str(row.get("claim_id") or "unknown")
        for row in claim_rows
        if not isinstance(row, dict)
        or any(
            not isinstance(row.get(field), str) or not row.get(field).strip()
            for field in ("statement", "verification_predicate", "non_claim")
        )
    ]
    add_check(
        checks,
        issues,
        "claim_metadata_complete",
        not incomplete_claim_metadata,
        incomplete_claim_metadata,
    )
    claim_evidence_bindings = {
        str(row.get("claim_id")): tuple(row.get("evidence_paths") or ())
        for row in claim_rows
        if isinstance(row, dict) and row.get("claim_id")
    }
    add_check(
        checks,
        issues,
        "claim_to_evidence_bindings",
        claim_evidence_bindings == EXPECTED_CLAIM_EVIDENCE,
        claim_evidence_bindings,
    )
    claim_evidence_issues, verified_claim_evidence = verify_claim_evidence(
        root, claim, expected_names, downloaded_identities
    )
    add_check(
        checks,
        issues,
        "claim_evidence_identities",
        not claim_evidence_issues,
        claim_evidence_issues,
    )
    add_check(
        checks,
        issues,
        "release_readiness",
        release.get("schema") == "tsds-release-readiness-v2"
        and release.get("valid") is True
        and not release.get("issues"),
        release.get("issues"),
    )
    add_check(
        checks,
        issues,
        "remote_archive_verification",
        remote_archive.get("schema")
        == "tsds-deterministic-artifact-verification-v1"
        and remote_archive.get("verified") is True
        and not remote_archive.get("issues"),
        remote_archive.get("issues"),
    )

    local_archive = verify_archive(archive_path, archive_manifest_path)
    add_check(checks, issues, "local_archive_verification", local_archive.get("verified") is True and not local_archive.get("issues"), local_archive.get("issues"))
    archive_binding_issues: list[str] = []
    archive_bound_prefixes: dict[str, int] = {}
    if local_archive.get("verified") is True:
        archive_binding_issues, archive_bound_prefixes = verify_archive_release_bindings(
            archive_path, archive_prefix_locations(root, tag, suffix)
        )
    else:
        archive_binding_issues.append("archive is not internally verified")
    add_check(
        checks,
        issues,
        "archive_release_bindings",
        not archive_binding_issues,
        archive_binding_issues,
    )

    rebuilt_binding = build_binding(claim_path, accepted)
    add_check(checks, issues, "manuscript_binding_schema", binding.get("schema") == "tsds-v20-manuscript-binding-v1", binding.get("schema"))
    add_check(checks, issues, "manuscript_binding_ready", binding.get("ready") is True, binding.get("ready"))
    add_check(checks, issues, "manuscript_binding_rebuild", rebuilt_binding == binding, "content equality")
    add_check(
        checks,
        issues,
        "manuscript_counts_rebuild",
        counts_path.read_text(encoding="utf-8") == latex_counts(rebuilt_binding),
        "content equality",
    )
    fetch_binding = fetch.get("manuscript_binding") or {}
    add_check(
        checks,
        issues,
        "fetch_binding_identity",
        identity_matches(fetch_binding.get("binding") or {}, binding_path),
        fetch_binding.get("binding"),
    )
    add_check(
        checks,
        issues,
        "fetch_counts_identity",
        identity_matches(fetch_binding.get("counts_tex") or {}, counts_path),
        fetch_binding.get("counts_tex"),
    )
    binding_directory = root / "manuscript_binding"
    binding_members = {
        path.relative_to(binding_directory).as_posix()
        for path in binding_directory.rglob("*")
        if path.is_file() and not is_link_like(path)
    }
    add_check(
        checks,
        issues,
        "manuscript_binding_file_set",
        binding_members
        == {"README.md", "manuscript_binding.json", "manuscript_counts.tex"},
        sorted(binding_members),
    )

    marker_path = root / f"tsds_v20_experiment_queue_{tag}.complete"
    marker_text = marker_path.read_text(encoding="utf-8", errors="replace").strip()
    add_check(
        checks,
        issues,
        "queue_marker_semantics",
        marker_text == f"TSDS_V20_EXPERIMENT_QUEUE_COMPLETE {tag}",
        marker_text,
    )

    inspected = [
        fetch_path,
        binding_path,
        counts_path,
        binding_readme_path,
        marker_path,
    ]
    inspected.extend(
        value["path"] for value in downloaded_identities.values() if value["path"].is_file()
    )
    contamination = scan_forbidden_tokens(inspected)
    add_check(checks, issues, "diagnostic_run_exclusion", not contamination, contamination)

    valid = not issues
    return {
        "schema": SCHEMA,
        "tag": tag,
        "post_release_suffix": suffix,
        "valid": valid,
        "records": binding.get("records"),
        "verdicts": binding.get("verdicts"),
        "claims": claim_statuses,
        "claim_evidence": verified_claim_evidence,
        "downloaded_files": downloaded_files,
        "archive": {
            "path": str(archive_path),
            "size": archive_path.stat().st_size,
            "sha256": sha256_file(archive_path),
            "files": local_archive.get("files"),
            "bound_prefixes": archive_bound_prefixes,
        },
        "checks": checks,
        "issues": sorted(set(issues)),
        "claim_boundary": (
            "This audit verifies downloaded artifact identity and paper-evidence "
            "readiness. It does not add device-level or comparative accuracy claims."
        ),
    }


def write_outputs(out_dir: Path, document: dict[str, Any]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError(f"refusing to reuse non-empty output directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "downloaded_release_audit.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (out_dir / "downloaded_release_checks.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(
            stream, fieldnames=["check", "passed", "detail"], lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(document["checks"])
    (out_dir / "README.md").write_text(
        "# TSDS v20 downloaded-release audit\n\n"
        f"Valid: **{document['valid']}**; issues: **{len(document['issues'])}**.\n\n"
        + document.get("claim_boundary", "")
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-root", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--post-release-suffix", default="v2")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--fail-on-issues", action="store_true")
    args = parser.parse_args()
    try:
        document = audit_release(
            args.release_root.resolve(), args.tag, args.post_release_suffix
        )
        write_outputs(args.out_dir.resolve(), document)
    except (OSError, TypeError, ValueError, json.JSONDecodeError, tarfile.TarError) as exc:
        print(f"V20_DOWNLOADED_RELEASE_AUDIT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(document, indent=2, sort_keys=True))
    return 3 if args.fail_on_issues and not document["valid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
