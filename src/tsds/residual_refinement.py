"""Fail-closed planning and auditing for TSDS residual refinement.

This module turns unresolved ledger rows into deterministic, bounded replay
plans.  Synthetic fixtures are *branch-enabling conditions*, never proof that
a real device exposes the same configuration.  Consequently any replay that
uses a fixture is labelled ``fixture_conditioned`` and cannot silently enter
the primary analyzer-level aggregate.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from typing import Any, Iterable, Mapping


REFINEMENT_SCHEMA = "tsds-residual-refinement-v2"
FIXTURE_SCHEMA = "tsds-synthetic-branch-fixture-v1"
TRANSITION_SCHEMA = "tsds-residual-refinement-transition-v1"

RESIDUAL_STATUSES = frozenset(
    {
        "residual",
        "unreachable",
        "timeout",
        "crashed",
        "eval_error",
        "state_error",
        "static_source_inference",
    }
)
RESOLVED_STATUSES = frozenset({"vulnerable", "filtered", "no_taint_sink"})
PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
FIXTURE_KINDS = frozenset({"config_key", "web", "file", "argv_env"})


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _text(value: Any) -> str:
    return str(value or "").strip().strip("\x00")


def _safe_key(value: Any) -> str:
    text = _text(value)
    text = re.sub(r"[\x00-\x1f\x7f]", "", text)
    return text[:120]


def _normalise_requests(record: Mapping[str, Any]) -> list[dict[str, str]]:
    requests: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw in record.get("model_gap_requests") or []:
        if not isinstance(raw, Mapping):
            continue
        kind = _text(raw.get("kind"))
        key = _safe_key(raw.get("key"))
        if kind not in FIXTURE_KINDS or not key:
            continue
        identity = (kind, key.lower())
        if identity in seen:
            continue
        seen.add(identity)
        requests.append(
            {
                "kind": kind,
                "key": key,
                "reason": _text(raw.get("reason")),
                "confidence": _text(raw.get("confidence")) or "medium",
            }
        )
    return sorted(requests, key=lambda item: (item["kind"], item["key"].lower()))


def _value_for_variant(kind: str, key: str, variant: str) -> str:
    """Return a non-exploit, deterministic branch-enabling placeholder."""

    lower = key.lower()
    if variant == "false_branch":
        return "0" if kind != "file" else "0\n"
    if variant == "network_profile":
        if any(token in lower for token in ("ip", "addr", "gateway", "dns")):
            return "192.0.2.1"
        if any(token in lower for token in ("ifname", "iface", "interface", "port")):
            return "eth0"
        if "ssid" in lower:
            return "tsds-lab"
    if kind == "file":
        return "1\n"
    if kind == "argv_env":
        return "1"
    return "1"


def _fixture_section(kind: str) -> str:
    return {
        "config_key": "config",
        "web": "web",
        "file": "files",
        "argv_env": "env",
    }[kind]


def synthesize_fixture_variants(
    record: Mapping[str, Any],
    *,
    max_variants: int = 3,
) -> list[dict[str, Any]]:
    """Create a bounded set of explicitly synthetic fixture variants.

    A variant is emitted only for concrete config/web/file/env requests.  It
    carries the source-record digest and cannot be confused with a collected
    device configuration.
    """

    requests = _normalise_requests(record)
    if not requests or max_variants <= 0:
        return []
    variant_names = ["true_branch", "false_branch", "network_profile"][:max_variants]
    source_digest = sha256_json(dict(record or {}))
    variants: list[dict[str, Any]] = []
    for name in variant_names:
        fixture: dict[str, Any] = {
            "_tsds_fixture_schema": FIXTURE_SCHEMA,
            "_tsds_fixture_origin": "synthetic_branch_enablement",
            "_tsds_fixture_variant": name,
            "_tsds_source_record_sha256": source_digest,
            "config": {},
            "web": {},
            "files": {},
            "env": {},
        }
        bindings: list[dict[str, str]] = []
        for request in requests:
            section = _fixture_section(request["kind"])
            value = _value_for_variant(request["kind"], request["key"], name)
            if section == "files":
                fixture[section][request["key"]] = {"content": value}
            else:
                fixture[section][request["key"]] = value
            bindings.append(
                {
                    "kind": request["kind"],
                    "key": request["key"],
                    "value_class": name,
                    "reason": request["reason"],
                }
            )
        # Omit empty sections to keep the serialized fixture directly usable by
        # the evaluator's environment-fixture loader.
        compact_fixture = {
            key: value
            for key, value in fixture.items()
            if key.startswith("_tsds_") or value
        }
        variants.append(
            {
                "schema": REFINEMENT_SCHEMA,
                "variant": name,
                "fixture": compact_fixture,
                "fixture_sha256": sha256_json(compact_fixture),
                "source_record_sha256": source_digest,
                "bindings": bindings,
                "claim_scope": "fixture_conditioned",
                "primary_aggregate_eligible": False,
            }
        )
    return variants


def build_refinement_plan(
    records: Iterable[Mapping[str, Any]],
    *,
    max_records: int = 0,
    max_variants: int = 3,
    priorities: Iterable[str] | None = None,
    strategies: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Build a deterministic plan without launching analysis subprocesses."""

    priority_filter = {str(item) for item in (priorities or []) if str(item)}
    strategy_filter = {str(item) for item in (strategies or []) if str(item)}
    candidates: list[Mapping[str, Any]] = []
    for record in records or []:
        status = _text(record.get("status"))
        strategy = _text(record.get("residual_plan_strategy")) or "manual_review"
        priority = _text(record.get("residual_plan_priority")) or "medium"
        if status not in RESIDUAL_STATUSES:
            continue
        if priority_filter and priority not in priority_filter:
            continue
        if strategy_filter and strategy not in strategy_filter:
            continue
        candidates.append(record)
    candidates.sort(
        key=lambda record: (
            PRIORITY_ORDER.get(_text(record.get("residual_plan_priority")) or "medium", 4),
            int(record.get("closure_idx") or 0),
        )
    )
    if max_records > 0:
        candidates = candidates[:max_records]

    rows: list[dict[str, Any]] = []
    for record in candidates:
        variants = synthesize_fixture_variants(record, max_variants=max_variants)
        rows.append(
            {
                "closure_idx": record.get("closure_idx"),
                "closure_ordinal": record.get("closure_ordinal"),
                "old_status": record.get("status"),
                "strategy": _text(record.get("residual_plan_strategy")) or "manual_review",
                "priority": _text(record.get("residual_plan_priority")) or "medium",
                "config_overrides": dict(record.get("residual_plan_config_overrides") or {}),
                "model_gap_requests": _normalise_requests(record),
                "fixture_variants": variants,
                "source_record_sha256": sha256_json(dict(record or {})),
                "claim_scope": "conditional_replay_plan" if variants else "budget_or_model_replay_plan",
            }
        )
    return {
        "schema": REFINEMENT_SCHEMA,
        "records": rows,
        "summary": refinement_plan_summary(rows),
        "claim_boundary": (
            "Synthetic fixtures only establish fixture-conditioned replay paths. "
            "They are not firmware configuration observations and cannot by themselves promote a primary TSDS claim."
        ),
    }


def refinement_plan_summary(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = list(rows or [])
    priorities = Counter(str(row.get("priority") or "unknown") for row in rows)
    strategies = Counter(str(row.get("strategy") or "unknown") for row in rows)
    variants = sum(len(row.get("fixture_variants") or []) for row in rows)
    requests = sum(len(row.get("model_gap_requests") or []) for row in rows)
    return {
        "selected_records": len(rows),
        "fixture_variants": variants,
        "fixture_requests": requests,
        "priorities": dict(sorted(priorities.items())),
        "strategies": dict(sorted(strategies.items())),
    }


def fixture_was_used(result: Mapping[str, Any]) -> bool:
    usage = result.get("env_fixture_usage") or {}
    if isinstance(usage, Mapping) and int(usage.get("hits") or 0) > 0:
        return True
    summary = result.get("env_fixture_summary") or {}
    return bool(isinstance(summary, Mapping) and int(summary.get("entries") or 0) > 0)


def classify_transition(
    old_record: Mapping[str, Any],
    new_record: Mapping[str, Any],
    *,
    fixture_variant: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify a replay transition without allowing silent claim promotion."""

    old_status = _text(old_record.get("status")) or "unknown"
    new_status = _text(new_record.get("status")) or "unknown"
    contract_valid = bool(new_record.get("evidence_contract_valid"))
    fixture_used = fixture_was_used(new_record) or fixture_variant is not None
    new_resolved = new_status in RESOLVED_STATUSES and contract_valid
    if new_resolved and fixture_used:
        transition = "fixture_conditioned_resolution"
        primary_eligible = False
    elif new_resolved and old_status not in RESOLVED_STATUSES:
        transition = "unconditional_resolution"
        primary_eligible = True
    elif new_status != old_status:
        transition = "changed_nonprimary"
        primary_eligible = False
    else:
        transition = "unchanged"
        primary_eligible = False
    row = {
        "schema": TRANSITION_SCHEMA,
        "closure_idx": old_record.get("closure_idx"),
        "old_status": old_status,
        "new_status": new_status,
        "new_contract_valid": contract_valid,
        "fixture_used": fixture_used,
        "fixture_sha256": (fixture_variant or {}).get("fixture_sha256"),
        "transition": transition,
        "primary_aggregate_eligible": primary_eligible,
        "old_record_sha256": sha256_json(dict(old_record or {})),
        "new_record_sha256": sha256_json(dict(new_record or {})),
    }
    row["transition_sha256"] = sha256_json(row)
    return row


def transition_violations(transition: Mapping[str, Any]) -> list[str]:
    transition = transition or {}
    issues: list[str] = []
    digest_body = dict(transition)
    expected = digest_body.pop("transition_sha256", None)
    if not expected or expected != sha256_json(digest_body):
        issues.append("transition_digest_mismatch")
    if transition.get("transition") == "fixture_conditioned_resolution":
        if transition.get("primary_aggregate_eligible"):
            issues.append("fixture_conditioned_transition_in_primary_aggregate")
        if not transition.get("fixture_used"):
            issues.append("fixture_conditioned_transition_without_fixture")
    if transition.get("transition") == "unconditional_resolution":
        if not transition.get("new_contract_valid"):
            issues.append("unconditional_resolution_without_valid_contract")
        if transition.get("fixture_used"):
            issues.append("unconditional_resolution_with_fixture")
    return sorted(set(issues))


def transition_summary(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = list(rows or [])
    counts = Counter(str(row.get("transition") or "unknown") for row in rows)
    issues = Counter()
    for row in rows:
        for issue in transition_violations(row):
            issues[issue] += 1
    return {
        "schema": "tsds-residual-refinement-transition-audit-v1",
        "records": len(rows),
        "transition_counts": dict(sorted(counts.items())),
        "records_with_issues": sum(1 for row in rows if transition_violations(row)),
        "issue_counts": dict(sorted(issues.items())),
    }


def group_plan_by_target(
    target_records: Iterable[tuple[str, Mapping[str, Any]]],
    *,
    max_records_per_target: int = 0,
    max_variants: int = 3,
) -> dict[str, Any]:
    """Convenience planner used by experiment drivers with multiple targets."""

    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for target, record in target_records:
        grouped[str(target)].append(record)
    targets = {
        target: build_refinement_plan(
            records,
            max_records=max_records_per_target,
            max_variants=max_variants,
        )
        for target, records in sorted(grouped.items())
    }
    return {
        "schema": REFINEMENT_SCHEMA,
        "targets": targets,
        "targets_count": len(targets),
    }
