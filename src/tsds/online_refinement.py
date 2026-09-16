"""Checkpointed online refinement control for bounded TSDS residual replay."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping


ONLINE_REFINEMENT_SCHEMA = "tsds-online-refinement-v1"


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class RefinementRound:
    round_index: int
    trigger: str
    candidate_ids: tuple[str, ...]
    installed_ids: tuple[str, ...]
    outcome: str
    evidence_status: str = "residual"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["candidate_ids"] = list(value["candidate_ids"])
        value["installed_ids"] = list(value["installed_ids"])
        return value


@dataclass
class OnlineRefinementController:
    max_rounds: int = 1
    max_candidates_per_round: int = 3
    allowed_triggers: tuple[str, ...] = (
        "model_gap_reachability",
        "static_dynamic_taint_disagreement",
        "environment_branch_model",
        "source_liveness_saturated",
        "adaptive_source_liveness_saturated",
    )
    rounds: list[RefinementRound] = field(default_factory=list)

    def should_attempt(self, record: Mapping[str, Any]) -> bool:
        if len(self.rounds) >= max(0, int(self.max_rounds)):
            return False
        if str(record.get("status") or "") not in {
            "residual",
            "unreachable",
            "no_taint_sink",
        }:
            return False
        trigger = str(
            record.get("residual_diagnosis_class")
            or record.get("engine_stop_reason")
            or ""
        ).lower()
        return trigger in set(self.allowed_triggers)

    def select(self, candidates: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        admitted = [
            dict(candidate)
            for candidate in candidates
            if bool((candidate.get("admission") or {}).get("admitted", True))
        ]
        admitted.sort(
            key=lambda row: (
                0 if row.get("confidence") == "high" else 1,
                str(row.get("candidate_id") or ""),
            )
        )
        return admitted[: max(0, int(self.max_candidates_per_round))]

    def record(
        self,
        *,
        trigger: str,
        candidates: Iterable[Mapping[str, Any]],
        installed_ids: Iterable[str],
        outcome: str,
        evidence_status: str = "residual",
    ) -> RefinementRound:
        selected = list(candidates)
        row = RefinementRound(
            round_index=len(self.rounds) + 1,
            trigger=str(trigger),
            candidate_ids=tuple(str(item.get("candidate_id") or "") for item in selected),
            installed_ids=tuple(sorted(str(item) for item in installed_ids)),
            outcome=str(outcome),
            evidence_status=str(evidence_status),
        )
        self.rounds.append(row)
        return row

    def to_dict(self) -> dict[str, Any]:
        value = {
            "schema": ONLINE_REFINEMENT_SCHEMA,
            "max_rounds": int(self.max_rounds),
            "max_candidates_per_round": int(self.max_candidates_per_round),
            "allowed_triggers": list(self.allowed_triggers),
            "rounds": [item.to_dict() for item in self.rounds],
        }
        value["checkpoint_sha256"] = _digest(value)
        return value

    def write_checkpoint(self, path: str | Path) -> dict[str, Any]:
        value = self.to_dict()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return value

