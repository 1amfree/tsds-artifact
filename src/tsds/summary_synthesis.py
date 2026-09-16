"""Deterministic function-summary synthesis and persistence for TSDS.

The module defines a small, auditable summary IR.  It deliberately does not
depend on angr: the symbolic evaluator translates admitted summaries into
SimProcedures, while tests and artifact tools can inspect the same model in a
minimal Python environment.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SUMMARY_SCHEMA = "tsds-function-summary-v1"
SUMMARY_DB_SCHEMA = "tsds-function-summary-db-v1"

EFFECT_KINDS = {
    "return_symbolic_cstring",
    "copy_source_to_destination",
    "bind_format_slot",
    "fork_boolean_predicate",
    "passthrough_return",
}


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _bounded_text(value: Any, limit: int = 200) -> str:
    text = str(value or "").strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


@dataclass(frozen=True)
class SummaryPrecondition:
    kind: str
    argument: int | None = None
    value: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SummaryEffect:
    kind: str
    destination_arg: int | None = None
    source_arg: int | None = None
    source_kind: str = "source"
    max_bytes: int = 128
    format_arg: int | None = None
    source_slot: int | None = None
    return_value: int | None = None

    def normalized(self) -> "SummaryEffect":
        if self.kind not in EFFECT_KINDS:
            raise ValueError(f"unsupported summary effect: {self.kind}")
        return SummaryEffect(
            kind=self.kind,
            destination_arg=self.destination_arg,
            source_arg=self.source_arg,
            source_kind=_bounded_text(self.source_kind, 48) or "source",
            max_bytes=max(1, min(4096, int(self.max_bytes))),
            format_arg=self.format_arg,
            source_slot=self.source_slot,
            return_value=self.return_value,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self.normalized())


@dataclass(frozen=True)
class FunctionSummary:
    target: str
    architecture: str
    calling_convention: str
    binary_sha256: str
    preconditions: tuple[SummaryPrecondition, ...]
    effects: tuple[SummaryEffect, ...]
    confidence: str
    evidence: tuple[str, ...] = field(default_factory=tuple)
    origin: str = "synthesized"
    summary_id: str = ""
    schema: str = SUMMARY_SCHEMA

    def normalized(self) -> "FunctionSummary":
        confidence = str(self.confidence or "low").lower()
        if confidence not in {"high", "medium", "low"}:
            raise ValueError(f"unsupported summary confidence: {confidence}")
        effects = tuple(effect.normalized() for effect in self.effects)
        if not effects:
            raise ValueError("a function summary requires at least one effect")
        base = {
            "target": _bounded_text(self.target, 160),
            "architecture": _bounded_text(self.architecture, 48) or "unknown",
            "calling_convention": _bounded_text(self.calling_convention, 48) or "default",
            "binary_sha256": str(self.binary_sha256 or "unknown").lower(),
            "preconditions": [item.to_dict() for item in self.preconditions],
            "effects": [item.to_dict() for item in effects],
            "confidence": confidence,
            "evidence": sorted({_bounded_text(item, 240) for item in self.evidence if item}),
            "origin": _bounded_text(self.origin, 64) or "synthesized",
        }
        return FunctionSummary(
            target=base["target"],
            architecture=base["architecture"],
            calling_convention=base["calling_convention"],
            binary_sha256=base["binary_sha256"],
            preconditions=tuple(self.preconditions),
            effects=effects,
            confidence=confidence,
            evidence=tuple(base["evidence"]),
            origin=base["origin"],
            summary_id=self.summary_id or canonical_digest(base)[:24],
        )

    @property
    def database_key(self) -> str:
        value = self.normalized()
        return "|".join(
            (
                value.binary_sha256,
                value.architecture,
                value.calling_convention,
                value.target,
                value.schema,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        value = self.normalized()
        return {
            "schema": value.schema,
            "summary_id": value.summary_id,
            "target": value.target,
            "architecture": value.architecture,
            "calling_convention": value.calling_convention,
            "binary_sha256": value.binary_sha256,
            "preconditions": [item.to_dict() for item in value.preconditions],
            "effects": [item.to_dict() for item in value.effects],
            "confidence": value.confidence,
            "evidence": list(value.evidence),
            "origin": value.origin,
        }

    @classmethod
    def from_dict(cls, row: Mapping[str, Any]) -> "FunctionSummary":
        if row.get("schema", SUMMARY_SCHEMA) != SUMMARY_SCHEMA:
            raise ValueError("unsupported function-summary schema")
        supplied_id = str(row.get("summary_id") or "")
        summary = cls(
            target=str(row.get("target") or ""),
            architecture=str(row.get("architecture") or "unknown"),
            calling_convention=str(row.get("calling_convention") or "default"),
            binary_sha256=str(row.get("binary_sha256") or "unknown"),
            preconditions=tuple(
                SummaryPrecondition(
                    kind=str(item.get("kind") or ""),
                    argument=item.get("argument"),
                    value=str(item.get("value") or ""),
                )
                for item in row.get("preconditions", [])
            ),
            effects=tuple(
                SummaryEffect(
                    kind=str(item.get("kind") or ""),
                    destination_arg=item.get("destination_arg"),
                    source_arg=item.get("source_arg"),
                    source_kind=str(item.get("source_kind") or "source"),
                    max_bytes=int(item.get("max_bytes") or 128),
                    format_arg=item.get("format_arg"),
                    source_slot=item.get("source_slot"),
                    return_value=item.get("return_value"),
                )
                for item in row.get("effects", [])
            ),
            confidence=str(row.get("confidence") or "low"),
            evidence=tuple(str(item) for item in row.get("evidence", [])),
            origin=str(row.get("origin") or "synthesized"),
            summary_id="",
        ).normalized()
        if supplied_id and supplied_id != summary.summary_id:
            raise ValueError("function-summary identifier mismatch")
        return summary


class SummaryDatabase:
    """Strict deterministic store keyed by binary, target, ABI, and schema."""

    def __init__(self, summaries: Iterable[FunctionSummary] = ()) -> None:
        self._rows: dict[str, FunctionSummary] = {}
        for summary in summaries:
            self.add(summary)

    def add(self, summary: FunctionSummary) -> FunctionSummary:
        value = summary.normalized()
        self._rows[value.database_key] = value
        return value

    def get(
        self,
        *,
        binary_sha256: str,
        architecture: str,
        calling_convention: str,
        target: str,
    ) -> FunctionSummary | None:
        key = "|".join(
            (
                str(binary_sha256 or "unknown").lower(),
                str(architecture or "unknown"),
                str(calling_convention or "default"),
                str(target),
                SUMMARY_SCHEMA,
            )
        )
        return self._rows.get(key)

    def matching(self, *, binary_sha256: str, architecture: str) -> list[FunctionSummary]:
        return sorted(
            (
                row
                for row in self._rows.values()
                if row.binary_sha256 == str(binary_sha256).lower()
                and row.architecture == architecture
            ),
            key=lambda item: item.database_key,
        )

    def to_dict(self) -> dict[str, Any]:
        rows = [self._rows[key].to_dict() for key in sorted(self._rows)]
        unsigned = {"schema": SUMMARY_DB_SCHEMA, "summaries": rows}
        return {**unsigned, "database_sha256": canonical_digest(unsigned)}

    def write(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> "SummaryDatabase":
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        if document.get("schema") != SUMMARY_DB_SCHEMA:
            raise ValueError("unsupported summary database schema")
        supplied = str(document.get("database_sha256") or "")
        unsigned = dict(document)
        unsigned.pop("database_sha256", None)
        if not supplied or supplied != canonical_digest(unsigned):
            raise ValueError("summary database digest mismatch")
        return cls(FunctionSummary.from_dict(row) for row in document.get("summaries", []))


def summary_from_refinement_candidate(
    candidate: Mapping[str, Any],
    *,
    binary_sha256: str,
    architecture: str,
    calling_convention: str = "default",
) -> FunctionSummary:
    kind = str(candidate.get("kind") or "")
    source_kind = str(candidate.get("source_kind") or "source")
    source_slot = candidate.get("source_slot")
    if kind == "source_wrapper_summary":
        effects = (SummaryEffect("return_symbolic_cstring", source_kind=source_kind),)
    elif kind == "string_transfer_summary":
        effects = (
            SummaryEffect(
                "copy_source_to_destination",
                destination_arg=0,
                source_arg=1,
                source_kind=source_kind,
            ),
        )
    elif kind == "format_binding_summary":
        effects = (
            SummaryEffect(
                "bind_format_slot",
                destination_arg=0,
                format_arg=1,
                source_arg=(2 if source_slot is None else int(source_slot) + 2),
                source_slot=source_slot,
                source_kind=source_kind,
            ),
        )
    elif kind == "environment_predicate_summary":
        effects = (SummaryEffect("fork_boolean_predicate", return_value=None),)
    else:
        raise ValueError(f"unsupported refinement candidate kind: {kind}")
    return FunctionSummary(
        target=str(candidate.get("target") or ""),
        architecture=architecture,
        calling_convention=calling_convention,
        binary_sha256=binary_sha256,
        preconditions=tuple(
            SummaryPrecondition("candidate_guard", value=str(item))
            for item in candidate.get("preconditions", [])
        ),
        effects=effects,
        confidence=str(candidate.get("confidence") or "low"),
        evidence=(
            str(candidate.get("reason") or ""),
            str(candidate.get("evidence") or ""),
        ),
        origin="residual_cegar",
    ).normalized()


def synthesize_from_observations(
    observations: Sequence[Mapping[str, Any]],
    *,
    target: str,
    binary_sha256: str,
    architecture: str,
    calling_convention: str = "default",
) -> FunctionSummary | None:
    """Infer one bounded summary from repeated call/write observations.

    The inference is intentionally conservative: all observations must agree
    on one recognized behavior before a medium-confidence model is emitted.
    """

    rows = list(observations)
    if not rows:
        return None
    behaviors = {str(row.get("behavior") or "") for row in rows}
    if len(behaviors) != 1:
        return None
    behavior = next(iter(behaviors))
    effect: SummaryEffect | None = None
    if behavior == "source_return":
        kinds = {str(row.get("source_kind") or "source") for row in rows}
        if len(kinds) == 1:
            effect = SummaryEffect(
                "return_symbolic_cstring", source_kind=next(iter(kinds))
            )
    elif behavior == "string_copy":
        pairs = {
            (int(row.get("destination_arg", 0)), int(row.get("source_arg", 1)))
            for row in rows
        }
        if len(pairs) == 1:
            destination, source = next(iter(pairs))
            effect = SummaryEffect(
                "copy_source_to_destination",
                destination_arg=destination,
                source_arg=source,
            )
    elif behavior == "format_binding":
        slots = {int(row.get("source_slot", 0)) for row in rows}
        if len(slots) == 1:
            slot = next(iter(slots))
            effect = SummaryEffect(
                "bind_format_slot",
                destination_arg=0,
                format_arg=1,
                source_arg=slot + 2,
                source_slot=slot,
            )
    elif behavior == "boolean_predicate":
        values = {int(row.get("return_value", -1)) for row in rows}
        if values <= {0, 1}:
            effect = SummaryEffect("fork_boolean_predicate")
    if effect is None:
        return None
    evidence = tuple(
        sorted(
            {
                _bounded_text(row.get("evidence") or row.get("callsite") or "observation")
                for row in rows
            }
        )
    )
    return FunctionSummary(
        target=target,
        architecture=architecture,
        calling_convention=calling_convention,
        binary_sha256=binary_sha256,
        preconditions=(SummaryPrecondition("observation_agreement", value=str(len(rows))),),
        effects=(effect,),
        confidence="medium" if len(rows) >= 2 else "low",
        evidence=evidence,
        origin="dynamic_observation",
    ).normalized()
