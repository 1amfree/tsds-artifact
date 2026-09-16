"""Deterministic evidence-aware scheduling for TSDS symbolic frontiers.

The scheduler is intentionally independent of angr.  The execution engine
projects each symbolic state into :class:`StateProjection`; this module then
allocates a frontier budget and selects a semantically diverse subset.  Keeping
the policy pure makes its preservation properties testable without firmware
or solver dependencies.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Hashable, Iterable, Sequence


SCHEDULER_SCHEMA = "tsds-evidence-aware-scheduler-v3"


def source_liveness_stop_blockers(
    *,
    strong_source_obligation: bool,
    near_sink: bool = False,
    protected: bool = False,
) -> tuple[str, ...]:
    """Return the evidence obligations that prohibit a liveness stop.

    The executor has two source-liveness control paths: the adaptive
    scheduler and the legacy frontier-cap safeguard. Keeping their
    admissibility inputs in one pure function prevents the safeguard from
    finalizing a trajectory that the scheduler would preserve.
    """

    blockers: list[str] = []
    if strong_source_obligation:
        blockers.append("strong_source_obligation")
    if near_sink:
        blockers.append("near_sink_frontier")
    if protected:
        blockers.append("protected_evidence_state")
    return tuple(blockers)


def source_liveness_stop_admissible(
    *,
    strong_source_obligation: bool,
    near_sink: bool = False,
    protected: bool = False,
) -> bool:
    """Return whether source-liveness loss can terminate this trajectory.

    Register-local taint is an intentionally incomplete liveness observation.
    A strong front-end source obligation, a near-sink state, or protected
    source-to-sink evidence therefore keeps the trajectory subject to the
    remaining bounded controls instead of allowing this heuristic to finalize
    it as source-dead.
    """

    return not source_liveness_stop_blockers(
        strong_source_obligation=strong_source_obligation,
        near_sink=near_sink,
        protected=protected,
    )


@dataclass(frozen=True)
class StateProjection:
    """Evidence-relevant projection of one symbolic state."""

    index: int
    pc: int
    sink_distance: int | None
    source_carrier: bool
    propagated_source: bool
    near_sink: bool
    sink_progress: int = 0
    quote_context: str = "unknown"
    constraint_digest: str = "none:0"
    return_signature: str = "unknown"
    corridor_class: str = "unknown"
    constraint_count: int = 0
    semantic_key: Hashable = field(default_factory=tuple)

    @property
    def protected(self) -> bool:
        return bool(self.propagated_source and self.near_sink)

    @property
    def corridor_priority(self) -> int:
        return {
            "target": 0,
            "inside": 1,
            "guide": 1,
            "escape": 2,
            "unknown": 3,
            "outside": 4,
        }.get(self.corridor_class, 3)

    def rank_key(self) -> tuple[Any, ...]:
        distance = self.sink_distance if self.sink_distance is not None else 1 << 60
        return (
            0 if self.protected else 1,
            self.corridor_priority,
            0 if self.propagated_source else (1 if self.source_carrier else 2),
            distance,
            -int(self.sink_progress),
            int(self.constraint_count),
            int(self.pc),
            int(self.index),
        )

    def diversity_key(self) -> Hashable:
        if self.semantic_key:
            return self.semantic_key
        distance_bucket: str | int
        if self.sink_distance is None:
            distance_bucket = "unknown"
        elif self.sink_distance <= 0:
            distance_bucket = "target"
        elif self.sink_distance <= 0x20:
            distance_bucket = "near"
        elif self.sink_distance <= 0x100:
            distance_bucket = "local"
        elif self.sink_distance <= 0x1000:
            distance_bucket = "region"
        else:
            distance_bucket = "far"
        return (
            self.pc,
            distance_bucket,
            self.corridor_class,
            self.source_carrier,
            self.propagated_source,
            self.quote_context,
            self.constraint_digest,
            self.return_signature,
        )


@dataclass(frozen=True)
class SchedulerConfig:
    base_active_cap: int = 60
    min_active_cap: int = 20
    max_active_cap: int = 120
    expansion_step: int = 20
    shrink_step: int = 10
    base_bucket_limit: int = 2
    max_bucket_limit: int = 4
    protected_quota: int = 16
    escape_quota: int = 4
    progress_window: int = 2
    stagnation_window: int = 3
    source_dead_limit: int = 4
    constraint_soft_limit: int = 800
    rss_soft_limit_mib: float = 0.0
    rss_hard_limit_mib: float = 0.0

    def normalized(self) -> "SchedulerConfig":
        minimum = max(1, int(self.min_active_cap))
        maximum = max(minimum, int(self.max_active_cap))
        base = min(maximum, max(minimum, int(self.base_active_cap)))
        return SchedulerConfig(
            base_active_cap=base,
            min_active_cap=minimum,
            max_active_cap=maximum,
            expansion_step=max(1, int(self.expansion_step)),
            shrink_step=max(1, int(self.shrink_step)),
            base_bucket_limit=max(1, int(self.base_bucket_limit)),
            max_bucket_limit=max(1, int(self.max_bucket_limit)),
            protected_quota=max(1, int(self.protected_quota)),
            escape_quota=max(0, int(self.escape_quota)),
            progress_window=max(1, int(self.progress_window)),
            stagnation_window=max(1, int(self.stagnation_window)),
            source_dead_limit=max(0, int(self.source_dead_limit)),
            constraint_soft_limit=max(1, int(self.constraint_soft_limit)),
            rss_soft_limit_mib=max(0.0, float(self.rss_soft_limit_mib)),
            rss_hard_limit_mib=max(0.0, float(self.rss_hard_limit_mib)),
        )


@dataclass(frozen=True)
class BudgetDecision:
    step: int
    tier: str
    active_cap: int
    bucket_limit: int
    protected_states: int
    source_live_states: int
    near_sink_states: int
    escape_quota: int
    best_sink_distance: int | None
    progress: bool
    stagnant_rounds: int
    source_dead_rounds: int
    should_stop: bool
    stop_reason: str | None
    reasons: tuple[str, ...]
    schema: str = SCHEDULER_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["reasons"] = list(self.reasons)
        return value


class EvidenceAwareScheduler:
    """Stateful but deterministic adaptive frontier controller."""

    def __init__(self, config: SchedulerConfig | None = None) -> None:
        self.config = (config or SchedulerConfig()).normalized()
        self.best_distance: int | None = None
        self.stagnant_rounds = 0
        self.source_dead_rounds = 0
        self.progress_rounds = 0
        self.decisions: list[BudgetDecision] = []

    @staticmethod
    def _best_distance(projections: Sequence[StateProjection]) -> int | None:
        values = [p.sink_distance for p in projections if p.sink_distance is not None]
        return min(values) if values else None

    def observe(
        self,
        step: int,
        projections: Sequence[StateProjection],
        *,
        rss_mib: float | None = None,
        strong_source_obligation: bool = False,
    ) -> BudgetDecision:
        cfg = self.config
        best = self._best_distance(projections)
        source_live = sum(1 for p in projections if p.source_carrier)
        propagated = sum(1 for p in projections if p.propagated_source)
        protected = sum(1 for p in projections if p.protected)
        near_sink = sum(1 for p in projections if p.near_sink)
        average_constraints = (
            sum(max(0, p.constraint_count) for p in projections) / len(projections)
            if projections
            else 0.0
        )

        progress = bool(
            best is not None
            and (self.best_distance is None or best < self.best_distance)
        )
        if progress:
            self.best_distance = best
            self.progress_rounds += 1
            self.stagnant_rounds = 0
        else:
            self.progress_rounds = 0
            self.stagnant_rounds += 1

        if source_live:
            self.source_dead_rounds = 0
        else:
            self.source_dead_rounds += 1

        cap = cfg.base_active_cap
        bucket_limit = cfg.base_bucket_limit
        tier = "balanced"
        reasons: list[str] = []

        hard_memory = bool(
            rss_mib is not None
            and cfg.rss_hard_limit_mib
            and rss_mib >= cfg.rss_hard_limit_mib
        )
        soft_memory = bool(
            rss_mib is not None
            and cfg.rss_soft_limit_mib
            and rss_mib >= cfg.rss_soft_limit_mib
        )
        solver_pressure = average_constraints >= cfg.constraint_soft_limit

        if hard_memory:
            tier = "memory_emergency"
            cap = cfg.min_active_cap
            bucket_limit = 1
            reasons.append("rss_hard_limit")
        elif soft_memory or solver_pressure:
            tier = "pressure_control"
            cap = max(cfg.min_active_cap, cfg.base_active_cap - cfg.shrink_step)
            bucket_limit = 1
            reasons.append("rss_soft_limit" if soft_memory else "constraint_pressure")
        elif protected or (near_sink and propagated):
            tier = "evidence_expansion"
            cap = min(cfg.max_active_cap, cfg.base_active_cap + cfg.expansion_step)
            bucket_limit = min(cfg.max_bucket_limit, cfg.base_bucket_limit + 1)
            reasons.append("protected_near_sink_state")
        elif progress and propagated:
            tier = "progress_expansion"
            cap = min(cfg.max_active_cap, cfg.base_active_cap + cfg.expansion_step)
            bucket_limit = min(cfg.max_bucket_limit, cfg.base_bucket_limit + 1)
            reasons.append("sink_distance_improved")
        elif self.stagnant_rounds >= cfg.stagnation_window:
            tier = "stagnation_compression"
            shrink = cfg.shrink_step * (
                1 + self.stagnant_rounds - cfg.stagnation_window
            )
            cap = max(cfg.min_active_cap, cfg.base_active_cap - shrink)
            bucket_limit = 1
            reasons.append("stagnant_frontier")
        else:
            reasons.append("balanced_frontier")

        should_stop = False
        stop_reason: str | None = None
        liveness_blockers = source_liveness_stop_blockers(
            strong_source_obligation=strong_source_obligation,
            near_sink=bool(near_sink),
            protected=bool(protected),
        )
        if (
            cfg.source_dead_limit
            and self.source_dead_rounds >= cfg.source_dead_limit
        ):
            if not liveness_blockers:
                should_stop = True
                stop_reason = "adaptive_source_liveness_saturated"
                reasons.append(stop_reason)
            else:
                reasons.extend(
                    f"source_liveness_suppressed:{blocker}"
                    for blocker in liveness_blockers
                )

        decision = BudgetDecision(
            step=int(step),
            tier=tier,
            active_cap=int(cap),
            bucket_limit=int(bucket_limit),
            protected_states=int(protected),
            source_live_states=int(source_live),
            near_sink_states=int(near_sink),
            escape_quota=int(cfg.escape_quota),
            best_sink_distance=best,
            progress=progress,
            stagnant_rounds=int(self.stagnant_rounds),
            source_dead_rounds=int(self.source_dead_rounds),
            should_stop=should_stop,
            stop_reason=stop_reason,
            reasons=tuple(reasons),
        )
        self.decisions.append(decision)
        return decision

    def select_indices(
        self,
        projections: Sequence[StateProjection],
        decision: BudgetDecision,
    ) -> list[int]:
        """Select representatives while preserving protected and diverse states."""

        if len(projections) <= decision.active_cap:
            return [p.index for p in sorted(projections, key=StateProjection.rank_key)]

        ordered = sorted(projections, key=StateProjection.rank_key)
        selected: list[StateProjection] = []
        selected_indices: set[int] = set()

        def add(projection: StateProjection) -> None:
            if projection.index not in selected_indices and len(selected) < decision.active_cap:
                selected.append(projection)
                selected_indices.add(projection.index)

        protected = [p for p in ordered if p.protected]
        for projection in protected[: self.config.protected_quota]:
            add(projection)

        # Preserve the best source-carrying state even when it is outside the
        # near-sink window.  This is the scheduler's central fail-closed
        # liveness invariant.
        source_states = [p for p in ordered if p.source_carrier]
        if source_states:
            add(source_states[0])

        # Reserve the configured escape quota before filling semantic buckets.
        # The corridor is intentionally incomplete, so these states preserve
        # paths through unresolved indirect edges instead of being crowded out
        # by higher-ranked in-corridor representatives.
        escape_added = 0
        for projection in ordered:
            if projection.corridor_class not in {"escape", "unknown", "outside"}:
                continue
            if escape_added >= decision.escape_quota:
                break
            before = len(selected)
            add(projection)
            if len(selected) > before:
                escape_added += 1

        bucket_counts: dict[Hashable, int] = {}
        for projection in ordered:
            key = projection.diversity_key()
            if bucket_counts.get(key, 0) >= decision.bucket_limit:
                continue
            add(projection)
            if projection.index in selected_indices:
                bucket_counts[key] = bucket_counts.get(key, 0) + 1

        for projection in ordered:
            add(projection)
            if len(selected) >= decision.active_cap:
                break
        return [projection.index for projection in selected]

    def summary(self) -> dict[str, Any]:
        tiers: dict[str, int] = {}
        for decision in self.decisions:
            tiers[decision.tier] = tiers.get(decision.tier, 0) + 1
        return {
            "schema": SCHEDULER_SCHEMA,
            "decisions": len(self.decisions),
            "tiers": dict(sorted(tiers.items())),
            "best_sink_distance": self.best_distance,
            "max_active_cap": max(
                (decision.active_cap for decision in self.decisions), default=0
            ),
            "min_active_cap": min(
                (decision.active_cap for decision in self.decisions), default=0
            ),
            "stops_requested": sum(
                1 for decision in self.decisions if decision.should_stop
            ),
        }


def projections_from_rows(rows: Iterable[dict[str, Any]]) -> list[StateProjection]:
    """Construct projections from serialized test or replay records."""

    values = []
    for index, row in enumerate(rows):
        values.append(
            StateProjection(
                index=int(row.get("index", index)),
                pc=int(row.get("pc", 0)),
                sink_distance=(
                    None
                    if row.get("sink_distance") is None
                    else int(row.get("sink_distance"))
                ),
                source_carrier=bool(row.get("source_carrier")),
                propagated_source=bool(row.get("propagated_source")),
                near_sink=bool(row.get("near_sink")),
                sink_progress=int(row.get("sink_progress", 0)),
                quote_context=str(row.get("quote_context", "unknown")),
                constraint_digest=str(row.get("constraint_digest", "none:0")),
                return_signature=str(row.get("return_signature", "unknown")),
                corridor_class=str(row.get("corridor_class", "unknown")),
                constraint_count=int(row.get("constraint_count", 0)),
                semantic_key=tuple(row.get("semantic_key") or ()),
            )
        )
    return values
