"""Source-projected path-constraint slicing and deterministic query caching."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Iterable, Sequence


PROJECTION_SCHEMA = "tsds-source-projected-constraints-v1"


def expression_variables(expression: Any) -> frozenset[str]:
    try:
        return frozenset(str(value) for value in expression.variables)
    except (AttributeError, TypeError):
        return frozenset()


def expression_fingerprint(expression: Any, depth: int = 0) -> Any:
    """Return a bounded structural representation for AST-like values."""

    if depth >= 32:
        return ["depth_limit", sorted(expression_variables(expression))]
    if expression is None or isinstance(expression, (bool, int, float, str)):
        return expression
    op = getattr(expression, "op", None)
    args = getattr(expression, "args", None)
    if op is not None and args is not None:
        return [
            "ast",
            str(op),
            [expression_fingerprint(item, depth + 1) for item in list(args)[:128]],
            sorted(expression_variables(expression)),
            int(getattr(expression, "length", 0) or 0),
        ]
    if isinstance(expression, (tuple, list)):
        return [expression_fingerprint(item, depth + 1) for item in expression[:128]]
    if isinstance(expression, dict):
        return {
            str(key): expression_fingerprint(value, depth + 1)
            for key, value in sorted(expression.items(), key=lambda item: str(item[0]))
        }
    return ["opaque", type(expression).__name__, repr(expression)[:512]]


def canonical_digest(values: Iterable[Any]) -> str:
    document = [expression_fingerprint(value) for value in values]
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class ProjectionResult:
    selected_constraints: tuple[Any, ...]
    selected_indices: tuple[int, ...]
    relevant_variables: tuple[str, ...]
    full_count: int
    projected_count: int
    full_digest: str
    projected_digest: str
    closure_rounds: int
    cache_hit: bool = False
    schema: str = PROJECTION_SCHEMA

    def metadata(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "selected_indices": list(self.selected_indices),
            "relevant_variables": list(self.relevant_variables),
            "full_count": self.full_count,
            "projected_count": self.projected_count,
            "full_digest": self.full_digest,
            "projected_digest": self.projected_digest,
            "closure_rounds": self.closure_rounds,
            "cache_hit": self.cache_hit,
        }


class ConstraintProjectionStore:
    """LRU-backed transitive variable-hypergraph slicer."""

    def __init__(self, max_entries: int = 2048) -> None:
        self.max_entries = max(1, int(max_entries))
        self._projection_cache: OrderedDict[str, tuple[tuple[int, ...], tuple[str, ...], int]] = OrderedDict()
        self._query_cache: OrderedDict[str, bool] = OrderedDict()
        self.projection_hits = 0
        self.projection_misses = 0
        self.query_hits = 0
        self.query_misses = 0

    def _remember(self, cache: OrderedDict[str, Any], key: str, value: Any) -> None:
        cache[key] = value
        cache.move_to_end(key)
        while len(cache) > self.max_entries:
            cache.popitem(last=False)

    def project(
        self,
        constraints: Sequence[Any],
        relevant_expressions: Sequence[Any],
    ) -> ProjectionResult:
        rows = tuple(constraints)
        full_digest = canonical_digest(rows)
        seed_variables = set()
        for expression in relevant_expressions:
            seed_variables.update(expression_variables(expression))
        seed_digest = canonical_digest(relevant_expressions)
        cache_key = f"{full_digest}:{seed_digest}"
        cached = self._projection_cache.get(cache_key)
        if cached is not None:
            self.projection_hits += 1
            self._projection_cache.move_to_end(cache_key)
            indices, variables, rounds = cached
            selected = tuple(rows[index] for index in indices)
            return ProjectionResult(
                selected_constraints=selected,
                selected_indices=indices,
                relevant_variables=variables,
                full_count=len(rows),
                projected_count=len(selected),
                full_digest=full_digest,
                projected_digest=canonical_digest(selected),
                closure_rounds=rounds,
                cache_hit=True,
            )

        self.projection_misses += 1
        variable_sets = [expression_variables(row) for row in rows]
        relevant = set(seed_variables)
        selected: set[int] = {
            index for index, variables in enumerate(variable_sets) if not variables
        }
        rounds = 0
        changed = True
        while changed:
            rounds += 1
            changed = False
            for index, variables in enumerate(variable_sets):
                if index in selected:
                    continue
                if variables & relevant:
                    selected.add(index)
                    before = len(relevant)
                    relevant.update(variables)
                    changed = changed or len(relevant) != before
            # Selecting a constraint is itself a fixed-point change even when
            # it adds no new variable; one more scan is unnecessary then.
            if not changed:
                break
        indices = tuple(sorted(selected))
        variables = tuple(sorted(relevant))
        selected_rows = tuple(rows[index] for index in indices)
        self._remember(self._projection_cache, cache_key, (indices, variables, rounds))
        return ProjectionResult(
            selected_constraints=selected_rows,
            selected_indices=indices,
            relevant_variables=variables,
            full_count=len(rows),
            projected_count=len(selected_rows),
            full_digest=full_digest,
            projected_digest=canonical_digest(selected_rows),
            closure_rounds=rounds,
        )

    def query_key(self, projection: ProjectionResult, extra_constraints: Sequence[Any]) -> str:
        return (
            f"{projection.full_digest}:{projection.projected_digest}:"
            f"{canonical_digest(extra_constraints)}"
        )

    def get_query(self, key: str) -> bool | None:
        if key not in self._query_cache:
            self.query_misses += 1
            return None
        self.query_hits += 1
        value = self._query_cache[key]
        self._query_cache.move_to_end(key)
        return bool(value)

    def put_query(self, key: str, satisfiable: bool) -> None:
        self._remember(self._query_cache, key, bool(satisfiable))

    def stats(self) -> dict[str, int | str]:
        return {
            "schema": PROJECTION_SCHEMA,
            "projection_hits": self.projection_hits,
            "projection_misses": self.projection_misses,
            "query_hits": self.query_hits,
            "query_misses": self.query_misses,
            "projection_entries": len(self._projection_cache),
            "query_entries": len(self._query_cache),
        }
