"""Closure-specific sink corridor construction and classification.

The data structure accepts a generic directed graph so it can be populated from
an angr CFG, a static front-end trace, or both.  Reverse reachability from exact
sink callsites gives a structural distance that is more meaningful than raw
address proximity while an explicit escape set preserves bounded exploration
around unresolved indirect edges.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping, Sequence


CORRIDOR_SCHEMA = "tsds-sink-corridor-v1"


def _ints(values: Iterable[Any]) -> tuple[int, ...]:
    result = set()
    for value in values:
        try:
            result.add(int(value))
        except (TypeError, ValueError):
            continue
    return tuple(sorted(result))


@dataclass(frozen=True)
class CorridorIndex:
    sinks: tuple[int, ...]
    guides: tuple[int, ...]
    wrappers: tuple[int, ...]
    reverse_distance: Mapping[int, int]
    escape_nodes: tuple[int, ...]
    graph_nodes: int
    graph_edges: int
    source: str
    complete: bool
    schema: str = CORRIDOR_SCHEMA

    def classify(self, pc: int) -> str:
        address = int(pc)
        if address in self.sinks:
            return "target"
        if address in self.guides:
            return "guide"
        if address in self.reverse_distance:
            return "inside"
        if address in self.escape_nodes:
            return "escape"
        return "outside" if self.complete else "unknown"

    def distance(self, pc: int) -> int | None:
        address = int(pc)
        if address in self.reverse_distance:
            return int(self.reverse_distance[address])
        if address in self.sinks:
            return 0
        return None

    def contains(self, pc: int) -> bool:
        return self.classify(pc) in {"target", "guide", "inside"}

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["reverse_distance"] = {
            hex(int(key)): int(distance)
            for key, distance in sorted(self.reverse_distance.items())
        }
        value["fingerprint"] = self.fingerprint()
        return value

    def fingerprint(self) -> str:
        document = {
            "sinks": list(self.sinks),
            "guides": list(self.guides),
            "wrappers": list(self.wrappers),
            "reverse_distance": sorted(
                (int(key), int(value)) for key, value in self.reverse_distance.items()
            ),
            "escape_nodes": list(self.escape_nodes),
            "source": self.source,
            "complete": self.complete,
        }
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(payload).hexdigest()


def build_corridor(
    edges: Iterable[tuple[int, int]],
    sinks: Iterable[int],
    *,
    guides: Iterable[int] = (),
    wrappers: Iterable[int] = (),
    unresolved_sources: Iterable[int] = (),
    max_reverse_nodes: int = 200_000,
    escape_hops: int = 1,
    source: str = "graph",
    complete: bool = True,
) -> CorridorIndex:
    sink_nodes = _ints(sinks)
    guide_nodes = _ints(guides)
    wrapper_nodes = _ints(wrappers)
    reverse: dict[int, set[int]] = {}
    forward: dict[int, set[int]] = {}
    edge_count = 0
    for raw_source, raw_target in edges:
        try:
            source_node = int(raw_source)
            target_node = int(raw_target)
        except (TypeError, ValueError):
            continue
        reverse.setdefault(target_node, set()).add(source_node)
        forward.setdefault(source_node, set()).add(target_node)
        reverse.setdefault(source_node, set())
        forward.setdefault(target_node, set())
        edge_count += 1

    distance: dict[int, int] = {}
    queue: deque[int] = deque()
    for node in (*sink_nodes, *wrapper_nodes):
        if node not in distance:
            distance[node] = 0
            queue.append(node)
    while queue and len(distance) < max(1, int(max_reverse_nodes)):
        node = queue.popleft()
        next_distance = distance[node] + 1
        for predecessor in sorted(reverse.get(node, ())):
            if predecessor in distance:
                continue
            distance[predecessor] = next_distance
            queue.append(predecessor)

    # A front-end trace is admissible as guidance even when a recovered CFG is
    # incomplete.  Give each guide a monotonic synthetic distance rather than
    # excluding it solely because an indirect edge was unresolved.
    previous = 0
    for node in reversed(guide_nodes):
        if node in distance:
            previous = distance[node]
        else:
            previous += 1
            distance[node] = previous

    escape: set[int] = set(_ints(unresolved_sources))
    frontier = set(escape)
    for _ in range(max(0, int(escape_hops))):
        expanded: set[int] = set()
        for node in frontier:
            expanded.update(forward.get(node, ()))
            expanded.update(reverse.get(node, ()))
        expanded.difference_update(distance)
        escape.update(expanded)
        frontier = expanded

    graph_nodes = len(set(reverse) | set(forward) | set(distance))
    return CorridorIndex(
        sinks=sink_nodes,
        guides=guide_nodes,
        wrappers=wrapper_nodes,
        reverse_distance=dict(sorted(distance.items())),
        escape_nodes=tuple(sorted(escape)),
        graph_nodes=graph_nodes,
        graph_edges=edge_count,
        source=str(source),
        complete=bool(complete),
    )


def build_trace_corridor(
    trace_addresses: Sequence[int],
    sinks: Iterable[int],
    *,
    wrappers: Iterable[int] = (),
) -> CorridorIndex:
    trace = _ints(trace_addresses)
    sink_nodes = _ints(sinks)
    wrapper_nodes = _ints(wrappers)
    # Preserve the supplied execution order rather than numeric sorting for
    # edges.  `_ints` is used only for identity sets above, so rebuild the
    # ordered list here.
    ordered: list[int] = []
    seen: set[int] = set()
    for value in trace_addresses:
        try:
            address = int(value)
        except (TypeError, ValueError):
            continue
        if address not in seen:
            seen.add(address)
            ordered.append(address)
    edges = list(zip(ordered, ordered[1:]))
    if ordered:
        for sink in sink_nodes:
            if ordered[-1] != sink:
                edges.append((ordered[-1], sink))
    for wrapper in wrapper_nodes:
        for sink in sink_nodes:
            edges.append((wrapper, sink))
    return build_corridor(
        edges,
        sink_nodes,
        guides=ordered or trace,
        wrappers=wrapper_nodes,
        source="front_end_trace",
        complete=False,
    )


def merge_corridors(primary: CorridorIndex, supplemental: CorridorIndex) -> CorridorIndex:
    distances = dict(primary.reverse_distance)
    for node, distance in supplemental.reverse_distance.items():
        distances[node] = min(distances.get(node, distance), distance)
    return CorridorIndex(
        sinks=_ints((*primary.sinks, *supplemental.sinks)),
        guides=_ints((*primary.guides, *supplemental.guides)),
        wrappers=_ints((*primary.wrappers, *supplemental.wrappers)),
        reverse_distance=dict(sorted(distances.items())),
        escape_nodes=_ints((*primary.escape_nodes, *supplemental.escape_nodes)),
        graph_nodes=max(primary.graph_nodes, supplemental.graph_nodes, len(distances)),
        graph_edges=primary.graph_edges + supplemental.graph_edges,
        source=f"{primary.source}+{supplemental.source}",
        complete=bool(primary.complete or supplemental.complete),
    )


def graph_edges_from_adjacency(adjacency: Mapping[int, Iterable[int]]) -> list[tuple[int, int]]:
    edges: list[tuple[int, int]] = []
    for source, targets in adjacency.items():
        for target in targets:
            edges.append((int(source), int(target)))
    return sorted(set(edges))
