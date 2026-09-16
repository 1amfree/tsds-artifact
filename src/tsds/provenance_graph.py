"""Deterministic byte-level provenance graphs for TSDS sink evidence."""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence


PROVENANCE_GRAPH_SCHEMA = "tsds-byte-provenance-graph-v1"


def _variables(value: Any) -> tuple[str, ...]:
    try:
        return tuple(sorted(str(item) for item in value.variables))
    except (AttributeError, TypeError):
        return ()


def _digest(value: Any) -> str:
    try:
        op = str(getattr(value, "op", type(value).__name__))
        args = repr(getattr(value, "args", value))[:1024]
    except Exception:
        op, args = type(value).__name__, repr(value)[:1024]
    payload = json.dumps(
        {"op": op, "variables": _variables(value), "args": args},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:24]


@dataclass(frozen=True)
class ProvenanceNode:
    node_id: str
    kind: str
    label: str
    offset: int | None = None
    variables: tuple[str, ...] = ()
    digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["variables"] = list(value["variables"])
        return value


@dataclass(frozen=True)
class ProvenanceEdge:
    source: str
    target: str
    relation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ByteProvenanceGraph:
    def __init__(
        self,
        nodes: Iterable[ProvenanceNode] = (),
        edges: Iterable[ProvenanceEdge] = (),
        *,
        sink_id: str = "sink",
    ) -> None:
        self.nodes: dict[str, ProvenanceNode] = {node.node_id: node for node in nodes}
        self.edges: set[ProvenanceEdge] = set(edges)
        self.sink_id = sink_id

    def add_node(self, node: ProvenanceNode) -> None:
        self.nodes.setdefault(node.node_id, node)

    def add_edge(self, source: str, target: str, relation: str) -> None:
        if source in self.nodes and target in self.nodes:
            self.edges.add(ProvenanceEdge(source, target, relation))

    def paths_to_sink(self, source_id: str, max_paths: int = 16) -> list[list[str]]:
        adjacency: dict[str, list[str]] = {}
        for edge in sorted(self.edges, key=lambda item: (item.source, item.target, item.relation)):
            adjacency.setdefault(edge.source, []).append(edge.target)
        result: list[list[str]] = []
        queue: deque[list[str]] = deque([[source_id]])
        while queue and len(result) < max(1, int(max_paths)):
            path = queue.popleft()
            tail = path[-1]
            if tail == self.sink_id:
                result.append(path)
                continue
            for target in adjacency.get(tail, []):
                if target not in path:
                    queue.append(path + [target])
        return result

    def controlled_offsets(self, source_predicate: Callable[[str], bool] | None = None) -> list[int]:
        predicate = source_predicate or (lambda value: True)
        offsets = []
        for node in self.nodes.values():
            if node.kind != "sink_byte" or node.offset is None:
                continue
            ancestors = self._ancestors(node.node_id)
            if any(
                self.nodes[item].kind == "source_variable"
                and predicate(self.nodes[item].label)
                for item in ancestors
                if item in self.nodes
            ):
                offsets.append(int(node.offset))
        return sorted(set(offsets))

    def _ancestors(self, node_id: str) -> set[str]:
        reverse: dict[str, list[str]] = {}
        for edge in self.edges:
            reverse.setdefault(edge.target, []).append(edge.source)
        seen: set[str] = set()
        queue: deque[str] = deque([node_id])
        while queue:
            current = queue.popleft()
            for parent in reverse.get(current, []):
                if parent not in seen:
                    seen.add(parent)
                    queue.append(parent)
        return seen

    def to_dict(self) -> dict[str, Any]:
        nodes = [self.nodes[key].to_dict() for key in sorted(self.nodes)]
        edges = [
            edge.to_dict()
            for edge in sorted(self.edges, key=lambda item: (item.source, item.target, item.relation))
        ]
        value = {
            "schema": PROVENANCE_GRAPH_SCHEMA,
            "sink_id": self.sink_id,
            "nodes": nodes,
            "edges": edges,
        }
        value["graph_sha256"] = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return value


def build_byte_provenance_graph(
    sink_bytes: Sequence[Any],
    *,
    source_predicate: Callable[[str], bool] | None = None,
    transformations: Mapping[int, Sequence[str]] | None = None,
    max_variables_per_byte: int = 16,
) -> ByteProvenanceGraph:
    """Build a bounded DAG from sink AST variable sets and transform labels."""

    predicate = source_predicate or (lambda value: True)
    graph = ByteProvenanceGraph()
    graph.add_node(ProvenanceNode("sink", "sink", "final_command_argument"))
    transformations = transformations or {}
    for offset, byte_ast in enumerate(sink_bytes or []):
        variables = _variables(byte_ast)
        sink_id = f"sink_byte:{offset}"
        graph.add_node(
            ProvenanceNode(
                sink_id,
                "sink_byte",
                f"B[{offset}]",
                offset=offset,
                variables=variables,
                digest=_digest(byte_ast),
            )
        )
        graph.add_edge(sink_id, "sink", "part_of_argument")
        transform_id = f"transform:{offset}:{_digest(byte_ast)}"
        graph.add_node(
            ProvenanceNode(
                transform_id,
                "transform",
                str(getattr(byte_ast, "op", "concrete")),
                offset=offset,
                variables=variables,
                digest=_digest(byte_ast),
            )
        )
        graph.add_edge(transform_id, sink_id, "produces")
        for label in sorted(transformations.get(offset, ())):
            label_id = f"annotation:{offset}:{hashlib.sha256(str(label).encode()).hexdigest()[:12]}"
            graph.add_node(ProvenanceNode(label_id, "annotation", str(label), offset=offset))
            graph.add_edge(label_id, transform_id, "annotates")
        for variable in variables[: max(1, int(max_variables_per_byte))]:
            kind = "source_variable" if predicate(variable) else "symbolic_variable"
            source_id = f"variable:{hashlib.sha256(variable.encode()).hexdigest()[:16]}"
            graph.add_node(ProvenanceNode(source_id, kind, variable, variables=(variable,)))
            graph.add_edge(source_id, transform_id, "flows_to")
        if not variables:
            constant_id = f"constant:{offset}:{_digest(byte_ast)}"
            graph.add_node(ProvenanceNode(constant_id, "constant", "concrete", offset=offset, digest=_digest(byte_ast)))
            graph.add_edge(constant_id, transform_id, "flows_to")
    return graph

