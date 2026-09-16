#!/usr/bin/env python3

from __future__ import annotations

import unittest

from tsds.provenance_graph import build_byte_provenance_graph


class FakeByte:
    def __init__(self, op: str, variables: set[str]) -> None:
        self.op = op
        self.variables = variables
        self.args = ()


class ProvenanceGraphTest(unittest.TestCase):
    def test_source_paths_and_controlled_offsets_are_deterministic(self) -> None:
        graph = build_byte_provenance_graph(
            [FakeByte("Concat", {"webvar_0_0"}), FakeByte("BVV", set())],
            source_predicate=lambda name: name.startswith("webvar_"),
            transformations={0: ["strcpy", "format"]},
        )
        document = graph.to_dict()
        source = next(node for node in document["nodes"] if node["kind"] == "source_variable")
        self.assertEqual([0], graph.controlled_offsets(lambda name: name.startswith("webvar_")))
        self.assertTrue(graph.paths_to_sink(source["node_id"]))
        self.assertEqual(document, graph.to_dict())


if __name__ == "__main__":
    unittest.main()

