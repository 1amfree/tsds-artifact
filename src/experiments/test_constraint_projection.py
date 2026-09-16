#!/usr/bin/env python3

from __future__ import annotations

import unittest

from tsds.constraint_projection import ConstraintProjectionStore


class FakeAst:
    def __init__(self, op: str, variables: set[str], *args: object) -> None:
        self.op = op
        self.variables = variables
        self.args = args
        self.length = 8


class ConstraintProjectionTest(unittest.TestCase):
    def test_transitive_variable_closure(self) -> None:
        constraints = [
            FakeAst("Eq", {"sink", "bridge"}),
            FakeAst("Eq", {"bridge", "source"}),
            FakeAst("Eq", {"unrelated"}),
            True,
        ]
        store = ConstraintProjectionStore()
        result = store.project(constraints, [FakeAst("BVS", {"sink"})])
        self.assertEqual((0, 1, 3), result.selected_indices)
        self.assertEqual(("bridge", "sink", "source"), result.relevant_variables)

    def test_projection_and_query_caches(self) -> None:
        constraints = [FakeAst("Eq", {"x", "y"})]
        relevant = [FakeAst("BVS", {"x"})]
        store = ConstraintProjectionStore(max_entries=2)
        first = store.project(constraints, relevant)
        second = store.project(constraints, relevant)
        self.assertFalse(first.cache_hit)
        self.assertTrue(second.cache_hit)
        key = store.query_key(second, [FakeAst("Eq", {"x"})])
        self.assertIsNone(store.get_query(key))
        store.put_query(key, True)
        self.assertTrue(store.get_query(key))
        self.assertEqual(1, store.stats()["query_hits"])
        different_state = store.project(
            constraints + [FakeAst("Eq", {"unrelated"})], relevant
        )
        self.assertNotEqual(
            key,
            store.query_key(different_state, [FakeAst("Eq", {"x"})]),
        )


if __name__ == "__main__":
    unittest.main()
