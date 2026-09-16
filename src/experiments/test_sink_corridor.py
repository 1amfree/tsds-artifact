#!/usr/bin/env python3

from __future__ import annotations

import unittest

from tsds.sink_corridor import build_corridor, build_trace_corridor, merge_corridors


class SinkCorridorTest(unittest.TestCase):
    def test_reverse_reachability_and_distance(self) -> None:
        corridor = build_corridor(
            [(1, 2), (2, 3), (4, 5)],
            [3],
            unresolved_sources=[4],
            complete=True,
        )
        self.assertEqual(2, corridor.distance(1))
        self.assertEqual("target", corridor.classify(3))
        self.assertEqual("inside", corridor.classify(2))
        self.assertEqual("escape", corridor.classify(4))
        self.assertEqual("outside", corridor.classify(99))

    def test_trace_corridor_is_incomplete_and_preserves_order(self) -> None:
        corridor = build_trace_corridor([0x30, 0x10, 0x20], [0x40])
        self.assertFalse(corridor.complete)
        self.assertEqual("guide", corridor.classify(0x10))
        self.assertEqual(3, corridor.distance(0x30))
        self.assertEqual(2, corridor.distance(0x10))
        self.assertEqual(1, corridor.distance(0x20))
        self.assertEqual("unknown", corridor.classify(0x999))

    def test_merge_prefers_shorter_structural_distance(self) -> None:
        primary = build_corridor([(1, 2), (2, 3)], [3], complete=True)
        supplemental = build_corridor([(1, 3)], [3], complete=False)
        merged = merge_corridors(primary, supplemental)
        self.assertEqual(1, merged.distance(1))
        self.assertTrue(merged.complete)
        self.assertEqual(64, len(merged.fingerprint()))


if __name__ == "__main__":
    unittest.main()
