#!/usr/bin/env python3

from __future__ import annotations

import unittest

from tsds.evidence_scheduler import (
    EvidenceAwareScheduler,
    SchedulerConfig,
    StateProjection,
    source_liveness_stop_admissible,
    source_liveness_stop_blockers,
)


def projection(index: int, **kwargs: object) -> StateProjection:
    defaults = {
        "pc": 0x1000 + index * 4,
        "sink_distance": 100 + index,
        "source_carrier": False,
        "propagated_source": False,
        "near_sink": False,
        "corridor_class": "inside",
        "semantic_key": (index % 3,),
    }
    defaults.update(kwargs)
    return StateProjection(index=index, **defaults)


class EvidenceAwareSchedulerTest(unittest.TestCase):
    def test_preserves_last_source_carrier_under_pressure(self) -> None:
        scheduler = EvidenceAwareScheduler(
            SchedulerConfig(base_active_cap=4, min_active_cap=3, max_active_cap=6)
        )
        rows = [projection(i) for i in range(8)]
        rows[7] = projection(
            7,
            source_carrier=True,
            propagated_source=True,
            sink_distance=0x200,
        )
        decision = scheduler.observe(1, rows, rss_mib=10_000)
        selected = scheduler.select_indices(rows, decision)
        self.assertIn(7, selected)
        self.assertLessEqual(len(selected), decision.active_cap)

    def test_expands_for_protected_near_sink_state(self) -> None:
        scheduler = EvidenceAwareScheduler(
            SchedulerConfig(base_active_cap=10, min_active_cap=5, max_active_cap=30)
        )
        rows = [projection(0, source_carrier=True, propagated_source=True, near_sink=True, sink_distance=4)]
        decision = scheduler.observe(1, rows, strong_source_obligation=True)
        self.assertEqual("evidence_expansion", decision.tier)
        self.assertGreater(decision.active_cap, 10)

    def test_stagnation_compresses_and_source_dead_stops_fail_closed(self) -> None:
        scheduler = EvidenceAwareScheduler(
            SchedulerConfig(
                base_active_cap=20,
                min_active_cap=5,
                max_active_cap=40,
                stagnation_window=2,
                source_dead_limit=3,
            )
        )
        rows = [projection(i) for i in range(6)]
        scheduler.observe(1, rows)
        second = scheduler.observe(2, rows)
        third = scheduler.observe(3, rows)
        self.assertEqual("balanced", second.tier)
        self.assertEqual("stagnation_compression", third.tier)
        self.assertTrue(third.should_stop)
        self.assertEqual("adaptive_source_liveness_saturated", third.stop_reason)

    def test_strong_source_obligation_suppresses_incomplete_liveness_stop(self) -> None:
        scheduler = EvidenceAwareScheduler(
            SchedulerConfig(source_dead_limit=2)
        )
        rows = [projection(index) for index in range(6)]
        scheduler.observe(1, rows, strong_source_obligation=True)
        second = scheduler.observe(2, rows, strong_source_obligation=True)

        self.assertFalse(second.should_stop)
        self.assertTrue(
            source_liveness_stop_admissible(strong_source_obligation=False)
        )
        self.assertFalse(
            source_liveness_stop_admissible(strong_source_obligation=True)
        )
        self.assertFalse(
            source_liveness_stop_admissible(
                strong_source_obligation=False, near_sink=True
            )
        )
        self.assertFalse(
            source_liveness_stop_admissible(
                strong_source_obligation=False, protected=True
            )
        )
        self.assertEqual(
            ("strong_source_obligation", "near_sink_frontier"),
            source_liveness_stop_blockers(
                strong_source_obligation=True,
                near_sink=True,
            ),
        )

    def test_scheduler_records_liveness_suppression_reason(self) -> None:
        scheduler = EvidenceAwareScheduler(SchedulerConfig(source_dead_limit=1))
        rows = [projection(index, near_sink=True) for index in range(4)]
        decision = scheduler.observe(1, rows)
        self.assertFalse(decision.should_stop)
        self.assertIn(
            "source_liveness_suppressed:near_sink_frontier", decision.reasons
        )

    def test_selection_is_deterministic_and_diverse(self) -> None:
        scheduler = EvidenceAwareScheduler(
            SchedulerConfig(base_active_cap=5, min_active_cap=5, max_active_cap=5)
        )
        rows = [projection(i, semantic_key=(i % 4,)) for i in range(12)]
        decision = scheduler.observe(1, rows, strong_source_obligation=True)
        first = scheduler.select_indices(rows, decision)
        second = scheduler.select_indices(list(reversed(rows)), decision)
        self.assertEqual(first, second)
        self.assertGreaterEqual(len({rows[index].semantic_key for index in first}), 3)

    def test_incomplete_corridor_reserves_escape_quota(self) -> None:
        scheduler = EvidenceAwareScheduler(
            SchedulerConfig(
                base_active_cap=4,
                min_active_cap=4,
                max_active_cap=4,
                escape_quota=2,
            )
        )
        rows = [projection(index, corridor_class="inside") for index in range(8)]
        rows.extend(
            projection(index, corridor_class="outside", sink_distance=None)
            for index in range(8, 11)
        )
        decision = scheduler.observe(1, rows, strong_source_obligation=True)
        selected = scheduler.select_indices(rows, decision)
        self.assertEqual(
            2,
            sum(1 for index in selected if rows[index].corridor_class == "outside"),
        )


if __name__ == "__main__":
    unittest.main()
