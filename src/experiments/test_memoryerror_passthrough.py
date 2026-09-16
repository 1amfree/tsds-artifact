#!/usr/bin/env python3

from __future__ import annotations

import unittest

from experiments.enforce_memoryerror_passthrough import transform


class MemoryErrorPassthroughTest(unittest.TestCase):
    def test_broad_handlers_receive_passthrough_guard(self) -> None:
        source = "try:\n    work()\nexcept Exception as exc:\n    recover(exc)\n"
        transformed, inserted = transform(source)
        self.assertEqual(1, inserted)
        self.assertIn("except MemoryError:\n    raise\nexcept Exception as exc:", transformed)

    def test_transform_is_idempotent(self) -> None:
        source = (
            "try:\n    work()\nexcept MemoryError:\n    raise\n"
            "except Exception:\n    recover()\n"
        )
        transformed, inserted = transform(source)
        self.assertEqual(0, inserted)
        self.assertEqual(source, transformed)


if __name__ == "__main__":
    unittest.main()
