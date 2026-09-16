#!/usr/bin/env python3

from __future__ import annotations

import os
import time
import unittest

from tsds.forkserver import fork_available, run_forked_json


def add_one(value: int) -> dict[str, int]:
    return {"value": value + 1, "pid": os.getpid()}


def fail_worker(_value: object) -> object:
    raise ValueError("fixture failure")


def slow_worker(_value: object) -> object:
    time.sleep(2.0)
    return None


def large_worker(_value: object) -> dict[str, str]:
    return {"payload": "x" * (2 * 1024 * 1024)}


@unittest.skipUnless(fork_available(), "POSIX fork is required")
class ForkserverTest(unittest.TestCase):
    def test_success_and_failure_are_serialized(self) -> None:
        success = run_forked_json(add_one, 4, timeout_sec=2.0)
        self.assertTrue(success.ok)
        self.assertEqual(5, success.payload["value"])
        self.assertNotEqual(os.getpid(), success.payload["pid"])
        failure = run_forked_json(fail_worker, None, timeout_sec=2.0)
        self.assertFalse(failure.ok)
        self.assertIn("ValueError", failure.error)

    def test_timeout_terminates_child(self) -> None:
        result = run_forked_json(slow_worker, None, timeout_sec=0.05)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.ok)

    def test_large_payload_is_drained_before_join(self) -> None:
        result = run_forked_json(large_worker, None, timeout_sec=3.0)
        self.assertTrue(result.ok)
        self.assertEqual(2 * 1024 * 1024, len(result.payload["payload"]))


if __name__ == "__main__":
    unittest.main()
