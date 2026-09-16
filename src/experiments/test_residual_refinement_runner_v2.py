#!/usr/bin/env python3
"""Tests for the isolated v2 residual-refinement replay driver."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from experiments.run_residual_refinement_v2 import (
    command_for_replay,
    DETERMINISTIC_REPLAY_ENVIRONMENT,
    parse_result_marker,
    resolve_replay_python,
    run_one,
)


class ResidualRefinementRunnerV2Test(unittest.TestCase):
    def test_command_uses_list_arguments_and_fixture_scope(self) -> None:
        command = command_for_replay(
            Path("python"), Path("/repo"), "/bin/httpd", "/tmp/input.json", 2,
            {"max_steps": 1000}, fixture_path=Path("/tmp/fixture.json"), memory_limit_mib=512,
        )
        self.assertIn("--closure-idx", command)
        self.assertIn("2", command)
        self.assertIn("--env-fixture-json", command)
        self.assertIn(str(Path("/tmp/fixture.json")), command)
        self.assertIn("--subprocess-memory-limit-mib", command)
        self.assertIn("512", command)

    def test_marker_parser_uses_last_marker(self) -> None:
        output = "noise\nRESULT_JSON: " + json.dumps({"status": "residual"}) + "\n"
        self.assertEqual("residual", parse_result_marker(output)["status"])

    def test_explicit_venv_path_is_not_resolved_through_symlink(self) -> None:
        path = Path("virtualenv/bin/python")
        self.assertEqual(path.absolute(), resolve_replay_python(path))

    def test_replay_subprocess_receives_deterministic_environment(self) -> None:
        completed = type(
            "Completed",
            (),
            {
                "stdout": 'RESULT_JSON: {"status": "residual"}\n',
                "returncode": 0,
            },
        )()
        with patch(
            "experiments.run_residual_refinement_v2.subprocess.run",
            return_value=completed,
        ) as runner:
            result, returncode, _elapsed, _output = run_one(
                ["python", "worker.py"], Path("."), 10
            )
        self.assertEqual("residual", result["status"])
        self.assertEqual(0, returncode)
        child_env = runner.call_args.kwargs["env"]
        for key, value in DETERMINISTIC_REPLAY_ENVIRONMENT.items():
            self.assertEqual(value, child_env[key])


if __name__ == "__main__":
    unittest.main()
