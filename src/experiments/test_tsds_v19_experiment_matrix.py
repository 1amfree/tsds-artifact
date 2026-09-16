#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from run_tsds_v19_experiment_matrix import (
    build_campaign_command,
    canonical_digest,
    completed_campaign,
    parse_configurations,
    preserve_executable_path,
    prepare_plan,
)


class V19ExperimentMatrixTest(unittest.TestCase):
    def test_configuration_names_are_unique_and_validated(self) -> None:
        self.assertEqual(
            ["full", "p1_projection_off"],
            parse_configurations("full,p1_projection_off,full"),
        )
        with self.assertRaises(ValueError):
            parse_configurations("full,unknown")
        self.assertNotIn("p2_refinement_replay", parse_configurations(""))

    def test_command_replaces_backend_and_forwards_slice_controls(self) -> None:
        args = SimpleNamespace(
            python=Path("python"),
            campaign_driver=Path("campaign.py"),
            root=Path("root"),
            evaluator=Path("evaluator.py"),
            engine_timeout=45,
            max_steps=500,
            closure_timeout=90,
            subprocess_timeout=150,
            subprocess_memory_limit_mib=8192,
            target_timeout=7200,
            max_closures=12,
            target=["dir878", "xr300"],
            generate_refinement_bundles=False,
            refinement_bundle_dir=None,
            dry_run=False,
        )
        command = build_campaign_command(
            args,
            "p1_spawn_backend",
            Path("out"),
        )
        joined = " ".join(str(value) for value in command)
        self.assertIn("--max-closures 12", joined)
        self.assertIn("--target dir878 --target xr300", joined)
        self.assertEqual(1, command.count("--execution-backend"))
        backend_index = command.index("--execution-backend")
        self.assertEqual("spawn", command[backend_index + 1])

    def test_refinement_replay_binds_target_bundle_directory(self) -> None:
        args = SimpleNamespace(
            python=Path("python"),
            campaign_driver=Path("campaign.py"),
            root=Path("root"),
            evaluator=Path("evaluator.py"),
            engine_timeout=45,
            max_steps=500,
            closure_timeout=90,
            subprocess_timeout=150,
            subprocess_memory_limit_mib=8192,
            target_timeout=7200,
            max_closures=2,
            target=[],
            generate_refinement_bundles=False,
            refinement_bundle_dir=Path("bundles"),
            dry_run=False,
        )
        command = build_campaign_command(
            args, "p2_refinement_replay", Path("out")
        )
        index = command.index("--refinement-bundle-dir")
        self.assertEqual("bundles", str(command[index + 1]))

    def test_plan_is_immutable_and_resume_requires_same_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "matrix"
            identity = {"schema": "fixture", "value": 1}
            plan = prepare_plan(out, identity, resume=False)
            self.assertEqual(canonical_digest(identity), plan["identity_sha256"])
            resumed = prepare_plan(out, identity, resume=True)
            self.assertEqual(plan, resumed)
            with self.assertRaises(ValueError):
                prepare_plan(out, {"schema": "fixture", "value": 2}, resume=True)
            with self.assertRaises(ValueError):
                prepare_plan(out, identity, resume=False)

    def test_completed_campaign_requires_successful_nonempty_target_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Path(tmp)
            aggregate = campaign / "full_campaign_aggregate.json"
            aggregate.write_text(
                json.dumps({"targets": [{"returncode": 0}]}), encoding="utf-8"
            )
            self.assertTrue(completed_campaign(campaign))
            aggregate.write_text(
                json.dumps({"targets": [{"returncode": 1}]}), encoding="utf-8"
            )
            self.assertFalse(completed_campaign(campaign))

    def test_python_executable_path_preserves_virtualenv_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            interpreter = root / "python3"
            interpreter.write_bytes(b"fixture")
            launcher = root / "venv" / "bin" / "python"
            launcher.parent.mkdir(parents=True)
            try:
                launcher.symlink_to(interpreter)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")

            normalized = preserve_executable_path(launcher)
            self.assertEqual(launcher.absolute(), normalized)
            self.assertNotEqual(interpreter.resolve(), normalized)


if __name__ == "__main__":
    unittest.main()
