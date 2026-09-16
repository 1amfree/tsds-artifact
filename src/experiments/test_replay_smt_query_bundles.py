"""Dependency-light tests for isolated SMT replay bookkeeping."""

from __future__ import annotations

import hashlib
import json
import shlex
import sys
import tempfile
import unittest
from pathlib import Path

from experiments.replay_smt_query_bundles import (
    compare,
    extract_model_text,
    _model_check_query,
    parse_solver_result,
    replay_file,
    replay_manifest,
    safe_member,
)


class SMTReplayBundleTests(unittest.TestCase):
    def test_solver_argv_is_shell_free_and_supports_interpreter_wrappers(self) -> None:
        command = "/opt/venv/bin/python wrapper.py --mode replay"
        self.assertEqual(
            ["/opt/venv/bin/python", "wrapper.py", "--mode", "replay"],
            shlex.split(command, posix=True),
        )

    def test_parse_solver_result_preserves_unknown(self) -> None:
        self.assertEqual(parse_solver_result("sat\n"), "SAT")
        self.assertEqual(parse_solver_result("unsat\n"), "UNSAT")
        self.assertEqual(parse_solver_result("solver did not decide"), "UNKNOWN")

    def test_compare_does_not_turn_unknown_into_a_match(self) -> None:
        self.assertEqual(compare(None, "SAT"), "UNKNOWN")
        self.assertEqual(compare("UNKNOWN", "UNSAT"), "UNKNOWN")
        self.assertEqual(compare("SAT", "SAT"), "MATCH")
        self.assertEqual(compare("SAT", "UNSAT"), "MISMATCH")
        self.assertEqual(compare("SAT", "CACHED"), "NOT_APPLICABLE")

    def test_model_text_is_extracted_only_from_solver_output(self) -> None:
        self.assertEqual("(model\n  (define-fun x () Int 7)\n)", extract_model_text("sat\n(model\n  (define-fun x () Int 7)\n)\n"))
        self.assertIsNone(extract_model_text("sat\n"))

    def test_model_check_removes_embedded_get_model_request(self) -> None:
        rendered = _model_check_query(
            "(declare-const x Int)\n(check-sat)\n(get-model)\n",
            ["(assert (= x 7))"],
        )
        self.assertNotIn("(get-model)", rendered)
        self.assertTrue(rendered.endswith("(check-sat)\n"))

    def test_member_validation_rejects_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIsNotNone(safe_member(root, "query.smt2"))
            self.assertIsNone(safe_member(root, "../query.smt2"))

    def test_missing_solver_is_unavailable_not_unsat(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            query = root / "q.full.smt2"
            query.write_text("(set-logic QF_LIA)\n(check-sat)\n", encoding="utf-8")
            manifest = root / "q.manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "tsds-solver-query-bundle-v1",
                        "query_id": "q",
                        "files": {"full": query.name, "projected": None},
                        "sha256": {
                            "full_smt2": hashlib.sha256(query.read_bytes()).hexdigest(),
                            "projected_smt2": None,
                        },
                        "producer": {
                            "decision": "UNSAT",
                            "full_result": "UNSAT",
                            "projected_result": "NOT_RUN",
                            "full_validation": "performed",
                        },
                    }
                ),
                encoding="utf-8",
            )
            receipt = replay_manifest(
                manifest,
                ["definitely-not-a-solver"],
                timeout=1,
                root=root,
            )
            self.assertEqual(receipt["status"], "OK")
            self.assertEqual(receipt["replays"][0]["status"], "UNAVAILABLE")
            self.assertEqual(receipt["replays"][0]["observed"], None)
            self.assertEqual(receipt["replays"][0]["comparison"], "UNKNOWN")

    def test_external_argv_solver_produces_a_real_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            query = root / "q.smt2"
            query.write_text("; emit-sat\n(check-sat)\n", encoding="utf-8")
            solver = root / "reference_solver.py"
            solver.write_text(
                "from pathlib import Path\n"
                "import sys\n"
                "payload = Path(sys.argv[1]).read_text(encoding='utf-8')\n"
                "print('sat' if 'emit-sat' in payload else 'unsat')\n",
                encoding="utf-8",
            )
            replay = replay_file(
                [sys.executable, str(solver)],
                query,
                timeout=5,
                root=root,
            )
            self.assertEqual(replay["status"], "OK")
            self.assertEqual(replay["observed"], "SAT")
            self.assertEqual(compare(replay["observed"], "SAT"), "MATCH")

    def test_external_argv_solver_mismatch_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            query = root / "q.full.smt2"
            query.write_text("; emit-sat\n(check-sat)\n", encoding="utf-8")
            manifest = root / "q.manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "tsds-solver-query-bundle-v1",
                        "query_id": "q",
                        "files": {"full": query.name, "projected": None},
                        "sha256": {
                            "full_smt2": hashlib.sha256(query.read_bytes()).hexdigest(),
                            "projected_smt2": None,
                        },
                        "producer": {
                            "decision": "UNSAT",
                            "full_result": "UNSAT",
                            "projected_result": "NOT_RUN",
                            "full_validation": "performed",
                        },
                    }
                ),
                encoding="utf-8",
            )
            solver = root / "reference_solver.py"
            solver.write_text(
                "print('sat')\n",
                encoding="utf-8",
            )
            receipt = replay_manifest(
                manifest,
                [[sys.executable, str(solver)]],
                timeout=5,
                root=root,
            )
            self.assertEqual(receipt["status"], "OK")
            self.assertEqual(receipt["replays"][0]["comparison"], "MISMATCH")

    def test_sat_model_that_violates_full_query_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            query = root / "model.full.smt2"
            query.write_text(
                "(set-logic QF_LIA)\n"
                "(declare-const x Int)\n"
                "(assert (= x 7))\n"
                "(check-sat)\n",
                encoding="utf-8",
            )
            solver = root / "restricted_reference_checker.py"
            solver.write_text(
                "from pathlib import Path\n"
                "import sys\n"
                "payload = Path(sys.argv[1]).read_text(encoding='utf-8')\n"
                "print('unsat' if '(assert (= x 8))' in payload else 'sat')\n",
                encoding="utf-8",
            )
            manifest = root / "model.manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "tsds-solver-query-bundle-v1",
                        "query_id": "model",
                        "files": {"full": query.name, "projected": None},
                        "sha256": {
                            "full_smt2": hashlib.sha256(query.read_bytes()).hexdigest(),
                            "projected_smt2": None,
                        },
                        "producer": {
                            "decision": "SAT",
                            "full_result": "SAT",
                            "projected_result": "NOT_RUN",
                            "full_validation": "performed",
                            "model": {
                                "status": "provided",
                                "scope": "full_model",
                                "assignments": [
                                    {"name": "x", "sort": "Int", "value": 8}
                                ],
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            receipt = replay_manifest(
                manifest,
                [[sys.executable, str(solver)]],
                timeout=5,
                root=root,
            )
            replay = receipt["replays"][0]
            self.assertEqual(replay["comparison"], "MATCH")
            self.assertEqual(replay["model_check"]["comparison"], "MISMATCH")
            self.assertEqual(replay["model_check"]["observed"], "UNSAT")

    def test_external_model_request_is_recorded_without_claiming_producer_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            query = root / "model_request.full.smt2"
            query.write_text(
                "(set-logic QF_LIA)\n"
                "(declare-const x Int)\n"
                "(assert (= x 7))\n"
                "(check-sat)\n"
                "(get-model)\n",
                encoding="utf-8",
            )
            manifest = root / "model_request.manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "tsds-solver-query-bundle-v1",
                        "query_id": "model_request",
                        "files": {"full": query.name, "projected": None},
                        "sha256": {
                            "full_smt2": hashlib.sha256(query.read_bytes()).hexdigest(),
                            "projected_smt2": None,
                        },
                        "producer": {
                            "decision": "SAT",
                            "full_result": "SAT",
                            "projected_result": "NOT_RUN",
                            "full_validation": "performed",
                            "model": {"status": "embedded_get_model_request"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            solver = root / "model_solver.py"
            solver.write_text(
                "print('sat')\n"
                "print('(model\\n  (define-fun x () Int 7)\\n)')\n",
                encoding="utf-8",
            )
            receipt = replay_manifest(
                manifest,
                [[sys.executable, str(solver)]],
                timeout=5,
                root=root,
            )
            model = receipt["replays"][0]["external_model"]
            self.assertEqual(model["status"], "CAPTURED")
            self.assertIn("define-fun x", model["text"])


if __name__ == "__main__":
    unittest.main()
