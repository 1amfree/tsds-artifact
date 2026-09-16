"""Tests for the finite exported-SMT model-binding audit."""

from __future__ import annotations

import json
from pathlib import Path

try:
    from experiments.audit_smt_model_binding import (
        _parse_sexpr,
        extract_model_text,
        model_assertions,
        remove_terminal_commands,
        select_manifests,
    )
except ModuleNotFoundError:  # pragma: no cover - direct pytest path invocation
    from audit_smt_model_binding import (
        _parse_sexpr,
        extract_model_text,
        model_assertions,
        remove_terminal_commands,
        select_manifests,
    )


def test_model_parser_renders_primitive_constant_assignments() -> None:
    text = """(model
      (define-fun x () (_ BitVec 8) #x41)
      (define-fun n () Int (- 1))
      (define-fun flag () Bool true)
    )"""
    assertions, info = model_assertions(text)
    assert "(assert (= x #x41))" in assertions
    assert "(assert (= flag true))" in assertions
    assert info["primitive_definitions"] == 3
    assert info["issues"] == []


def test_model_block_extraction_is_balanced() -> None:
    output = "sat\n(model\n  (define-fun x () Int 7)\n)\n"
    assert extract_model_text(output) == "(model\n  (define-fun x () Int 7)\n)"


def test_z3_cli_model_without_model_atom_is_supported() -> None:
    output = "sat\n(\n  (define-fun x () Int 7)\n)\n"
    model = extract_model_text(output)
    assert model == "(\n  (define-fun x () Int 7)\n)"
    assertions, info = model_assertions(model)
    assert assertions == ["(assert (= x 7))"]
    assert info["issues"] == []


def test_terminal_commands_are_replaced_without_dropping_assertions() -> None:
    query = "(declare-const x Int)\n(assert (= x 1))\n(check-sat)\n(get-model)\n"
    rendered = remove_terminal_commands(query)
    assert "(assert (= x 1))" in rendered
    assert "(check-sat)" not in rendered
    assert "(get-model)" not in rendered


def test_sexpr_parser_handles_bitvector_constructor() -> None:
    parsed = _parse_sexpr("(model (define-fun x () (_ BitVec 8) (_ bv65 8)))")
    assert parsed[0] == "model"
    assert parsed[1][4][1] == "bv65"


def test_manifest_selection_is_deterministic_and_stratified(tmp_path: Path) -> None:
    paths: list[Path] = []
    for target, decision in (("a", "SAT"), ("a", "UNSAT"), ("b", "SAT"), ("b", "UNSAT")):
        directory = tmp_path / target / decision
        directory.mkdir(parents=True)
        path = directory / f"{decision}.manifest.json"
        path.write_text(
            json.dumps({
                "schema": "tsds-solver-query-bundle-v1",
                "producer": {"decision": decision},
            }),
            encoding="utf-8",
        )
        paths.append(path)
    selected = select_manifests(sorted(paths), tmp_path, 4)
    assert selected == sorted(paths)
    selected_again = select_manifests(sorted(paths), tmp_path, 2)
    assert selected_again == select_manifests(sorted(paths), tmp_path, 2)
    assert {json.loads(path.read_text(encoding="utf-8"))["producer"]["decision"] for path in selected_again} == {"SAT", "UNSAT"}
