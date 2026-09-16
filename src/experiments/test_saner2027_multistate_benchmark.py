from __future__ import annotations

from experiments.run_saner2027_multistate_benchmark import (
    classify,
    label_contract,
    profile_positive,
)
from tsds.multi_state_aggregation import (
    aggregate_sink_profiles,
    gate_negative_status_for_incomplete_collection,
    select_primary_state_index,
)
from tsds.shell_matrix_spec import VECTOR_IDS


def _profile(*, conditioned: bool = False, complete: bool = True, sat: bool = True) -> dict:
    decisions = [
        {
            "vector_id": vector_id,
            "decision": "VECTOR_SAT" if sat and index == 0 else "MATRIX_UNSAT",
        }
        for index, vector_id in enumerate(VECTOR_IDS)
    ]
    profile = {
        "claimable": True,
        "matrix_complete": complete,
        "expected_vector_ids": list(VECTOR_IDS),
        "vector_decisions": decisions,
        "status": "VECTOR_SAT" if sat else "MATRIX_UNSAT",
        "mode": "D",
        "evidence_scope_mode": "direct",
        "evidence_provenance": "DIRECT_SINK_BYTE",
        "primary_aggregate_eligible": True,
    }
    if conditioned:
        profile["mode"] = "C"
        profile["evidence_scope_mode"] = "conditioned"
        profile["evidence_provenance"] = "SINK_RECONCILED"
        profile["primary_aggregate_eligible"] = False
        profile["evidence_conditioning"] = "conditioned_template_feasibility"
    return profile


def test_benchmark_positive_reuses_direct_admission_gate() -> None:
    assert profile_positive(_profile()) is True
    assert profile_positive(_profile(conditioned=True)) is False
    assert profile_positive(_profile(complete=False)) is False


def test_benchmark_does_not_trust_top_level_vulnerable_status() -> None:
    record = {"status": "vulnerable", "multi_state_audit": {"profiles": []}}
    assert classify(record) == ("UNRESOLVED", False)


def test_benchmark_uses_selected_admissible_profile() -> None:
    record = {
        "status": "vulnerable",
        "multi_state_selection": {"selected_state_index": 1},
        "multi_state_audit": {
            "profiles": [_profile(complete=False), _profile()],
        },
    }
    assert classify(record) == ("POSITIVE", True)


def test_primary_selection_prefers_a_later_complete_positive() -> None:
    selection = select_primary_state_index(
        [_profile(sat=False), _profile(sat=True)]
    )
    assert selection["selected_state_index"] == 1
    assert selection["selected_reason"] == "later_collected_positive"
    assert selection["later_positive_observed"] is True


def test_label_contract_rejects_missing_or_unexpected_positive() -> None:
    rows = [
        {"index": 0, "expected": "POSITIVE", "primary_positive": False},
        {"index": 1, "expected": "NEGATIVE", "primary_positive": True},
    ]
    result = label_contract(rows)
    assert result["matches"] is False
    assert result["missing_expected_positive_indices"] == [0]
    assert result["unexpected_primary_positive_indices"] == [1]


def test_negative_gate_requires_a_complete_homogeneous_collection() -> None:
    unsat = _profile(sat=False)
    complete_aggregate = aggregate_sink_profiles(
        [unsat], collection_complete=True
    )
    complete_payload = {
        "collection_complete": True,
        "profiles": [unsat],
        "aggregate": complete_aggregate,
    }

    status, fields = gate_negative_status_for_incomplete_collection(
        "M-Filt", complete_payload
    )
    assert status == "M-Filt"
    assert fields == {}

    incomplete_aggregate = aggregate_sink_profiles(
        [unsat], collection_complete=False
    )
    status, fields = gate_negative_status_for_incomplete_collection(
        "M-Filt",
        {
            "collection_complete": False,
            "profiles": [unsat],
            "aggregate": incomplete_aggregate,
        },
    )
    assert status == "residual"
    assert fields["multi_state_negative_gate"] == "blocked"


def test_negative_gate_blocks_mixed_or_conditioned_profiles() -> None:
    unsat = _profile(sat=False)
    positive = _profile(sat=True)
    mixed = [unsat, positive]
    mixed_payload = {
        "collection_complete": True,
        "profiles": mixed,
        "aggregate": aggregate_sink_profiles(mixed, collection_complete=True),
    }
    status, fields = gate_negative_status_for_incomplete_collection(
        "M-Filt", mixed_payload
    )
    assert status == "residual"
    assert fields["multi_state_negative_gate"] == "blocked"


def test_negative_gate_respects_explicit_incomplete_accounting() -> None:
    unsat = _profile(sat=False)
    aggregate = aggregate_sink_profiles(
        [unsat],
        collection_complete=True,
        collection_accounting={"complete": False},
    )
    assert aggregate["collection_complete"] is False
    assert "collection_accounting_incomplete" in aggregate["collection_accounting"]["blockers"]
    status, fields = gate_negative_status_for_incomplete_collection(
        "M-Filt",
        {
            "collection_complete": True,
            "profiles": [unsat],
            "aggregate": aggregate,
        },
    )
    assert status == "residual"
    assert fields["multi_state_negative_gate"] == "blocked"

    conditioned = _profile(conditioned=True, sat=False)
    conditioned_payload = {
        "collection_complete": True,
        "profiles": [conditioned],
        "aggregate": aggregate_sink_profiles(
            [conditioned], collection_complete=True
        ),
    }
    status, fields = gate_negative_status_for_incomplete_collection(
        "M-Filt", conditioned_payload
    )
    assert status == "residual"
    assert fields["multi_state_negative_gate"] == "blocked"
