#!/usr/bin/env python3

from __future__ import annotations

import unittest

from experiments.audit_vector_decision_integrity import (
    MATRIX_VECTOR_IDS,
    audit_records,
)


def _decision(vector_id: str, decision: str) -> dict:
    row = {
        "schema": "tsds-shell-witness-v3",
        "lexical_gate": "tsds-shell-lexical-gate-v1",
        "vector_id": vector_id,
        "vector": vector_id,
        "decision": decision,
        "grammar_complete": True,
        "parser_calibration": "unit-test-calibration",
    }
    if decision == "VECTOR_SAT":
        row.update(
            {
                "witness": ":;:;#",
                "lexical_reason": "lexically_complete",
                "lexical_model_source": "raw_solver_model",
            }
        )
    elif decision == "INCONCLUSIVE":
        row.update(
            {
                "reason": "incomplete_shell_lexeme",
                "rejected_witness": "prefix substitution trailing quote",
                "lexical_reason": "unterminated_quote",
                "lexical_model_source": "escaped_witness_decode",
            }
        )
    return row


def _record(decisions: list[dict], status: str = "vulnerable") -> dict:
    counts = {
        "VECTOR_SAT": sum(item["decision"] == "VECTOR_SAT" for item in decisions),
        "MATRIX_UNSAT": sum(
            item["decision"] == "MATRIX_UNSAT" for item in decisions
        ),
        "INCONCLUSIVE": sum(
            item["decision"] == "INCONCLUSIVE" for item in decisions
        ),
    }
    return {
        "status": status,
        "features": {
            "threat_matrix": True,
            "shell_lexical_gate": "tsds-shell-lexical-gate-v1",
        },
        "tainted_byte_count": 4,
        "vector_decisions": decisions,
        "vulnerable_vectors": counts["VECTOR_SAT"],
        "secure_vectors": counts["MATRIX_UNSAT"],
        "inconclusive_vectors": counts["INCONCLUSIVE"],
        "sanitizer_gap_profile": {
            "total_vectors": len(decisions),
            "vulnerable_count": counts["VECTOR_SAT"],
            "secure_count": counts["MATRIX_UNSAT"],
            "inconclusive_count": counts["INCONCLUSIVE"],
        },
    }


class VectorDecisionIntegrityAuditTest(unittest.TestCase):
    def test_complete_v14_matrix_is_consistent(self) -> None:
        decisions = [
            _decision(vector_id, "VECTOR_SAT" if index == 0 else "MATRIX_UNSAT")
            for index, vector_id in enumerate(MATRIX_VECTOR_IDS)
        ]
        rows, summary = audit_records([_record(decisions)])
        self.assertEqual(rows[0]["issues"], "")
        self.assertEqual(summary["records_with_integrity_issues"], 0)
        self.assertEqual(summary["decision_outcomes"]["VECTOR_SAT"], 1)
        self.assertEqual(summary["decision_outcomes"]["MATRIX_UNSAT"], 10)

    def test_lexical_inconclusive_requires_rejected_model_trace(self) -> None:
        decisions = [
            _decision(
                vector_id,
                (
                    "VECTOR_SAT"
                    if index == 0
                    else "INCONCLUSIVE"
                    if index == 1
                    else "MATRIX_UNSAT"
                ),
            )
            for index, vector_id in enumerate(MATRIX_VECTOR_IDS)
        ]
        rows, summary = audit_records([_record(decisions)])
        self.assertEqual(rows[0]["issues"], "")
        self.assertEqual(summary["lexical_reasons"]["unterminated_quote"], 1)

        decisions[1].pop("rejected_witness")
        rows, summary = audit_records([_record(decisions)])
        self.assertIn(
            "lexical_inconclusive_without_rejected_witness",
            rows[0]["issues"],
        )
        self.assertEqual(summary["records_with_integrity_issues"], 1)

    def test_missing_vector_and_counter_drift_fail_closed(self) -> None:
        decisions = [
            _decision(vector_id, "MATRIX_UNSAT")
            for vector_id in MATRIX_VECTOR_IDS[:-1]
        ]
        record = _record(decisions, status="filtered")
        record["secure_vectors"] = 11
        rows, summary = audit_records([record])
        self.assertIn("matrix_vector_count_mismatch", rows[0]["issues"])
        self.assertIn("matrix_vector_set_mismatch", rows[0]["issues"])
        self.assertIn(
            "vector_decision_count_disagrees_with_record",
            rows[0]["issues"],
        )
        self.assertEqual(summary["records_with_integrity_issues"], 1)

    def test_no_modeled_source_without_decisions_is_not_a_matrix_omission(self) -> None:
        record = {
            "status": "no_taint_sink",
            "features": {
                "threat_matrix": True,
                "shell_lexical_gate": "tsds-shell-lexical-gate-v1",
            },
            "tainted_byte_count": 0,
            "vector_decisions": [],
            "vulnerable_vectors": 0,
            "secure_vectors": 0,
            "inconclusive_vectors": 0,
        }
        rows, summary = audit_records([record])
        self.assertEqual(rows[0]["issues"], "")
        self.assertEqual(summary["records_with_integrity_issues"], 0)


if __name__ == "__main__":
    unittest.main()
