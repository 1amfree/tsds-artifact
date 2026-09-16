from __future__ import annotations

import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("resume_v20_queue_after_runtime_audit.sh")


class V20QueueResumeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = SCRIPT.read_text(encoding="utf-8")

    def test_resume_is_bound_to_policy_audit_and_campaign_identities(self) -> None:
        for fragment in (
            '"schema") != "tsds-runtime-repeatability-v3"',
            '"sink_semantic_drift_common_records"',
            '"non_residual_evidence_drift_common_records"',
            '"unaccounted_residual_evidence_drift_common_records"',
            "campaign_results_identity(path)",
            'document.get("success") is not True',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.text)

    def test_resume_writes_observable_status_and_only_marks_complete_at_end(self) -> None:
        self.assertIn("set -eEuo pipefail", self.text)
        self.assertIn("tsds-v20-queue-resume-status-v1", self.text)
        self.assertIn('write_status "failed"', self.text)
        self.assertIn('if "$@"; then', self.text)
        marker = 'printf \'TSDS_V20_EXPERIMENT_QUEUE_COMPLETE %s\\n\''
        self.assertIn(marker, self.text)
        self.assertGreater(
            self.text.index(marker),
            self.text.index("run_stage blinded_role_packaging"),
        )

    def test_resume_does_not_rerun_expensive_campaign_or_matrix_stages(self) -> None:
        self.assertNotIn("run_full_firmware_campaign.py", self.text)
        self.assertNotIn("run_tsds_v19_experiment_matrix.py", self.text)
        for stage in (
            "runtime_validation_expansion",
            "shell_witness_syntax",
            "threat_matrix_boundary",
            "evidence_extension",
            "evidence_extension_verification",
            "blinded_role_packaging",
        ):
            with self.subTest(stage=stage):
                self.assertIn(f"run_stage {stage}", self.text)


if __name__ == "__main__":
    unittest.main()
