import re
import unittest
from pathlib import Path

from audit_v20_downloaded_release import archive_prefix_locations


SCRIPT = Path(__file__).with_name("run_v20_post_release.sh")


class V20PostReleaseOrchestratorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = SCRIPT.read_text(encoding="utf-8")

    def test_archive_inputs_match_the_independent_release_audit(self):
        observed = set(re.findall(r'--input "([a-z_]+)=', self.text))
        expected = set(archive_prefix_locations(Path("fixture"), "tag", "v2")) | {
            "liveness_probe"
        }
        self.assertEqual(expected, observed)

    def test_claim_and_release_gates_are_fail_closed(self):
        for fragment in (
            "--out-dir \"$CLAIMS\" --require-ready",
            "--require-repeatability --require-negative-confirmation --minimum-negative-records 16",
            "--out-dir \"$READINESS\" --fail-on-issues",
            "--require-valid > \"$ARCHIVE_VERIFY\"",
            "TSDS_V20_EXPERIMENT_QUEUE_COMPLETE $TAG",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.text)

    def test_satc_ingestion_uses_one_manifest_for_the_consumed_keyword_slice(self):
        for stage in (
            "satc_js_parser_environment",
            "satc_keyword_extraction",
            "satc_keyword_slice",
            "satc_keyword_workload_identity",
            "satc_ingestion",
        ):
            with self.subTest(stage=stage):
                self.assertIn(f"run_stage {stage}", self.text)
        self.assertIn("--keyword-provenance-manifest", self.text)
        self.assertNotIn("--keyword-extraction-manifest", self.text)
        self.assertIn('"$SATC_SLICE/experiment_manifest.json"', self.text)
        self.assertIn('"$SATC_SLICE/keywords.sorted_prefix_32.txt"', self.text)
        self.assertNotIn("--require-identical", self.text)

    def test_verification_json_is_not_prefixed_by_stage_logging(self):
        start = self.text.index("run_stage() {")
        end = self.text.index("\n}\n", start) + 2
        helper = self.text[start:end]
        self.assertIn("printf 'POST_RELEASE_STAGE %q' \"$CURRENT_STAGE\" >&2", helper)
        self.assertIn("printf ' %q' \"$@\" >&2", helper)
        self.assertIn("printf '\\n' >&2", helper)

    def test_post_release_emits_a_terminal_stage_error(self):
        self.assertIn("set -eEuo pipefail", self.text)
        self.assertIn("POST_RELEASE_ERROR stage=%s exit_code=%s", self.text)
        self.assertIn('if "$@"; then', self.text)


if __name__ == "__main__":
    unittest.main()
