import tempfile
import unittest
from pathlib import Path

try:  # Works for ``python -m unittest experiments.test_...``.
    from experiments.convert_satc_native_results import (
        convert_records,
        parse_satc_config,
        parse_satc_result,
    )
except ModuleNotFoundError:  # Works for discovery with ``-s experiments``.
    from convert_satc_native_results import (
        convert_records,
        parse_satc_config,
        parse_satc_result,
    )


class ConvertSaTCNativeResultsTest(unittest.TestCase):
    def test_result_and_config_are_converted_without_false_negatives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fixture.result-alter2"
            config.write_text(
                "0x100 0x110\n0x120\n0x200 0x201\n"
                "0x101 0x111\n\n0x202\n",
                encoding="utf-8",
            )
            result = root / "result-fixture.txt"
            result.write_text(
                "binary: /tmp/fixture\n"
                "configfile: /tmp/fixture.result-alter2\n"
                "0x100 0x110 found : 0x200\n"
                "0x101 0x111 not found\n"
                "total cases: 2\n"
                "find cases: 1\n",
                encoding="utf-8",
            )
            config_cases, config_issues = parse_satc_config(config)
            parsed = parse_satc_result(result)
            records, conversion_issues = convert_records(
                "fixture", config_cases, parsed["cases"]
            )
            self.assertEqual(config_issues, [])
            self.assertEqual(parsed["issues"], [])
            self.assertEqual(conversion_issues, [])
            verdicts = {
                (row["source_addr"], row["sink_addr"]): row["verdict"]
                for row in records
            }
            self.assertEqual(verdicts[("0x100", "0x200")], "POSITIVE")
            self.assertEqual(verdicts[("0x100", "0x201")], "UNRESOLVED")
            self.assertEqual(verdicts[("0x101", "0x202")], "NEGATIVE")

    def test_missing_case_is_residualized(self):
        config_cases = [
            {
                "case_idx": 0,
                "source_addr": "0x100",
                "start_addr": "0x110",
                "follow_trace": [],
                "expected_sinks": ["0x200"],
            }
        ]
        records, issues = convert_records("fixture", config_cases, [])
        self.assertEqual(issues, [])
        self.assertEqual(records[0]["verdict"], "UNRESOLVED")
        self.assertEqual(
            records[0]["stop_reason"], "satc_case_missing_from_result_file"
        )

    def test_result_parser_reports_silent_case_loss(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = Path(tmp) / "result.txt"
            result.write_text(
                "binary: fixture\n"
                "0x100 0x110 found : 0x200\n"
                "total cases: 2\n"
                "find cases: 2\n",
                encoding="utf-8",
            )
            parsed = parse_satc_result(result)
            self.assertIn("find_case_count_mismatch", parsed["issues"])


if __name__ == "__main__":
    unittest.main()
