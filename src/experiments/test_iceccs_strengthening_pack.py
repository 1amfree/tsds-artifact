import unittest

from experiments import build_iceccs_strengthening_pack as pack


class IceccsStrengtheningPackTest(unittest.TestCase):
    def test_validator_rows_include_full_and_naive_baselines(self) -> None:
        ablation = [
            {"config": "full", "analyzed": 10, "resolved": 8, "injectable": 3, "filtered": 1, "no_taint": 4, "residual": 2},
            {"config": "static_only", "analyzed": 10, "resolved": 0, "injectable": 0, "filtered": 0, "no_taint": 0, "residual": 0},
            {"config": "no_threat_matrix", "analyzed": 10, "resolved": 7, "injectable": 3, "filtered": 1, "no_taint": 3, "residual": 3},
            {"config": "no_firmware_summaries", "analyzed": 10, "resolved": 6, "injectable": 2, "filtered": 1, "no_taint": 3, "residual": 4},
            {"config": "no_reconciliation", "analyzed": 10, "resolved": 7, "injectable": 2, "filtered": 2, "no_taint": 3, "residual": 3},
            {"config": "no_path_control", "analyzed": 10, "resolved": 8, "injectable": 3, "filtered": 1, "no_taint": 4, "residual": 2},
        ]
        rows = pack.validator_rows(ablation)
        labels = {row["baseline"] for row in rows}
        self.assertIn("No-summary guided sink hook", labels)
        self.assertIn("Coarse metacharacter validator", labels)
        self.assertIn("Direct-only validator", labels)
        self.assertIn("Full TSDS", labels)

    def test_canary_rows_preserve_boundary(self) -> None:
        rows = pack.canary_rows(
            {
                "positive_canaries": [
                    {
                        "id": "sample",
                        "firmware": "fw",
                        "level": "handler-level runtime consistency",
                        "entry": "/goform/x",
                        "sink": "system@plt",
                    }
                ]
            }
        )
        self.assertIn("shell skipped", rows[0]["boundary"])
        self.assertNotIn("device", rows[0]["boundary"].lower())
        self.assertEqual(rows[-1]["id"], "Boundary probes")


if __name__ == "__main__":
    unittest.main()
