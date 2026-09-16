import argparse
import json
import tempfile
import unittest
from pathlib import Path

from experiments.build_satc_keyword_slice import build_slice, load_canonical_tokens
from experiments.run_satc_ghidra_experiment import sha256_file


class SaTCKeywordSliceTest(unittest.TestCase):
    def fixture(self, root: Path) -> argparse.Namespace:
        source = root / "keywords.canonical.txt"
        source.write_text("a\nb\nc\nd\n", encoding="utf-8")
        return argparse.Namespace(
            input=source,
            out_dir=root / "out",
            count=2,
            parent_manifest=None,
        )

    def test_sorted_prefix_slice_is_content_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(Path(directory))
            manifest = build_slice(args)
            self.assertTrue(manifest["success"])
            self.assertEqual(manifest["selection"], {"strategy": "sorted_prefix", "count": 2, "input_tokens": 4})
            self.assertEqual(
                (args.out_dir / "keywords.sorted_prefix_2.txt").read_text(encoding="utf-8"),
                "a\nb\n",
            )
            self.assertEqual(manifest["slice_output"]["size"], 4)

    def test_noncanonical_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keywords.txt"
            path.write_text("b\na\na\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_canonical_tokens(path)

    def test_parent_manifest_must_bind_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            parent = root / "keyword_parent.json"
            parent.write_text(
                json.dumps(
                    {
                        "schema": "tsds-satc-keyword-extraction-v1",
                        "success": True,
                        "environment": {"js_parser_environment_bound": True},
                        "keyword_output": {
                            "size": args.input.stat().st_size,
                            "sha256": sha256_file(args.input),
                        },
                    }
                ),
                encoding="utf-8",
            )
            args.parent_manifest = parent
            manifest = build_slice(args)
            self.assertIsNotNone(manifest["parent_keyword_manifest"])
            self.assertTrue(manifest["parent_js_parser_environment_bound"])

    def test_parent_manifest_requires_js_parser_lineage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            parent = root / "keyword_parent.json"
            parent.write_text(
                json.dumps(
                    {
                        "schema": "tsds-satc-keyword-extraction-v1",
                        "success": True,
                        "keyword_output": {
                            "size": args.input.stat().st_size,
                            "sha256": sha256_file(args.input),
                        },
                    }
                ),
                encoding="utf-8",
            )
            args.parent_manifest = parent
            with self.assertRaises(ValueError):
                build_slice(args)


if __name__ == "__main__":
    unittest.main()
