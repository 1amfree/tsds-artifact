from __future__ import annotations

import stat
import tempfile
import unittest
from io import BytesIO
from dataclasses import dataclass
from pathlib import Path

from experiments.fetch_v20_release import (
    FETCH_STATUS_SCHEMA,
    download_tree,
    build_downloaded_manuscript_binding,
    remote_terminal_failure,
    release_names,
    required_remote_paths,
    relative_remote_path,
    wait_for_release,
)


@dataclass
class Attribute:
    filename: str
    st_mode: int
    st_size: int = 0


class FakeSftp:
    def __init__(self, directories: dict[str, list[Attribute]], files: dict[str, bytes]) -> None:
        self.directories = directories
        self.files = files

    def listdir_attr(self, path: str):
        return self.directories[path]

    def get(self, remote_path: str, local_path: str) -> None:
        Path(local_path).write_bytes(self.files[remote_path])

    def stat(self, path: str) -> Attribute:
        if path in self.directories:
            return Attribute(Path(path).name, stat.S_IFDIR | 0o755)
        if path in self.files:
            return Attribute(Path(path).name, stat.S_IFREG | 0o644, len(self.files[path]))
        raise OSError(path)

    def open(self, path: str, mode: str):
        if mode != "rb" or path not in self.files:
            raise OSError(path)
        return BytesIO(self.files[path])


class ReleaseFetchPathTest(unittest.TestCase):
    def test_release_names_include_every_expected_stage(self) -> None:
        names = release_names("20260717_r5", "v2")
        self.assertIn("tsds_v20_full_20260717_r5", names)
        self.assertIn("tsds_v20_accepted_repeat_20260717_r5", names)
        self.assertIn("tsds_v20_post_release_20260717_r5_v2", names)
        self.assertEqual(len(names), len(set(names)))

    def test_required_paths_bind_marker_and_post_release_summary(self) -> None:
        paths = required_remote_paths("/reports", "r5", "v2")
        self.assertEqual("/reports/tsds_v20_experiment_queue_r5.complete", paths["queue_marker"])
        self.assertEqual(
            "/reports/tsds_v20_post_release_r5_v2/post_release_summary.json",
            paths["post_release_summary"],
        )
        self.assertEqual("/reports/tsds_v20_post_release_r5_v2", paths["post_release_root"])

    def test_terminal_post_release_failure_is_reported_without_waiting(self) -> None:
        paths = required_remote_paths("/reports", "r5", "v2")
        error_log = paths["post_release_root"] + "/orchestrator.stderr.log"
        sftp = FakeSftp(
            {paths["post_release_root"]: []},
            {error_log: b"POST_RELEASE_ABORT queue marker missing\n"},
        )
        self.assertEqual(
            "POST_RELEASE_ABORT queue marker missing",
            remote_terminal_failure(sftp, paths),
        )
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory) / "fetch.status.json"
            with self.assertRaisesRegex(RuntimeError, "remote post-release failed"):
                wait_for_release(
                    sftp,
                    paths,
                    timeout_seconds=30,
                    poll_seconds=1,
                    status_path=status,
                    tag="r5",
                    post_release_suffix="v2",
                )
            document = __import__("json").loads(status.read_text(encoding="utf-8"))
            self.assertEqual(FETCH_STATUS_SCHEMA, document["schema"])
            self.assertEqual("failed", document["state"])
            self.assertEqual("remote_post_release_failure", document["phase"])

    def test_rejects_unsafe_tag(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsafe"):
            release_names("r5/../../bad", "v2")

    def test_relative_remote_path_stays_below_root(self) -> None:
        self.assertEqual(
            "nested/file.json",
            relative_remote_path("/reports/run", "/reports/run/nested/file.json").as_posix(),
        )
        with self.assertRaises(ValueError):
            relative_remote_path("/reports/run", "/reports/other/file.json")

    def test_download_tree_preserves_file_identity(self) -> None:
        remote = "/reports/run"
        sftp = FakeSftp(
            {
                remote: [
                    Attribute("nested", stat.S_IFDIR | 0o755),
                    Attribute("summary.json", stat.S_IFREG | 0o644, 2),
                ],
                remote + "/nested": [
                    Attribute("records.jsonl", stat.S_IFREG | 0o644, 3),
                ],
            },
            {
                remote + "/summary.json": b"{}",
                remote + "/nested/records.jsonl": b"row",
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            rows = download_tree(sftp, remote, Path(directory))
            self.assertEqual(["nested/records.jsonl", "summary.json"], [row["path"] for row in rows])
            self.assertEqual(b"row", (Path(directory) / "nested" / "records.jsonl").read_bytes())

    def test_download_tree_rejects_remote_symbolic_link(self) -> None:
        remote = "/reports/run"
        sftp = FakeSftp(
            {remote: [Attribute("link", stat.S_IFLNK | 0o777)]},
            {},
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                download_tree(sftp, remote, Path(directory))

    def test_downloaded_release_emits_bound_manuscript_values(self) -> None:
        import hashlib
        import json

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            accepted = root / "tsds_v20_accepted_repeat_r5"
            manifest = accepted / "pipeline_manifest.json"
            paper = accepted / "paper_tables" / "paper_data_summary.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps({"schema": "tsds-v18-pipeline-v7", "success": True}),
                encoding="utf-8",
            )
            paper.parent.mkdir(parents=True)
            paper.write_text(
                json.dumps(
                    {
                        "all_contract_valid": True,
                        "records": 3,
                        "verdicts": {
                            "VECTOR_SAT": 1,
                            "MATRIX_UNSAT": 0,
                            "NO_MODELED_SOURCE": 1,
                            "STATIC_SOURCE_INFERENCE": 0,
                            "STATIC_WARNING_REDUCTION": 0,
                            "RESIDUAL": 1,
                        },
                    }
                ),
                encoding="utf-8",
            )
            digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            claim = root / "tsds_v20_post_release_r5_v2" / "claims" / "claim_evidence_matrix.json"
            claim.parent.mkdir(parents=True)
            claim.write_text(
                json.dumps(
                    {
                        "schema": "tsds-v20-claim-evidence-matrix-v1",
                        "ready_for_full_paper_writing": True,
                        "claims": [{"claim_id": "C1", "status": "supported"}],
                        "input_summary": {"accepted_records": 3},
                        "evidence": {
                            "accepted_manifest": {"sha256": digest(manifest)},
                            "paper_tables": {"sha256": digest(paper)},
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = build_downloaded_manuscript_binding(root, "r5", "v2")
            self.assertTrue((root / result["binding"]["path"]).is_file())
            self.assertIn(
                r"\newcommand{\TSDSRecords}{3}",
                (root / result["counts_tex"]["path"]).read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
