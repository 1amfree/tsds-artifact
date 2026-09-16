import gzip
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import experiments.build_deterministic_artifact_archive as archive_module
from experiments.build_deterministic_artifact_archive import (
    build_archive,
    parse_inputs,
    sha256_file,
)
from experiments.verify_deterministic_artifact_archive import verify_archive


class DeterministicArtifactArchiveTest(unittest.TestCase):
    def test_noncanonical_prefix_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.mkdir()
            for prefix in ("/absolute", "trailing/", "double//slash", "dot/./part"):
                with self.subTest(prefix=prefix):
                    with self.assertRaises(ValueError):
                        parse_inputs([f"{prefix}={source}"])

    def test_top_level_symlink_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            link = root / "link"
            try:
                link.symlink_to(source, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaises(ValueError):
                parse_inputs([f"artifact={link}"])

    def test_archive_output_inside_input_tree_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.mkdir()
            (source / "input.txt").write_text("x\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                build_archive([("artifact", source)], source / "artifact.tar.gz")

    def test_member_set_drift_is_transactionally_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "input.txt").write_text("x\n", encoding="utf-8")
            archive = root / "artifact.tar.gz"
            original_collect = archive_module.collect_members
            calls = 0

            def collect_with_drift(inputs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    (source / "added.txt").write_text("late\n", encoding="utf-8")
                return original_collect(inputs)

            with patch.object(
                archive_module, "collect_members", side_effect=collect_with_drift
            ):
                with self.assertRaisesRegex(RuntimeError, "member set changed"):
                    build_archive([("artifact", source)], archive)
            self.assertFalse(archive.exists())
            self.assertFalse(list(root.glob(".artifact.tar.gz.*.tmp")))

    def test_same_inputs_produce_same_archive_and_verify(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "b.txt").write_text("b\n", encoding="utf-8")
            (source / "a.txt").write_text("a\n", encoding="utf-8")
            first = root / "first.tar.gz"
            second = root / "second.tar.gz"
            first_summary = build_archive([("artifact", source)], first)
            second_summary = build_archive([("artifact", source)], second)
            self.assertEqual(
                first_summary["archive_sha256"], second_summary["archive_sha256"]
            )
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(first_summary), encoding="utf-8")
            self.assertTrue(verify_archive(first, manifest)["verified"])

    def test_archive_mutation_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.txt"
            source.write_text("evidence\n", encoding="utf-8")
            archive = root / "artifact.tar.gz"
            summary = build_archive([("artifact", source)], archive)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(summary), encoding="utf-8")
            with archive.open("ab") as stream:
                stream.write(b"tamper")
            verification = verify_archive(archive, manifest)
            self.assertFalse(verification["verified"])
            self.assertIn("archive_size_mismatch", verification["issues"])

    def test_trailing_data_is_detected_even_when_external_hash_is_updated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.txt"
            source.write_text("evidence\n", encoding="utf-8")
            archive = root / "artifact.tar.gz"
            summary = build_archive([("artifact", source)], archive)
            with archive.open("ab") as stream:
                stream.write(b"trailing")
            summary["archive_size"] = archive.stat().st_size
            summary["archive_sha256"] = sha256_file(archive)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(summary), encoding="utf-8")
            verification = verify_archive(archive, manifest)
            self.assertFalse(verification["verified"])
            self.assertIn(
                "gzip_trailing_or_concatenated_data", verification["issues"]
            )

    def test_duplicate_external_manifest_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.txt"
            source.write_text("evidence\n", encoding="utf-8")
            archive = root / "artifact.tar.gz"
            summary = build_archive([("artifact", source)], archive)
            manifest = root / "manifest.json"
            encoded = json.dumps(summary)
            manifest.write_text(
                encoded.replace("{", '{"schema":"wrong",', 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                verify_archive(archive, manifest)

    def test_member_owner_metadata_mutation_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.txt"
            source.write_text("evidence\n", encoding="utf-8")
            original = root / "original.tar.gz"
            summary = build_archive([("artifact", source)], original)

            with tarfile.open(original, "r:gz") as archive:
                rows = [
                    (member, archive.extractfile(member).read())
                    for member in archive.getmembers()
                ]
            tar_buffer = io.BytesIO()
            with tarfile.open(
                fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT
            ) as archive:
                for original_member, data in rows:
                    member = tarfile.TarInfo(original_member.name)
                    member.size = len(data)
                    member.mode = original_member.mode
                    member.uid = 1000 if original_member.name != "ARTIFACT_CONTENTS.json" else 0
                    member.gid = 0
                    member.uname = "ubuntu" if member.uid else ""
                    member.gname = ""
                    member.mtime = 0
                    archive.addfile(member, io.BytesIO(data))
            tampered = root / "tampered.tar.gz"
            with tampered.open("wb") as raw:
                with gzip.GzipFile(
                    fileobj=raw, mode="wb", filename="", mtime=0
                ) as compressed:
                    compressed.write(tar_buffer.getvalue())

            summary["archive"] = tampered.name
            summary["archive_size"] = tampered.stat().st_size
            summary["archive_sha256"] = sha256_file(tampered)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(summary), encoding="utf-8")
            verification = verify_archive(tampered, manifest)
            self.assertFalse(verification["verified"])
            self.assertIn(
                "metadata_mismatch:artifact/input.txt", verification["issues"]
            )

    def test_non_regular_member_is_rejected_even_with_matching_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.txt"
            source.write_text("evidence\n", encoding="utf-8")
            original = root / "original.tar.gz"
            summary = build_archive([("artifact", source)], original)

            with tarfile.open(original, "r:gz") as archive:
                rows = [
                    (member, archive.extractfile(member).read())
                    for member in archive.getmembers()
                ]
            tar_buffer = io.BytesIO()
            with tarfile.open(
                fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT
            ) as archive:
                for original_member, data in rows:
                    member = tarfile.TarInfo(original_member.name)
                    member.size = len(data)
                    member.mode = original_member.mode
                    member.uid = member.gid = 0
                    member.uname = member.gname = ""
                    member.mtime = 0
                    archive.addfile(member, io.BytesIO(data))
                link = tarfile.TarInfo("artifact/link")
                link.type = tarfile.SYMTYPE
                link.linkname = "input.txt"
                link.mode = 0o777
                link.uid = link.gid = 0
                link.mtime = 0
                archive.addfile(link)
            tampered = root / "tampered.tar.gz"
            with tampered.open("wb") as raw:
                with gzip.GzipFile(
                    fileobj=raw, mode="wb", filename="", mtime=0
                ) as compressed:
                    compressed.write(tar_buffer.getvalue())

            summary["archive"] = tampered.name
            summary["archive_size"] = tampered.stat().st_size
            summary["archive_sha256"] = sha256_file(tampered)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(summary), encoding="utf-8")
            verification = verify_archive(tampered, manifest)
            self.assertFalse(verification["verified"])
            self.assertIn("non_regular_member:artifact/link", verification["issues"])
            self.assertIn("archive_member_set_mismatch", verification["issues"])


if __name__ == "__main__":
    unittest.main()
