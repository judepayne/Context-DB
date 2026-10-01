"""Focused tests for prebuilt cdb release packaging."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tarfile
import tempfile
import unittest

import package_release as packaging


class ReleasePackaging(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "Cargo.toml").write_text(
            '[workspace]\n[workspace.package]\nversion = "0.1.0"\n', encoding="utf-8"
        )
        (self.root / "README.md").write_text("project readme\n", encoding="utf-8")
        (self.root / "AGENTS.md").write_text("build instructions\n", encoding="utf-8")
        (self.root / "Cargo.lock").write_text("lock data\n", encoding="utf-8")
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.94.0"\n', encoding="utf-8")
        (self.root / "docs").mkdir()
        (self.root / "docs/service.md").write_text("service docs\n", encoding="utf-8")
        (self.root / "docs/contracts").mkdir()
        (self.root / "docs/contracts/chat-v1.md").write_text("chat contract\n", encoding="utf-8")
        (self.root / "assets/pi/prompts").mkdir(parents=True)
        (self.root / "assets/pi/prompts/system.md").write_text("verified prompt\n", encoding="utf-8")
        (self.root / "assets/private.txt").write_text("not part of pi bundle\n", encoding="utf-8")
        (self.root / "third_party/licenses/dependency").mkdir(parents=True)
        (self.root / "third_party/README.md").write_text("notices\n", encoding="utf-8")
        (self.root / "third_party/license-manifest.json").write_text("{}\n", encoding="utf-8")
        (self.root / "third_party/licenses/dependency/LICENSE").write_text("license text\n", encoding="utf-8")
        (self.root / "demo").mkdir()
        (self.root / "demo/credentials.json").write_text("private\n", encoding="utf-8")
        (self.root / "temp-data").write_text("private\n", encoding="utf-8")
        self.binary = self.base / "prebuilt-cdb"
        self.binary.write_bytes(b"fake executable bytes\n")
        self.binary.chmod(0o600)

    def package(self, name="dist", target="aarch64-apple-darwin", tag=None):
        return packaging.package_release(
            self.binary,
            target,
            self.base / name,
            tag,
            root=self.root,
        )

    def test_archive_has_only_release_payload_with_normalized_modes(self):
        archive_path, checksum_path = self.package(tag="v0.1.0")
        top = "cdb-0.1.0-aarch64-apple-darwin"
        expected_files = {
            f"{top}/bin/cdb",
            f"{top}/assets/pi/prompts/system.md",
            f"{top}/README.md",
            f"{top}/AGENTS.md",
            f"{top}/docs/service.md",
            f"{top}/docs/contracts/chat-v1.md",
            f"{top}/third_party/README.md",
            f"{top}/third_party/license-manifest.json",
            f"{top}/third_party/licenses/dependency/LICENSE",
            f"{top}/Cargo.lock",
            f"{top}/rust-toolchain.toml",
            f"{top}/RELEASE.txt",
        }

        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            files = {member.name for member in members if member.isfile()}
            self.assertEqual(files, expected_files)
            self.assertTrue(all(member.name == top or member.name.startswith(top + "/") for member in members))
            self.assertTrue(all(member.mtime == 0 for member in members))
            self.assertTrue(all(member.mode == 0o755 for member in members if member.isdir()))
            self.assertEqual(archive.getmember(f"{top}/bin/cdb").mode, 0o755)
            self.assertTrue(
                all(member.mode == 0o644 for member in members if member.isfile() and member.name != f"{top}/bin/cdb")
            )
            self.assertEqual(archive.extractfile(f"{top}/bin/cdb").read(), self.binary.read_bytes())
            notice = archive.extractfile(f"{top}/RELEASE.txt").read().decode("utf-8")

        self.assertIn("technical alpha", notice)
        self.assertIn("Node.js and Pi 0.87.1", notice)
        self.assertIn("unsigned", notice)
        self.assertIn("Ubuntu 24.04 / glibc 2.39", notice)
        self.assertIn("macOS 15", notice)
        self.assertIn("No project license", notice)
        self.assertIn("BUSL-1.1", notice)
        self.assertIn("not treated as Apache-2.0", notice)
        expected_checksum = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        self.assertEqual(checksum_path.read_text(encoding="ascii"), f"{expected_checksum}  {archive_path.name}\n")

    def test_archives_are_deterministic(self):
        first, _ = self.package("first")
        second, _ = self.package("second")
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_rejects_mismatched_or_unsafe_tag_and_target(self):
        for tag in ("0.1.0", "v0.1.1", "v0.1.0/escape"):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "exactly v0.1.0"):
                self.package("tag-" + hashlib.sha256(tag.encode()).hexdigest()[:8], tag=tag)
        with self.assertRaisesRegex(ValueError, "unsupported release target"):
            self.package("bad-target", target="../../private")
        self.assertFalse((self.base / "bad-target").exists())

    def test_existing_archive_is_not_overwritten(self):
        output = self.base / "existing-archive"
        output.mkdir()
        archive = output / "cdb-0.1.0-aarch64-apple-darwin.tar.gz"
        archive.write_bytes(b"owner data")
        with self.assertRaises(FileExistsError):
            self.package("existing-archive")
        self.assertEqual(archive.read_bytes(), b"owner data")
        self.assertFalse((output / (archive.name + ".sha256")).exists())

    def test_existing_checksum_is_not_overwritten_or_joined_by_archive(self):
        output = self.base / "existing-checksum"
        output.mkdir()
        archive = output / "cdb-0.1.0-aarch64-apple-darwin.tar.gz"
        checksum = output / (archive.name + ".sha256")
        checksum.write_bytes(b"owner data")
        with self.assertRaises(FileExistsError):
            self.package("existing-checksum")
        self.assertEqual(checksum.read_bytes(), b"owner data")
        self.assertFalse(archive.exists())

    def test_binary_parent_symlink_is_rejected(self):
        link = self.base / "binary-parent"
        link.symlink_to(self.binary.parent, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "noncanonical ancestor"):
            packaging.package_release(link / self.binary.name, "aarch64-apple-darwin",
                                      self.base / "binary-symlink", root=self.root)

    def test_asset_and_document_parent_symlinks_are_rejected(self):
        for directory in ("assets", "docs"):
            with self.subTest(directory=directory):
                original = self.root / directory
                outside = self.base / ("outside-" + directory)
                original.rename(outside)
                original.symlink_to(outside, target_is_directory=True)
                try:
                    with self.assertRaisesRegex(ValueError, "symbolic link ancestor"):
                        self.package("parent-symlink-" + directory)
                finally:
                    original.unlink()
                    outside.rename(original)

    def test_symlinks_in_packaged_trees_are_rejected(self):
        link = self.root / "assets/pi/outside"
        try:
            link.symlink_to(self.root / "README.md")
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links are unavailable")
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            self.package("symlink")


if __name__ == "__main__":
    unittest.main()
