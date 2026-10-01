"""Tests for deterministic, create-new validation staging."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import stage_validation as staging


class ValidationStaging(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base / "source"
        self.source.mkdir()
        (self.source / "Cargo.toml").write_bytes(b"[workspace]\n")
        (self.source / "src").mkdir()
        (self.source / "src/lib.rs").write_bytes(b"pub fn canonical() {}\n")
        for name in (".pi", "out", "newout", "dist", "experiments", "target"):
            path = self.source / name
            path.mkdir()
            (path / "private").write_bytes(b"excluded")
        (self.source / "src/lib (owner's conflicted copy).rs").write_bytes(b"conflict")

    def run_stage(self, name):
        destination = self.base / name
        manifest_path = self.base / (name + ".json")
        return destination, manifest_path, staging.stage(self.source, destination, manifest_path)

    def test_stage_is_byte_exact_and_excludes_non_product_content(self):
        first, first_path, manifest = self.run_stage("first")
        second, second_path, second_manifest = self.run_stage("second")
        self.assertEqual(manifest, second_manifest)
        self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
        self.assertEqual(staging.file_map(staging.inventory(first)[0]), staging.file_map(manifest["files"]))
        self.assertEqual(staging.file_map(staging.inventory(second)[0]), staging.file_map(manifest["files"]))
        self.assertEqual(
            {row["reason"] for row in manifest["exclusions"]},
            {"private-agent-state", "generated-output", "non-product-experiment", "cargo-build-output", "conflicted-copy"},
        )
        self.assertEqual(json.loads(first_path.read_text())["schema"], staging.SCHEMA)

    def test_private_demo_including_logs_is_entirely_excluded(self):
        demo = self.source / "demo"
        demo.mkdir()
        (demo / "README.md").write_text("Portable instructions")
        for name in ("bin", "instance", "ontology", "receipts", "logs"):
            (demo / name).mkdir()
            (demo / name / "private-data").write_text("excluded")
        (demo / "README.txt").write_text("local paths")
        destination, _, manifest = self.run_stage("demo")
        self.assertFalse((destination / "demo").exists())
        self.assertEqual(sum(row["reason"] == "private-demo-runtime" for row in manifest["exclusions"]), 1)

    def test_create_new_refuses_existing_paths(self):
        destination = self.base / "existing"
        destination.mkdir()
        marker = destination / "marker"
        marker.write_bytes(b"untouched")
        with self.assertRaises(FileExistsError):
            staging.stage(self.source, destination, self.base / "new.json")
        self.assertEqual(marker.read_bytes(), b"untouched")
        manifest = self.base / "existing.json"
        manifest.write_bytes(b"untouched")
        with self.assertRaises(FileExistsError):
            staging.stage(self.source, self.base / "new", manifest)

    def test_manifest_race_never_overwrites(self):
        destination = self.base / "raced"
        manifest_path = self.base / "raced.json"
        original_verify = staging.verify

        def publish_racer(root, mirror, expected):
            original_verify(root, mirror, expected)
            manifest_path.write_bytes(b"racer-owned")

        with patch.object(staging, "verify", side_effect=publish_racer):
            with self.assertRaises(FileExistsError):
                staging.stage(self.source, destination, manifest_path)
        self.assertEqual(manifest_path.read_bytes(), b"racer-owned")

    def test_verification_rejects_changed_bytes_and_source_races(self):
        destination, _, manifest = self.run_stage("mirror")
        (destination / "src/lib.rs").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "omitted or changed"):
            staging.verify(self.source, destination, manifest["files"])
        (destination / "src/lib.rs").write_bytes(b"pub fn canonical() {}\n")
        (self.source / "new.rs").write_bytes(b"new")
        with self.assertRaisesRegex(ValueError, "source files changed"):
            staging.verify(self.source, destination, manifest["files"])

    def test_rejects_destination_inside_source_and_canonical_manifest(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            staging.stage(self.source, self.source / "mirror", self.base / "manifest.json")
        with self.assertRaisesRegex(ValueError, "canonical source"):
            staging.stage(self.source, self.base / "mirror", self.source / "manifest.json")


if __name__ == "__main__":
    unittest.main()
