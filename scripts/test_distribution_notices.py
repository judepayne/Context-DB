"""Keep shipped project and third-party license metadata internally consistent."""
import hashlib
import json
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DistributionNotices(unittest.TestCase):
    def test_workspace_packages_inherit_mit(self):
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]
        self.assertEqual(workspace["package"]["license"], "MIT")
        for member in workspace["members"]:
            with self.subTest(member=member):
                package = tomllib.loads((ROOT / member / "Cargo.toml").read_text())["package"]
                self.assertEqual(package["license"], {"workspace": True})
        license_text = (ROOT / "LICENSE").read_text()
        self.assertTrue(license_text.startswith("MIT License\n"))
        self.assertIn("Copyright (c) 2026 Jude Payne", license_text)

    def test_conspicuous_fluree_license_is_exact_upstream_text(self):
        nested = ROOT / "third_party/licenses/fluree-db-api-4.2.1/LICENSE.fluree"
        self.assertEqual((ROOT / "LICENSE-FLUREE").read_bytes(), nested.read_bytes())
        self.assertIn("BUSL-1.1", (ROOT / "NOTICE.md").read_text())

    def test_retained_license_hashes_and_gap_inventory(self):
        manifest = json.loads((ROOT / "third_party/license-manifest.json").read_text())
        self.assertEqual(manifest["package_count"], len(manifest["packages"]))
        self.assertEqual(manifest["schema"], "cdb.third-party-license-files/v2")
        for package in manifest["packages"]:
            with self.subTest(package=(package["name"], package["version"])):
                self.assertTrue(package["files"], "missing retained terms/notices")
                for entry in package["files"]:
                    relative = Path(entry["path"])
                    self.assertFalse(relative.is_absolute())
                    self.assertNotIn("..", relative.parts)
                    self.assertEqual(relative.parts[:2], ("third_party", "licenses"))
                    path = ROOT / relative
                    self.assertEqual(path.resolve(strict=True), path)
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry["sha256"])
        provenance = json.loads((ROOT / "third_party/license-sources.json").read_text())
        gaps = {(item["name"], item["version"]) for item in provenance["packages"]
                if item.get("upstream_text_missing")}
        declared = {(item["name"], item["version"]) for item in manifest["packages_with_no_verified_license_text"]}
        self.assertEqual(gaps, declared)
        for package in provenance["packages"]:
            for entry in package["retained_files"]:
                path = ROOT / entry["path"]
                self.assertTrue(path.resolve(strict=True).is_relative_to(ROOT / "third_party/licenses"))
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry["sha256"])


if __name__ == "__main__":
    unittest.main()
