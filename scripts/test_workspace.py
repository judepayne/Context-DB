"""Synthetic adversarial tests for the current dependency firewall."""
import copy
from pathlib import Path
import unittest

from check_workspace import validate


class DependencyBoundary(unittest.TestCase):
    def setUp(self):
        self.root = Path("/fixture")
        names = [
            "cdb-core", "cdb-engine", "cdb-testkit", "cdb-backend-fluree",
            "cdb-projection-redb", "cdb-service", "cdb-source-store",
            "cdb-acquisition", "cdb-provider-pi",
        ]
        self.metadata = {
            "workspace_root": str(self.root),
            "workspace_members": names.copy(),
            "workspace_default_members": names.copy(),
            "packages": [
                {"id": name, "name": name, "version": "0.1.0", "source": None,
                 "manifest_path": f"/fixture/crates/{name}/Cargo.toml"}
                for name in names
            ] + [{"id": "helper", "name": "pure-helper", "version": "1", "source": "registry"}],
            "resolve": {"nodes": [
                {"id": name, "features": [], "deps": []} for name in names
            ] + [{"id": "helper", "features": ["std"], "deps": []}]},
        }
        self.node("cdb-core")["deps"] = [self.edge("helper")]
        self.node("cdb-engine")["deps"] = [self.edge("cdb-core")]
        self.allowed = {"packages": [
            {"name": "pure-helper", "version": "1", "source": "registry", "features": ["std"]}
        ]}

    @staticmethod
    def edge(package, kind=None, target=None):
        return {"name": package, "pkg": package, "dep_kinds": [{"kind": kind, "target": target}]}

    def node(self, ident):
        return next(node for node in self.metadata["resolve"]["nodes"] if node["id"] == ident)

    def check(self, metadata=None, allowed=None):
        return validate(metadata or self.metadata, allowed or self.allowed, self.root)

    def test_accepts_current_shape_and_pure_core(self):
        self.assertEqual(self.check(), (10, 2))

    def test_rejects_unreviewed_dependency_and_feature_change(self):
        self.metadata["packages"][-1]["version"] = "2"
        with self.assertRaisesRegex(ValueError, "unreviewed dependency"):
            self.check()
        self.metadata["packages"][-1]["version"] = "1"
        self.node("helper")["features"].append("network")
        with self.assertRaisesRegex(ValueError, "feature change"):
            self.check()

    def test_rejects_path_dependency_and_incomplete_edges(self):
        self.metadata["packages"][-1]["source"] = None
        with self.assertRaisesRegex(ValueError, "unreviewed dependency"):
            self.check()
        self.metadata["packages"][-1]["source"] = "registry"
        self.node("helper")["deps"].append(self.edge("missing"))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.check()

    def test_rejects_extra_member_and_escaped_member_path(self):
        self.metadata["workspace_members"].append("helper")
        with self.assertRaisesRegex(ValueError, "nine"):
            self.check()
        self.metadata["workspace_members"].pop()
        self.metadata["packages"][0]["manifest_path"] = "/fixture/elsewhere/Cargo.toml"
        with self.assertRaisesRegex(ValueError, "escaped"):
            self.check()

    def test_core_and_engine_reject_runtime_and_native_storage_transitively(self):
        for owner in ("cdb-core", "cdb-engine"):
            for name in ("tokio", "redb", "fluree-db-core"):
                with self.subTest(owner=owner, name=name):
                    changed = copy.deepcopy(self.metadata)
                    package = next(row for row in changed["packages"] if row["id"] == "helper")
                    package["name"] = name
                    allowed = {"packages": [{"name": name, "version": "1", "source": "registry", "features": ["std"]}]}
                    with self.assertRaisesRegex(ValueError, "forbidden"):
                        self.check(changed, allowed)

    def test_architecture_crossings_are_rejected_for_every_dependency_kind(self):
        crossings = [
            ("cdb-core", "cdb-engine"),
            ("cdb-engine", "cdb-testkit"),
            ("cdb-backend-fluree", "cdb-projection-redb"),
            ("cdb-projection-redb", "cdb-backend-fluree"),
            ("cdb-service", "cdb-testkit"),
        ]
        for owner, forbidden in crossings:
            for kind in (None, "build", "dev"):
                with self.subTest(owner=owner, forbidden=forbidden, kind=kind):
                    changed = copy.deepcopy(self.metadata)
                    node = next(row for row in changed["resolve"]["nodes"] if row["id"] == owner)
                    node["deps"].append(self.edge(forbidden, kind, "cfg(unix)"))
                    with self.assertRaisesRegex(ValueError, "forbidden"):
                        self.check(changed)

    def test_service_can_compose_production_crates(self):
        self.node("cdb-service")["deps"] = [
            self.edge(name) for name in (
                "cdb-core", "cdb-engine", "cdb-backend-fluree", "cdb-projection-redb",
                "cdb-source-store", "cdb-acquisition", "cdb-provider-pi",
            )
        ]
        self.assertEqual(self.check(), (10, 2))


if __name__ == "__main__":
    unittest.main()
