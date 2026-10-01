#!/usr/bin/env python3
"""Validate the current locked dependency graph and crate architecture."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MEMBERS = {
    "cdb-core", "cdb-engine", "cdb-testkit", "cdb-backend-fluree",
    "cdb-projection-redb", "cdb-service", "cdb-source-store",
    "cdb-acquisition", "cdb-provider-pi",
}
FORBIDDEN = {
    "cdb-core": {"cdb-engine", "cdb-testkit", "tokio", "cdb-backend-fluree", "cdb-projection-redb", "cdb-source-store", "cdb-acquisition", "cdb-provider-pi"},
    "cdb-engine": {"cdb-testkit", "tokio", "cdb-backend-fluree", "cdb-projection-redb", "cdb-source-store", "cdb-acquisition", "cdb-provider-pi"},
    "cdb-source-store": {"cdb-engine", "cdb-testkit", "tokio", "cdb-backend-fluree", "cdb-projection-redb", "cdb-acquisition", "cdb-provider-pi"},
    "cdb-acquisition": {"cdb-engine", "cdb-testkit", "tokio", "cdb-backend-fluree", "cdb-projection-redb", "cdb-source-store", "cdb-provider-pi"},
    "cdb-provider-pi": {"cdb-engine", "cdb-testkit", "tokio", "cdb-backend-fluree", "cdb-projection-redb", "cdb-source-store"},
    "cdb-backend-fluree": {"cdb-engine", "cdb-testkit", "cdb-projection-redb", "cdb-source-store", "cdb-provider-pi", "redb"},
    "cdb-projection-redb": {"cdb-backend-fluree", "cdb-testkit", "cdb-source-store", "cdb-provider-pi"},
    "cdb-service": {"cdb-testkit"},
}


def validate(metadata: dict, allowed: dict, root: Path) -> tuple[int, int]:
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    member_ids = set(metadata["workspace_members"])
    if {packages[ident]["name"] for ident in member_ids} != MEMBERS or len(member_ids) != 9:
        raise ValueError("expected exactly nine current workspace members")
    if set(metadata["workspace_default_members"]) != member_ids:
        raise ValueError("default members must equal workspace members")
    if Path(metadata["workspace_root"]).resolve() != root.resolve():
        raise ValueError("unexpected workspace root")

    permits = {
        (package["name"], package["version"], package["source"]): package
        for package in allowed["packages"]
    }
    for ident, package in packages.items():
        node = nodes.get(ident)
        if node is None:
            raise ValueError("package is missing from resolved dependency graph")
        if ident in member_ids:
            expected = root / "crates" / package["name"] / "Cargo.toml"
            if Path(package["manifest_path"]).resolve() != expected.resolve():
                raise ValueError("workspace member path escaped its crate")
        else:
            permit = permits.get((package["name"], package["version"], package["source"]))
            if not package["source"] or permit is None:
                raise ValueError(f"unreviewed dependency: {package['name']} {package['version']}")
            if sorted(node["features"]) != sorted(permit["features"]):
                raise ValueError(f"unreviewed feature change: {package['name']}")
        for dependency in node["deps"]:
            if dependency["pkg"] not in packages or not dependency["dep_kinds"]:
                raise ValueError("incomplete dependency graph")

    core_count = 0
    for owner, forbidden in FORBIDDEN.items():
        effective_forbidden = set(forbidden)
        if owner != "cdb-service":
            effective_forbidden.add("cdb-service")
        start = next(ident for ident in member_ids if packages[ident]["name"] == owner)
        seen, pending = set(), [start]
        while pending:
            ident = pending.pop()
            if ident in seen:
                continue
            seen.add(ident)
            name = packages[ident]["name"]
            if name in effective_forbidden:
                raise ValueError(f"{owner} depends on forbidden engine/testkit/runtime/storage: {name}")
            if owner in {"cdb-core", "cdb-engine"} and (
                name == "redb" or name.startswith("fluree-")
            ):
                raise ValueError(f"{owner} depends on forbidden native storage: {name}")
            if owner == "cdb-projection-redb" and (name == "fluree" or name.startswith("fluree-")):
                raise ValueError(f"{owner} depends on forbidden semantic backend: {name}")
            pending.extend(dependency["pkg"] for dependency in nodes[ident]["deps"])
        if owner == "cdb-core":
            core_count = len(seen)
    return len(packages), core_count


def main() -> None:
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--offline", "--all-features", "--format-version", "1"],
        cwd=ROOT,
        text=True,
    ))
    allowed = json.loads((ROOT / "scripts/allowed-packages.json").read_text(encoding="utf-8"))
    count, core_count = validate(metadata, allowed, ROOT)
    print(
        f"Workspace boundary passed: 9 members, {count} resolved packages; "
        f"{core_count} reachable from core (all dependency kinds and targets)."
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Workspace boundary FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
