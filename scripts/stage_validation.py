#!/usr/bin/env python3
"""Create a byte-verified validation mirror outside the working repository."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

SCHEMA = "cdb-validation-stage/v1"
CONFLICT_MARKER = "conflicted copy"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def exclusion(relative: Path, is_dir: bool) -> str | None:
    parts = relative.parts
    if not parts:
        return None
    if parts[0] == ".git":
        return "repository-metadata"
    if parts[0] == ".pi":
        return "private-agent-state"
    if parts[0] in {"out", "newout", "dist"}:
        return "generated-output"
    if parts[0] == "experiments":
        return "non-product-experiment"
    if parts[0] == "demo":
        return "private-demo-runtime"
    if "target" in parts:
        return "cargo-build-output"
    if "__pycache__" in parts or (not is_dir and relative.suffix in {".pyc", ".pyo"}):
        return "python-generated-output"
    if CONFLICT_MARKER in relative.name.casefold():
        return "conflicted-copy"
    return None


def inventory(root: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    files: list[dict[str, object]] = []
    excluded: list[dict[str, object]] = []

    def visit(directory: Path) -> None:
        for entry in sorted(directory.iterdir(), key=lambda item: item.name):
            relative = entry.relative_to(root)
            is_dir = entry.is_dir() and not entry.is_symlink()
            reason = exclusion(relative, is_dir)
            if reason:
                row: dict[str, object] = {
                    "path": relative.as_posix(),
                    "kind": "directory" if is_dir else "file",
                    "reason": reason,
                }
                if entry.is_file() and not entry.is_symlink():
                    row.update(sha256=sha256(entry), size=entry.stat().st_size)
                excluded.append(row)
                continue
            if entry.is_symlink():
                raise ValueError("canonical path is a symlink: " + relative.as_posix())
            if is_dir:
                visit(entry)
            elif entry.is_file():
                files.append(
                    {"path": relative.as_posix(), "sha256": sha256(entry), "size": entry.stat().st_size}
                )
            else:
                raise ValueError("canonical path is not a regular file: " + relative.as_posix())

    visit(root)
    return files, excluded


def file_map(records: list[dict[str, object]]) -> dict[str, tuple[str, int]]:
    return {str(row["path"]): (str(row["sha256"]), int(row["size"])) for row in records}


def verify(root: Path, mirror: Path, expected: list[dict[str, object]]) -> None:
    current, _ = inventory(root)
    if file_map(current) != file_map(expected):
        raise ValueError("canonical source files changed during staging")
    staged, excluded = inventory(mirror)
    if excluded:
        raise ValueError("staged mirror unexpectedly contains excluded paths")
    if file_map(staged) != file_map(expected):
        raise ValueError("staged mirror omitted or changed canonical bytes")


def stage(root: Path, destination: Path, manifest_path: Path) -> dict[str, object]:
    root = root.resolve(strict=True)
    destination = destination.resolve(strict=False)
    manifest_path = manifest_path.resolve(strict=False)
    if destination == root or root in destination.parents:
        raise ValueError("destination must be outside the source repository")
    if root in manifest_path.parents and exclusion(manifest_path.relative_to(root), False) is None:
        raise ValueError("manifest cannot alter canonical source bytes")
    if manifest_path == destination or destination in manifest_path.parents:
        raise ValueError("manifest must be outside the staged mirror")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("destination already exists: " + str(destination))
    if manifest_path.exists() or manifest_path.is_symlink():
        raise FileExistsError("manifest already exists: " + str(manifest_path))

    files, exclusions = inventory(root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix="." + destination.name + ".staging-", dir=destination.parent))
    try:
        for row in files:
            relative = Path(str(row["path"]))
            source, target = root / relative, temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            os.chmod(target, stat.S_IMODE(source.stat().st_mode))
        verify(root, temporary, files)
        temporary.rename(destination)
        manifest = {
            "schema": SCHEMA,
            "source": ".",
            "hash": "sha256",
            "files": files,
            "exclusions": exclusions,
            "verification": {
                "canonical_file_count": len(files),
                "staged_file_count": len(files),
                "all_canonical_files_present": True,
                "all_bytes_equal": True,
            },
        }
        with manifest_path.open("x", encoding="utf-8") as manifest_file:
            manifest_file.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        return manifest
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        if destination.exists() and not manifest_path.exists():
            shutil.rmtree(destination, ignore_errors=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    manifest_path = args.manifest or args.destination.with_name(args.destination.name + ".manifest.json")
    result = stage(args.source, args.destination, manifest_path)
    print(
        f"staged and verified {result['verification']['canonical_file_count']} files; "
        f"manifest: {manifest_path}"
    )


if __name__ == "__main__":
    main()
