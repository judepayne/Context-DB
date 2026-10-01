#!/usr/bin/env python3
"""Package a prebuilt cdb binary and its required release assets."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import stat
import tarfile
import tomllib

TARGETS = {
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
}
VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]*\Z")
FIXED_MTIME = 0


def workspace_version(root: Path) -> str:
    cargo_toml = root / "Cargo.toml"
    with cargo_toml.open("rb") as handle:
        version = tomllib.load(handle)["workspace"]["package"]["version"]
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ValueError("workspace package version is not safe for a release filename")
    return version


def _regular_file(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise FileNotFoundError(f"required release file is missing: {path}") from None
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"release input is not a regular file: {path}")
    return metadata


def _tree_files(root: Path) -> list[tuple[Path, Path]]:
    """Return sorted (relative, source) files, rejecting links and special files."""
    try:
        metadata = root.lstat()
    except FileNotFoundError:
        raise FileNotFoundError(f"required release directory is missing: {root}") from None
    if root.resolve(strict=True) != root:
        raise ValueError(f"release input has a symbolic link ancestor: {root}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"release input is not a directory: {root}")

    files: list[tuple[Path, Path]] = []

    def visit(directory: Path) -> None:
        for entry in sorted(directory.iterdir(), key=lambda item: item.name):
            entry_metadata = entry.lstat()
            if stat.S_ISLNK(entry_metadata.st_mode):
                raise ValueError(f"release input contains a symbolic link: {entry}")
            if stat.S_ISDIR(entry_metadata.st_mode):
                visit(entry)
            elif stat.S_ISREG(entry_metadata.st_mode):
                files.append((entry.relative_to(root), entry))
            else:
                raise ValueError(f"release input is not a regular file or directory: {entry}")

    visit(root)
    return files


def _open_without_symlinks(path: Path):
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    handle = os.fdopen(descriptor, "rb")
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        handle.close()
        raise ValueError(f"release input is not a regular file: {path}")
    return handle


def _add_directory(archive: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name.rstrip("/") + "/")
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.mtime = FIXED_MTIME
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    archive.addfile(info)


def _add_bytes(archive: tarfile.TarFile, name: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = FIXED_MTIME
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    archive.addfile(info, io.BytesIO(data))


def _add_file(archive: tarfile.TarFile, name: str, source: Path, mode: int) -> None:
    with _open_without_symlinks(source) as handle:
        data = handle.read()
    _add_bytes(archive, name, data, mode)


def release_notice(version: str, target: str) -> bytes:
    return f"""Context DB {version} ({target}) release notes

This package is a technical alpha. The cdb binary is unsigned.
Model-backed acquisition and chat require separately installed Node.js and Pi 0.87.1.
The release baselines are Ubuntu 24.04 / glibc 2.39 for Linux and macOS 15 on
Apple Silicon for macOS.

Run bin/cdb --help and see docs/service.md. Configure pi-bundle to this package's
assets/pi directory. Documentation links into fixtures, crates or scripts refer
to the source checkout at https://github.com/judepayne/Context-DB, not this binary
package; no demo or populated stores are included.

Context DB's own code is MIT-licensed; see LICENSE. Third-party components retain
their respective licenses; MIT does not replace those terms. Upstream Fluree 4.2.1 remains subject to BUSL-1.1
restrictions and is not treated as Apache-2.0 today. Read LICENSE-FLUREE, NOTICE.md
and third_party/README.md before use.
""".encode("utf-8")


def _archive_contents(root: Path, binary: Path) -> tuple[list[tuple[str, Path, int]], list[str]]:
    _regular_file(binary)
    files: list[tuple[str, Path, int]] = [("bin/cdb", binary, 0o755)]
    directories = {"bin", "assets", "assets/pi", "docs", "third_party"}

    for relative, source in _tree_files(root / "assets" / "pi"):
        archive_name = (Path("assets/pi") / relative).as_posix()
        files.append((archive_name, source, 0o644))
        directories.update(parent.as_posix() for parent in Path(archive_name).parents if parent.as_posix() != ".")

    for relative, source in _tree_files(root / "third_party"):
        archive_name = (Path("third_party") / relative).as_posix()
        files.append((archive_name, source, 0o644))
        directories.update(parent.as_posix() for parent in Path(archive_name).parents if parent.as_posix() != ".")

    for relative, source in _tree_files(root / "docs"):
        archive_name = (Path("docs") / relative).as_posix()
        files.append((archive_name, source, 0o644))
        directories.update(parent.as_posix() for parent in Path(archive_name).parents if parent.as_posix() != ".")

    for name in ("README.md", "LICENSE", "LICENSE-FLUREE", "NOTICE.md", "AGENTS.md", "Cargo.lock", "rust-toolchain.toml"):
        source = root / name
        if source.resolve(strict=True) != source:
            raise ValueError(f"release input has a symbolic link ancestor: {source}")
        _regular_file(source)
        files.append((name, source, 0o644))

    return sorted(files), sorted(directories, key=lambda item: (item.count("/"), item))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def package_release(
    binary: Path,
    target: str,
    output_dir: Path,
    tag: str | None = None,
    *,
    root: Path | None = None,
) -> tuple[Path, Path]:
    if target not in TARGETS:
        raise ValueError(f"unsupported release target: {target}")

    root = (root or Path(__file__).resolve().parents[1]).resolve(strict=True)
    version = workspace_version(root)
    if tag is not None and tag != f"v{version}":
        raise ValueError(f"release tag must be exactly v{version}")

    binary = Path(binary).absolute()
    if binary.resolve(strict=True) != binary:
        raise ValueError(f"binary has a symbolic link or noncanonical ancestor: {binary}")
    output_dir = Path(output_dir)
    top = f"cdb-{version}-{target}"
    archive_path = output_dir / f"{top}.tar.gz"
    checksum_path = archive_path.with_name(archive_path.name + ".sha256")

    output_dir.mkdir(parents=True, exist_ok=True)
    if archive_path.exists() or archive_path.is_symlink():
        raise FileExistsError(f"release archive already exists: {archive_path}")
    if checksum_path.exists() or checksum_path.is_symlink():
        raise FileExistsError(f"release checksum already exists: {checksum_path}")

    files, directories = _archive_contents(root, binary)
    created_archive = False
    created_checksum = False
    try:
        with archive_path.open("xb") as raw:
            created_archive = True
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=FIXED_MTIME) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    _add_directory(archive, top)
                    for directory in directories:
                        _add_directory(archive, f"{top}/{directory}")
                    for name, source, mode in files:
                        _add_file(archive, f"{top}/{name}", source, mode)
                    _add_bytes(archive, f"{top}/RELEASE.txt", release_notice(version, target), 0o644)

        checksum = f"{sha256(archive_path)}  {archive_path.name}\n"
        with checksum_path.open("x", encoding="ascii", newline="\n") as checksum_file:
            created_checksum = True
            checksum_file.write(checksum)
    except BaseException:
        if created_checksum:
            checksum_path.unlink(missing_ok=True)
        if created_archive:
            archive_path.unlink(missing_ok=True)
        raise

    return archive_path, checksum_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="prebuilt cdb binary to package")
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--tag", help="optional release tag, which must exactly match vVERSION")
    args = parser.parse_args()

    archive, checksum = package_release(args.binary, args.target, args.output_dir, args.tag)
    print(archive)
    print(checksum)


if __name__ == "__main__":
    main()
