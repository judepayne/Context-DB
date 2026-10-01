#!/usr/bin/env python3
"""Run a Cargo command under a process lock and retain its output."""
from __future__ import annotations

import datetime
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

REPOSITORY = Path(__file__).resolve().parents[1]


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] != "cargo":
        raise SystemExit("usage: python3 scripts/cargo_serial.py cargo ...")

    cargo_root = Path(os.environ.get("CTXQL_CARGO_ROOT", REPOSITORY)).expanduser().resolve()
    evidence = Path(
        os.environ.get("CTXQL_CARGO_EVIDENCE", REPOSITORY / "out" / "validation" / "cargo")
    ).expanduser().resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    lock_path = Path(
        os.environ.get("CTXQL_CARGO_LOCK", evidence.parent / "cargo-serial.lock")
    ).expanduser().resolve()
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    label = datetime.datetime.now(datetime.timezone.utc).strftime("cargo-%Y%m%dT%H%M%SZ")
    label += f"-{os.getpid()}"
    environment = dict(os.environ)
    environment.setdefault("CARGO_BUILD_JOBS", "1")
    environment.setdefault("CARGO_INCREMENTAL", "0")
    environment.setdefault("CARGO_TARGET_DIR", str(cargo_root / "target"))

    with lock_path.open("a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        started = time.monotonic()
        stdout_path = evidence / f"{label}.stdout"
        stderr_path = evidence / f"{label}.stderr"
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
            "w", encoding="utf-8"
        ) as stderr:
            result = subprocess.run(
                args, cwd=cargo_root, env=environment, stdout=stdout, stderr=stderr, text=True
            )

    record = {
        "argv": args,
        "cwd": str(cargo_root),
        "exit": result.returncode,
        "seconds": time.monotonic() - started,
    }
    (evidence / f"{label}.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )
    for path in (stdout_path, stderr_path):
        text = path.read_text(encoding="utf-8", errors="replace")
        if text:
            print(text[-16000:], end="" if text.endswith("\n") else "\n")
    print(f"Evidence: {evidence / label}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
