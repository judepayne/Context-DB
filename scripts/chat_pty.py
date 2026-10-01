#!/usr/bin/env python3
"""Hermetic real-PTY acceptance driver for ``cdb chat``.

The Rust test supplies disposable native stores and a deterministic fake Pi.
This helper sends terminal controls; it never supplies remote credentials and
never persists a conversation transcript.
"""
import errno
import json
import os
import pathlib
import pty
import select
import signal
import subprocess
import sys
import time


def wait_for(fd: int, buffer: bytearray, needle: bytes, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while needle not in buffer:
        if time.monotonic() >= deadline:
            tail = bytes(buffer[-1000:]).decode("utf-8", "replace")
            raise RuntimeError(f"PTY timeout waiting for {needle!r}; tail={tail!r}")
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    tail = bytes(buffer[-2000:]).decode("utf-8", "replace")
                    raise RuntimeError(
                        f"chat exited before {needle!r}; tail={tail!r}"
                    ) from error
                raise
            if not chunk:
                tail = bytes(buffer[-2000:]).decode("utf-8", "replace")
                raise RuntimeError(f"chat exited before {needle!r}; tail={tail!r}")
            buffer.extend(chunk)


def send(fd: int, line: str) -> None:
    os.write(fd, line.encode("utf-8") + b"\n")


def spawn(binary: str, config: str, token: str):
    master, slave = pty.openpty()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "OPENROUTER_API_KEY": "cdb-hermetic-chat-only",
        # Native debug integration requires the same large Rust worker stack as
        # the serial Cargo harness; do not inherit unrelated environment state.
        "RUST_MIN_STACK": "33554432",
    }
    process = subprocess.Popen(
        [binary, "chat", "--config", config, "--token-file", token],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
        env=env,
    )
    os.close(slave)
    return process, master


def finish(process: subprocess.Popen, master: int, timeout: float = 15.0) -> None:
    try:
        status = process.wait(timeout=timeout)
        if status != 0:
            raise RuntimeError(f"chat returned {status}")
    finally:
        os.close(master)
        if process.poll() is None:
            process.kill()
            process.wait()


def normal_flow(binary: str, config: str, token: str) -> None:
    process, master = spawn(binary, config, token)
    output = bytearray()
    try:
        wait_for(master, output, b"You> ")
        output.clear()
        send(master, "first question")
        wait_for(master, output, b"turn-1 graph-and-source complete")
        delta_seen_at = time.monotonic()
        assert b"You> " not in output, "assistant text must arrive before settlement"
        wait_for(master, output, b"You> ")
        assert output.count(b"[session cost: $0.01]") == 1
        assert b"[checking read-only data]" not in output
        assert output.count(b"cdb> ") == 1, "tool progress must not repeat assistant prompts"
        assert time.monotonic() > delta_seen_at
        assert b"[C1]" in output and b"[S1]" in output
        assert b"Warning: unresolved citation [C999]." in output
        assert b'"claim_id"' not in output and b'"source_id"' not in output

        output.clear()
        send(master, "/evidence C1")
        wait_for(master, output, b"You> ")
        assert b"Retained citation metadata (not a fresh source read)" in output
        assert b'"claim_id"' in output and b'"metadata"' in output
        assert b'"relation"' in output and b'"object_id"' in output
        assert b"[session cost:" not in output, "local inspection must not start a model turn"

        output.clear()
        send(master, "/evidence [S1]")
        wait_for(master, output, b"You> ")
        assert b'"source_id"' in output and b'"selectors"' in output

        output.clear()
        send(master, "/evidence")
        wait_for(master, output, b"You> ")
        assert b"Usage: /evidence" in output

        output.clear()
        send(master, "follow up")
        wait_for(master, output, b"turn-2 follow-up retained first question=true")
        wait_for(master, output, b"You> ")
        assert output.count(b"[session cost: $0.02]") == 1
        assert b"[checking read-only data]" not in output
        assert output.count(b"cdb> ") == 1

        output.clear()
        send(master, "/queries")
        wait_for(master, output, b'"snapshot":')
        wait_for(master, output, b"You> ")
        assert b'"about":[' in output, "must show the actual executed query"
        assert b'"status":"complete"' in output
        assert b'"result_id":"R2-E1"' in output, "must show the last turn's graph handle"

        output.clear()
        send(master, "/help")
        wait_for(master, output, b"/queries show last-turn executed queries")
        wait_for(master, output, b"You> ")

        output.clear()
        send(master, "/clear")
        wait_for(master, output, b"Conversation context cleared; process usage ceilings remain.")
        wait_for(master, output, b"You> ")
        assert b"[session cost: $0.02]" in output, "/clear must not reset session cost"
        output.clear()
        send(master, "/evidence C1")
        wait_for(master, output, b"You> ")
        assert b"No retained citation [C1]" in output
        assert b'"claim_id"' not in output
        send(master, "quit")
        finish(process, master)
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        raise


def revoked_read(binary: str, config: str, token: str, credentials: pathlib.Path) -> None:
    # This file belongs solely to the disposable test instance. Revoking a fresh
    # read must not retroactively gate prose based on already obtained context.
    original = credentials.read_bytes()
    process, master = spawn(binary, config, token)
    output = bytearray()
    try:
        wait_for(master, output, b"You> ")
        output.clear()
        send(master, "first question")
        wait_for(master, output, b"turn-1 graph-and-source complete")
        wait_for(master, output, b"You> ")
        table = json.loads(original)
        for entry in table["entries"]:
            entry["enabled"] = False
        credentials.write_text(json.dumps(table))

        output.clear()
        send(master, "attempt protected read")
        wait_for(master, output, b"protected-read denied")
        wait_for(master, output, b"You> ")
        output.clear()
        send(master, "remember without reading")
        wait_for(master, output, b"prior-context retained=true")
        wait_for(master, output, b"You> ")
        send(master, "quit")
        finish(process, master)
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        raise
    finally:
        credentials.write_bytes(original)


def idle_exit(binary: str, config: str, token: str, control: str) -> None:
    process, master = spawn(binary, config, token)
    output = bytearray()
    try:
        wait_for(master, output, b"You> ")
        if control == "eof":
            os.write(master, b"\x04")
        else:
            process.send_signal(signal.SIGINT)
        finish(process, master)
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        raise


def busy_exit(binary: str, config: str, token: str, control: str) -> None:
    process, master = spawn(binary, config, token)
    output = bytearray()
    try:
        wait_for(master, output, b"You> ")
        output.clear()
        send(master, "busy question")
        wait_for(master, output, b"busy-delta")
        send(master, "/evidence C999")
        wait_for(master, output, b"No retained citation [C999]")
        if control == "eof":
            os.write(master, b"\x04")
            finish(process, master)
        else:
            process.send_signal(signal.SIGINT)
            wait_for(master, output, b"[answer incomplete]")
            wait_for(master, output, b"[session cost: unavailable]")
            wait_for(master, output, b"You> ")
            send(master, "quit")
            finish(process, master)
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        raise


def verify_audit(audit: pathlib.Path) -> None:
    tools = (audit / "tools.log").read_text().splitlines()
    assert tools.count("capabilities") >= 2, tools
    assert tools.count("graph_query") >= 2, tools
    assert tools.count("source") >= 2, tools
    pid_files = list(audit.glob("pid-*"))
    assert tools.count("denied:graph_query") == 1, tools
    assert len(pid_files) == 6, [path.name for path in pid_files]
    for pid_file in pid_files:
        pid = int(pid_file.read_text())
        assert (audit / f"closed-{pid}").exists(), f"Pi {pid} did not observe orderly EOF"
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError(f"orphan Pi process remains: {pid}")
        session = pathlib.Path((audit / f"session-{pid}").read_text())
        assert not session.exists(), f"private Pi session directory persisted: {session}"


def main() -> int:
    if len(sys.argv) != 6:
        raise SystemExit("usage: chat_pty.py CDB CDB_CONFIG CDB_TOKEN_FILE AUDIT_DIR CREDENTIALS")
    binary, config, token, audit_text, credentials = sys.argv[1:]
    audit = pathlib.Path(audit_text)
    normal_flow(binary, config, token)
    revoked_read(binary, config, token, pathlib.Path(credentials))
    idle_exit(binary, config, token, "eof")
    idle_exit(binary, config, token, "ctrl-c")
    busy_exit(binary, config, token, "eof")
    busy_exit(binary, config, token, "ctrl-c")
    verify_audit(audit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
