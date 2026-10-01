#!/usr/bin/env python3
"""Deterministic Pi RPC double for the native PTY acceptance test."""
import json
import os
import pathlib
import socket
import sys
import time
import traceback

if "--version" in sys.argv:
    print("0.87.1")
    raise SystemExit(0)

AUDIT = pathlib.Path("{{AUDIT}}")
SUBJECT = "{{SUBJECT}}"
AUDIT.mkdir(parents=True, exist_ok=True)
pid = os.getpid()
(AUDIT / f"pid-{pid}").write_text(str(pid))
(AUDIT / f"session-{pid}").write_text(os.environ.get("PI_CODING_AGENT_SESSION_DIR", ""))
turn = 0
prior = []
call_sequence = 0


def emit(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


def host_call(capability, request, expect_denied=False):
    global call_sequence
    call_sequence += 1
    call_id = f"pty-{pid}-{call_sequence}"
    emit({"type": "tool_execution_start", "toolCallId": call_id,
          "toolName": "ctxql_" + capability, "args": request})
    envelope = {
        "token": os.environ["CTXQL_ONTOLOGY_TOKEN"],
        "kind": "call",
        "call_id": call_id,
        "capability": capability,
        "request": request,
    }
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(10)
    client.connect(os.environ["CTXQL_ONTOLOGY_SOCKET"])
    client.sendall(json.dumps(envelope, separators=(",", ":")).encode() + b"\n")
    chunks = []
    while True:
        chunk = client.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    client.close()
    response = json.loads(b"".join(chunks))
    if expect_denied:
        if response != {"ok": True, "response": {"status": "denied"}}:
            raise RuntimeError("revoked read did not return the exact handle-free denial")
        with (AUDIT / "tools.log").open("a") as audit:
            audit.write("denied:" + capability + "\n")
        return None
    if response.get("ok") is not True:
        raise RuntimeError(f"host denied {capability}: {response.get('error')}")
    with (AUDIT / "tools.log").open("a") as audit:
        audit.write(capability + "\n")
    return response["response"]


def assistant(text, hang=False):
    global turn
    identity = f"pty-response-{turn}"
    usage = {"input": 10, "output": 2, "cacheRead": 0, "cacheWrite": 0,
             "totalTokens": 12, "cost": {"input": 0, "output": 0,
                                       "cacheRead": 0, "cacheWrite": 0, "total": 0.01}}
    emit({"type": "agent_start"})
    emit({"type": "turn_start"})
    emit({"type": "message_start", "message": {"role": "assistant",
          "provider": "openrouter", "model": "deepseek/deepseek-v4.1-flash",
          "responseId": identity, "content": [], "stopReason": "pending", "usage": usage}})
    emit({"type": "message_update",
          "assistantMessageEvent": {"type": "text_start", "contentIndex": 0}})
    emit({"type": "message_update", "usage": usage,
          "assistantMessageEvent": {"type": "text_delta", "contentIndex": 0, "delta": text}})
    if hang:
        return
    # Ensure the PTY observes streamed prose before the completion event.
    time.sleep(0.25)
    emit({"type": "message_update",
          "assistantMessageEvent": {"type": "text_end", "contentIndex": 0, "content": text}})
    emit({"type": "message_end", "message": {"role": "assistant",
          "provider": "openrouter", "model": "deepseek/deepseek-v4.1-flash",
          "responseId": identity, "content": [{"type": "text", "text": text}],
          "stopReason": "stop", "usage": usage}})
    emit({"type": "agent_end", "messages": [], "willRetry": False})
    emit({"type": "agent_settled"})


try:
    for line in sys.stdin:
        request = json.loads(line)
        ident = request.get("id", "")
        kind = request.get("type", "")
        if kind == "get_state":
            emit({"type": "response", "id": ident, "command": kind, "success": True,
                  "data": {"model": {"provider": "openrouter", "id": "deepseek/deepseek-v4.1-flash"},
                           "thinkingLevel": "high", "isStreaming": False,
                           "pendingMessageCount": 0, "sessionFile": None}})
        elif kind in ("set_auto_compaction", "set_auto_retry"):
            emit({"type": "response", "id": ident, "command": kind, "success": True})
        elif kind == "get_commands":
            emit({"type": "response", "id": ident, "command": kind, "success": True,
                  "data": {"commands": []}})
        elif kind == "new_session":
            prior.clear()
            emit({"type": "response", "id": ident, "command": kind, "success": True,
                  "data": {"cancelled": False}})
        elif kind == "clear_queue":
            emit({"type": "response", "id": ident, "command": kind, "success": True,
                  "data": {"steering": [], "followUp": []}})
        elif kind == "abort":
            emit({"type": "agent_settled"})
            emit({"type": "response", "id": ident, "command": kind, "success": True})
        elif kind == "prompt":
            turn += 1
            message = request["message"].split("\n", 1)[-1]
            prior.append(message)
            emit({"type": "response", "id": ident, "command": kind, "success": True})
            if message == "busy question":
                assistant("busy-delta", hang=True)
                continue
            if message == "remember without reading":
                assistant("prior-context retained=" + str(prior[0] == "first question").lower())
                continue
            if message == "attempt protected read":
                host_call("graph_query", {"query": json.dumps({
                    "about": [{"from": [SUBJECT], "match": "exact"}],
                    "bounds": {"max_depth": 1, "seed_limit": 1, "fanout_limit": 16,
                               "max_claims": 32, "path_limit": 16}
                }, separators=(",", ":"))}, expect_denied=True)
                assistant("protected-read denied")
                continue
            host_call("capabilities", {})
            graph = host_call("graph_query", {"query": json.dumps({
                "about": [{"from": [SUBJECT], "match": "exact"}],
                "bounds": {"max_depth": 1, "seed_limit": 1, "fanout_limit": 16,
                           "max_claims": 32, "path_limit": 16}
            }, separators=(",", ":"))})
            references = graph.get("source_references", [])
            resolvable = next((item for item in references if item.get("resolvable") and item.get("citation")), None)
            if resolvable:
                host_call("source", {"reference": resolvable["citation"]})
            if turn == 1:
                text = "turn-1 graph-and-source complete"
            else:
                text = "turn-2 follow-up retained first question=" + str(prior[0] == "first question").lower()
            text += " " + graph["claims"][0]["citation"]
            if resolvable:
                text += " " + resolvable["citation"]
            text += " [C999]"  # Unknown references must still produce a warning.
            assistant(text)
except BaseException:
    (AUDIT / f"error-{pid}").write_text(traceback.format_exc())
    raise
finally:
    (AUDIT / f"closed-{pid}").write_text("closed")
