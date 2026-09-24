"""Shared fixture code for the merge-level tests: one real MCP session, recorded.

`record_session()` drives the adapter's SeamObserver in-process with frames a
client would send, answers them with the adapter's own deterministic echo
server, and records BOTH ends of every tool call the way production does:

  agent side   the seam ledger (one chained row per call) + the agent tape
  tool side    a second observer with `side="tool"`, its own seam log and tape
               (what `arcaeon proxy --side tool` wraps around the server)

No subprocess, no network. Frames go through the same observer code the proxy
runs; only the pipe is skipped.
"""
from __future__ import annotations

import json
from pathlib import Path

from arcaeon.record.adapter._echo_server import handle
from arcaeon.record.adapter._ledger import open_ledger
from arcaeon.record.adapter.observer import SeamObserver
from arcaeon.record.adapter.tape import TapeWriter
from arcaeon.record import row as ROW


def _frames(texts):
    yield {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "chain-test", "version": "0"}}}
    yield {"jsonrpc": "2.0", "method": "notifications/initialized"}
    for i, text in enumerate(texts, start=2):
        yield {"jsonrpc": "2.0", "id": i, "method": "tools/call",
               "params": {"name": "echo", "arguments": {"text": text}}}


def record_session(d: Path, texts=("alpha", "bravo", "charlie")) -> dict:
    d.mkdir(parents=True, exist_ok=True)
    paths = {k: d / f"{k}.jsonl" for k in ("seam", "agent_tape", "tool_seam", "tool_tape")}
    agent = SeamObserver(open_ledger(paths["seam"]).append, server="echo", session="agent",
                         tape=TapeWriter(paths["agent_tape"], side="agent", namespace="demo"))
    tool = SeamObserver(open_ledger(paths["tool_seam"]).append, server="echo", session="tool",
                        tape=TapeWriter(paths["tool_tape"], side="tool", namespace="demo"))
    agent.session_begin()
    tool.session_begin()
    for msg in _frames(texts):
        raw = json.dumps(msg).encode("utf-8")
        agent.observe_client_frame(raw)
        tool.observe_client_frame(raw)
        resp = handle(msg)
        if resp is not None:
            out = json.dumps(resp).encode("utf-8")
            tool.observe_server_frame(out)
            agent.observe_server_frame(out)
    for obs in (agent, tool):
        obs.flush_pending(reason="session_end")
        obs.session_end(reason="test_done", exit_code=0)
        obs.tape.flush()
    return paths


def rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip()]


def write_rechained(path: Path, rs: list[dict]) -> None:
    """Write rows with a freshly computed, VALID chain: a forger's copy that
    verifies on its own. Reconcile must still catch what it changed."""
    prev = ROW.GENESIS
    out = []
    for r in rs:
        r = {k: v for k, v in r.items() if k != "chain"}
        r["chain"] = ROW.chain(prev, r)
        prev = r["chain"]
        out.append(json.dumps(r, ensure_ascii=False))
    Path(path).write_text("\n".join(out) + "\n", encoding="utf-8")
