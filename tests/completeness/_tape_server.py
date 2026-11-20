# SPDX-License-Identifier: MIT
"""A tiny MCP stdio server that keeps its OWN tape of every tools/call.

    python _tape_server.py --tape tool.tape.jsonl

This is the tool side of the completeness proof: the server records what it
received and what it answered, in its own process, with `TapeWriter` (the one
integration a tool vendor adds: `open_call` when a request arrives,
`close_call` with the response). It knows nothing about the proxy in front of
it, so a call that reaches it by any route lands on its tape.

One tool, `add`, so each call's arguments (and so its digest) are distinct.
Deterministic, newline-delimited JSON-RPC, binary stdio.
"""
from __future__ import annotations

import argparse
import json
import sys

from arcaeon.record.adapter.tape import TapeWriter


def handle(msg: dict, tape: TapeWriter):
    mid = msg.get("id")
    method = msg.get("method")
    if mid is None:
        return None
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
            "serverInfo": {"name": "tape-server", "version": "1.0.0"}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": [
            {"name": "add", "description": "Add two integers.",
             "inputSchema": {"type": "object",
                             "properties": {"a": {"type": "integer"},
                                            "b": {"type": "integer"}}}}]}}
    if method == "tools/call":
        params = msg.get("params") or {}
        idx = tape.open_call(params, mid)
        args = params.get("arguments") or {}
        if params.get("name") == "add":
            out = {"jsonrpc": "2.0", "id": mid, "result": {"content": [
                {"type": "text", "text": str(int(args.get("a", 0)) + int(args.get("b", 0)))}]}}
        else:
            out = {"jsonrpc": "2.0", "id": mid, "error": {
                "code": -32602, "message": f"unknown tool {params.get('name')}"}}
        tape.close_call(idx, out)
        return out
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": -32601, "message": f"method not found: {method}"}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tape", required=True)
    args = ap.parse_args(argv)
    tape = TapeWriter(args.tape, side="tool", namespace="tape-server")
    out = sys.stdout.buffer
    try:
        for line in sys.stdin.buffer:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if not isinstance(msg, dict):
                continue
            resp = handle(msg, tape)
            if resp is not None:
                out.write(json.dumps(resp).encode() + b"\n")
                out.flush()
    finally:
        tape.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
