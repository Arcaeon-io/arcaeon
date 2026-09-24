# SPDX-License-Identifier: MIT
"""Authorship Receipt MCP server — lets a recording tool other than
`web/authorship-recorder.html` (an editor plugin, a CLI wrapper) drive an
authorship session directly, and lets any agent ingest an already-exported
session, over stdio.

Same house shape as `approval_mcp.py` / `cite_mcp.py` / `call_mcp.py`:
JSON-RPC 2.0 over stdio, `initialize`, `tools/list`, `tools/call`;
notifications get no reply; nothing a caller sends ever crashes the
process.

TOOLS:

  authorship_open(author?, document?)   -> {session_id}
      Opens a new `authorship.AuthorshipSession` against this server's
      ledger. Nothing is receipted yet.
  authorship_event(session_id, op, n?, text?)
                                          -> {rolling_hash, events}
      Records one edit event (type / paste / delete / idle) via
      `session.event()`. `text` is digested inside `event()`, never stored
      by this server -- the same "shareable without a keylog" rule
      authorship.py states on its own face.
  authorship_close(session_id, final_text)
                                          -> {receipt_body_digest, receipt_path,
                                             typed_chars, pasted_chars, pasted_share}
      Calls `session.close(final_text)` and writes the receipt. The
      session is gone from server memory afterward -- closing twice is
      refused, matching the one-shot shape `AuthorshipSession.close()`
      already has (a second ledger checkpoint over an already-closed
      session would not be a session at all).
  authorship_ingest_export(export)      -> {receipt_body_digest, receipt_path,
                                            export_rolling_hash_matches}
      Wraps `authorship_ingest.from_export` for a session that was already
      run and exported elsewhere (e.g. the browser recorder page). `export`
      is the parsed JSON object the export file holds, passed inline
      rather than by path, since an MCP host may not share this process's
      filesystem view of the caller's machine.

STATE. Open (not yet closed) sessions live only in this process's memory,
keyed by session_id -- there is no `--state` file, unlike approval_mcp,
because an `AuthorshipSession` holds a live `Ledger` handle and an
in-progress rolling hash that a JSON snapshot cannot round-trip cleanly
without re-deriving from the ledger anyway. A restarted server loses any
session that was open and not yet closed; the ledger itself still holds
every event fold up to the last checkpoint written, which is the honest
half of "resuming" available here. `authorship_ingest_export` needs no
open session at all -- it replays a complete, already-closed export in
one call.

Run:  python -m arcaeon.record.receipt.authorship_mcp --ledger writing.log.jsonl \
        --receipts-dir receipts [--namespace authorship]
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Optional

from . import authorship, authorship_ingest
from .core import save_receipt

PROTOCOL_VERSION = "2025-06-18"


class _ToolError(ValueError):
    """A caller-fixable argument or sequencing problem. Becomes isError:true."""


# --------------------------------------------------------------------------
# the four tools
# --------------------------------------------------------------------------

def _authorship_open(args: dict, *, ledger_path: Path, namespace: str, sessions: dict) -> dict:
    author = args.get("author", "")
    document = args.get("document", "")
    if not isinstance(author, str):
        raise _ToolError(f"author must be a string, got {type(author).__name__}")
    if not isinstance(document, str):
        raise _ToolError(f"document must be a string, got {type(document).__name__}")
    session = authorship.AuthorshipSession(ledger_path, namespace=namespace,
                                           author=author, document=document)
    handle = uuid.uuid4().hex
    sessions[handle] = session
    return {"session_id": handle}


def _get_session(args: dict, sessions: dict) -> tuple:
    session_id = args.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise _ToolError("session_id must be a non-empty string")
    session = sessions.get(session_id)
    if session is None:
        raise _ToolError(f"no open session for session_id: {session_id!r} "
                         "(never opened, already closed, or the server restarted)")
    return session_id, session


def _authorship_event(args: dict, sessions: dict) -> dict:
    session_id, session = _get_session(args, sessions)
    op = args.get("op")
    if op not in authorship.OPS:
        raise _ToolError(f"op must be one of {authorship.OPS}, got {op!r}")
    n = args.get("n", 0)
    if not isinstance(n, int):
        raise _ToolError(f"n must be an integer, got {type(n).__name__}")
    text = args.get("text")
    if text is not None and not isinstance(text, str):
        raise _ToolError(f"text must be a string or omitted, got {type(text).__name__}")
    try:
        rolling = session.event(op, n, text=text)
    except ValueError as e:
        raise _ToolError(str(e)) from e
    return {"rolling_hash": rolling, "events": session.events}


def _authorship_close(args: dict, *, sessions: dict, receipts_dir: Path) -> dict:
    session_id, session = _get_session(args, sessions)
    final_text = args.get("final_text")
    if not isinstance(final_text, str):
        raise _ToolError(f"final_text must be a string, got {type(final_text).__name__}")
    receipt = session.close(final_text)
    del sessions[session_id]  # one-shot: a second close() would checkpoint a dead session
    receipts_dir.mkdir(parents=True, exist_ok=True)
    digest_tail = receipt["body_digest"].rsplit(":", 1)[-1]
    receipt_path = receipts_dir / f"{digest_tail}.json"
    save_receipt(receipt, receipt_path)
    check = receipt["checks"][0]
    return {"receipt_body_digest": receipt["body_digest"], "receipt_path": str(receipt_path),
            "typed_chars": check["typed_chars"], "pasted_chars": check["pasted_chars"],
            "pasted_share": check["pasted_share"]}


def _authorship_ingest_export(args: dict, *, ledger_path: Path, namespace: str) -> dict:
    export = args.get("export")
    if not isinstance(export, dict):
        raise _ToolError(f"export must be a JSON object, got {type(export).__name__}")
    try:
        receipt = authorship_ingest.from_export(export, ledger_path=ledger_path, namespace=namespace)
    except (KeyError, ValueError, TypeError) as e:
        raise _ToolError(str(e)) from e
    return {"receipt_body_digest": receipt["body_digest"],
            "export_rolling_hash_matches": receipt["extra"]["export_rolling_hash_matches"]}


# --------------------------------------------------------------------------
# JSON-RPC / MCP plumbing (same shape as approval_mcp)
# --------------------------------------------------------------------------

TOOLS = [
    {
        "name": "authorship_open",
        "description": "Open a new authorship-recording session. Nothing is receipted yet.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "author": {"type": "string", "description": "Asserted author name."},
                "document": {"type": "string", "description": "Document label."},
            },
        },
    },
    {
        "name": "authorship_event",
        "description": ("Record one edit event (type / paste / delete / idle) in an open "
                        "session. `text`, if given, is digested inside this call and never "
                        "stored -- the receipt is shareable with an accuser without handing "
                        "them a keylog."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "op": {"type": "string", "enum": list(authorship.OPS)},
                "n": {"type": "integer", "description": "Character count, if text is omitted."},
                "text": {"type": "string", "description": "The actual span typed/pasted/deleted; "
                         "digested here, never stored."},
            },
            "required": ["session_id", "op"],
        },
    },
    {
        "name": "authorship_close",
        "description": ("Close a session and issue the Authorship Receipt. This proves the "
                        "recorded edit stream was folded in order with no event inserted, "
                        "removed, or reordered afterward -- never that a human produced the "
                        "keystrokes, and never that pasted text was not generated. A closed "
                        "session cannot be closed again."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "final_text": {"type": "string", "description": "The finished document text."},
            },
            "required": ["session_id", "final_text"],
        },
    },
    {
        "name": "authorship_ingest_export",
        "description": ("Turn an already-exported authorship session (e.g. from "
                        "web/authorship-recorder.html) into an Authorship Receipt. `export` "
                        "is the export's parsed JSON object, passed inline. Reports whether "
                        "the export's own declared rolling_hash matched its events."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "export": {"type": "object", "description": "The parsed *.authorship-export.json "
                          "object."},
            },
            "required": ["export"],
        },
    },
]


def _result(id_, payload):
    return {"jsonrpc": "2.0", "id": id_, "result": payload}


def _error(id_, code, message, data=None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": id_, "error": err}


ERROR_TEXT_MAX = 200


def _clip_error(detail: str, limit: int = ERROR_TEXT_MAX):
    if len(detail) <= limit:
        return detail, None
    return (f"{detail[:limit]}... [truncated: {len(detail)} chars total, {limit} shown]",
            {"error_truncated": True, "error_len": len(detail), "error_shown": limit})


def _text_content(obj) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(obj)}]}


class _Server:
    """Holds the ledger config + the open-session table a stdio session
    serves. Split out of module-level globals so tests can drive
    `dispatch()` directly without a subprocess, mirroring
    approval_mcp._Server's shape."""

    def __init__(self, *, ledger: str | Path, receipts_dir: str | Path, namespace: str = "authorship"):
        self.ledger_path = Path(ledger)
        self.receipts_dir = Path(receipts_dir)
        self.namespace = namespace
        self.sessions: dict = {}

    def dispatch(self, mid, name, args) -> dict:
        try:
            if not isinstance(args, dict):
                raise _ToolError(f"arguments must be a JSON object, got {type(args).__name__}")
            if name == "authorship_open":
                out = _authorship_open(args, ledger_path=self.ledger_path,
                                       namespace=self.namespace, sessions=self.sessions)
                return _result(mid, _text_content(out))
            if name == "authorship_event":
                out = _authorship_event(args, self.sessions)
                return _result(mid, _text_content(out))
            if name == "authorship_close":
                out = _authorship_close(args, sessions=self.sessions, receipts_dir=self.receipts_dir)
                return _result(mid, _text_content(out))
            if name == "authorship_ingest_export":
                out = _authorship_ingest_export(args, ledger_path=self.ledger_path,
                                                namespace=self.namespace)
                return _result(mid, _text_content(out))
            return _result(mid, {**_text_content({"error": f"unknown tool {name}"}), "isError": True})
        except Exception as e:  # never crash the server on one bad call
            detail, extra = _clip_error(str(e))
            payload = {"error": detail}
            if extra is not None:
                payload.update(extra)
            return _result(mid, {**_text_content(payload), "isError": True})

    def handle(self, msg: dict) -> Optional[dict]:
        if not isinstance(msg, dict):
            return _error(None, -32600,
                          f"invalid request: expected a JSON object, got {type(msg).__name__}")
        mid = msg.get("id")
        method = msg.get("method")
        if mid is None:  # notification — no reply
            return None
        if method == "initialize":
            return _result(mid, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "authorship", "version": "0.1.0"},
            })
        if method == "tools/list":
            return _result(mid, {"tools": TOOLS})
        if method == "tools/call":
            params = msg.get("params") or {}
            if not isinstance(params, dict):
                return _error(mid, -32602,
                              f"invalid params: expected an object, got {type(params).__name__}")
            name = params.get("name")
            args = params.get("arguments") or {}
            return self.dispatch(mid, name, args)
        return _error(mid, -32601, f"method not found: {method}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="arcaeon-receipt-authorship-mcp")
    ap.add_argument("--ledger", default="writing.log.jsonl", help="the shared receipt ledger file")
    ap.add_argument("--receipts-dir", default="receipts", help="where authorship_close writes the receipt JSON")
    ap.add_argument("--namespace", default="authorship")
    args = ap.parse_args(argv)

    server = _Server(ledger=args.ledger, receipts_dir=args.receipts_dir, namespace=args.namespace)

    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(errors="replace")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError as e:
            detail, data = _clip_error(str(e))
            resp = _error(None, -32700, f"parse error: {detail}", data=data)
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue
        resp = server.handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
