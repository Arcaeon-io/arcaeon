"""arcaeon-continuity MCP server — drop `snapshot()` into any MCP agent with
no code beyond wiring this in.

Zero extra dependencies beyond the package's own: MCP is JSON-RPC 2.0 over
stdio, so this speaks it directly rather than pulling the MCP SDK. Any MCP
client (Claude Code, etc.) gets one tool:

  continuity_snapshot(manifest, label, ledger_path)
      -> the sealed ContinuitySnapshot, as a dict (see ContinuitySnapshot.to_dict)

Run:  python -m arcaeon.prove.continuity.mcp_server
Wire into an MCP client (e.g. Claude Code .mcp.json):
  { "mcpServers": { "continuity": {
      "command": "python", "args": ["-m", "arcaeon.prove.continuity.mcp_server"] } } }

Implements the slice of MCP a tool server needs: initialize, tools/list,
tools/call. Protocol version 2025-06-18. Notifications are ignored (no id).

Every tools/call leaves one hash-chained row in the server's own call record
(`$ARCAEON_CALL_RECORD`, default `./continuity.calls.jsonl`; format shared with
arcaeon-ledger). `python -m arcaeon.prove.continuity.mcp_server --verify-calls [path]`
walks the chain. See `_ledger.py` for what the record proves and does not.
This module is import-guarded from the rest of the package: `arcaeon_continuity`
itself never imports this file, so `snapshot()`/`carry_forward()`/
`verify_continuation()`/`drop_receipt()` work with zero MCP awareness and this
server is only touched if you run it directly. Same pattern as
arcaeon_distill.mcp_server and arcaeon_ledger.mcp_server.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from arcaeon.prove.continuity import ContinuityDependencyError, __version__, snapshot
from arcaeon.record.call_record import CallRecord, default_path, verify_call_record

PROTOCOL_VERSION = "2025-06-18"
ARGS_INLINE_MAX = 4096  # bytes of canonical JSON; above this only the digest is kept

TOOLS = [
    {
        "name": "continuity_snapshot",
        "description": (
            "Bundle a declared manifest (identity anchors, open commitments, "
            "canon pointers, live threads — any JSON-serializable dict) into "
            "a sealed, portable continuity snapshot: a pre-registered "
            "arcaeon-baseline probe set over the declared content, digested, "
            "and optionally hash-chained into an arcaeon-ledger log. Returns "
            "the snapshot plus its `digest` — the value to publish so a later "
            "instance (or a stranger) can verify a faithful continuation "
            "against it. Proves the manifest was preserved and the "
            "continuation matches the DECLARED probes, not that 'the same "
            "self' answered them."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest": {
                    "type": "object",
                    "description": "The declared load-bearing state — a JSON "
                                   "object, e.g. {identity_anchors: [...], "
                                   "open_commitments: [...], canon_pointers: "
                                   "[...], live_threads: [...]}.",
                },
                "label": {
                    "type": "string", "default": "continuity",
                    "description": "Label for this snapshot's registration.",
                },
                "ledger_path": {
                    "type": "string",
                    "description": "Optional path to an arcaeon-ledger JSONL "
                                   "file to chain this snapshot into.",
                },
            },
            "required": ["manifest"],
        },
    },
]


def _result(id_, payload):
    return {"jsonrpc": "2.0", "id": id_, "result": payload}


def _error(id_, code, message, data=None):
    """JSON-RPC 2.0 error. `data` is the spec's optional member and is omitted
    entirely when there is nothing to say, so an ordinary error keeps the exact
    shape it has always had on the wire."""
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": id_, "error": err}


ERROR_TEXT_MAX = 200  # chars of a hostile exception's own text we quote back


def _clip_error(detail: str, limit: int = ERROR_TEXT_MAX):
    """Cut an exception's text to `limit` and SAY SO.

    The cut itself is deliberate and stays. A 100k-deep line's own parse
    failure quoted whole into the reply is a 100k-deep reply, which is the
    denial of service arriving a second time through a different door. What
    was missing was the receipt: a caller handed `parse error: <200 chars>`
    could not tell a 200-character complaint from the first 200 characters of
    a 40,000-character one, so a fragment read as the whole thing. One marker
    plus the true length turns the lie into a summary.

    Returns (message_text, data_or_None). `None` when nothing was cut, because
    labelling an intact error as truncated is the same defect pointed the
    other way.

    Latency, stated rather than left to be rediscovered: the stdlib's own
    JSONDecodeError messages run 36 to 80 characters and RecursionError's
    runs 79, so against `json` as it ships today this limit never fires. It
    guards the parser being swapped (orjson and friends quote the offending
    input), a wrapper that interpolates context, and any future caller that
    routes a fatter exception through here.
    """
    if len(detail) <= limit:
        return detail, None
    return (
        f"{detail[:limit]}... [truncated: {len(detail)} chars total, "
        f"{limit} shown]",
        {"error_truncated": True, "error_len": len(detail), "error_shown": limit},
    )


def _text_content(obj) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(obj, default=str)}]}


def _call_continuity_snapshot(args: dict) -> dict:
    if "manifest" not in args:
        return {"error": "manifest is required"}
    kwargs = {}
    if args.get("label"):
        kwargs["label"] = args["label"]
    if args.get("ledger_path"):
        kwargs["ledger_path"] = args["ledger_path"]
    try:
        snap = snapshot(args["manifest"], **kwargs)
    except ContinuityDependencyError as e:
        return {"error": str(e)}
    return snap.to_dict()


def handle(msg: dict):
    """Return a response dict, or None for notifications (no id)."""
    if not isinstance(msg, dict):
        # JSON that parsed but is not a request object (an array, a string,
        # a number, null). JSON-RPC 2.0 answers these with an Invalid Request
        # error carrying id null; before 0.2.3 this line killed the server.
        return _error(None, -32600, "invalid request: not a JSON-RPC object")
    mid = msg.get("id")
    method = msg.get("method")
    if mid is None:
        return None

    if method == "initialize":
        return _result(mid, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "continuity", "version": __version__},
        })
    if method == "tools/list":
        return _result(mid, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        if not isinstance(params, dict):
            return _error(mid, -32602, "invalid params: must be an object")
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            return _error(mid, -32602, "invalid params: arguments must be an object")
        resp = _dispatch_tool(mid, name, args)
        # The server's own call record (OWASP MCP08): one chained row per
        # tools/call, success or refusal, written AFTER the tool so the row
        # carries the outcome. A call whose record cannot be written is
        # reported as an error rather than answered as if it had been logged.
        try:
            _record_call(name, args, resp)
        except Exception as e:
            return _result(mid, {**_text_content(
                {"error": f"tool ran but its call record could not be written: {e}"}),
                "isError": True})
        return resp

    return _error(mid, -32601, f"method not found: {method}")


def _record_call(tool, args, resp) -> dict:
    """Append one call-record row: tool name, the server's own timestamp,
    sha256 of the canonical arguments (always), the arguments inline when
    small, outcome, and the error text on a refused call. `_ledger.CallRecord`
    chains it to the previous row."""
    ok = not resp["result"].get("isError")
    error = None
    if not ok:
        try:
            error = json.loads(resp["result"]["content"][0]["text"]).get("error")
        except (ValueError, KeyError, IndexError, AttributeError):
            error = "error"
    raw = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    row = {"op": "tool_call", "tool": tool,
           "ts": datetime.now(timezone.utc).isoformat(),
           "args_digest": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
           "args": args if len(raw) <= ARGS_INLINE_MAX else None,
           "args_bytes": len(raw), "ok": bool(ok)}
    if error is not None:
        row["error"] = str(error)[:2000]
    return CallRecord(default_path("continuity")).append(row)


def _dispatch_tool(mid, name, args):
    try:
        if name == "continuity_snapshot":
            out = _call_continuity_snapshot(args)
            is_error = "error" in out and len(out) == 1
            payload = _text_content(out)
            if is_error:
                payload["isError"] = True
            return _result(mid, payload)
        return _result(mid, {**_text_content(
            {"error": f"unknown tool {name}"}), "isError": True})
    except Exception as e:  # never crash the server on one bad call
        return _result(mid, {**_text_content({"error": str(e)}), "isError": True})


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ["--verify-calls"]:
        # `python -m arcaeon_continuity.mcp_server --verify-calls [path]`: walk the
        # call record's chain and print the verdict. Exit 1 on a break.
        path = Path(argv[1]) if len(argv) > 1 else default_path("continuity")
        v = verify_call_record(path)
        sys.stdout.write(json.dumps({"path": str(path), **v}) + "\n")
        return 0 if v["ok"] is not False else 1
    # Bytes that are not UTF-8 used to raise UnicodeDecodeError inside the
    # `for` itself, outside every try below. Decode leniently; the line then
    # fails as a parse error or an unknown method, in words, like any other.
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(errors="replace")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except (ValueError, RecursionError) as e:
            # Used to skip in silence, which left a caller waiting on a request
            # the server never acknowledged. JSON-RPC 2.0 answers a parse error
            # with -32700 and a null id. The hostile line is NOT echoed back: a
            # 100k-deep line quoted into the message is a 100k-deep message.
            # The cut now carries a receipt (see _clip_error) so a shortened
            # complaint cannot read as a whole one.
            detail, data = _clip_error(str(e))
            resp = _error(None, -32700, f"parse error: {detail}", data=data)
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue
        resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, default=str) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
