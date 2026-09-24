"""distill MCP server — drop `distill()` into any MCP agent with no code.

Zero dependencies: MCP is JSON-RPC 2.0 over stdio, so this speaks it directly
rather than pulling the SDK (keeps the whole product install-free). Any MCP
client (Claude Code, etc.) gets one tool:

  distill_tool_output(tool_output, budget, schema_hint, query, receipt)
      -> {content, strategy, est_tokens_before, est_tokens_after,
          truncated, receipt}

Run:  python -m arcaeon.save.distill.mcp_server
Wire into an MCP client (e.g. Claude Code .mcp.json):
  { "mcpServers": { "distill": {
      "command": "python", "args": ["-m", "arcaeon.save.distill.mcp_server"] } } }

Implements the slice of MCP a tool server needs: initialize, tools/list,
tools/call. Protocol version 2025-06-18. Notifications are ignored (no id).

Every tools/call leaves one hash-chained row in the server's own call record
(`$ARCAEON_CALL_RECORD`, default `./distill.calls.jsonl`; format shared with
arcaeon-ledger). `python -m arcaeon.save.distill.mcp_server --verify-calls [path]`
walks the chain. See `_ledger.py` for what the record proves and does not.
This module is import-guarded from the rest of the package: `arcaeon_distill`
itself never imports this file, so `distill()` works with zero MCP awareness
and this server is only touched if you run it directly.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from arcaeon.save.distill import distill, __version__
from arcaeon.record.call_record import CallRecord, default_path, verify_call_record

PROTOCOL_VERSION = "2025-06-18"
ARGS_INLINE_MAX = 4096  # bytes of canonical JSON; above this only the digest is kept

TOOLS = [
    {
        "name": "distill_tool_output",
        "description": (
            "Deterministically compact a large tool output (JSON, a table, or "
            "free text) under a token budget. Same input at the same budget "
            "always returns byte-identical output (cache-stable — see the "
            "package docstring for why that matters under prompt caching). "
            "Does NOT guarantee lower billed cost, only a smaller, more "
            "reliable context footprint. Returns a drop receipt describing "
            "exactly what was cut, so you can re-fetch the original if the "
            "cut looks load-bearing."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_output": {
                    "description": "The large tool output to distill: a JSON "
                                   "object/array, or a string (JSON text, a "
                                   "CSV/TSV/markdown table, or free text).",
                },
                "budget": {
                    "type": "integer", "minimum": 1, "default": 2000,
                    "description": "Approximate token budget (heuristic, ~chars/4).",
                },
                "schema_hint": {
                    "type": "string", "enum": ["json", "tabular", "text"],
                    "description": "Force a strategy instead of auto-detecting.",
                },
                "query": {
                    "type": "string",
                    "description": "Optional relevance query for the text "
                                   "strategy's sentence ranking.",
                },
                "timestamp": {
                    "type": "boolean",
                    "description": "Include the receipt's wall-clock "
                                   "created_at. Off by default: it would make "
                                   "two identical calls return different "
                                   "bytes and bust your prefix cache.",
                },
                "receipt": {
                    "type": "boolean", "default": True,
                    "description": "Include a drop receipt in the response.",
                },
            },
            "required": ["tool_output"],
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


def _call_distill(args: dict) -> dict:
    if "tool_output" not in args:
        return {"error": "tool_output is required"}
    kwargs = {}
    if "budget" in args:
        kwargs["budget"] = int(args["budget"])
    if args.get("schema_hint") is not None:
        kwargs["schema_hint"] = args["schema_hint"]
    if args.get("query") is not None:
        kwargs["query"] = args["query"]
    if "receipt" in args:
        kwargs["receipt"] = bool(args["receipt"])
    result = distill(args["tool_output"], **kwargs)
    out = {
        "content": result.content,
        "strategy": result.strategy,
        "budget_tokens": result.budget_tokens,
        "est_tokens_before": result.est_tokens_before,
        "est_tokens_after": result.est_tokens_after,
        "truncated": result.truncated,
        # The receipt's `created_at` is wall-clock. Serialized into the tool
        # result it lands in the agent's context and makes the response NOT
        # byte-identical between two identical calls — busting the prefix
        # cache this tool exists to protect, on the one surface where the
        # claim is advertised. The library's own tests strip it before
        # comparing; the shipped surface has to strip it too. Ask for
        # `timestamp: true` if you want the stamp.
        "receipt": _receipt_payload(result.receipt,
                                    stamp=bool(args.get("timestamp"))),
    }
    return out


def _receipt_payload(receipt, *, stamp: bool):
    if receipt is None:
        return None
    row = receipt.to_dict()
    if not stamp:
        row.pop("created_at", None)
    return row


def handle(msg: dict):
    """Return a response dict, or None for notifications (no id).

    A JSON-RPC message is an object. Anything else that parsed as JSON (a
    bare array, string, number, null) used to reach `msg.get` and kill the
    whole server with an AttributeError (0.1.6) -- one malformed line from a
    client and every later, valid call went unanswered. 0.1.6 stopped the
    crash by returning None, i.e. silence. JSON-RPC 2.0 answers a non-object
    request with Invalid Request and a null id, and silence leaves a caller
    that sent a request waiting on a reply that never comes -- a hang instead
    of a crash is a quieter version of the same defect. It now answers, which
    also matches arcaeon-continuity. A non-object `params` gets the
    invalid-params error, unchanged.
    """
    if not isinstance(msg, dict):
        return _error(None, -32600, "invalid request: not a JSON-RPC object")
    mid = msg.get("id")
    method = msg.get("method")
    if mid is None:
        return None

    if method == "initialize":
        return _result(mid, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "distill", "version": __version__},
        })
    if method == "tools/list":
        return _result(mid, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        if not isinstance(params, dict):
            return _error(mid, -32602, "invalid params: expected an object")
        name = params.get("name")
        args = params.get("arguments") or {}
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
    return CallRecord(default_path("distill")).append(row)


def _dispatch_tool(mid, name, args):
    try:
        if name == "distill_tool_output":
            out = _call_distill(args)
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
        # `python -m arcaeon_distill.mcp_server --verify-calls [path]`: walk the
        # call record's chain and print the verdict. Exit 1 on a break.
        path = Path(argv[1]) if len(argv) > 1 else default_path("distill")
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
