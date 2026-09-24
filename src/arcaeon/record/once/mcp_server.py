"""arcaeon-once MCP server -- claim/complete an idempotency key with no code.

Zero dependencies beyond arcaeon-once itself: MCP is JSON-RPC 2.0 over stdio,
so this speaks it directly (same pattern as arcaeon-distill's server). One
tool, two actions, mirroring the library's own two-phase design so the crash
window is real even across the MCP boundary:

  guard_side_effect(action="claim", key, ledger_path=None, on_duplicate=...,
                     allow_retry_after_indeterminate=False)
      -> {claimed: bool, reason?, receipt?}
      Call BEFORE performing the side effect (e.g. before calling another
      tool that issues the refund / deploy / email). If claimed=False, DO
      NOT perform the side effect -- reason is "already_executed" or
      "indeterminate", receipt carries the detail.

  guard_side_effect(action="complete", key, ledger_path=None, outcome=None,
                     store_outcome=False)
      -> {completed: bool, chain, outcome_digest}
      Call AFTER the side effect succeeds. If the calling agent/session dies
      between claim and complete, the key is left `intent`-only --
      indeterminate on the next claim, exactly the crash window the library
      documents, not hidden by the MCP wrapping.

Run:  python -m arcaeon.record.once.mcp_server
Wire into an MCP client (e.g. Claude Code .mcp.json):
  { "mcpServers": { "once": {
      "command": "python", "args": ["-m", "arcaeon.record.once.mcp_server"] } } }

Every tools/call leaves one hash-chained row in the server's own call record
(`$ARCAEON_CALL_RECORD`, default `./once.calls.jsonl`; format shared with
arcaeon-ledger). `python -m arcaeon.record.once.mcp_server --verify-calls [path]`
walks the chain. See `_ledger.py` for what the record proves and does not.

Import-guarded from the rest of the package: `arcaeon_once` itself never
imports this file, so `guard()` works with zero MCP awareness.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from arcaeon.record.once import (
    AlreadyExecuted, IndexUnavailable, Indeterminate, TamperDetected,
    __version__, complete, guard,
)
from arcaeon.record.call_record import CallRecord, default_path, verify_call_record

PROTOCOL_VERSION = "2025-06-18"
ARGS_INLINE_MAX = 4096  # bytes of canonical JSON; above this only the digest is kept
DEFAULT_LEDGER = "once.log.jsonl"

TOOLS = [
    {
        "name": "guard_side_effect",
        "description": (
            "Guard a non-idempotent side effect (refund, deploy, outbound "
            "email, any real-world action that must not double-fire) with an "
            "idempotency key, backed by a tamper-evident hash-chained "
            "ledger. Two actions: 'claim' BEFORE performing the effect "
            "(refuses if this key already executed or is stuck in an "
            "unresolved crash-window state), 'complete' AFTER it succeeds. "
            "NOT exactly-once: if you claim and then never complete (e.g. "
            "your own process/session dies mid-effect), the key is left "
            "flagged indeterminate rather than silently assumed either way."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["claim", "complete"]},
                "key": {"type": "string",
                        "description": "The idempotency key, e.g. 'refund:pi_123'."},
                "ledger_path": {"type": "string",
                                "description": f"Default {DEFAULT_LEDGER!r}."},
                "on_duplicate": {"type": "string", "enum": ["raise", "return_receipt"],
                                  "default": "raise",
                                  "description": "claim only. 'raise' returns "
                                  "claimed=false + an error-shaped reason; "
                                  "'return_receipt' returns claimed=false + "
                                  "the prior receipt, no exception either way "
                                  "over this JSON-RPC boundary."},
                "allow_retry_after_indeterminate": {
                    "type": "boolean", "default": False,
                    "description": "claim only, and ONLY after you manually "
                    "verified an indeterminate key's effect did NOT happen. "
                    "NOTE: this flag alone no longer recovers a key crashed "
                    "mid-effect -- it will still return claimed=false / "
                    "indeterminate, BY DESIGN (the flag once let a second "
                    "caller steal a live claim and double-fire). Recovering a "
                    "crashed claim needs an operator to quiesce all guarded "
                    "work and run `python -m arcaeon.record.once rebuild_index` (or "
                    "arcaeon_once.rebuild_index()) OUT OF BAND -- there is "
                    "deliberately no rebuild action over MCP, because a rebuild "
                    "run while other agents hold live claims would make those "
                    "claims stealable. If the effect DID land, use "
                    "action=complete instead; that path is unchanged."},
                "outcome": {
                    "description": "complete only. JSON-serializable result "
                    "of the side effect, digested into the receipt."},
                "store_outcome": {
                    "type": "boolean", "default": False,
                    "description": "complete only. Also store the raw "
                    "outcome (not just its digest) in the ledger row."},
            },
            "required": ["action", "key"],
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


def _call_guard(args: dict) -> dict:
    action = args.get("action")
    key = args.get("key")
    if not key:
        return {"error": "key is required"}
    ledger_path = args.get("ledger_path") or DEFAULT_LEDGER

    if action == "claim":
        g = guard(
            key, ledger_path=ledger_path,
            on_duplicate=args.get("on_duplicate", "raise"),
            allow_retry_after_indeterminate=bool(
                args.get("allow_retry_after_indeterminate", False)))
        try:
            g.__enter__()
        except AlreadyExecuted as e:
            return {"claimed": False, "reason": "already_executed",
                    "receipt": e.receipt.to_dict()}
        except Indeterminate as e:
            return {"claimed": False, "reason": "indeterminate",
                    "receipt": e.receipt.to_dict()}
        except TamperDetected as e:
            return {"claimed": False, "reason": "tamper_detected",
                    "verify": {
                        "ok": e.verify_result.ok,
                        "first_break": e.verify_result.first_break,
                        # first_break alone reads as "there is one fault".
                        "breaks": getattr(e.verify_result, "breaks", None),
                        "verified_scope": getattr(
                            e.verify_result, "verified_scope", None)}}
        except IndexUnavailable as e:
            # Contention on the concurrency index, not a verdict about the
            # key. Fails safe -- nothing was claimed, nothing ran -- so the
            # caller may retry. Named across the MCP boundary too, rather
            # than degrading into a generic error blob.
            return {"claimed": False, "reason": "index_unavailable",
                    "retryable": True, "operation": e.operation,
                    "detail": str(e)}
        if g.already_executed:
            return {"claimed": False, "reason": "already_executed",
                    "receipt": g.receipt.to_dict()}
        return {"claimed": True, "key": key, "ledger_path": str(ledger_path)}

    if action == "complete":
        try:
            rec = complete(key, args.get("outcome"), ledger_path=ledger_path,
                           store_outcome=bool(args.get("store_outcome", False)))
        except ValueError as e:
            return {"error": str(e)}
        except IndexUnavailable as e:
            # `.ledger_committed` decides the whole meaning here: True means
            # the executed row IS durable and only the index is stale -- so
            # this is emphatically NOT retryable as a side effect.
            return {"completed": bool(e.ledger_committed),
                    "reason": "index_unavailable",
                    "ledger_committed": bool(e.ledger_committed),
                    "retryable": not e.ledger_committed,
                    "detail": str(e)}
        return {"completed": True, "key": key, "chain": rec.executed_chain,
                "outcome_digest": rec.outcome_digest}

    return {"error": f"unknown action {action!r}, must be 'claim' or 'complete'"}


def handle(msg: dict):
    """Return a response dict, or None for notifications (no id)."""
    mid = msg.get("id")
    method = msg.get("method")
    if mid is None:
        return None

    if method == "initialize":
        return _result(mid, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "once", "version": __version__},
        })
    if method == "tools/list":
        return _result(mid, {"tools": TOOLS})
    if method == "tools/call":
        # `params` / `arguments` are client-supplied; a non-object value
        # (`"params": [1]`) used to AttributeError here, outside the try,
        # and take the whole server down (audit 2026-09-01).
        params = msg.get("params")
        if not isinstance(params, dict):
            params = {}
        name = params.get("name")
        args = params.get("arguments")
        if not isinstance(args, dict):
            args = {}
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
    return CallRecord(default_path("once")).append(row)


def _dispatch_tool(mid, name, args):
    try:
        if name == "guard_side_effect":
            out = _call_guard(args)
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
        # `python -m arcaeon_once.mcp_server --verify-calls [path]`: walk the
        # call record's chain and print the verdict. Exit 1 on a break.
        path = Path(argv[1]) if len(argv) > 1 else default_path("once")
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
        if not isinstance(msg, dict):
            # JSON that parsed but is not a request object (an array, a string,
            # a number, null). JSON-RPC 2.0 answers these with Invalid Request
            # and a null id; skipping in silence leaves a caller waiting.
            resp = _error(None, -32600, "invalid request: not a JSON-RPC object")
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
