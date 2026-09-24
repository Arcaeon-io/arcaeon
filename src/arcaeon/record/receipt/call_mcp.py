# SPDX-License-Identifier: MIT
"""Receipted Call MCP server — lets an agent that made an x402 (or kin) call
itself mint the delivery receipt, without standing up `call_proxy`'s reverse
proxy in front of the traffic.

Same house shape as `approval_mcp.py` / `cite_mcp.py`: JSON-RPC 2.0 over
stdio, `initialize`, `tools/list`, `tools/call`; notifications get no
reply; nothing a caller sends ever crashes the process.

TOOLS:

  call_receipt(request, response, seller?, elapsed_ms?, raw_payloads?)
      -> {receipt_body_digest, receipt_path}
      Wraps `call.call_receipt` directly: digests of the request body, the
      response body, and any payment header (X-Payment and kin, matched
      case-insensitively the same way call.py does), in sequence, with
      timing. Digests only unless the caller opts into raw_payloads (and
      the tool description says so plainly, same as call_proxy's
      `--raw-payloads` warning) -- never a claim that the response was
      correct or that a payment settled; that is call.SCOPE's own
      does_not_prove, unchanged, on every receipt this tool issues.

`anchor` is always off here, matching `call.call_receipt`'s own default and
`call_proxy`'s stated reasoning: one OTS stamp per call is the wrong
cadence for a sub-dollar transaction. `witness` (the ledger-head pin) is on
by default, same as everywhere else in this package.

Run:  python -m arcaeon.record.receipt.call_mcp --ledger calls.log.jsonl \
        --receipts-dir receipts [--no-witness] [--seller acme]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from . import call
from .core import save_receipt

PROTOCOL_VERSION = "2025-06-18"


class _ToolError(ValueError):
    """A caller-fixable argument problem. Becomes isError:true."""


# --------------------------------------------------------------------------
# the one tool
# --------------------------------------------------------------------------

def _require_dict(v, name: str) -> dict:
    if not isinstance(v, dict):
        raise _ToolError(f"{name} must be a JSON object, got {type(v).__name__}")
    return v


def _call_receipt(args: dict, *, ledger_path: Path, namespace: str, receipts_dir: Path,
                  default_seller: str, witness: bool) -> dict:
    request = _require_dict(args.get("request"), "request")
    response = _require_dict(args.get("response"), "response")
    seller = args.get("seller", default_seller)
    if not isinstance(seller, str):
        raise _ToolError(f"seller must be a string, got {type(seller).__name__}")
    elapsed_ms = args.get("elapsed_ms")
    if elapsed_ms is not None and not isinstance(elapsed_ms, int):
        raise _ToolError(f"elapsed_ms must be an integer, got {type(elapsed_ms).__name__}")
    raw_payloads = args.get("raw_payloads", False)
    if not isinstance(raw_payloads, bool):
        raise _ToolError(f"raw_payloads must be a boolean, got {type(raw_payloads).__name__}")
    error = args.get("error")
    if error is not None and not isinstance(error, str):
        raise _ToolError(f"error must be a string or null, got {type(error).__name__}")

    receipt = call.call_receipt(request, response, ledger_path=ledger_path, namespace=namespace,
                                seller=seller, elapsed_ms=elapsed_ms, raw_payloads=raw_payloads,
                                witness=witness, anchor=False, error=error)
    receipts_dir.mkdir(parents=True, exist_ok=True)
    digest_tail = receipt["body_digest"].rsplit(":", 1)[-1]
    receipt_path = receipts_dir / f"{digest_tail}.json"
    save_receipt(receipt, receipt_path)
    check = receipt["checks"][0]
    return {"receipt_body_digest": receipt["body_digest"], "receipt_path": str(receipt_path),
            "response_status": check["response_status"], "elapsed_ms": check["elapsed_ms"],
            "paid": check.get("payment_header_digest") is not None}


TOOLS = [
    {
        "name": "call_receipt",
        "description": ("Issue a Receipted Call receipt for one agent-to-agent call already "
                        "made: request digest, response digest, payment-header digest (if "
                        "present), in sequence, with timing. Digests only by default -- pass "
                        "raw_payloads:true to embed the actual request/response bodies "
                        "instead, a data-retention choice the caller must make explicitly. "
                        "Never says the response was correct or that a payment settled; that "
                        "belongs to the buyer's own check and to the payment facilitator."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "request": {"type": "object", "description": "{method, url, headers?, body?} "
                           "for the call that was made."},
                "response": {"type": "object", "description": "{status, headers?, body?} "
                            "returned for that call."},
                "seller": {"type": "string", "description": "Overrides the server's default "
                          "--seller for this one receipt."},
                "elapsed_ms": {"type": "integer", "description": "Wall-clock time the call took, "
                              "if known."},
                "raw_payloads": {"type": "boolean", "description": "Embed the actual request/"
                                "response bodies in the receipt instead of only their digests. "
                                "Default false."},
                "error": {"type": ["string", "null"], "description": "A transport-level failure "
                         "note (e.g. upstream unreachable); the call is still receipted, with "
                         "the failure on the check."},
            },
            "required": ["request", "response"],
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
    """Holds the one ledger/seller config a stdio session serves. Split out
    of module-level globals so tests can drive `dispatch()` directly
    without a subprocess, mirroring approval_mcp._Server's shape."""

    def __init__(self, *, ledger: str | Path, receipts_dir: str | Path, namespace: str = "receipted-call",
                seller: str = "", witness: bool = True):
        self.ledger_path = Path(ledger)
        self.receipts_dir = Path(receipts_dir)
        self.namespace = namespace
        self.seller = seller
        self.witness = witness

    def dispatch(self, mid, name, args) -> dict:
        try:
            if not isinstance(args, dict):
                raise _ToolError(f"arguments must be a JSON object, got {type(args).__name__}")
            if name == "call_receipt":
                out = _call_receipt(args, ledger_path=self.ledger_path, namespace=self.namespace,
                                    receipts_dir=self.receipts_dir, default_seller=self.seller,
                                    witness=self.witness)
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
                "serverInfo": {"name": "call", "version": "0.1.0"},
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
    ap = argparse.ArgumentParser(prog="arcaeon-receipt-call-mcp")
    ap.add_argument("--ledger", default="calls.log.jsonl", help="the shared receipt ledger file")
    ap.add_argument("--receipts-dir", default="receipts", help="where call_receipt writes the receipt JSON")
    ap.add_argument("--namespace", default="receipted-call")
    ap.add_argument("--seller", default="", help="default seller name recorded on every receipt")
    ap.add_argument("--no-witness", action="store_true")
    args = ap.parse_args(argv)

    server = _Server(ledger=args.ledger, receipts_dir=args.receipts_dir, namespace=args.namespace,
                     seller=args.seller, witness=not args.no_witness)

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
