# SPDX-License-Identifier: MIT
"""Citation Receipt MCP server — lets a lawyer's own MCP-capable agent mint
a citation-existence receipt directly, without shelling out to the CLI.

Same house shape as `approval_mcp.py` (itself matching arcaeon-ledger's
`arcaeon_ledger/mcp_server.py`): JSON-RPC 2.0 over stdio, `initialize`,
`tools/list`, `tools/call`; notifications get no reply; nothing a caller
sends ever crashes the process.

TOOLS:

  cite_check(text, document_name?)  -> {receipt_body_digest, receipt_path,
                                         total, flagged, not_checked}
      Runs the citation-lookup over `text` (any length -- chunked and
      re-based through `cite_batch.citation_receipt_batched`, which behaves
      identically to `cite.citation_receipt` for text under the 64k cap),
      writes the receipt JSON to `--receipts-dir`, and returns its digest
      and path plus the two lists a caller actually needs to act on:
      `flagged` (not_found / invalid_reporter / ambiguous /
      not_recognized_by_service -- the exact statuses `cite.py` already
      uses; this tool invents no new verdict word) and `not_checked`
      (rate-limited citations still unresolved after the batch module's
      bounded retries). Nothing here says a citation is correct, good law,
      or quoted right -- that is the receipt's own `scope.does_not_prove`,
      unchanged, on every receipt this tool issues.

TRANSPORT. Configured once at server start, not per call: `--fixture` (a
saved API response, for the offline/demo case -- see
`cite.fixture_transport`) or, absent that, the live CourtListener API via
`cite.default_transport`, which reads `COURTLISTENER_TOKEN` from the
environment. A live call that fails (missing token, network error) comes
back as a tool error, never a guessed status.

Run:  python -m arcaeon.record.receipt.cite_mcp --ledger receipts.log.jsonl \
        --receipts-dir receipts [--fixture saved_api_response.json]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from . import cite, cite_batch
from .core import save_receipt

PROTOCOL_VERSION = "2025-06-18"


class _ToolError(ValueError):
    """A caller-fixable argument or transport problem. Becomes isError:true."""


# --------------------------------------------------------------------------
# the one tool
# --------------------------------------------------------------------------

def _cite_check(args: dict, *, ledger_path: Path, namespace: str, receipts_dir: Path,
                transport, witness: bool, anchor: bool) -> dict:
    text = args.get("text")
    if not isinstance(text, str) or not text:
        raise _ToolError(f"text must be a non-empty string, got {type(text).__name__}")
    document_name = args.get("document_name", "")
    if not isinstance(document_name, str):
        raise _ToolError(f"document_name must be a string, got {type(document_name).__name__}")
    try:
        receipt = cite_batch.citation_receipt_batched(
            text, ledger_path=ledger_path, namespace=namespace, document_name=document_name,
            transport=transport, witness=witness, anchor=anchor)
    except (RuntimeError, ValueError) as e:
        # missing COURTLISTENER_TOKEN, a transport that returned a non-list,
        # or anything else check_citations already refuses to guess at.
        raise _ToolError(str(e)) from e
    receipts_dir.mkdir(parents=True, exist_ok=True)
    digest_tail = receipt["body_digest"].rsplit(":", 1)[-1]
    receipt_path = receipts_dir / f"{digest_tail}.json"
    save_receipt(receipt, receipt_path)
    summ = receipt["extra"]["summary"]
    return {"receipt_body_digest": receipt["body_digest"], "receipt_path": str(receipt_path),
            "total": summ["total"], "flagged": summ["flagged"], "not_checked": summ["not_checked"]}


TOOLS = [
    {
        "name": "cite_check",
        "description": ("Check every citation in a block of text for existence against "
                        "CourtListener (or a configured offline fixture), and issue a "
                        "Citation Receipt. Returns the receipt's digest and file path, the "
                        "total citations detected, and the ones flagged (not_found / "
                        "invalid_reporter / ambiguous / not_recognized_by_service) or still "
                        "not_checked after rate-limit retries. Existence only: this never "
                        "says a citation supports the point it is cited for, is good law, or "
                        "is quoted correctly."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "The text to check citations in."},
                "document_name": {"type": "string", "description": "Optional label for the "
                                  "subject block (e.g. the brief's filename)."},
            },
            "required": ["text"],
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
    """Holds the one transport + ledger config a stdio session serves. Split
    out of module-level globals so tests can drive `dispatch()` directly
    without a subprocess, mirroring approval_mcp._Server's shape."""

    def __init__(self, *, ledger: str | Path, receipts_dir: str | Path, namespace: str = "citation-receipt",
                fixture: Optional[str | Path] = None, witness: bool = True, anchor: bool = True):
        self.ledger_path = Path(ledger)
        self.receipts_dir = Path(receipts_dir)
        self.namespace = namespace
        self.transport = cite.fixture_transport(fixture) if fixture else None
        self.witness = witness
        self.anchor = anchor

    def dispatch(self, mid, name, args) -> dict:
        try:
            if not isinstance(args, dict):
                raise _ToolError(f"arguments must be a JSON object, got {type(args).__name__}")
            if name == "cite_check":
                out = _cite_check(args, ledger_path=self.ledger_path, namespace=self.namespace,
                                  receipts_dir=self.receipts_dir, transport=self.transport,
                                  witness=self.witness, anchor=self.anchor)
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
                "serverInfo": {"name": "cite", "version": "0.1.0"},
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
    ap = argparse.ArgumentParser(prog="arcaeon-receipt-cite-mcp")
    ap.add_argument("--ledger", default="receipts.log.jsonl", help="the shared receipt ledger file")
    ap.add_argument("--receipts-dir", default="receipts", help="where cite_check writes the receipt JSON")
    ap.add_argument("--namespace", default="citation-receipt")
    ap.add_argument("--fixture", default=None,
                    help="replay a saved API response instead of calling CourtListener live")
    ap.add_argument("--no-anchor", action="store_true")
    ap.add_argument("--no-witness", action="store_true")
    args = ap.parse_args(argv)

    server = _Server(ledger=args.ledger, receipts_dir=args.receipts_dir, namespace=args.namespace,
                     fixture=args.fixture, witness=not args.no_witness, anchor=not args.no_anchor)

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
