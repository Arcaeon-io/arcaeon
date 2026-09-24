"""call_mcp.py driven dispatch-level (no subprocess): construct the
`_Server` directly and call `.dispatch()`/`.handle()`, the seam
approval_mcp.py's own docstring says exists for exactly this. Covers: the
protocol handshake, digests-only by default, a payment header digested and
flagged, raw_payloads opting in, an upstream error still receipted, and
that the written receipt verifies."""
from __future__ import annotations

import json
from pathlib import Path

from arcaeon.record.receipt.call_mcp import PROTOCOL_VERSION, TOOLS, _Server
from arcaeon.record.receipt.core import load_receipt, verify_receipt

TOOL_NAMES = {"call_receipt"}


def _server(tmp_path: Path, **kw) -> _Server:
    return _Server(ledger=tmp_path / "calls.log.jsonl", receipts_dir=tmp_path / "receipts",
                   witness=False, **kw)


def _payload(result: dict) -> dict:
    return json.loads(result["result"]["content"][0]["text"])


def test_initialize_and_tools_list(tmp_path):
    srv = _server(tmp_path)
    init = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                  "clientInfo": {"name": "test", "version": "0"}}})
    assert init["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert init["result"]["serverInfo"]["name"] == "call"

    listed = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in listed["result"]["tools"]}
    assert names == TOOL_NAMES
    assert TOOLS[0]["inputSchema"]["required"] == ["request", "response"]

    assert srv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_never_crashes_on_a_bad_call(tmp_path):
    srv = _server(tmp_path)
    resp = srv.dispatch(1, "call_receipt", {"request": "not-an-object", "response": {}})
    assert resp["result"]["isError"] is True
    assert "request" in _payload(resp)["error"]

    unknown = srv.dispatch(2, "nonexistent_tool", {})
    assert unknown["result"]["isError"] is True

    again = srv.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    assert {t["name"] for t in again["result"]["tools"]} == TOOL_NAMES


def test_digests_only_by_default_and_receipt_verifies(tmp_path):
    srv = _server(tmp_path)
    request = {"method": "GET", "url": "https://seller.example/v1/lookup",
              "headers": {"X-Payment": "sig-abc123"}, "body": {"q": "widget"}}
    response = {"status": 200, "body": {"answer": 42}}
    resp = srv.dispatch(1, "call_receipt", {"request": request, "response": response,
                                            "elapsed_ms": 120})
    assert resp["result"].get("isError") is None, resp
    out = _payload(resp)
    assert out["response_status"] == 200
    assert out["elapsed_ms"] == 120
    assert out["paid"] is True

    receipt = load_receipt(out["receipt_path"])
    assert receipt["body_digest"] == out["receipt_body_digest"]
    assert receipt["kind"] == "receipted-call"
    check = receipt["checks"][0]
    assert "request_body" not in check and "response_body" not in check
    assert check["payment_header_digest"]
    assert "correct" not in " ".join(receipt["scope"]["proves"]).lower()
    v = verify_receipt(receipt, ledger_path=srv.ledger_path)
    assert v["ok"], v


def test_raw_payloads_opt_in_embeds_bodies(tmp_path):
    srv = _server(tmp_path)
    request = {"method": "POST", "url": "https://seller.example/v1/act", "body": {"a": 1}}
    response = {"status": 200, "body": {"b": 2}}
    out = _payload(srv.dispatch(1, "call_receipt",
                                {"request": request, "response": response, "raw_payloads": True}))
    receipt = load_receipt(out["receipt_path"])
    check = receipt["checks"][0]
    assert check["request_body"] == {"a": 1}
    assert check["response_body"] == {"b": 2}


def test_upstream_error_is_still_receipted(tmp_path):
    srv = _server(tmp_path)
    request = {"method": "GET", "url": "https://seller.example/v1/down"}
    response = {"status": 502, "body": {"error": "upstream_error"}}
    out = _payload(srv.dispatch(1, "call_receipt",
                                {"request": request, "response": response,
                                 "error": "connection refused"}))
    receipt = load_receipt(out["receipt_path"])
    check = receipt["checks"][0]
    assert check["upstream_error"] == "connection refused"
    assert out["response_status"] == 502


def test_server_default_seller_used_unless_overridden(tmp_path):
    srv = _server(tmp_path, seller="acme")
    request = {"method": "GET", "url": "https://x/y"}
    response = {"status": 200, "body": {}}
    out = _payload(srv.dispatch(1, "call_receipt", {"request": request, "response": response}))
    receipt = load_receipt(out["receipt_path"])
    assert receipt["subject"]["seller"] == "acme"

    out2 = _payload(srv.dispatch(2, "call_receipt",
                                 {"request": request, "response": response, "seller": "other"}))
    receipt2 = load_receipt(out2["receipt_path"])
    assert receipt2["subject"]["seller"] == "other"
