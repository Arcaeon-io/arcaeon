"""cite_mcp.py driven dispatch-level (no subprocess): construct the
`_Server` directly and call `.dispatch()`/`.handle()`, the seam
approval_mcp.py's own docstring says exists for exactly this. Covers: the
protocol handshake, a clean citation check, the planted-fake fixture
flagging the same two citations test_receipts.py already proves, a bad
call that never crashes the server, and that the written receipt verifies."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from arcaeon.record.receipt.cite_mcp import PROTOCOL_VERSION, TOOLS, _Server
from arcaeon.record.receipt.core import load_receipt, verify_receipt

# A-022 (2026-09-12): scoped to exactly the citations BRIEF mentions -- see
# the matching note in test_receipts.py; do not repoint this at
# courtlistener_planted_full.json (that fixture carries entries this BRIEF
# never mentions and would inflate `total` with phantom checks).
FIX = Path(__file__).parent / "fixtures" / "courtlistener_planted.json"
# "100 Cal. 200" retired (real case, not a fake -- see test_receipts.py's
# note); "88 Zzq. 12" is the genuinely nonexistent replacement.
BRIEF = ("Plaintiff relies on Brown v. Board of Education, 347 U.S. 483 (1954), and on "
         "Roe v. Wade, 410 U.S. 113 (1973). Defendant cites Smith v. Nowhere, 999 F.3d 1234 "
         "(9th Cir. 2021), a case that does not exist, and 12 Fak. 34, and 88 Zzq. 12.")

TOOL_NAMES = {"cite_check"}


def _server(tmp_path: Path, **kw) -> _Server:
    return _Server(ledger=tmp_path / "receipts.log.jsonl", receipts_dir=tmp_path / "receipts",
                   fixture=FIX, witness=False, anchor=False, **kw)


def _payload(result: dict) -> dict:
    return json.loads(result["result"]["content"][0]["text"])


def test_initialize_and_tools_list(tmp_path):
    srv = _server(tmp_path)
    init = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                  "clientInfo": {"name": "test", "version": "0"}}})
    assert init["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert init["result"]["serverInfo"]["name"] == "cite"

    listed = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in listed["result"]["tools"]}
    assert names == TOOL_NAMES
    assert TOOLS[0]["inputSchema"]["required"] == ["text"]

    # a notification (no id) draws no reply at all
    assert srv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_never_crashes_on_a_bad_call(tmp_path):
    srv = _server(tmp_path)
    resp = srv.dispatch(1, "cite_check", {"text": 12345})
    assert resp["result"]["isError"] is True
    assert "text" in _payload(resp)["error"]

    unknown = srv.dispatch(2, "nonexistent_tool", {})
    assert unknown["result"]["isError"] is True

    not_object = srv.dispatch(3, "cite_check", "not-a-dict")
    assert not_object["result"]["isError"] is True

    # server is still alive afterward
    again = srv.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
    assert {t["name"] for t in again["result"]["tools"]} == TOOL_NAMES


def test_cite_check_flags_the_planted_fakes_and_receipt_verifies(tmp_path):
    srv = _server(tmp_path)
    resp = srv.dispatch(1, "cite_check", {"text": BRIEF, "document_name": "brief.txt"})
    assert resp["result"].get("isError") is None, resp
    out = _payload(resp)

    assert out["total"] == 5
    assert set(out["flagged"]) == {"999 F.3d 1234", "12 Fak. 34", "88 Zzq. 12"}
    assert out["not_checked"] == []
    assert out["receipt_body_digest"]

    receipt = load_receipt(out["receipt_path"])
    assert receipt["body_digest"] == out["receipt_body_digest"]
    assert receipt["kind"] == "citation-existence"
    assert "correct" not in " ".join(receipt["scope"]["proves"]).lower()
    v = verify_receipt(receipt, ledger_path=srv.ledger_path)
    assert v["ok"], v


def test_document_name_must_be_a_string(tmp_path):
    srv = _server(tmp_path)
    resp = srv.dispatch(1, "cite_check", {"text": BRIEF, "document_name": 5})
    assert resp["result"]["isError"] is True
    assert "document_name" in _payload(resp)["error"]


def test_missing_courtlistener_token_becomes_a_tool_error(tmp_path, monkeypatch):
    # No --fixture this time: the live transport path requires the token.
    monkeypatch.delenv("COURTLISTENER_TOKEN", raising=False)
    srv = _Server(ledger=tmp_path / "receipts.log.jsonl", receipts_dir=tmp_path / "receipts",
                 witness=False, anchor=False)
    resp = srv.dispatch(1, "cite_check", {"text": "347 U.S. 483"})
    assert resp["result"]["isError"] is True
    assert "COURTLISTENER_TOKEN" in _payload(resp)["error"]
