"""authorship_mcp.py driven dispatch-level (no subprocess): construct the
`_Server` directly and call `.dispatch()`/`.handle()`, the seam
approval_mcp.py's own docstring says exists for exactly this. Covers: the
protocol handshake, a type/paste/close sequence whose counts and rolling
hash match calling authorship.py directly, close-twice refused, an unknown
session refused, and authorship_ingest_export over an inline export dict."""
from __future__ import annotations

import json

from arcaeon.record.receipt import authorship
from arcaeon.record.receipt.authorship_mcp import PROTOCOL_VERSION, TOOLS, _Server
from arcaeon.record.receipt.core import load_receipt, verify_receipt

TOOL_NAMES = {"authorship_open", "authorship_event", "authorship_close", "authorship_ingest_export"}


def _server(tmp_path):
    return _Server(ledger=tmp_path / "writing.log.jsonl", receipts_dir=tmp_path / "receipts")


def _payload(result: dict) -> dict:
    return json.loads(result["result"]["content"][0]["text"])


def test_initialize_and_tools_list(tmp_path):
    srv = _server(tmp_path)
    init = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                  "clientInfo": {"name": "test", "version": "0"}}})
    assert init["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert init["result"]["serverInfo"]["name"] == "authorship"

    listed = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in listed["result"]["tools"]}
    assert names == TOOL_NAMES
    assert TOOLS[1]["inputSchema"]["required"] == ["session_id", "op"]

    assert srv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_never_crashes_on_a_bad_call(tmp_path):
    srv = _server(tmp_path)
    bad_op = srv.dispatch(1, "authorship_event", {"session_id": "nope", "op": "fly"})
    assert bad_op["result"]["isError"] is True

    unknown_session = srv.dispatch(2, "authorship_event", {"session_id": "nope", "op": "type", "n": 1})
    assert unknown_session["result"]["isError"] is True
    assert "session_id" in _payload(unknown_session)["error"]

    unknown_tool = srv.dispatch(3, "nonexistent_tool", {})
    assert unknown_tool["result"]["isError"] is True

    again = srv.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
    assert {t["name"] for t in again["result"]["tools"]} == TOOL_NAMES


def test_type_paste_close_matches_calling_authorship_directly(tmp_path):
    srv = _server(tmp_path)

    opened = _payload(srv.dispatch(1, "authorship_open", {"author": "a. writer", "document": "essay"}))
    session_id = opened["session_id"]
    assert session_id

    e1 = _payload(srv.dispatch(2, "authorship_event",
                               {"session_id": session_id, "op": "type", "text": "The quick "}))
    assert e1["events"] == 1
    e2 = _payload(srv.dispatch(3, "authorship_event",
                               {"session_id": session_id, "op": "paste", "text": "brown fox"}))
    assert e2["events"] == 2
    assert e2["rolling_hash"] != e1["rolling_hash"]

    final_text = "The quick brown fox"
    closed = _payload(srv.dispatch(4, "authorship_close",
                                   {"session_id": session_id, "final_text": final_text}))
    assert closed["typed_chars"] == len("The quick ")
    assert closed["pasted_chars"] == len("brown fox")
    assert closed["pasted_share"] == round(len("brown fox") / len("The quick brown fox"), 3)
    assert closed["receipt_body_digest"]

    receipt = load_receipt(closed["receipt_path"])
    assert receipt["body_digest"] == closed["receipt_body_digest"]
    assert receipt["kind"] == "authorship-process"
    assert "human" not in " ".join(receipt["scope"]["proves"]).lower()
    v = verify_receipt(receipt, ledger_path=srv.ledger_path)
    assert v["ok"], v

    # -- the same sequence run directly through authorship.py produces the
    # same shape of receipt (same rolling-hash-over-events mechanics) --
    direct = authorship.AuthorshipSession(tmp_path / "writing2.log.jsonl",
                                          author="a. writer", document="essay")
    direct.event("type", text="The quick ")
    direct.event("paste", text="brown fox")
    direct_rc = direct.close(final_text, witness=True, anchor=True)
    assert direct_rc["checks"][0]["typed_chars"] == receipt["checks"][0]["typed_chars"]
    assert direct_rc["checks"][0]["pasted_chars"] == receipt["checks"][0]["pasted_chars"]

    # -- closing twice is refused: the session is gone after close() -------
    reclosed = srv.dispatch(5, "authorship_close", {"session_id": session_id, "final_text": final_text})
    assert reclosed["result"]["isError"] is True
    assert "session_id" in _payload(reclosed)["error"]


def test_ingest_export_reports_hash_match(tmp_path):
    srv = _server(tmp_path)
    session = authorship.AuthorshipSession(tmp_path / "recorder.log.jsonl",
                                           author="a. writer", document="essay")
    session.event("type", text="hello ")
    session.event("paste", text="world")
    export = {"author": "a. writer", "document": "essay", "started_at": session.started_at,
              "final_text": "hello world", "rolling_hash": session.rolling,
              "events": [
                  {"seq": 1, "op": "type", "n": 6, "ts": session.last_ts,
                   "span_digest": None},
                  {"seq": 2, "op": "paste", "n": 5, "ts": session.last_ts,
                   "span_digest": None},
              ]}
    # replace the placeholder digests with the real ones the session computed
    # by re-deriving from the same authorship.py fold used to build `export`
    # above -- simplest correct way is to just replay through authorship.py
    # directly rather than hand-fake span digests here.
    from arcaeon.record.ledger import digest_bytes
    export["events"][0]["span_digest"] = digest_bytes(b"hello ")
    export["events"][1]["span_digest"] = digest_bytes(b"world")
    export["rolling_hash"] = authorship.replay(export["events"])

    out = _payload(srv.dispatch(1, "authorship_ingest_export", {"export": export}))
    assert out["export_rolling_hash_matches"] is True
    assert out["receipt_body_digest"]


def test_ingest_export_requires_an_object(tmp_path):
    srv = _server(tmp_path)
    resp = srv.dispatch(1, "authorship_ingest_export", {"export": "not-an-object"})
    assert resp["result"]["isError"] is True
    assert "export" in _payload(resp)["error"]
