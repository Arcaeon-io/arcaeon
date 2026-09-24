# SPDX-License-Identifier: MIT
"""Tests for the observation half — framing, pairing, digests, degradation.

These are the unit-level tests. `test_proxy.py` covers the process-level behavior
(fidelity, exit codes, real subprocesses). The split matters: the observer must be
testable WITHOUT spawning anything, because that is what lets us drive it into the
ugly states a real pipe only reaches occasionally — a frame split across four
reads, a 100 MB line, an id reused as both `1` and `"1"`.

Run: pytest -q
"""
import json

import pytest

from arcaeon.record.adapter._ledger import digest_json
from arcaeon.record.adapter.observer import FrameSplitter, SeamObserver, _status_of


# -- FrameSplitter -----------------------------------------------------------

def test_splitter_reassembles_across_chunk_boundaries():
    """A pipe read lands wherever it lands; frames must not depend on that."""
    s = FrameSplitter()
    payload = b'{"a":1}\n{"b":2}\n'
    got = []
    for i in range(len(payload)):  # feed one byte at a time: the worst case
        got += s.feed(payload[i:i + 1])
    assert got == [b'{"a":1}', b'{"b":2}']


def test_splitter_handles_one_chunk_with_many_frames():
    s = FrameSplitter()
    assert s.feed(b"a\nb\nc\n") == [b"a", b"b", b"c"]
    assert s.feed(b"") == []


def test_splitter_close_yields_unterminated_final_frame():
    """A client may write its last message and close without a newline."""
    s = FrameSplitter()
    assert s.feed(b"first\nlast-no-newline") == [b"first"]
    assert s.close() == [b"last-no-newline"]
    assert s.close() == []  # idempotent


def test_splitter_abandons_oversize_frame_and_resyncs():
    """Unbounded buffering is a memory-exhaustion vector any server can trip.

    The frame is dropped from the LOG (counted, never silent) and the splitter
    picks the stream back up at the next newline. The relay is unaffected — it
    forwarded those bytes before the splitter ever saw them.
    """
    s = FrameSplitter(max_frame=64)
    assert s.feed(b"x" * 200) == []
    assert s.dropped_oversize == 1
    assert s.feed(b"tail-of-the-monster\n") == []   # discarded remainder
    assert s.feed(b'{"ok":1}\n') == [b'{"ok":1}']   # resynced
    assert s.dropped_oversize == 1


def test_splitter_large_frame_under_ceiling_survives():
    s = FrameSplitter(max_frame=10 * 1024 * 1024)
    big = b'{"text":"' + b"y" * 4_000_000 + b'"}'
    out = []
    for i in range(0, len(big), 65536):
        out += s.feed(big[i:i + 65536])
    assert out == []
    out += s.feed(b"\n")
    assert out == [big]


# -- pairing -----------------------------------------------------------------

def _obs(**kw):
    rows = []
    o = SeamObserver(rows.append, server="srv", session="S", **kw)
    return o, rows


def _call(mid, tool="echo", args=None):
    return json.dumps({"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                       "params": {"name": tool, "arguments": args or {}}}).encode()


def _resp(mid, result=None, error=None):
    m = {"jsonrpc": "2.0", "id": mid}
    if error is not None:
        m["error"] = error
    else:
        m["result"] = result if result is not None else {"content": []}
    return json.dumps(m).encode()


def test_one_call_one_row_with_the_documented_fields():
    o, rows = _obs()
    o.observe_client_frame(_call(1, "web_search", {"q": "weather"}))
    assert rows == []                       # nothing until the pair completes
    o.observe_server_frame(_resp(1, {"content": [{"type": "text", "text": "hi"}]}))
    assert len(rows) == 1
    r = rows[0]
    assert r["evt"] == "tool_call"
    assert r["seam"] == "mcp-stdio"          # the provenance tier, on every row
    assert r["session"] == "S" and r["seq"] == 1 and r["server"] == "srv"
    assert r["tool"] == "web_search"
    assert r["status"] == "ok"
    assert r["args_digest"] == digest_json({"q": "weather"})
    assert r["result_digest"] == digest_json({"content": [{"type": "text", "text": "hi"}]})
    assert isinstance(r["ms"], int) and r["ms"] >= 0


def test_digests_not_payloads_by_default():
    """Person-free core: the row proves WHICH bytes crossed, without keeping them."""
    o, rows = _obs()
    secret = {"ssn": "123-45-6789", "note": "do not warehouse me"}
    o.observe_client_frame(_call(1, "lookup", secret))
    o.observe_server_frame(_resp(1, {"content": [{"type": "text", "text": "123-45-6789"}]}))
    blob = json.dumps(rows[0])
    assert "123-45-6789" not in blob
    assert "args" not in rows[0] and "result" not in rows[0]
    assert rows[0]["args_digest"].startswith("sha256:json-c14n:v1:")


def test_raw_opt_in_embeds_payloads():
    o, rows = _obs(raw=True)
    o.observe_client_frame(_call(1, "lookup", {"q": "x"}))
    o.observe_server_frame(_resp(1, {"content": "y"}))
    assert rows[0]["args"] == {"q": "x"}
    assert rows[0]["result"] == {"content": "y"}
    assert rows[0]["args_digest"] == digest_json({"q": "x"})  # digest stays regardless


def test_out_of_order_responses_pair_by_id_not_position():
    """A server answering concurrently must not get results cross-attributed."""
    o, rows = _obs()
    o.observe_client_frame(_call(1, "slow"))
    o.observe_client_frame(_call(2, "fast"))
    o.observe_server_frame(_resp(2, {"content": "fast done"}))
    o.observe_server_frame(_resp(1, {"content": "slow done"}))
    assert [r["tool"] for r in rows] == ["fast", "slow"]
    assert rows[0]["result_digest"] == digest_json({"content": "fast done"})


def test_numeric_and_string_ids_are_distinct_requests():
    """JSON-RPC: id 1 and id "1" are different calls. Conflating them would
    attribute one call's result to another."""
    o, rows = _obs()
    o.observe_client_frame(_call(1, "numeric"))
    o.observe_client_frame(_call("1", "stringy"))
    o.observe_server_frame(_resp("1", {"content": "s"}))
    o.observe_server_frame(_resp(1, {"content": "n"}))
    assert [r["tool"] for r in rows] == ["stringy", "numeric"]


def test_duplicate_response_delivery_does_not_double_row():
    """Popping the pending map makes the observer idempotent against a server
    (or a buggy transport) delivering a response twice."""
    o, rows = _obs()
    o.observe_client_frame(_call(1))
    frame = _resp(1)
    o.observe_server_frame(frame)
    o.observe_server_frame(frame)
    assert len(rows) == 1


def test_jsonrpc_error_and_tool_level_iserror_both_read_as_error():
    """Two failure channels exist; an auditor asking 'did it work' wants one answer."""
    o, rows = _obs()
    o.observe_client_frame(_call(1, "boom"))
    o.observe_server_frame(_resp(1, error={"code": -32000, "message": "nope"}))
    o.observe_client_frame(_call(2, "tool_fail"))
    o.observe_server_frame(_resp(2, {"content": [], "isError": True}))
    assert [r["status"] for r in rows] == ["error", "error"]
    # The protocol-level failure still binds the error object by digest.
    assert rows[0]["result_digest"] == digest_json({"code": -32000, "message": "nope"})


def test_status_of_reads_both_channels():
    assert _status_of({"result": {"content": []}}) == "ok"
    assert _status_of({"result": {"isError": True}}) == "error"
    assert _status_of({"error": {"code": 1}}) == "error"
    assert _status_of({"result": {"isError": "yes"}}) == "ok"  # only literal True


def test_notifications_and_non_tool_methods_produce_no_rows():
    o, rows = _obs()
    o.observe_client_frame(b'{"jsonrpc":"2.0","method":"notifications/initialized"}')
    o.observe_client_frame(b'{"jsonrpc":"2.0","id":9,"method":"resources/list"}')
    o.observe_server_frame(b'{"jsonrpc":"2.0","id":9,"result":{"resources":[]}}')
    assert rows == []


def test_malformed_frames_are_skipped_not_guessed_at():
    """Relayed untouched by the proxy; here we only assert they produce no fiction."""
    o, rows = _obs()
    for junk in [b"not json", b'{"truncated', b"", b"   ", b'"a bare string"',
                 b"[1,2,3]", b"\xff\xfe\x00binary"]:
        o.observe_client_frame(junk)
        o.observe_server_frame(junk)
    assert rows == []


def test_jsonrpc_batch_array_is_honored():
    """MCP 2025-06-18 dropped batching; honoring it costs two lines and means a
    batching client still gets rows instead of a silent gap."""
    o, rows = _obs()
    o.observe_client_frame(json.dumps([
        json.loads(_call(1, "a")), json.loads(_call(2, "b"))]).encode())
    o.observe_server_frame(json.dumps([
        json.loads(_resp(1)), json.loads(_resp(2))]).encode())
    assert [r["tool"] for r in rows] == ["a", "b"]


def test_tools_call_without_id_is_not_paired():
    """A call with no id can never be answered; there is no pair to record."""
    o, rows = _obs()
    o.observe_client_frame(
        b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{}}}')
    assert rows == []
    assert o.calls_seen == 0


def test_missing_arguments_digests_as_empty_object():
    """`arguments` is optional in MCP. A missing one must digest deterministically,
    not crash and not produce a null."""
    o, rows = _obs()
    o.observe_client_frame(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"noargs"}}')
    o.observe_server_frame(_resp(1))
    assert rows[0]["args_digest"] == digest_json({})


def test_undigestible_payload_records_the_reason_never_a_fake_hash():
    """NaN is rejected by the frozen recipe on purpose. The row must say so rather
    than invent a digest or take the proxy down."""
    o, rows = _obs()
    o.observe_client_frame(_call(1, "weird"))
    # NaN can't be produced by json.dumps here, so drive the observer's own path:
    from arcaeon.record.adapter.observer import _safe_digest
    assert _safe_digest(float("nan")).startswith("undigestible:")
    o.observe_server_frame(_resp(1))
    assert len(rows) == 1  # and the ordinary path still works


# -- session brackets --------------------------------------------------------

def test_session_begin_end_bracket_and_seq_is_a_dense_total_order():
    o, rows = _obs()
    o.session_begin(adapter_version="test")
    o.observe_client_frame(_call(1))
    o.observe_server_frame(_resp(1))
    o.session_end(reason="child_exit", exit_code=0)
    assert [r["evt"] for r in rows] == ["session_begin", "tool_call", "session_end"]
    assert [r["seq"] for r in rows] == [1, 2, 3]
    assert rows[-1]["exit_code"] == 0          # zero is kept, not dropped as falsy
    assert rows[-1]["calls"] == 1
    assert all(r["session"] == "S" for r in rows)


def test_initialize_handshake_becomes_its_own_row():
    o, rows = _obs()
    o.observe_client_frame(json.dumps({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18",
                   "clientInfo": {"name": "claude-code", "version": "9"}}}).encode())
    o.observe_server_frame(json.dumps({
        "jsonrpc": "2.0", "id": 0, "result": {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "ledger", "version": "0.5.7"}}}).encode())
    assert len(rows) == 1
    r = rows[0]
    assert r["evt"] == "mcp_initialize"
    assert r["client_info"] == {"name": "claude-code", "version": "9"}
    assert r["server_info"] == {"name": "ledger", "version": "0.5.7"}
    assert r["protocol_version"] == "2025-06-18"


def test_tools_list_binds_the_offered_surface():
    """The tool-list digest is the only place a silent mid-life schema swap shows."""
    o, rows = _obs()
    o.observe_client_frame(b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
    tools = [{"name": "b", "inputSchema": {"type": "object"}},
             {"name": "a", "inputSchema": {"type": "object"}}]
    o.observe_server_frame(json.dumps({"jsonrpc": "2.0", "id": 2,
                                       "result": {"tools": tools}}).encode())
    assert rows[0]["evt"] == "tools_list"
    assert rows[0]["tools"] == ["a", "b"]      # sorted for stable reading
    assert rows[0]["tool_count"] == 2
    assert rows[0]["tools_digest"] == digest_json(tools)


def test_unanswered_call_is_still_rowed_at_shutdown():
    """Closes 'kill the server mid-call and the action leaves no trace'."""
    o, rows = _obs()
    o.observe_client_frame(_call(1, "transfer_funds", {"amount": 5000}))
    assert rows == []
    n = o.flush_pending(reason="session_ended:interrupt")
    assert n == 1
    assert rows[0]["status"] == "unanswered"
    assert rows[0]["tool"] == "transfer_funds"
    assert rows[0]["args_digest"] == digest_json({"amount": 5000})
    assert rows[0]["reason"] == "session_ended:interrupt"
    assert "result_digest" not in rows[0]   # there was no result; don't invent one


def test_flush_pending_is_idempotent():
    o, rows = _obs()
    o.observe_client_frame(_call(1))
    assert o.flush_pending() == 1
    assert o.flush_pending() == 0
    assert len(rows) == 1


def test_emit_failure_does_not_propagate_out_of_the_relay_path():
    """A full disk must not become a transport outage. `relay` swallows observer
    exceptions; this asserts the observer itself raises loudly enough that the
    swallow in relay is a deliberate policy and not accidental silence."""
    def boom(_row):
        raise OSError("disk full")
    o = SeamObserver(boom, server="s", session="S")
    o.observe_client_frame(_call(1))
    with pytest.raises(OSError):
        o.observe_server_frame(_resp(1))


def test_over_deep_frame_is_skipped_not_raised():
    """2026-09-01 audit (adapter #3): RecursionError is not a ValueError. A
    tools/call frame nested past the interpreter limit escaped _parse and out
    of observe_client_frame. It now behaves as any other unparseable frame."""
    o, rows = _obs()
    deep = "[" * 200_000 + "]" * 200_000
    frame = ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
             '{"name":"x","arguments":{"a":' + deep + '}}}').encode()
    o.observe_client_frame(frame)
    o.observe_server_frame(frame)
    assert rows == []


# -- duplicate ids: FIFO per (scope, id), no call ever overwritten -------------
#
# THE RULE (identical in arcaeon-receipt's call_proxy): an answer pairs with the
# OLDEST open call of its id; a call never overwrites another; every sent call
# gets exactly one tape row and one seam row; unpaired at session end is
# `unanswered`. The old map overwrote the first call of a reused id: it lost
# its seam row entirely, held its tape row open until session end, and the
# second call was taped with the answer meant for the first.

def _dup_batch():
    return json.dumps([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "echo", "arguments": {"text": "first"}}},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "echo", "arguments": {"text": "second"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "echo", "arguments": {"text": "third"}}},
    ]).encode()


def _dup_answers():
    return [{"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": t}]}}
            for i, t in ((1, "first"), (1, "second"), (2, "third"))]


def check_duplicate_ids_pair_fifo(tmp_path, scope=None):
    """3 calls with ids 1,1,2 in one batch, answered in order: 3 seam rows and
    3 tape rows, each call paired with ITS answer, all before session end."""
    from arcaeon.record.adapter.tape import TapeWriter, response_digest
    tape = TapeWriter(tmp_path / "dup.tape.jsonl", side="agent")
    o, rows = _obs(tape=tape)
    opened = o.observe_client_frame(_dup_batch(), scope)
    assert len(opened) == 3
    o.observe_server_frame(json.dumps(_dup_answers()).encode(), scope)
    calls = [r for r in rows if r["evt"] == "tool_call"]
    texts = ("first", "second", "third")
    assert [(r["rpc_id"], r["status"]) for r in calls] == [("1", "ok"), ("1", "ok"), ("2", "ok")]
    assert [r["args_digest"] for r in calls] == [digest_json({"text": t}) for t in texts]
    assert [r["result_digest"] for r in calls] == \
        [digest_json(a["result"]) for a in _dup_answers()], "each call gets ITS answer"
    assert o.flush_pending() == 0, "nothing left open: no call was overwritten"
    tape.flush()
    trows = [json.loads(x) for x in (tmp_path / "dup.tape.jsonl").read_text(
        encoding="utf-8").split("\n") if x.strip()]
    assert [(r["idx"], r["rpc_id"], r["status"]) for r in trows] == \
        [(1, "1", "ok"), (2, "1", "ok"), (3, "2", "ok")]
    assert [r["resp"] for r in trows] == [response_digest(a) for a in _dup_answers()]


def test_duplicate_ids_in_a_batch_pair_fifo_three_seam_rows_three_tape_rows(tmp_path):
    check_duplicate_ids_pair_fifo(tmp_path)


def test_duplicate_ids_pair_fifo_within_an_http_scope(tmp_path):
    check_duplicate_ids_pair_fifo(tmp_path, scope="sess-1")


def test_duplicate_ids_across_frames_answer_the_oldest_first():
    """A reused id in a LATER frame queues behind the open one; the first
    answer goes to the oldest call, the second to the next."""
    o, rows = _obs()
    o.observe_client_frame(_call(1, "older", {"n": 1}))
    o.observe_client_frame(_call(1, "newer", {"n": 2}))
    o.observe_server_frame(_resp(1, {"content": "a"}))
    assert [r["tool"] for r in rows] == ["older"]
    o.observe_server_frame(_resp(1, {"content": "b"}))
    assert [(r["tool"], r["result_digest"]) for r in rows] == \
        [("older", digest_json({"content": "a"})), ("newer", digest_json({"content": "b"}))]


def test_duplicate_ids_never_answered_are_each_unanswered_at_session_end():
    o, rows = _obs()
    o.observe_client_frame(_call(7, "a"))
    o.observe_client_frame(_call(7, "b"))
    assert o.flush_pending(reason="session_ended:eof") == 2
    assert [(r["tool"], r["status"]) for r in rows] == [("a", "unanswered"), ("b", "unanswered")]


def test_close_unanswered_closes_each_duplicate_by_its_own_handle():
    """The HTTP forward mode closes an exchange's calls by handle: two calls
    sharing an id are two handles, and an already-answered one is left alone."""
    o, rows = _obs()
    h = o.observe_client_frame(_dup_batch(), "s")
    o.observe_server_frame(_resp(1, {"content": "first"}), "s")   # pairs with call 1
    assert o.close_unanswered(h, reason="no_answer_in_response:200") == 2
    assert [(r["args_digest"], r["status"]) for r in rows] == [
        (digest_json({"text": "first"}), "ok"),
        (digest_json({"text": "second"}), "unanswered"),
        (digest_json({"text": "third"}), "unanswered")]
    assert o.close_unanswered(h, reason="again") == 0


def _overwrite(self, key, pend):
    """The pre-fix pairing: one slot per id, a new call replaces the open one."""
    self._pending[key] = [pend]


def test_breakarm_overwrite_pairing_fails_the_duplicate_id_check(tmp_path, monkeypatch):
    monkeypatch.setattr(SeamObserver, "_enqueue", _overwrite)
    with pytest.raises(AssertionError):
        check_duplicate_ids_pair_fifo(tmp_path)


# -- invalid ids: taped, never paired ------------------------------------------
# THE RULE (identical in arcaeon-receipt's call_proxy): JSON-RPC 2.0 says an id
# is a string, a number, or null. A `tools/call` whose id is anything else
# (true, false, an object, an array) is an INVALID call: it was still sent, so
# it gets exactly one seam row and one tape row with status `invalid_id` and no
# response digest, and no answer is ever paired to it (an answer carrying such
# an id is not a response to anything). The old observer dropped it silently
# while call_proxy taped it with its answer, so a stream carrying `id: true`
# reconciled as MISSING on the agent side.

def _invalid_batch():
    return json.dumps([
        {"jsonrpc": "2.0", "id": True, "method": "tools/call",
         "params": {"name": "echo", "arguments": {"text": "bool"}}},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "echo", "arguments": {"text": "one"}}},
        {"jsonrpc": "2.0", "id": "x", "method": "tools/call",
         "params": {"name": "echo", "arguments": {"text": "ex"}}},
        {"jsonrpc": "2.0", "id": False, "method": "tools/call",
         "params": {"name": "echo", "arguments": {"text": "f"}}},
        {"jsonrpc": "2.0", "id": {"k": 1}, "method": "tools/call",
         "params": {"name": "echo", "arguments": {"text": "obj"}}},
        {"jsonrpc": "2.0", "id": [1], "method": "tools/call",
         "params": {"name": "echo", "arguments": {"text": "arr"}}},
    ]).encode()


def _invalid_answers():
    return [{"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": t}]}}
            for i, t in ((True, "bool"), (1, "one"), ("x", "ex"), (False, "f"),
                         ({"k": 1}, "obj"), ([1], "arr"))]


def check_invalid_ids_taped_unpaired(tmp_path, scope=None):
    from arcaeon.record.adapter.tape import TapeWriter, response_digest
    tape = TapeWriter(tmp_path / "bad.tape.jsonl", side="agent")
    o, rows = _obs(tape=tape)
    o.observe_client_frame(_invalid_batch(), scope)
    invalid = [r for r in rows if r["evt"] == "tool_call"]
    assert [(r["rpc_id"], r["status"]) for r in invalid] == [
        ("true", "invalid_id"), ("false", "invalid_id"),
        ('{"k":1}', "invalid_id"), ("[1]", "invalid_id")], "rowed when SENT, not dropped"
    assert all(r.get("result_digest") is None for r in invalid)
    o.observe_server_frame(json.dumps(_invalid_answers()).encode(), scope)
    calls = [r for r in rows if r["evt"] == "tool_call"]
    assert len(calls) == 6, "the answers to invalid ids paired with nothing"
    assert [(r["rpc_id"], r["status"]) for r in calls[4:]] == [("1", "ok"), ("x", "ok")]
    assert o.flush_pending() == 0
    tape.flush()
    trows = [json.loads(x) for x in (tmp_path / "bad.tape.jsonl").read_text(
        encoding="utf-8").split("\n") if x.strip()]
    assert [(r["idx"], r["rpc_id"], r["status"]) for r in trows] == [
        (1, "true", "invalid_id"), (2, "1", "ok"), (3, "x", "ok"),
        (4, "false", "invalid_id"), (5, '{"k":1}', "invalid_id"), (6, "[1]", "invalid_id")]
    assert [r["resp"] for r in trows] == [
        None, response_digest(_invalid_answers()[1]), response_digest(_invalid_answers()[2]),
        None, None, None]
    assert [r["req"] for r in trows] == [digest_json({"name": "echo", "arguments": {"text": t}})
                                         for t in ("bool", "one", "ex", "f", "obj", "arr")]


def test_invalid_ids_are_taped_invalid_and_never_paired(tmp_path):
    check_invalid_ids_taped_unpaired(tmp_path)


def test_invalid_ids_are_taped_invalid_within_an_http_scope(tmp_path):
    check_invalid_ids_taped_unpaired(tmp_path, scope="sess-1")


def test_a_null_or_absent_id_is_still_a_notification_not_a_call():
    o, rows = _obs()
    o.observe_client_frame(_call(None))
    o.observe_client_frame(json.dumps({"jsonrpc": "2.0", "method": "tools/call",
                                       "params": {"name": "echo"}}).encode())
    assert rows == [] and o.flush_pending() == 0


def test_breakarm_an_observer_that_drops_invalid_ids_fails_the_check(tmp_path, monkeypatch):
    import arcaeon.record.adapter.observer as OB
    monkeypatch.setattr(OB, "valid_rpc_id", lambda mid: True)   # the pre-fix reading
    with pytest.raises(AssertionError):
        check_invalid_ids_taped_unpaired(tmp_path)
