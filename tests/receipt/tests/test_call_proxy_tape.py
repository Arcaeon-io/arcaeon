"""call_proxy keeps the TOOL-side tape (`arcaeon-tape/1`) of every MCP
`tools/call` it forwards, with the same writer and the same digests as the
arcaeon-adapter's agent-side tape, so `arcaeon-ledger reconcile` can line the
two up: MATCHED n of n, MISSING at k, ALTERED at k, or COULD NOT LOOK.

The writer is NOT vendored here. It lives in the arcaeon-ledger repo
(`adapter/arcaeon_adapter/tape.py`) and call_proxy imports it; when it is not
installed, call_proxy still forwards every call and says the tape is off.

Most tests need that repo. It is found at $ARCAEON_LEDGER_REPO, else at
../arcaeon-ledger, and only if it carries the tape writer AND reconcile;
otherwise those tests SKIP with the reason (the fallback test always runs).

The cross-repo test runs the real chain, the adapter as a real process:

    client -> arcaeon-adapter --http-forward (agent tape) -> hop -> call_proxy (tool tape)
           -> HTTP MCP server

and reconciles the two tapes with the ledger's own CLI in a subprocess (it
needs the adapter's --http-forward mode, completeness slice 3; without it
those tests SKIP with the reason). Break arms swap in a call_proxy that loses
or re-digests the answer, closes a call on a 202, or reads compressed bytes
raw, and assert the same checks then FAIL.
"""
from __future__ import annotations

import gzip
import http.client
import http.server
import json
import os
import re
import signal
import subprocess
import sys
import threading
import zlib
from pathlib import Path

import pytest

from arcaeon.record.receipt import call_proxy

HERE = Path(__file__).resolve().parent
REPO = HERE.parent


def _ledger_repo():
    # arcaeon merge: ledger, adapter and reconcile are in this repo now.
    for c in (Path(__file__).resolve().parents[3] / "src" / "arcaeon",):
        if not c:
            continue
        p = Path(c)
        if (p / "record" / "adapter" / "tape.py").exists() and \
                (p / "prove" / "reconcile.py").exists():
            return p
    return None


LEDGER = _ledger_repo()
needs_ledger = pytest.mark.skipif(
    LEDGER is None, reason="arcaeon-ledger checkout with the tape writer + reconcile not found "
                           "(set ARCAEON_LEDGER_REPO): the tape could not be looked at")
if LEDGER is not None and str(LEDGER / "adapter") not in sys.path:
    sys.path.insert(0, str(LEDGER / "adapter"))


def _tape_mod():
    from arcaeon.record.adapter import tape
    return tape


# -- an HTTP MCP server (Streamable HTTP, JSON or SSE answers) ----------------

def handle(msg, later=None):
    """A small MCP server's answers (echo / boom / quiet / later / initialize),
    kept here so the fallback tests run without the ledger checkout. `later`
    collects answers that go out on the GET stream instead of the POST."""
    later = [] if later is None else later
    if not isinstance(msg, dict) or msg.get("id") is None:
        return None
    mid, method = msg["id"], msg.get("method")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}}, "serverInfo": {"name": "echo", "version": "1"}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": []}}
    if method == "tools/call":
        p = msg.get("params") or {}
        name, args = p.get("name"), p.get("arguments") or {}
        if name == "quiet":
            return None
        if name == "later":      # 202 now; the answer goes out on the GET stream
            later.append({"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": "late " + str(args.get("text", ""))}]}})
            return None
        if name == "boom":
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": "detonated"}], "isError": True}}
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": str(args.get("text", ""))}]}}
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "not found"}}


class _McpHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _later(self):
        if not hasattr(self.server, "later"):
            self.server.later = {}
        return self.server.later.setdefault(self.headers.get("Mcp-Session-Id"), [])

    def do_GET(self):
        # The session's GET stream, finite here: whatever answers are waiting
        # for this Mcp-Session-Id, as SSE events, then the stream ends.
        q = self._later()
        out = b"".join(b"event: message\ndata: " + json.dumps(a).encode() + b"\n\n" for a in q)
        q.clear()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/err":
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            msg = json.loads(body)
        except ValueError:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        later = self._later()
        answers = [a for a in (handle(m, later) for m in (msg if isinstance(msg, list) else [msg]))
                   if a is not None]
        if not answers:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path in ("/sse", "/gzsse"):
            out = b"".join(b"event: message\ndata: " + json.dumps(a).encode() + b"\n\n"
                           for a in answers)
            ctype = "text/event-stream"
        else:
            out = json.dumps(answers if isinstance(msg, list) else answers[0]).encode()
            ctype = "application/json"
        enc = None
        if self.path in ("/gz", "/gzsse"):
            out, enc = gzip.compress(out), "gzip"
        elif self.path == "/deflate":
            out, enc = zlib.compress(out), "deflate"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        if enc:
            self.send_header("Content-Encoding", enc)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def _serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def mcp():
    s = _serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), _McpHandler))
    yield s
    s.shutdown()
    s.server_close()


def _proxy(tmp_path, upstream_port, **kw):
    kw.setdefault("tape_path", tmp_path / "tool.tape.jsonl")
    kw.setdefault("tape_namespace", "demo-tool")
    return _serve(call_proxy.build_server(
        listen="127.0.0.1:0", upstream=f"http://127.0.0.1:{upstream_port}", seller="acme",
        ledger_path=tmp_path / "calls.log.jsonl", witness=False, **kw))


@pytest.fixture
def taped(tmp_path, mcp):
    s = _proxy(tmp_path, mcp.server_address[1])
    yield s, tmp_path / "tool.tape.jsonl"
    s.shutdown()
    s.server_close()


def _post(port, obj, path="/mcp", session=None):
    raw = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Content-Type": "application/json"}
    if session:
        h["Mcp-Session-Id"] = session
    c.request("POST", path, body=raw, headers=h)
    r = c.getresponse()
    out = (r.status, r.read())
    c.close()
    return out


def _stream(port, session, path="/mcp"):
    """The session's GET stream (finite in this test server). Returns the body."""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", path, headers={"Accept": "text/event-stream", "Mcp-Session-Id": session})
    r = c.getresponse()
    out = r.read()
    c.close()
    return out


def _sse_data(body: bytes) -> list:
    return [json.loads(ln[5:].strip()) for ln in body.decode().splitlines()
            if ln.startswith("data:")]


def _rows(p):
    p = Path(p)
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").split("\n") if x.strip()]


def _call(mid, name, text=None):
    return {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
            "params": {"name": name, "arguments": {} if text is None else {"text": text}}}


# -- the checks, as functions, so the break arms can replay them -------------

def check_json_answer_taped(tmp_path, mcp):
    tmp_path.mkdir(parents=True, exist_ok=True)
    T = _tape_mod()
    s = _proxy(tmp_path, mcp.server_address[1])
    try:
        status, body = _post(s.server_address[1], _call(7, "echo", "hi"))
    finally:
        s.shutdown()
        s.server_close()
    assert status == 200
    rows = _rows(tmp_path / "tool.tape.jsonl")
    assert len(rows) == 1, rows
    r = rows[0]
    assert (r["evt"], r["tape"], r["side"], r["ns"], r["idx"], r["tool"], r["rpc_id"]) == \
        ("tape_call", "arcaeon-tape/1", "tool", "demo-tool", 1, "echo", "7")
    assert r["req"] == T.request_digest({"name": "echo", "arguments": {"text": "hi"}})
    assert r["resp"] == T.response_digest(json.loads(body))
    assert r["status"] == "ok" and r["chain"]


def check_sse_answer_taped(tmp_path, mcp):
    tmp_path.mkdir(parents=True, exist_ok=True)
    T = _tape_mod()
    s = _proxy(tmp_path, mcp.server_address[1])
    try:
        status, body = _post(s.server_address[1], _call(1, "echo", "sse"), path="/sse")
    finally:
        s.shutdown()
        s.server_close()
    data = [ln[5:].strip() for ln in body.decode().splitlines() if ln.startswith("data:")]
    rows = _rows(tmp_path / "tool.tape.jsonl")
    assert [r["status"] for r in rows] == ["ok"]
    assert rows[0]["resp"] == T.response_digest(json.loads(data[0]))


def check_later_answer(tmp_path, mcp):
    """202 now; the answer on the session's GET stream later closes the call
    with the real response digest (the adapter's rule, so both tapes agree)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    T = _tape_mod()
    s = _proxy(tmp_path, mcp.server_address[1])
    tape = tmp_path / "tool.tape.jsonl"
    try:
        p = s.server_address[1]
        s1, _ = _post(p, _call(1, "later", "one"), session="sess-A")
        s2, b2 = _post(p, _call(2, "echo", "two"), session="sess-A")
        before = _rows(tape)
        body = _stream(p, "sess-A")
    finally:
        s.shutdown()
        s.server_close()
        s.tape.writer.flush()
    assert (s1, s2) == (202, 200)
    assert before == [], "call 1 is still open after its 202, so call 2 waits behind it"
    late = _sse_data(body)
    assert len(late) == 1 and late[0]["id"] == 1, body
    rows = _rows(tape)
    assert [(r["idx"], r["tool"], r["status"]) for r in rows] == \
        [(1, "later", "ok"), (2, "echo", "ok")], rows
    assert rows[0]["resp"] == T.response_digest(late[0])
    assert rows[1]["resp"] == T.response_digest(json.loads(b2))


def check_encoded_answer(tmp_path, mcp, path):
    """A gzip/deflate answer: the caller gets the encoded bytes untouched, the
    tape reads the answer from a decompressed copy."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    T = _tape_mod()
    s = _proxy(tmp_path, mcp.server_address[1])
    try:
        direct = _post(mcp.server_address[1], _call(1, "echo", "packed"), path=path)
        via = _post(s.server_address[1], _call(1, "echo", "packed"), path=path)
    finally:
        s.shutdown()
        s.server_close()
    assert via == direct, "the caller must get the encoded bytes as the upstream sent them"
    plain = zlib.decompressobj(47).decompress(via[1])
    ans = _sse_data(plain)[0] if path == "/gzsse" else json.loads(plain)
    rows = _rows(tmp_path / "tool.tape.jsonl")
    assert [r["status"] for r in rows] == ["ok"], rows
    assert rows[0]["resp"] == T.response_digest(ans)


# -- failure-first unit tests ------------------------------------------------

@needs_ledger
def test_a_json_answered_tools_call_is_taped_with_the_adapter_digests(tmp_path, mcp):
    check_json_answer_taped(tmp_path, mcp)


@needs_ledger
def test_an_sse_answered_tools_call_is_taped(tmp_path, mcp):
    check_sse_answer_taped(tmp_path, mcp)


@needs_ledger
def test_non_tool_traffic_is_not_on_the_tape(taped):
    s, tape = taped
    port = s.server_address[1]
    _post(port, {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
    _post(port, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    _post(port, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    _post(port, b"not json at all")
    assert _rows(tape) == []


@needs_ledger
def test_a_batch_tapes_each_call_in_order(taped):
    s, tape = taped
    _post(s.server_address[1], [_call(1, "echo", "a"), _call(2, "boom"), _call(3, "echo", "c")])
    rows = _rows(tape)
    assert [(r["idx"], r["tool"], r["rpc_id"], r["status"]) for r in rows] == \
        [(1, "echo", "1", "ok"), (2, "boom", "2", "error"), (3, "echo", "3", "ok")]


DUP_BATCH = [_call(1, "echo", "first"), _call(1, "echo", "second"), _call(2, "echo", "third")]


def check_duplicate_ids_taped(tmp_path, mcp):
    """THE PAIRING RULE (the adapter's too): open calls queue per
    (Mcp-Session-Id, id) in send order; an answer pairs with the OLDEST open
    call of its id; a call never overwrites another; every sent call gets one
    tape row. A batch reusing id 1 (a JSON-RPC violation) is 3 calls, 3 rows,
    each with ITS answer."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    T = _tape_mod()
    s = _proxy(tmp_path, mcp.server_address[1])
    try:
        status, body = _post(s.server_address[1], DUP_BATCH)
        before_flush = _rows(tmp_path / "tool.tape.jsonl")
    finally:
        s.shutdown()
        s.server_close()
        s.tape.writer.flush()
    answers = json.loads(body)
    assert status == 200 and len(answers) == 3
    assert len(before_flush) == 3, "all three closed by the response, none held to session end"
    rows = _rows(tmp_path / "tool.tape.jsonl")
    assert [(r["idx"], r["rpc_id"], r["status"]) for r in rows] == \
        [(1, "1", "ok"), (2, "1", "ok"), (3, "2", "ok")], rows
    assert [r["req"] for r in rows] == [T.request_digest(c["params"]) for c in DUP_BATCH]
    assert [r["resp"] for r in rows] == [T.response_digest(a) for a in answers]


@needs_ledger
def test_duplicate_ids_in_a_batch_pair_fifo_three_calls_three_rows(tmp_path, mcp):
    check_duplicate_ids_taped(tmp_path, mcp)


@needs_ledger
def test_duplicate_ids_across_requests_answer_the_oldest_open_call_first(taped):
    """A 202 leaves call 1 open; a second call reusing id 1 queues BEHIND it,
    it does not take the id over. Both answers arrive on the GET stream, in
    order, and each closes its own call."""
    s, tape = taped
    p = s.server_address[1]
    assert _post(p, _call(1, "later", "older"), session="sess-A")[0] == 202
    assert _post(p, _call(1, "later", "newer"), session="sess-A")[0] == 202
    late = _sse_data(_stream(p, "sess-A"))
    rows = _rows(tape)
    T = _tape_mod()
    assert [(r["idx"], r["status"]) for r in rows] == [(1, "ok"), (2, "ok")], rows
    assert [r["resp"] for r in rows] == [T.response_digest(a) for a in late]
    assert "older" in json.dumps(late[0]) and "newer" in json.dumps(late[1])


@needs_ledger
def test_a_202_never_answered_is_unanswered_at_session_end_not_dropped(taped):
    s, tape = taped
    status, _ = _post(s.server_address[1], _call(1, "quiet"))
    assert status == 202
    assert _rows(tape) == [], "a 202 leaves the call open for a later answer"
    s.tape.writer.flush()  # session end: what the CLI does on shutdown
    rows = _rows(tape)
    assert [(r["idx"], r["status"], r["resp"]) for r in rows] == [(1, "unanswered", None)]


@needs_ledger
def test_a_202_answered_later_on_the_get_stream_is_taped_with_that_answer(tmp_path, mcp):
    check_later_answer(tmp_path, mcp)


@needs_ledger
def test_a_later_answer_in_another_session_does_not_close_the_call(taped):
    s, tape = taped
    p = s.server_address[1]
    assert _post(p, _call(1, "later", "x"), session="sess-A")[0] == 202
    other = _stream(p, "sess-B")
    assert _sse_data(other) == []
    assert _rows(tape) == []
    s.tape.writer.flush()
    assert [r["status"] for r in _rows(tape)] == ["unanswered"]


@needs_ledger
def test_a_non_202_response_without_the_answer_closes_the_call_then(taped):
    s, tape = taped
    status, _ = _post(s.server_address[1], _call(1, "echo", "x"), path="/err")
    assert status == 500
    assert [(r["idx"], r["status"]) for r in _rows(tape)] == [(1, "unanswered")]


@needs_ledger
@pytest.mark.parametrize("path", ["/gz", "/gzsse", "/deflate"])
def test_a_compressed_answer_is_read_from_a_decompressed_copy(tmp_path, mcp, path):
    check_encoded_answer(tmp_path, mcp, path)


@needs_ledger
def test_upstream_down_is_taped_unanswered(tmp_path):
    import socket
    sk = socket.socket()
    sk.bind(("127.0.0.1", 0))
    dead = sk.getsockname()[1]
    sk.close()
    s = _proxy(tmp_path, dead, upstream_timeout=2.0)
    try:
        status, _ = _post(s.server_address[1], _call(1, "echo", "x"))
    finally:
        s.shutdown()
        s.server_close()
    assert status == 502
    assert [r["status"] for r in _rows(tmp_path / "tool.tape.jsonl")] == ["unanswered"]


@needs_ledger
def test_the_tape_does_not_change_a_byte_the_caller_sees(tmp_path, mcp):
    plain = _serve(call_proxy.build_server(
        listen="127.0.0.1:0", upstream=f"http://127.0.0.1:{mcp.server_address[1]}",
        seller="acme", ledger_path=tmp_path / "plain.log.jsonl", witness=False))
    s = _proxy(tmp_path, mcp.server_address[1])
    try:
        a = _post(plain.server_address[1], _call(1, "echo", "same"))
        b = _post(s.server_address[1], _call(1, "echo", "same"))
    finally:
        for x in (plain, s):
            x.shutdown()
            x.server_close()
    assert a == b


@needs_ledger
def test_the_tape_is_a_chained_ledger_that_verifies_strict(taped):
    from arcaeon.record.ledger import verify_file
    s, tape = taped
    for k in range(3):
        _post(s.server_address[1], _call(k, "echo", str(k)))
    res = verify_file(tape, strict=True)
    assert res.ok is True and res.rows == 3


@needs_ledger
def test_numbering_resumes_across_a_proxy_restart(tmp_path, mcp):
    for _ in range(2):
        s = _proxy(tmp_path, mcp.server_address[1])
        _post(s.server_address[1], _call(1, "echo", "x"))
        s.shutdown()
        s.server_close()
    assert [r["idx"] for r in _rows(tmp_path / "tool.tape.jsonl")] == [1, 2]


@needs_ledger
def test_a_tape_failure_never_costs_the_call_or_its_receipt(tmp_path, mcp, monkeypatch):
    T = _tape_mod()

    def boom(self, *a, **k):
        raise RuntimeError("tape down")

    monkeypatch.setattr(T.TapeWriter, "open_call", boom)
    s = _proxy(tmp_path, mcp.server_address[1])
    try:
        status, body = _post(s.server_address[1], _call(1, "echo", "still here"))
        health = _get(s.server_address[1], call_proxy.HEALTH_PATH)
    finally:
        s.shutdown()
        s.server_close()
    assert status == 200 and b"still here" in body
    assert _rows(tmp_path / "calls.log.jsonl"), "the receipt row must still be written"
    assert health["tape"]["failures"] == 1


def _get(port, path):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", path)
    r = c.getresponse()
    out = json.loads(r.read())
    c.close()
    return out


def test_no_tape_writer_installed_is_a_clean_fallback(tmp_path, mcp, monkeypatch):
    """Runs without arcaeon-ledger's writer: the proxy must still forward every
    call, write its receipt, and SAY the tape is off (a missing tape then reads
    COULD NOT LOOK in reconcile, which is the truth)."""
    monkeypatch.setattr(call_proxy, "_load_tape_writer",
                        lambda: (None, "ModuleNotFoundError: No module named 'arcaeon_adapter'"))
    s = _proxy(tmp_path, mcp.server_address[1])
    try:
        status, body = _post(s.server_address[1], _call(1, "echo", "fine"))
        health = _get(s.server_address[1], call_proxy.HEALTH_PATH)
    finally:
        s.shutdown()
        s.server_close()
    assert status == 200 and b"fine" in body
    assert not (tmp_path / "tool.tape.jsonl").exists()
    assert health["tape"]["on"] is False
    assert "arcaeon_adapter" in health["tape"]["reason"]
    assert s.tape_status["on"] is False


def test_no_tape_requested_reports_tape_off_without_blame(tmp_path, mcp):
    s = _serve(call_proxy.build_server(
        listen="127.0.0.1:0", upstream=f"http://127.0.0.1:{mcp.server_address[1]}",
        seller="acme", ledger_path=tmp_path / "c.log.jsonl", witness=False))
    try:
        health = _get(s.server_address[1], call_proxy.HEALTH_PATH)
    finally:
        s.shutdown()
        s.server_close()
    assert health["tape"] == {"on": False, "reason": "no --tape configured"}


# -- cross-repo: the adapter's agent tape against call_proxy's tool tape -----

STREAM = [
    {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
    _call(1, "echo", "one"),
    _call(2, "echo", "alter me"),
    _call(3, "boom"),
    _call(4, "quiet"),
    _call(5, "echo", "five"),
]


class _Hop:
    """Between the two tapes: `clean` passes answers on; `alter_response`
    rewrites the text "alter me" to "ALTERED!" in every answer."""

    def __init__(self, target_port, mode):

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                c = http.client.HTTPConnection("127.0.0.1", target_port, timeout=30)
                c.request("POST", self.path, body=body,
                          headers={k: v for k, v in self.headers.items()
                                   if k.lower() not in ("host", "content-length", "connection")})
                r = c.getresponse()
                out, headers = r.read(), r.getheaders()
                c.close()
                if mode == "alter_response":
                    out = out.replace(b"alter me", b"ALTERED!")
                self.send_response_only(r.status, r.reason)
                for k, v in headers:
                    if k.lower() not in ("content-length", "transfer-encoding", "connection"):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self.srv = _serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), H))
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


HAS_FORWARD = LEDGER is not None and \
    (LEDGER / "record" / "adapter" / "http_forward.py").exists()
needs_forward = pytest.mark.skipif(
    not HAS_FORWARD, reason="arcaeon-ledger checkout without the adapter's --http-forward mode "
                            "(completeness slice 3): the agent-side tape of an HTTP call "
                            "could not be kept")


def run_chain(tmp_path, mcp, mode, stream=None):
    """client -> arcaeon-adapter --http-forward (agent tape) -> hop -> call_proxy
    (tool tape) -> HTTP MCP server, the adapter as a real process.
    Returns (reconcile JSON, exit code, agent rows, tool rows)."""
    s = _proxy(tmp_path, mcp.server_address[1])
    hop = _Hop(s.server_address[1], mode)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(LEDGER), str(LEDGER / "adapter"),
                                         env.get("PYTHONPATH", "")])
    kw = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == "win32" else {}
    agent = subprocess.Popen(
        [sys.executable, "-m", "arcaeon.record.adapter.proxy",
         "--ledger", str(tmp_path / "agent.seam.jsonl"),
         "--tape", str(tmp_path / "agent.tape.jsonl"), "--side", "agent",
         "--tape-namespace", "demo-agent",
         "--http-forward", hop.url + "/mcp", "--listen", "127.0.0.1:0"],
        stderr=subprocess.PIPE, env=env, **kw)
    try:
        line = agent.stderr.readline().decode(errors="replace")
        m = re.search(r"listening on http://127\.0\.0\.1:(\d+)", line)
        assert m, line
        for msg in (STREAM if stream is None else stream):
            _post(int(m.group(1)), msg, path="/")
        agent.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
        assert agent.wait(30) == 0
    finally:
        if agent.poll() is None:
            agent.kill()
        agent.stderr.close()
        hop.close()
        s.shutdown()
        s.server_close()
        s.tape.writer.flush()  # session end on the tool side
    rc = subprocess.run([sys.executable, "-m", "arcaeon.record.ledger.cli", "reconcile",
                         str(tmp_path / "agent.tape.jsonl"), str(tmp_path / "tool.tape.jsonl")],
                        capture_output=True, env=env, timeout=60)
    out = json.loads(rc.stdout)
    return out, rc.returncode, _rows(tmp_path / "agent.tape.jsonl"), _rows(tmp_path / "tool.tape.jsonl")


def check_cross_repo_matched(tmp_path, mcp):
    out, code, a, t = run_chain(tmp_path, mcp, "clean")
    assert len(a) == len(t) == 5, (a, t)
    assert [r["side"] for r in a] == ["agent"] * 5 and [r["side"] for r in t] == ["tool"] * 5
    assert [r["status"] for r in t] == ["ok", "ok", "error", "unanswered", "ok"]
    assert (out["verdict"], out["summary"], code) == ("MATCHED", "MATCHED 5 of 5", 0), out
    return out


def check_cross_repo_altered(tmp_path, mcp):
    out, code, a, t = run_chain(tmp_path, mcp, "alter_response")
    assert [x["idx"] for x, y in zip(a, t) if x["resp"] != y["resp"]] == [2]
    assert (out["verdict"], out["at"], code) == ("ALTERED", 2, 1), out
    return out


def _adapter_pairs_fifo():
    obs = LEDGER / "record" / "adapter" / "observer.py" if LEDGER else None
    return bool(obs and obs.exists() and "_take_oldest" in obs.read_text(encoding="utf-8"))


needs_adapter_fifo = pytest.mark.skipif(
    not (HAS_FORWARD and _adapter_pairs_fifo()),
    reason="arcaeon-ledger checkout whose adapter pairs duplicate ids FIFO not found "
           "(set ARCAEON_LEDGER_REPO): both tapes' duplicate-id rule could not be compared")


def check_cross_repo_duplicate_ids(tmp_path, mcp):
    tmp_path.mkdir(parents=True, exist_ok=True)
    out, code, a, t = run_chain(tmp_path, mcp, "clean", stream=[DUP_BATCH])
    for rows in (a, t):
        assert [(r["idx"], r["rpc_id"], r["status"]) for r in rows] == \
            [(1, "1", "ok"), (2, "1", "ok"), (3, "2", "ok")], rows
    assert (out["verdict"], out["summary"], code) == ("MATCHED", "MATCHED 3 of 3", 0), out
    return out


@needs_ledger
@needs_adapter_fifo
def test_cross_repo_duplicate_ids_reconcile_matched(tmp_path, mcp):
    out = check_cross_repo_duplicate_ids(tmp_path, mcp)
    print("\nCROSS-REPO duplicate ids 1,1,2:", out["summary"])


@needs_ledger
@needs_forward
def test_cross_repo_adapter_tape_and_call_proxy_tape_reconcile_matched(tmp_path, mcp):
    out = check_cross_repo_matched(tmp_path, mcp)
    print("\nCROSS-REPO clean:", out["summary"])


@needs_ledger
@needs_forward
def test_cross_repo_answer_changed_between_the_tapes_is_altered_at_that_call(tmp_path, mcp):
    out = check_cross_repo_altered(tmp_path, mcp)
    print("\nCROSS-REPO alter_response:", out["summary"])


# -- break arms: a call_proxy that loses or re-digests the answer ------------

def _answers_lost(body, header_items):
    return []


def _answers_as_bytes(body, header_items):
    real = _REAL_ANSWERS(body, header_items)
    return [(k, {"result": body.decode("utf-8", "replace")}) for k, _ in real]


def _first_answer_per_id(body, header_items):
    """The pre-fix reading: one answer per id (the first), so a reused id's
    second call was closed with the FIRST call's answer."""
    first = {}
    for k, a in _REAL_ANSWERS(body, header_items):
        first.setdefault(k, a)
    return [(k, first[k]) for k, _ in _REAL_ANSWERS(body, header_items)]


def _overwrite(self, key, idx):
    self._open[key] = [idx]      # one slot per id: a new call replaces the open one


_REAL_ANSWERS = call_proxy._tape_answers if hasattr(call_proxy, "_tape_answers") else None


@needs_ledger
@pytest.mark.parametrize("liar", [_answers_lost, _answers_as_bytes], ids=["lost", "byte_digest"])
def test_breakarm_unit_checks_fail_against_a_lying_proxy(liar, tmp_path, mcp, monkeypatch):
    monkeypatch.setattr(call_proxy, "_tape_answers", liar)
    with pytest.raises(AssertionError):
        check_json_answer_taped(tmp_path, mcp)
    with pytest.raises(AssertionError):
        check_sse_answer_taped(tmp_path / "sse", mcp)


@needs_ledger
@needs_forward
@pytest.mark.parametrize("liar", [_answers_lost, _answers_as_bytes], ids=["lost", "byte_digest"])
def test_breakarm_cross_repo_matched_fails_against_a_lying_proxy(liar, tmp_path, mcp, monkeypatch):
    monkeypatch.setattr(call_proxy, "_tape_answers", liar)
    with pytest.raises(AssertionError):
        check_cross_repo_matched(tmp_path, mcp)


@needs_ledger
def test_breakarm_a_proxy_that_closes_on_a_202_fails_the_later_check(tmp_path, mcp, monkeypatch):
    monkeypatch.setattr(call_proxy, "KEEP_OPEN_STATUSES", frozenset())
    with pytest.raises(AssertionError):
        check_later_answer(tmp_path, mcp)


@needs_ledger
@pytest.mark.parametrize("path", ["/gz", "/gzsse", "/deflate"])
def test_breakarm_a_proxy_that_reads_compressed_bytes_raw_fails(tmp_path, mcp, monkeypatch, path):
    monkeypatch.setattr(call_proxy, "_decoded", lambda body, header_items: body)
    with pytest.raises(AssertionError):
        check_encoded_answer(tmp_path, mcp, path)


@needs_ledger
def test_breakarm_first_answer_per_id_fails_the_duplicate_check(tmp_path, mcp, monkeypatch):
    monkeypatch.setattr(call_proxy, "_tape_answers", _first_answer_per_id)
    with pytest.raises(AssertionError):
        check_duplicate_ids_taped(tmp_path, mcp)


@needs_ledger
def test_breakarm_overwrite_pairing_fails_the_duplicate_checks(tmp_path, mcp, monkeypatch):
    monkeypatch.setattr(call_proxy._ToolTape, "_enqueue", _overwrite)
    with pytest.raises(AssertionError):
        check_duplicate_ids_taped(tmp_path / "u", mcp)
    if HAS_FORWARD and _adapter_pairs_fifo():
        with pytest.raises(AssertionError):
            check_cross_repo_duplicate_ids(tmp_path / "x", mcp)


# -- invalid ids: taped `invalid_id`, never paired (the adapter's rule too) ----
# JSON-RPC 2.0 says an id is a string, a number, or null. A `tools/call` with
# any other id (true, false, an object, an array) is an INVALID call; it was
# still sent, so it gets exactly one tape row with status `invalid_id` and no
# response digest, and no answer is paired to it. The old proxy taped `id: true`
# as an ordinary call and paired the upstream's answer to it, while the adapter
# dropped it: a clean stream reconciled as MISSING on the agent side.

BAD_BATCH = [_call(True, "echo", "bool"), _call(1, "echo", "one"), _call("x", "echo", "ex")]
ODD_BATCH = [_call(False, "echo", "f"), _call({"k": 1}, "echo", "obj"), _call([1], "echo", "arr"),
             _call(2, "echo", "two")]


def check_invalid_ids_taped(tmp_path, mcp):
    tmp_path.mkdir(parents=True, exist_ok=True)
    T = _tape_mod()
    s = _proxy(tmp_path, mcp.server_address[1])
    try:
        status, body = _post(s.server_address[1], BAD_BATCH)
        status2, body2 = _post(s.server_address[1], ODD_BATCH)
        before_flush = _rows(tmp_path / "tool.tape.jsonl")
    finally:
        s.shutdown()
        s.server_close()
        s.tape.writer.flush()
    answers, answers2 = json.loads(body), json.loads(body2)
    assert status == status2 == 200 and len(answers) == 3 and len(answers2) == 4, \
        "the relay is unchanged: the upstream answers every call"
    assert len(before_flush) == 7, "nothing held open to session end"
    rows = _rows(tmp_path / "tool.tape.jsonl")
    assert [(r["idx"], r["rpc_id"], r["status"]) for r in rows] == [
        (1, "true", "invalid_id"), (2, "1", "ok"), (3, "x", "ok"),
        (4, "false", "invalid_id"), (5, '{"k":1}', "invalid_id"), (6, "[1]", "invalid_id"),
        (7, "2", "ok")], rows
    assert [r["req"] for r in rows] == [T.request_digest(c["params"])
                                        for c in BAD_BATCH + ODD_BATCH]
    assert [r["resp"] for r in rows] == [None, T.response_digest(answers[1]),
                                         T.response_digest(answers[2]), None, None, None,
                                         T.response_digest(answers2[3])]


@needs_ledger
def test_invalid_ids_are_taped_invalid_and_never_paired(tmp_path, mcp):
    check_invalid_ids_taped(tmp_path, mcp)


def _adapter_marks_invalid_ids():
    tp = LEDGER / "record" / "adapter" / "tape.py" if LEDGER else None
    return bool(tp and tp.exists() and "invalid_call" in tp.read_text(encoding="utf-8"))


needs_adapter_invalid = pytest.mark.skipif(
    not (HAS_FORWARD and _adapter_marks_invalid_ids()),
    reason="arcaeon-ledger checkout whose adapter tapes invalid ids as `invalid_id` not found "
           "(set ARCAEON_LEDGER_REPO): both tapes' invalid-id rule could not be compared")


def check_cross_repo_invalid_ids(tmp_path, mcp):
    tmp_path.mkdir(parents=True, exist_ok=True)
    out, code, a, t = run_chain(tmp_path, mcp, "clean", stream=[BAD_BATCH])
    for rows in (a, t):
        assert [(r["idx"], r["rpc_id"], r["status"]) for r in rows] == \
            [(1, "true", "invalid_id"), (2, "1", "ok"), (3, "x", "ok")], rows
    assert (out["verdict"], out["summary"], code) == ("MATCHED", "MATCHED 3 of 3", 0), out
    return out


@needs_ledger
@needs_adapter_invalid
def test_cross_repo_invalid_ids_reconcile_matched(tmp_path, mcp):
    out = check_cross_repo_invalid_ids(tmp_path, mcp)
    print("\nCROSS-REPO ids true,1,\"x\":", out["summary"])


@needs_ledger
def test_breakarm_a_proxy_that_pairs_invalid_ids_fails_the_checks(tmp_path, mcp, monkeypatch):
    monkeypatch.setattr(call_proxy, "_valid_rpc_id", lambda mid: True, raising=False)
    with pytest.raises(AssertionError):
        check_invalid_ids_taped(tmp_path / "u", mcp)
    if HAS_FORWARD and _adapter_marks_invalid_ids():
        with pytest.raises(AssertionError):
            check_cross_repo_invalid_ids(tmp_path / "x", mcp)
