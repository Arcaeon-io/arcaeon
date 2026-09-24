# SPDX-License-Identifier: MIT
"""The HTTP forward mode (completeness slice 3): an agent that talks to an HTTP
MCP server keeps an agent-side tape without a stdio pipe to sit in.

    arcaeon-adapter --ledger seam.jsonl --tape agent.tape.jsonl \\
        --http-forward http://tool-host/mcp --listen 127.0.0.1:8765

The agent is pointed at the listener. Every request is forwarded to the
upstream, the answer (JSON or SSE) is relayed byte-for-byte, and the tape row
carries the SAME digests the stdio path and arcaeon-receipt's call_proxy write.

The cross-repo tests run the slice-two demo again, this time WITHOUT the
test-only stdio->HTTP bridge:

    client -> adapter --http-forward (agent tape) -> tamper hop
           -> call_proxy (tool tape) -> HTTP MCP server

They need an arcaeon-receipt checkout whose call_proxy keeps a tape, found at
$ARCAEON_RECEIPT_REPO or ../../arcaeon-receipt; otherwise they SKIP with the
reason. Break arms plant a liar in the forwarder and assert the checks go red.
"""
from __future__ import annotations

import http.client
import http.server
import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from arcaeon.record.adapter import http_forward as HF
from arcaeon.record.adapter.proxy import FAULT_ENV
from arcaeon.record.adapter.tape import TapeWriter, request_digest, response_digest

ROOT = Path(__file__).resolve().parent          # adapter/
LEDGER_ROOT = ROOT.parent                       # arcaeon-ledger checkout


def _rows(path):
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").split("\n") if x.strip()]


def _call(mid, name, text=None):
    return {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
            "params": {"name": name, "arguments": {} if text is None else {"text": text}}}


# -- an HTTP MCP server: JSON, SSE (sized and chunked), batches, 202 + later ---

def handle(msg, later):
    if not isinstance(msg, dict) or msg.get("id") is None:
        return None
    mid, method = msg["id"], msg.get("method")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}}, "serverInfo": {"name": "echo", "version": "1"}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": [{"name": "echo"}]}}
    if method == "tools/call":
        p = msg.get("params") or {}
        name, args = p.get("name"), p.get("arguments") or {}
        if name == "quiet":
            return None
        if name == "later":        # answered on the GET stream, well after the 202
            later.append({"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": "late " + str(args.get("text", ""))}]}})
            return None
        if name == "boom":
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": "detonated"}], "isError": True}}
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": str(args.get("text", ""))}]}}
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "not found"}}


class Upstream:
    """Deterministic headers (no Date/Server), so relayed headers compare exactly."""

    def __init__(self):
        self.later: "queue.Queue" = queue.Queue()
        up = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _head(self, code, headers):
                self.send_response_only(code)
                for k, v in headers:
                    self.send_header(k, v)
                self.end_headers()

            def do_GET(self):
                if self.path.startswith("/once"):
                    # a GET stream that carries the next later answer, then ends
                    # (a proxy that reads responses whole, like call_proxy, can
                    # only relay a stream that ends)
                    try:
                        item = up.later.get(timeout=5)
                    except queue.Empty:
                        item = None
                    raw = b"" if item is None else \
                        b"event: message\r\ndata: " + json.dumps(item).encode() + b"\r\n\r\n"
                    self._head(200, [("Content-Type", "text/event-stream"),
                                     ("Content-Length", str(len(raw)))])
                    self.wfile.write(raw)
                    return
                if self.path.startswith("/stream"):
                    # close-delimited SSE stream: no length, no chunking
                    self.close_connection = True
                    self._head(200, [("Content-Type", "text/event-stream"),
                                     ("Cache-Control", "no-cache"), ("X-Up", "stream")])
                    while True:
                        item = up.later.get()
                        if item is None:
                            return
                        self.wfile.write(b"event: message\r\ndata: " +
                                         json.dumps(item).encode() + b"\r\n\r\n")
                        self.wfile.flush()
                raw = b"plain, not MCP \x00\xff bytes"
                self._head(200, [("Content-Type", "application/octet-stream"),
                                 ("Content-Length", str(len(raw))), ("X-Up", "plain")])
                self.wfile.write(raw)

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                try:
                    msg = json.loads(body)
                except ValueError:
                    raw = b"not json"
                    self._head(400, [("Content-Type", "text/plain"),
                                     ("Content-Length", str(len(raw)))])
                    self.wfile.write(raw)
                    return
                deferred = []
                answers = [a for a in (handle(m, deferred)
                                       for m in (msg if isinstance(msg, list) else [msg]))
                           if a is not None]
                if not answers:
                    self._head(202, [("Content-Length", "0")])
                    for d in deferred:
                        # after the 202 has had time to reach the agent side, so
                        # the answer really is LATER than the response
                        threading.Timer(0.5, up.later.put, (d,)).start()
                    return
                if self.path.startswith("/sse") or self.path.startswith("/chunked"):
                    # multi-line data field on the first event: a parser that
                    # keeps only the first data line gets it wrong
                    out = b""
                    for a in answers:
                        txt = json.dumps(a, indent=1).encode()
                        out += b"event: message\ndata: " + txt.replace(b"\n", b"\ndata: ") + b"\n\n"
                    if self.path.startswith("/chunked"):
                        self._head(200, [("Content-Type", "text/event-stream"),
                                         ("Transfer-Encoding", "chunked"), ("X-Up", "chunked")])
                        for i in range(0, len(out), 17):
                            piece = out[i:i + 17]
                            self.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece))
                        self.wfile.write(b"0\r\n\r\n")
                        return
                    ctype = "text/event-stream"
                else:
                    out = json.dumps(answers if isinstance(msg, list) else answers[0]).encode()
                    ctype = "application/json"
                self._head(200, [("Content-Type", ctype), ("Content-Length", str(len(out))),
                                 ("Mcp-Session-Id", "sess-1"), ("X-Up", "json")])
                self.wfile.write(out)

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def close(self):
        self.later.put(None)
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def up():
    u = Upstream()
    yield u
    u.close()


def _fwd(tmp, upstream_url, **kw):
    kw.setdefault("tape_path", tmp / "agent.tape.jsonl")
    kw.setdefault("tape_namespace", "demo-agent")
    srv = HF.build_forward_server(upstream_url, "127.0.0.1:0",
                                  ledger_path=tmp / "agent.seam.jsonl", **kw)
    srv.start()
    return srv


def _req(port, method, path, body=None, headers=None, timeout=10):
    raw = body if (body is None or isinstance(body, bytes)) else json.dumps(body).encode()
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    h.update(headers or {})
    c.request(method, path, body=raw, headers=h)
    r = c.getresponse()
    out = (r.status, r.reason, r.getheaders(), r.read())
    c.close()
    return out


def _post(port, obj, path="/mcp", headers=None):
    s, _, h, b = _req(port, "POST", path, obj, headers)
    return s, b, dict((k.lower(), v) for k, v in h)


def _sse_data(body):
    out = []
    for ev in re.split(rb"\r?\n\r?\n", body):
        data = b"\n".join(ln[6:] if ln.startswith(b"data: ") else ln[5:]
                          for ln in re.split(rb"\r?\n", ev) if ln.startswith(b"data:"))
        if data:
            out.append(json.loads(data))
    return out


# -- the checks, as functions, so the break arms can replay them -------------

def check_json_answer_taped(tmp, up):
    tmp.mkdir(parents=True, exist_ok=True)
    f = _fwd(tmp, up.url)
    try:
        status, body, _ = _post(f.port, _call(7, "echo", "hi"))
    finally:
        f.close()
    assert status == 200
    rows = _rows(tmp / "agent.tape.jsonl")
    assert len(rows) == 1, rows
    r = rows[0]
    assert (r["tape"], r["side"], r["ns"], r["idx"], r["tool"], r["rpc_id"], r["status"]) == \
        ("arcaeon-tape/1", "agent", "demo-agent", 1, "echo", "7", "ok")
    assert r["req"] == request_digest({"name": "echo", "arguments": {"text": "hi"}})
    assert r["resp"] == response_digest(json.loads(body))
    seam = [x for x in _rows(tmp / "agent.seam.jsonl") if x["evt"] == "tool_call"]
    assert [(x["seam"], x["status"]) for x in seam] == [(HF.SEAM_HTTP, "ok")]


def check_sse_answer_taped(tmp, up, path):
    tmp.mkdir(parents=True, exist_ok=True)
    f = _fwd(tmp, up.url)
    try:
        status, body, _ = _post(f.port, _call(1, "echo", "sse"), path=path)
    finally:
        f.close()
    assert status == 200
    rows = _rows(tmp / "agent.tape.jsonl")
    assert [x["status"] for x in rows] == ["ok"], rows
    assert rows[0]["resp"] == response_digest(_sse_data(body)[0])


def check_later_answer(tmp, up):
    """202 now, the answer later on the GET stream: the row carries that answer."""
    tmp.mkdir(parents=True, exist_ok=True)
    f = _fwd(tmp, up.url)
    got = []
    ready = threading.Event()

    def listen():
        c = http.client.HTTPConnection("127.0.0.1", f.port, timeout=20)
        c.request("GET", "/stream", headers={"Accept": "text/event-stream",
                                             "Mcp-Session-Id": "sess-1"})
        r = c.getresponse()
        ready.set()
        buf = b""
        while b"\n\n" not in buf.replace(b"\r\n", b"\n"):
            piece = r.read1(4096)
            if not piece:
                break
            buf += piece
        got.append(buf)
        c.close()

    t = threading.Thread(target=listen, daemon=True)
    t.start()
    try:
        assert ready.wait(10)
        sess = {"Mcp-Session-Id": "sess-1"}
        s1, _, _ = _post(f.port, _call(1, "later", "one"), "/mcp", sess)
        s2, b2, _ = _post(f.port, _call(2, "echo", "two"), "/mcp", sess)
        t.join(10)
    finally:
        up.later.put(None)
        f.close()
    assert (s1, s2) == (202, 200)
    assert got and got[0], "the later answer never reached the agent"
    late = _sse_data(got[0])[0]
    rows = _rows(tmp / "agent.tape.jsonl")
    assert [(x["idx"], x["tool"], x["status"]) for x in rows] == \
        [(1, "later", "ok"), (2, "echo", "ok")], rows
    assert rows[0]["resp"] == response_digest(late)
    assert rows[1]["resp"] == response_digest(json.loads(b2))


def check_fidelity(tmp, up):
    """Status, reason, every end-to-end header and every body byte: identical
    through the forwarder and straight from the upstream."""
    tmp.mkdir(parents=True, exist_ok=True)
    f = _fwd(tmp, up.url)
    hop = {"transfer-encoding", "connection", "keep-alive", "content-length"}
    try:
        cases = [("POST", "/mcp", _call(1, "echo", "same")),
                 ("POST", "/mcp", [_call(2, "echo", "a"), _call(3, "boom")]),
                 ("POST", "/sse", _call(4, "echo", "s")),
                 ("POST", "/chunked", _call(5, "echo", "c")),
                 ("POST", "/mcp", b"not json at all"),
                 ("GET", "/plain", None)]
        for method, path, body in cases:
            direct = _req(up.srv.server_address[1], method, path, body)
            via = _req(f.port, method, path, body)
            assert (via[0], via[1], via[3]) == (direct[0], direct[1], direct[3]), (path, via, direct)
            dh = [(k.lower(), v) for k, v in direct[2] if k.lower() not in hop]
            vh = [(k.lower(), v) for k, v in via[2] if k.lower() not in hop]
            assert vh == dh, (path, vh, dh)
            if path in ("/mcp", "/plain", "/sse") and direct[0] == 200:
                # a sized body stays sized: same Content-Length, no re-chunking
                assert dict(via[2]).get("Content-Length") == dict(direct[2]).get("Content-Length")
    finally:
        f.close()


class ShortUpstream:
    """Promises more body than it sends, then closes: a lying Content-Length."""

    def __init__(self):
        import socket
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}/mcp"
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                data = b""
                while b"\r\n\r\n" not in data:
                    data += c.recv(65536)
                head, _, rest = data.partition(b"\r\n\r\n")
                n = int(re.search(rb"(?i)content-length:\s*(\d+)", head).group(1))
                while len(rest) < n:
                    rest += c.recv(65536)
                mid = json.loads(rest)["id"]
                body = json.dumps({"jsonrpc": "2.0", "id": mid, "result": {
                    "content": [{"type": "text", "text": "cut short"}]}}).encode()
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                          b"Content-Length: %d\r\n\r\n%s" % (len(body) + 60, body))
            finally:
                c.close()

    def close(self):
        self.sock.close()


def check_short_body(tmp, port_of):
    """Upstream closes 60 bytes short of its Content-Length. Directly the agent
    gets the short body and EOF (IncompleteRead); through the forwarder it must
    get the same, promptly, not hang on a keep-alive socket."""
    tmp.mkdir(parents=True, exist_ok=True)
    liar = ShortUpstream()
    f = _fwd(tmp, liar.url)

    def outcome(port):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            c.request("POST", "/mcp", body=json.dumps(_call(1, "echo", "x")),
                      headers={"Content-Type": "application/json"})
            r = c.getresponse()
            try:
                r.read()
                return "complete"
            except http.client.IncompleteRead as e:
                return ("short", len(e.partial))
            except OSError as e:
                return type(e).__name__
        finally:
            c.close()

    try:
        direct = outcome(port_of(liar))
        via = outcome(f.port)
    finally:
        end = f.close()
        liar.close()
    assert direct[0] == "short", direct
    assert via == direct, (via, direct)
    assert end["relay_errors"] == 1, end


def test_a_content_length_that_lies_short_reaches_the_agent_short_and_closed(tmp_path):
    check_short_body(tmp_path, lambda liar: liar.sock.getsockname()[1])


DUP_BATCH = [_call(1, "echo", "first"), _call(1, "echo", "second"), _call(2, "echo", "third")]


def check_duplicate_ids_forwarded(tmp, up):
    """Two tools/call with the same id in one batch (a JSON-RPC violation):
    three calls sent, three tape rows and three seam rows, each call paired
    with ITS answer (FIFO per id), and the relay unchanged."""
    tmp.mkdir(parents=True, exist_ok=True)
    f = _fwd(tmp, up.url)
    try:
        s, body, _ = _post(f.port, DUP_BATCH)
    finally:
        end = f.close()
    answers = json.loads(body)
    assert s == 200 and len(answers) == 3
    rows = _rows(tmp / "agent.tape.jsonl")
    assert [(r["idx"], r["rpc_id"], r["status"]) for r in rows] == \
        [(1, "1", "ok"), (2, "1", "ok"), (3, "2", "ok")], rows
    assert [r["resp"] for r in rows] == [response_digest(a) for a in answers]
    seam = [r for r in _rows(tmp / "agent.seam.jsonl") if r["evt"] == "tool_call"]
    assert [(r["rpc_id"], r["status"]) for r in seam] == [("1", "ok"), ("1", "ok"), ("2", "ok")]
    assert end.get("unanswered") is None, end


def test_duplicate_ids_in_a_batch_pair_fifo_on_the_tape_and_the_seam(tmp_path, up):
    check_duplicate_ids_forwarded(tmp_path, up)


class _HeaderUpstream:
    """Records the request headers it got; answers with a `Connection` header
    that names a header of its own."""

    def __init__(self):
        seen = self.seen = []

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                seen.append([k.lower() for k in self.headers.keys()])
                out = b'{"jsonrpc":"2.0","id":1,"result":{}}'
                self.send_response_only(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Connection", "X-Up-Hop")
                self.send_header("X-Up-Hop", "this hop only")
                self.send_header("X-Up-End", "end to end")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/mcp"

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def check_connection_named_headers_stripped(tmp):
    """RFC 9110 7.6.1: a header named in `Connection` is this hop's business
    and is not forwarded, in either direction; end-to-end headers still are."""
    tmp.mkdir(parents=True, exist_ok=True)
    hu = _HeaderUpstream()
    f = _fwd(tmp, hu.url)
    try:
        _, _, headers, _ = _req(f.port, "POST", "/", _call(1, "echo", "x"),
                                {"Connection": "keep-alive, X-Agent-Hop",
                                 "X-Agent-Hop": "this hop only", "X-Agent-End": "end to end"})
    finally:
        f.close()
        hu.close()
    got_up = hu.seen[0]
    assert "x-agent-end" in got_up and "x-agent-hop" not in got_up, got_up
    down = [k.lower() for k, _ in headers]
    assert "x-up-end" in down and "x-up-hop" not in down, down


def test_headers_named_in_connection_are_not_forwarded_either_way(tmp_path):
    check_connection_named_headers_stripped(tmp_path)


def test_breakarm_a_forwarder_that_ignores_connection_named_headers_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(HF, "_connection_named", lambda items: frozenset())
    with pytest.raises(AssertionError):
        check_connection_named_headers_stripped(tmp_path)


# -- failure-first unit tests ------------------------------------------------

def test_a_json_answered_call_is_taped_with_the_same_digests_as_stdio(tmp_path, up):
    check_json_answer_taped(tmp_path, up)


@pytest.mark.parametrize("path", ["/sse", "/chunked"])
def test_an_sse_answered_call_is_taped(tmp_path, up, path):
    check_sse_answer_taped(tmp_path, up, path)


def test_bytes_and_headers_reach_the_agent_unchanged(tmp_path, up):
    check_fidelity(tmp_path, up)


@pytest.mark.parametrize("path", ["/mcp", "/sse"])
def test_a_batch_tapes_each_call_in_order(tmp_path, up, path):
    f = _fwd(tmp_path, up.url)
    try:
        _post(f.port, [_call(1, "echo", "a"), _call(2, "boom"), _call(3, "echo", "c")], path)
    finally:
        f.close()
    rows = _rows(tmp_path / "agent.tape.jsonl")
    assert [(r["idx"], r["tool"], r["rpc_id"], r["status"]) for r in rows] == \
        [(1, "echo", "1", "ok"), (2, "boom", "2", "error"), (3, "echo", "3", "ok")]


def test_a_202_with_a_later_answer_on_the_stream_is_taped_with_that_answer(tmp_path, up):
    check_later_answer(tmp_path, up)


def test_a_202_never_answered_is_unanswered_at_session_end_and_holds_no_row_hostage(tmp_path, up):
    f = _fwd(tmp_path, up.url)
    try:
        assert _post(f.port, _call(1, "quiet"))[0] == 202
        assert _post(f.port, _call(2, "echo", "after"))[0] == 200
        assert _rows(tmp_path / "agent.tape.jsonl") == []   # call 1 still open: 2 waits
    finally:
        end = f.close()
    rows = _rows(tmp_path / "agent.tape.jsonl")
    assert [(r["idx"], r["status"], r["resp"]) for r in rows][0] == (1, "unanswered", None)
    assert rows[1]["status"] == "ok"
    assert end["unanswered"] == 1 and end["tape_calls"] == 2


def test_upstream_down_is_a_502_and_an_unanswered_row_and_the_session_goes_on(tmp_path):
    import socket
    sk = socket.socket()
    sk.bind(("127.0.0.1", 0))
    dead = sk.getsockname()[1]
    sk.close()
    f = _fwd(tmp_path, f"http://127.0.0.1:{dead}/mcp", upstream_timeout=2.0)
    try:
        s1, b1, h1 = _post(f.port, _call(1, "echo", "x"))
        s2, _, _ = _post(f.port, _call(2, "echo", "y"))
    finally:
        end = f.close()
    assert (s1, s2) == (502, 502)
    assert b"jsonrpc" not in b1, "never invent a JSON-RPC answer no server gave"
    rows = _rows(tmp_path / "agent.tape.jsonl")
    assert [(r["idx"], r["status"]) for r in rows] == [(1, "unanswered"), (2, "unanswered")]
    seam = [r for r in _rows(tmp_path / "agent.seam.jsonl") if r["evt"] == "tool_call"]
    assert [r["status"] for r in seam] == ["unanswered", "unanswered"]
    assert end["upstream_errors"] == 2


def test_non_mcp_traffic_passes_through_untaped(tmp_path, up):
    f = _fwd(tmp_path, up.url)
    try:
        p = f.port
        _post(p, {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
        _post(p, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert _post(p, {"jsonrpc": "2.0", "method": "notifications/initialized"})[0] == 202
        assert _post(p, b"not json at all")[0] == 400
        assert _req(p, "GET", "/plain")[3] == b"plain, not MCP \x00\xff bytes"
    finally:
        f.close()
    assert _rows(tmp_path / "agent.tape.jsonl") == []
    evts = [r["evt"] for r in _rows(tmp_path / "agent.seam.jsonl")]
    assert evts == ["session_begin", "mcp_initialize", "tools_list", "session_end"], evts


def test_a_tape_failure_never_costs_the_call(tmp_path, up, monkeypatch):
    def boom(self, *a, **k):
        raise RuntimeError("tape down")
    monkeypatch.setattr(TapeWriter, "open_call", boom)
    f = _fwd(tmp_path, up.url)
    try:
        status, body, _ = _post(f.port, _call(1, "echo", "still here"))
    finally:
        end = f.close()
    assert status == 200 and b"still here" in body
    assert end["tape_failures"] == 1
    assert [r["status"] for r in _rows(tmp_path / "agent.seam.jsonl")
            if r["evt"] == "tool_call"] == ["ok"], "the seam row must still be written"


def test_session_brackets_and_the_seam_log_verifies(tmp_path, up):
    f = _fwd(tmp_path, up.url + "/mcp?key=sekrit-value-123", tape_namespace="demo-agent")
    try:
        _post(f.port, _call(1, "echo", "a"), path="/")
    finally:
        end = f.close()
        again = f.close()
    rows = _rows(tmp_path / "agent.seam.jsonl")
    begin = rows[0]
    assert begin["evt"] == "session_begin" and begin["transport"] == "http-forward"
    assert "sekrit" not in json.dumps(begin) and begin["upstream"].endswith("key=<redacted>")
    assert begin["listen"].startswith("http://127.0.0.1:")
    last = {k: v for k, v in rows[-1].items() if k not in ("ts", "chain")}
    assert last["evt"] == "session_end" and last == end and again is end
    assert [r["evt"] for r in rows].count("session_end") == 1, "close() is idempotent"
    assert end["tape_calls"] == 1 and end["exchanges"] == 1
    ok_rows = [r for r in _rows(tmp_path / "agent.tape.jsonl") if r["status"] == "ok"]
    assert len(ok_rows) == 1, "a request to / reaches the upstream's own path"
    try:
        from arcaeon.record.ledger import verify_file
    except ImportError:
        return
    assert verify_file(tmp_path / "agent.seam.jsonl", strict=True).ok is True
    assert verify_file(tmp_path / "agent.tape.jsonl", strict=True).ok is True


def test_session_end_pins_the_tape_head(tmp_path, up, monkeypatch):
    pytest.importorskip("arcaeon.record.ledger.tape_pin", reason="arcaeon-ledger without tape pinning")
    from test_tape import _Witness
    w = _Witness()
    monkeypatch.setenv("ARCAEON_WITNESS_KEY", w.key)
    f = _fwd(tmp_path, up.url, pin_witness=w.url, tape_pair="demo-tool")
    try:
        for k in range(3):
            _post(f.port, _call(k, "echo", str(k)))
    finally:
        end = f.close()
        w.close()
    pin = end["tape_pin"]
    assert pin["status"] == "pinned" and pin["rows"] == 3, pin
    assert w.bodies[-1][1]["pair"] == "demo-tool"
    assert pin["chain"] == _rows(tmp_path / "agent.tape.jsonl")[-1]["chain"]
    assert w.key not in (tmp_path / "agent.seam.jsonl").read_text(encoding="utf-8")


# -- the CLI, as a real process ----------------------------------------------

def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT), str(LEDGER_ROOT), env.get("PYTHONPATH", "")])
    env.pop(FAULT_ENV, None)
    return env


def test_cli_http_forward_runs_and_ends_its_session_on_interrupt(tmp_path, up):
    kw = {}
    if sys.platform == "win32":
        kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    p = subprocess.Popen([sys.executable, "-m", "arcaeon.record.adapter",
                          "--ledger", str(tmp_path / "seam.jsonl"),
                          "--tape", str(tmp_path / "agent.tape.jsonl"),
                          "--http-forward", up.url + "/mcp", "--listen", "127.0.0.1:0"],
                         stderr=subprocess.PIPE, env=_env(), **kw)
    try:
        line = p.stderr.readline().decode()
        m = re.search(r"listening on http://127\.0\.0\.1:(\d+)", line)
        assert m, line
        status, body, _ = _post(int(m.group(1)), _call(1, "echo", "cli"), path="/")
        assert status == 200 and b"cli" in body
        p.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
        code = p.wait(30)
    finally:
        if p.poll() is None:
            p.kill()
        p.stderr.close()
    assert code == 0
    end = _rows(tmp_path / "seam.jsonl")[-1]
    assert (end["evt"], end["reason"], end["tape_calls"]) == ("session_end", "interrupt", 1), end
    assert [r["status"] for r in _rows(tmp_path / "agent.tape.jsonl")] == ["ok"]


@pytest.mark.parametrize("argv", [
    ["--ledger", "x.jsonl", "--http-forward", "http://127.0.0.1:9/mcp", "--", "python", "s.py"],
    ["--ledger", "x.jsonl", "--listen", "127.0.0.1:0", "--", "python", "s.py"],
    ["--ledger", "x.jsonl", "--http-forward", "ftp://127.0.0.1:9/mcp"],
])
def test_cli_refuses_a_mixed_or_malformed_shape(argv, tmp_path, monkeypatch):
    from arcaeon.record.adapter.proxy import main
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as e:
        main(argv)
    assert e.value.code == 2


# -- cross-repo: agent tape here, tool tape in arcaeon-receipt's call_proxy ---

def _receipt_repo():
    # arcaeon merge: receipt is in this repo now, no sibling checkout to find.
    for c in (Path(__file__).resolve().parents[3] / "src" / "arcaeon" / "record",):
        if not c:
            continue
        p = Path(c)
        cp = p / "receipt" / "call_proxy.py"
        if cp.exists() and "_ToolTape" in cp.read_text(encoding="utf-8", errors="replace"):
            return p
    return None


RECEIPT = _receipt_repo()
needs_receipt = pytest.mark.skipif(
    RECEIPT is None, reason="arcaeon-receipt checkout whose call_proxy keeps a tape not found "
                            "(set ARCAEON_RECEIPT_REPO): the tool tape could not be looked at")


def _call_proxy():
    if str(RECEIPT) not in sys.path:
        sys.path.insert(0, str(RECEIPT))
    from arcaeon.record.receipt import call_proxy
    return call_proxy


class Hop:
    """A small tamper hop between the two tapes: clean, alter_response, or
    drop_request (the POST carrying call id `drop` never goes on; 202 back)."""

    def __init__(self, target_port, mode, drop=None):

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if mode == "drop_request":
                    try:
                        msgs = json.loads(body)
                    except ValueError:
                        msgs = None
                    ids = [m.get("id") for m in (msgs if isinstance(msgs, list) else [msgs])
                           if isinstance(m, dict)]
                    if drop in ids:
                        self.send_response_only(202)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
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

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


STREAM = [
    {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
    _call(1, "echo", "one"),
    _call(2, "echo", "alter me"),
    _call(3, "boom"),
    _call(4, "quiet"),
    [_call(5, "echo", "five"), _call(6, "echo", "six")],
    {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}},
    _call(7, "echo", "seven"),
]


def run_chain(tmp, up, mode, path="/mcp", drop=None):
    """client -> adapter (agent tape) -> hop -> call_proxy (tool tape) -> upstream.
    Returns (reconcile JSON, exit code, agent rows, tool rows)."""
    tmp.mkdir(parents=True, exist_ok=True)
    cp = _call_proxy()
    tool = cp.build_server(listen="127.0.0.1:0", upstream=up.url, seller="acme",
                           ledger_path=tmp / "calls.log.jsonl", witness=False,
                           tape_path=tmp / "tool.tape.jsonl", tape_namespace="demo-tool")
    threading.Thread(target=tool.serve_forever, daemon=True).start()
    hop = Hop(tool.server_address[1], mode, drop)
    agent = _fwd(tmp, hop.url + path)
    try:
        for m in STREAM:
            _post(agent.port, m, path="/")
    finally:
        agent.close()
        hop.close()
        tool.shutdown()
        tool.server_close()
        if tool.tape is not None:
            tool.tape.writer.flush()
    rc = subprocess.run([sys.executable, "-m", "arcaeon.record.ledger.cli", "reconcile",
                         str(tmp / "agent.tape.jsonl"), str(tmp / "tool.tape.jsonl")],
                        capture_output=True, env=_env(), timeout=60)
    out = json.loads(rc.stdout)
    return out, rc.returncode, _rows(tmp / "agent.tape.jsonl"), _rows(tmp / "tool.tape.jsonl")


def check_cross_repo_matched(tmp, up, path="/mcp"):
    out, code, a, t = run_chain(tmp, up, "clean", path)
    assert len(a) == len(t) == 7, (a, t)
    assert [r["side"] for r in a] == ["agent"] * 7 and [r["side"] for r in t] == ["tool"] * 7
    assert [r["status"] for r in a] == ["ok", "ok", "error", "unanswered", "ok", "ok", "ok"]
    assert (out["verdict"], out["summary"], code) == ("MATCHED", "MATCHED 7 of 7", 0), out
    return out


@needs_receipt
@pytest.mark.parametrize("path", ["/mcp", "/sse"])
def test_cross_repo_no_bridge_matched(tmp_path, up, path):
    out = check_cross_repo_matched(tmp_path, up, path)
    print(f"\nCROSS-REPO http-forward clean {path}:", out["summary"])


@needs_receipt
def test_cross_repo_no_bridge_answer_altered_in_transit(tmp_path, up):
    out, code, a, t = run_chain(tmp_path, up, "alter_response")
    assert [x["idx"] for x, y in zip(a, t) if x["resp"] != y["resp"]] == [2]
    assert (out["verdict"], out["at"], code) == ("ALTERED", 2, 1), out
    print("\nCROSS-REPO http-forward alter_response:", out["summary"])


@needs_receipt
def test_cross_repo_no_bridge_request_dropped_in_transit(tmp_path, up):
    out, code, a, t = run_chain(tmp_path, up, "drop_request", drop=3)
    assert (len(a), len(t)) == (7, 6)
    assert a[2]["status"] == "unanswered"
    assert (out["verdict"], out["at"], out["side"], code) == ("MISSING", 3, "tool", 1), out
    print("\nCROSS-REPO http-forward drop_request:", out["summary"])


def _receipt_keeps_202_open():
    if RECEIPT is None:
        return False
    src = (RECEIPT / "receipt" / "call_proxy.py").read_text(encoding="utf-8",
                                                                    errors="replace")
    return "KEEP_OPEN_STATUSES" in src


needs_receipt_later = pytest.mark.skipif(
    not _receipt_keeps_202_open(),
    reason="arcaeon-receipt call_proxy that leaves a 202 open for a later answer not found "
           "(set ARCAEON_RECEIPT_REPO): both tapes' later-answer rule could not be compared")


def check_cross_repo_later_answer_matched(tmp):
    """A 202 now, the answer on the session's GET stream later: BOTH tapes close
    the call with that answer, so reconcile says MATCHED."""
    tmp.mkdir(parents=True, exist_ok=True)
    up = Upstream()
    cp = _call_proxy()
    tool = cp.build_server(listen="127.0.0.1:0", upstream=up.url, seller="acme",
                           ledger_path=tmp / "calls.log.jsonl", witness=False,
                           tape_path=tmp / "tool.tape.jsonl", tape_namespace="demo-tool")
    threading.Thread(target=tool.serve_forever, daemon=True).start()
    agent = _fwd(tmp, f"http://127.0.0.1:{tool.server_address[1]}/mcp")
    sess = {"Mcp-Session-Id": "sess-1"}
    try:
        s1, _, _ = _post(agent.port, _call(1, "later", "one"), "/", sess)
        s2, b2, _ = _post(agent.port, _call(2, "echo", "two"), "/", sess)
        st, _, _, body = _req(agent.port, "GET", "/once", None,
                              dict(sess, Accept="text/event-stream"))
    finally:
        agent.close()
        tool.shutdown()
        tool.server_close()
        tool.tape.writer.flush()
        up.close()
    assert (s1, s2, st) == (202, 200, 200)
    late = _sse_data(body)
    assert len(late) == 1 and late[0]["id"] == 1, body
    a, t = _rows(tmp / "agent.tape.jsonl"), _rows(tmp / "tool.tape.jsonl")
    for rows in (a, t):
        assert [(r["idx"], r["tool"], r["status"]) for r in rows] == \
            [(1, "later", "ok"), (2, "echo", "ok")], rows
        assert rows[0]["resp"] == response_digest(late[0])
        assert rows[1]["resp"] == response_digest(json.loads(b2))
    rc = subprocess.run([sys.executable, "-m", "arcaeon.record.ledger.cli", "reconcile",
                         str(tmp / "agent.tape.jsonl"), str(tmp / "tool.tape.jsonl")],
                        capture_output=True, env=_env(), timeout=60)
    out = json.loads(rc.stdout)
    assert (out["verdict"], out["summary"], rc.returncode) == ("MATCHED", "MATCHED 2 of 2", 0), out
    return out


@needs_receipt_later
def test_cross_repo_a_202_answered_later_matches_on_both_tapes(tmp_path):
    out = check_cross_repo_later_answer_matched(tmp_path)
    print("\nCROSS-REPO http-forward 202 answered later:", out["summary"])


@needs_receipt_later
def test_breakarm_a_tool_side_that_closes_on_a_202_fails_the_later_match(tmp_path, monkeypatch):
    monkeypatch.setattr(_call_proxy(), "KEEP_OPEN_STATUSES", frozenset())
    with pytest.raises(AssertionError):
        check_cross_repo_later_answer_matched(tmp_path)


def _receipt_pairs_fifo():
    if RECEIPT is None:
        return False
    src = (RECEIPT / "receipt" / "call_proxy.py").read_text(encoding="utf-8",
                                                                    errors="replace")
    return "_take_oldest" in src


needs_receipt_fifo = pytest.mark.skipif(
    not _receipt_pairs_fifo(),
    reason="arcaeon-receipt call_proxy that pairs duplicate ids FIFO not found "
           "(set ARCAEON_RECEIPT_REPO): both tapes' duplicate-id rule could not be compared")


def check_cross_repo_duplicate_ids_matched(tmp, up):
    """client -> adapter (agent tape) -> call_proxy (tool tape) -> upstream, one
    batch with ids 1,1,2: both tapes pair FIFO, so reconcile says MATCHED 3 of 3
    and each tape row carries the answer to ITS call."""
    tmp.mkdir(parents=True, exist_ok=True)
    cp = _call_proxy()
    tool = cp.build_server(listen="127.0.0.1:0", upstream=up.url, seller="acme",
                           ledger_path=tmp / "calls.log.jsonl", witness=False,
                           tape_path=tmp / "tool.tape.jsonl", tape_namespace="demo-tool")
    threading.Thread(target=tool.serve_forever, daemon=True).start()
    agent = _fwd(tmp, f"http://127.0.0.1:{tool.server_address[1]}/mcp")
    try:
        s, body, _ = _post(agent.port, DUP_BATCH, "/")
    finally:
        agent.close()
        tool.shutdown()
        tool.server_close()
        tool.tape.writer.flush()
    answers = json.loads(body)
    assert s == 200 and len(answers) == 3
    a, t = _rows(tmp / "agent.tape.jsonl"), _rows(tmp / "tool.tape.jsonl")
    for rows in (a, t):
        assert [(r["idx"], r["rpc_id"], r["status"]) for r in rows] == \
            [(1, "1", "ok"), (2, "1", "ok"), (3, "2", "ok")], rows
        assert [r["resp"] for r in rows] == [response_digest(x) for x in answers]
    seam = [r for r in _rows(tmp / "agent.seam.jsonl") if r["evt"] == "tool_call"]
    assert len(seam) == 3, seam
    rc = subprocess.run([sys.executable, "-m", "arcaeon.record.ledger.cli", "reconcile",
                         str(tmp / "agent.tape.jsonl"), str(tmp / "tool.tape.jsonl")],
                        capture_output=True, env=_env(), timeout=60)
    out = json.loads(rc.stdout)
    assert (out["verdict"], out["summary"], rc.returncode) == ("MATCHED", "MATCHED 3 of 3", 0), out
    return out


@needs_receipt_fifo
def test_cross_repo_duplicate_ids_match_on_both_tapes(tmp_path, up):
    out = check_cross_repo_duplicate_ids_matched(tmp_path, up)
    print("\nCROSS-REPO http-forward duplicate ids 1,1,2:", out["summary"])


def _overwrite_agent(self, key, pend):
    self._pending[key] = [pend]         # the pre-fix observer: one slot per id


def _overwrite_tool(self, key, idx):
    self._open[key] = [idx]             # the same overwrite on the tool side


def test_breakarm_overwrite_pairing_on_the_agent_side_fails_the_duplicate_match(tmp_path, up,
                                                                                monkeypatch):
    from arcaeon.record.adapter.observer import SeamObserver
    monkeypatch.setattr(SeamObserver, "_enqueue", _overwrite_agent)
    with pytest.raises(AssertionError):
        check_duplicate_ids_forwarded(tmp_path / "u", up)
    if _receipt_pairs_fifo():
        with pytest.raises(AssertionError):
            check_cross_repo_duplicate_ids_matched(tmp_path / "x", up)


@needs_receipt_fifo
def test_breakarm_overwrite_pairing_on_the_tool_side_fails_the_duplicate_match(tmp_path, up,
                                                                               monkeypatch):
    monkeypatch.setattr(_call_proxy()._ToolTape, "_enqueue", _overwrite_tool)
    with pytest.raises(AssertionError):
        check_cross_repo_duplicate_ids_matched(tmp_path, up)


# -- break arms: plant a liar in the forwarder; the checks must go red --------

class _BlindWatcher(HF._AnswerWatcher):
    """Relays everything, reads no answers."""

    def feed(self, piece):
        return []

    def close(self):
        return []


class _FirstLineSSE(HF._SSEFrames):
    """Keeps only the first `data:` line of each event."""

    def _dispatch(self):
        self._data = self._data[:1]
        return super()._dispatch()


def test_breakarm_a_forwarder_that_reads_no_answers_fails_the_checks(tmp_path, up, monkeypatch):
    monkeypatch.setattr(HF, "_AnswerWatcher", _BlindWatcher)
    with pytest.raises(AssertionError):
        check_json_answer_taped(tmp_path / "j", up)
    with pytest.raises(AssertionError):
        check_sse_answer_taped(tmp_path / "s", up, "/sse")
    if RECEIPT is not None:
        with pytest.raises(AssertionError):
            check_cross_repo_matched(tmp_path / "x", up)


def test_breakarm_an_sse_parser_that_drops_continuation_lines_fails(tmp_path, up, monkeypatch):
    monkeypatch.setattr(HF, "_SSEFrames", _FirstLineSSE)
    with pytest.raises(AssertionError):
        check_sse_answer_taped(tmp_path, up, "/chunked")


def test_breakarm_a_forwarder_that_gives_up_on_a_202_fails_the_later_check(tmp_path, up,
                                                                          monkeypatch):
    monkeypatch.setattr(HF, "KEEP_OPEN_STATUSES", frozenset())
    with pytest.raises(AssertionError):
        check_later_answer(tmp_path, up)


def test_breakarm_a_reserializing_forwarder_fails_the_fidelity_check(tmp_path, up, monkeypatch):
    monkeypatch.setenv(FAULT_ENV, "reserialize")
    with pytest.raises(AssertionError):
        check_fidelity(tmp_path, up)


def test_breakarm_a_forwarder_that_ignores_a_short_body_fails_the_check(tmp_path, monkeypatch):
    monkeypatch.setattr(HF, "_upstream_short", lambda resp: False)
    with pytest.raises(AssertionError):
        check_short_body(tmp_path, lambda liar: liar.sock.getsockname()[1])


# -- invalid ids (true/false, objects, arrays): taped `invalid_id`, never paired --
# THE RULE (identical in arcaeon-receipt's call_proxy): JSON-RPC 2.0 says an id
# is a string, a number, or null. A `tools/call` with any other id is an invalid
# call; it was still sent, so it gets one tape row and one seam row with status
# `invalid_id` and no response digest, and no answer is paired to it. The old
# observer dropped it while call_proxy taped it with its answer: MISSING on the
# agent side for a clean stream.

BAD_BATCH = [_call(True, "echo", "bool"), _call(1, "echo", "one"), _call("x", "echo", "ex")]


def check_invalid_ids_forwarded(tmp, up):
    tmp.mkdir(parents=True, exist_ok=True)
    f = _fwd(tmp, up.url)
    try:
        s, body, _ = _post(f.port, BAD_BATCH)
    finally:
        end = f.close()
    answers = json.loads(body)
    assert s == 200 and len(answers) == 3, "the relay is unchanged: the upstream's answers pass"
    rows = _rows(tmp / "agent.tape.jsonl")
    assert [(r["idx"], r["rpc_id"], r["status"]) for r in rows] == \
        [(1, "true", "invalid_id"), (2, "1", "ok"), (3, "x", "ok")], rows
    assert [r["resp"] for r in rows] == [None] + [response_digest(a) for a in answers[1:]]
    assert [r["req"] for r in rows] == [request_digest(c["params"]) for c in BAD_BATCH]
    seam = [r for r in _rows(tmp / "agent.seam.jsonl") if r["evt"] == "tool_call"]
    assert sorted((r["rpc_id"], r["status"]) for r in seam) == \
        [("1", "ok"), ("true", "invalid_id"), ("x", "ok")], seam
    assert end.get("unanswered") is None, end


def test_an_invalid_id_is_taped_invalid_and_its_answer_pairs_with_nothing(tmp_path, up):
    check_invalid_ids_forwarded(tmp_path, up)


def _receipt_marks_invalid_ids():
    if RECEIPT is None:
        return False
    src = (RECEIPT / "receipt" / "call_proxy.py").read_text(encoding="utf-8",
                                                                    errors="replace")
    return "_valid_rpc_id" in src


needs_receipt_invalid = pytest.mark.skipif(
    not _receipt_marks_invalid_ids(),
    reason="arcaeon-receipt call_proxy that tapes invalid ids as `invalid_id` not found "
           "(set ARCAEON_RECEIPT_REPO): both tapes' invalid-id rule could not be compared")


def check_cross_repo_invalid_ids_matched(tmp, up):
    """client -> adapter (agent tape) -> call_proxy (tool tape) -> upstream, one
    batch with ids true, 1, "x": both tapes row the bool call `invalid_id` with
    no answer, so reconcile says MATCHED 3 of 3."""
    tmp.mkdir(parents=True, exist_ok=True)
    cp = _call_proxy()
    tool = cp.build_server(listen="127.0.0.1:0", upstream=up.url, seller="acme",
                           ledger_path=tmp / "calls.log.jsonl", witness=False,
                           tape_path=tmp / "tool.tape.jsonl", tape_namespace="demo-tool")
    threading.Thread(target=tool.serve_forever, daemon=True).start()
    agent = _fwd(tmp, f"http://127.0.0.1:{tool.server_address[1]}/mcp")
    try:
        s, body, _ = _post(agent.port, BAD_BATCH, "/")
    finally:
        agent.close()
        tool.shutdown()
        tool.server_close()
        tool.tape.writer.flush()
    assert s == 200 and len(json.loads(body)) == 3
    a, t = _rows(tmp / "agent.tape.jsonl"), _rows(tmp / "tool.tape.jsonl")
    for rows in (a, t):
        assert [(r["idx"], r["rpc_id"], r["status"]) for r in rows] == \
            [(1, "true", "invalid_id"), (2, "1", "ok"), (3, "x", "ok")], rows
    rc = subprocess.run([sys.executable, "-m", "arcaeon.record.ledger.cli", "reconcile",
                         str(tmp / "agent.tape.jsonl"), str(tmp / "tool.tape.jsonl")],
                        capture_output=True, env=_env(), timeout=60)
    out = json.loads(rc.stdout)
    assert (out["verdict"], out["summary"], rc.returncode) == ("MATCHED", "MATCHED 3 of 3", 0), out
    return out


@needs_receipt_invalid
def test_cross_repo_invalid_ids_match_on_both_tapes(tmp_path, up):
    out = check_cross_repo_invalid_ids_matched(tmp_path, up)
    print("\nCROSS-REPO http-forward ids true,1,\"x\":", out["summary"])


def test_breakarm_an_agent_side_that_drops_invalid_ids_fails_the_checks(tmp_path, up,
                                                                       monkeypatch):
    import arcaeon.record.adapter.observer as OB
    monkeypatch.setattr(OB, "valid_rpc_id", lambda mid: True)   # the pre-fix observer
    with pytest.raises(AssertionError):
        check_invalid_ids_forwarded(tmp_path / "u", up)
    if _receipt_marks_invalid_ids():
        with pytest.raises(AssertionError):
            check_cross_repo_invalid_ids_matched(tmp_path / "x", up)


@needs_receipt_invalid
def test_breakarm_a_tool_side_that_pairs_invalid_ids_fails_the_match(tmp_path, up, monkeypatch):
    monkeypatch.setattr(_call_proxy(), "_valid_rpc_id", lambda mid: True)  # pre-fix call_proxy
    with pytest.raises(AssertionError):
        check_cross_repo_invalid_ids_matched(tmp_path, up)
