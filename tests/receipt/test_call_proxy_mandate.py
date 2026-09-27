"""K072: the mandate gate in arcaeon.record.receipt.call_proxy.

Record-only by default: an outside tools/call is still forwarded and
receipted, and a `mandate_outside` row lands in the mandate log. Enforce is
opt-in. The upstream is a loopback stub this file starts.

    pytest tests/receipt/test_call_proxy_mandate.py
"""
from __future__ import annotations

import http.client
import http.server
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from arcaeon.record.adapter._ledger import verify_seam_log
from arcaeon.record.receipt import call_proxy

MANDATE = {"who": "tool-seller@acme", "allowed_acts": ["echo", "search_*"],
           "forbidden_acts": ["refund"]}


class Upstream:
    def __init__(self):
        self.bodies: list = []
        up = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                up.bodies.append(raw)
                msg = json.loads(raw)
                msgs = msg if isinstance(msg, list) else [msg]
                out = [{"jsonrpc": "2.0", "id": m["id"], "result": {"content": [
                    {"type": "text", "text": str(((m.get("params") or {})
                                                  .get("arguments") or {}).get("text", ""))}]}}
                       for m in msgs if m.get("id") is not None]
                body = json.dumps(out if isinstance(msg, list) else out[0]).encode()
                self.send_response_only(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def upstream():
    u = Upstream()
    yield u
    u.close()


@pytest.fixture
def mandate_file(tmp_path):
    p = tmp_path / "mandate.json"
    p.write_text(json.dumps(MANDATE), encoding="utf-8")
    return p


class Proxy:
    def __init__(self, upstream, tmp_path, **kw):
        self.ledger = tmp_path / "calls.log.jsonl"
        self.server = call_proxy.build_server(
            listen="127.0.0.1:0", upstream=upstream.url, seller="acme",
            ledger_path=self.ledger, witness=False, **kw)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def post(self, payload):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            c.request("POST", "/mcp", body=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"})
            r = c.getresponse()
            return r.status, dict(r.getheaders()), json.loads(r.read() or b"null")
        finally:
            c.close()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        return self.server.mandate_close()


def _call(mid, name, **args):
    return {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
            "params": {"name": name, "arguments": args}}


def _rows(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _receipts(ledger) -> int:
    return len(_rows(ledger))


# -- record-only (the default) --------------------------------------------------

def test_record_only_outside_call_is_forwarded_receipted_and_rowed(tmp_path, upstream,
                                                                    mandate_file):
    px = Proxy(upstream, tmp_path, mandate_path=mandate_file)
    try:
        st, hdr, body = px.post(_call(1, "echo", text="hi"))
        assert st == 200 and body["result"]["content"][0]["text"] == "hi"
        st, hdr, body = px.post(_call(2, "refund", text="still"))
        assert st == 200 and body["result"]["content"][0]["text"] == "still"
        assert "X-Arcaeon-Receipt" in hdr              # the outside call was receipted
    finally:
        end = px.close()
    assert len(upstream.bodies) == 2
    log = Path(f"{px.ledger}.mandate.jsonl")
    rows = _rows(log)
    assert rows[0]["evt"] == "session_begin"
    assert rows[0]["mandate_mode"] == "record-only" and rows[0]["seam"] == "call-proxy"
    assert rows[0]["mandate_file_sha256"]
    out = [r for r in rows if r["evt"] == "mandate_outside"]
    assert len(out) == 1
    assert out[0]["tool"] == "refund" and out[0]["rule"] == "forbidden_acts"
    assert out[0]["action"] == "forwarded" and out[0]["who"] == MANDATE["who"]
    assert end["mandate_inside"] == 1 and end["mandate_outside"] == 1
    assert "mandate_blocked" not in end
    assert verify_seam_log(log).ok is True


def test_record_only_is_the_default(tmp_path, upstream, mandate_file):
    px = Proxy(upstream, tmp_path, mandate_path=mandate_file)
    try:
        st, _, body = px.post(_call(1, "delete_all"))
        assert st == 200 and "error" not in body
    finally:
        px.close()
    assert len(upstream.bodies) == 1


@pytest.mark.parametrize("kind", ["unreadable", "missing"])
def test_unreadable_mandate_record_only_forwards_and_rows_could_not_look(
        tmp_path, upstream, kind):
    p = tmp_path / "mandate.json"
    if kind == "unreadable":
        p.write_text("{nope", encoding="utf-8")
    px = Proxy(upstream, tmp_path, mandate_path=p, mandate_log=tmp_path / "m.jsonl")
    try:
        for i in range(2):
            st, _, body = px.post(_call(i, "echo", text=str(i)))
            assert st == 200 and body["result"]["content"][0]["text"] == str(i)
    finally:
        px.close()
    rows = _rows(tmp_path / "m.jsonl")
    assert rows[0]["mandate_status"] == kind
    cnl = [r for r in rows if r["evt"] == "mandate_could_not_look"]
    assert len(cnl) == 2 and all(r["action"] == "forwarded" for r in cnl)


def test_no_mandate_writes_no_mandate_log(tmp_path, upstream):
    px = Proxy(upstream, tmp_path)
    try:
        px.post(_call(1, "refund"))
    finally:
        assert px.close() is None
    assert not Path(f"{px.ledger}.mandate.jsonl").exists()


def test_receipt_ledger_is_untouched_by_the_gate(tmp_path, upstream, mandate_file):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    for d, kw in ((a, {}), (b, {"mandate_path": mandate_file})):
        px = Proxy(upstream, d, **kw)
        try:
            px.post(_call(1, "refund"))
        finally:
            px.close()
    ra, rb = _rows(a / "calls.log.jsonl"), _rows(b / "calls.log.jsonl")
    assert len(ra) == len(rb) >= 1
    assert "mandate" not in json.dumps(rb)


# -- enforce (opt-in) -------------------------------------------------------------

def test_enforce_outside_call_is_answered_here_never_forwarded(tmp_path, upstream,
                                                               mandate_file):
    px = Proxy(upstream, tmp_path, mandate_path=mandate_file, mandate_enforce=True)
    try:
        st, _, body = px.post(_call(1, "echo", text="ok"))
        assert body["result"]["content"][0]["text"] == "ok"
        st, hdr, body = px.post(_call(2, "refund"))
        assert st == 200 and body["error"]["code"] == -32001
        assert "X-Arcaeon-Receipt" not in hdr           # never forwarded, never receipted
    finally:
        end = px.close()
    assert len(upstream.bodies) == 1
    assert _receipts(px.ledger) == 1
    rows = _rows(f"{px.ledger}.mandate.jsonl")
    assert rows[0]["mandate_mode"] == "enforce"
    o = [r for r in rows if r["evt"] == "mandate_outside"]
    assert len(o) == 1 and o[0]["action"] == "blocked"
    assert end["mandate_blocked"] == 1


def test_enforce_batch_with_one_outside_call_is_held_back_whole(tmp_path, upstream,
                                                                mandate_file):
    px = Proxy(upstream, tmp_path, mandate_path=mandate_file, mandate_enforce=True)
    try:
        st, _, body = px.post([_call(1, "echo", text="a"), _call(2, "refund")])
    finally:
        px.close()
    assert upstream.bodies == []
    assert isinstance(body, list) and {r["id"] for r in body} == {1, 2}


@pytest.mark.parametrize("kind", ["unreadable", "missing"])
def test_enforce_unreadable_mandate_refuses_to_start(tmp_path, upstream, kind):
    p = tmp_path / "mandate.json"
    if kind == "unreadable":
        p.write_text("{nope", encoding="utf-8")
    log = tmp_path / "m.jsonl"
    with pytest.raises(call_proxy.MandateUnreadable):
        call_proxy.build_server(listen="127.0.0.1:0", upstream=upstream.url,
                                seller="acme", ledger_path=tmp_path / "c.jsonl",
                                witness=False, mandate_path=p, mandate_enforce=True,
                                mandate_log=log)
    rows = _rows(log)
    assert [r["evt"] for r in rows] == ["session_begin", "session_end"]
    assert rows[-1]["exit_code"] == 3
    rc = call_proxy.main(["--listen", "127.0.0.1:0", "--upstream", upstream.url,
                          "--ledger", str(tmp_path / "d.jsonl"), "--no-witness",
                          "--mandate", str(p), "--mandate-enforce"])
    assert rc == 3


def test_enforce_without_mandate_is_a_usage_error(tmp_path, upstream):
    with pytest.raises(ValueError):
        call_proxy.build_server(listen="127.0.0.1:0", upstream=upstream.url,
                                seller="acme", ledger_path=tmp_path / "c.jsonl",
                                witness=False, mandate_enforce=True)
    with pytest.raises(SystemExit) as e:
        call_proxy.main(["--upstream", upstream.url, "--mandate-enforce"])
    assert e.value.code == 2


def test_gate_is_imported_lazily():
    code = ("import sys; import arcaeon.record.receipt.call_proxy; "
            "print('arcaeon.record.adapter.mandate_gate' in sys.modules)")
    src = str(Path(__file__).resolve().parents[2] / "src")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env={**os.environ, "PYTHONPATH": src}, timeout=60)
    assert out.stdout.strip() == "False", out.stderr
