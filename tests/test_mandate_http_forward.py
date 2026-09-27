"""K071: the mandate gate in the HTTP forward proxy.

Same rows as the stdio proxy (`mandate_outside`, `mandate_could_not_look`),
the gate imported lazily, enforce opt-in. The upstream is a loopback stub this
file starts; nothing leaves 127.0.0.1.

    pytest tests/test_mandate_http_forward.py
"""
from __future__ import annotations

import http.client
import http.server
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from arcaeon.record.adapter import http_forward as HF
from arcaeon.record.adapter._ledger import verify_seam_log

MANDATE = {
    "who": "purchasing-agent@acme",
    "allowed_acts": ["echo", "place_*"],
    "forbidden_acts": ["boom"],
    "spend_cap": {"amount": "60.00", "currency": "USD", "merchant": "acme-store"},
}


class Upstream:
    """A loopback JSON-RPC server: echoes `text`, remembers every POST body."""

    def __init__(self):
        self.bodies: list = []
        up = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n)
                up.bodies.append(raw)
                msg = json.loads(raw)
                msgs = msg if isinstance(msg, list) else [msg]
                out = []
                for m in msgs:
                    if m.get("id") is None:
                        continue
                    text = str(((m.get("params") or {}).get("arguments") or {})
                               .get("text", ""))
                    out.append({"jsonrpc": "2.0", "id": m["id"], "result": {
                        "content": [{"type": "text", "text": text}]}})
                if not out:
                    self.send_response_only(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = json.dumps(out if isinstance(msg, list) else out[0]).encode()
                self.send_response_only(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/mcp"
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


def _call(mid, name, **args):
    return {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
            "params": {"name": name, "arguments": args}}


def _post(srv, payload) -> tuple[int, bytes]:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=30)
    try:
        c.request("POST", "/", body=body, headers={"Content-Type": "application/json"})
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def _rows(path) -> list:
    p = Path(path)
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _serve(upstream, tmp_path, mandate=None, enforce=False, **kw):
    return HF.build_forward_server(upstream.url, ledger_path=tmp_path / "seam.jsonl",
                                   mandate_path=mandate, mandate_enforce=enforce,
                                   **kw).start()


# -- record-only (the default) --------------------------------------------------

def test_record_only_outside_call_is_forwarded_and_rowed(tmp_path, upstream, mandate_file):
    srv = _serve(upstream, tmp_path, mandate_file)
    try:
        st, body = _post(srv, _call(1, "echo", text="hi"))
        assert st == 200 and json.loads(body)["result"]["content"][0]["text"] == "hi"
        st, body = _post(srv, _call(2, "boom", text="still"))
        assert st == 200
        assert json.loads(body)["result"]["content"][0]["text"] == "still"
    finally:
        end = srv.close()
    assert len(upstream.bodies) == 2                  # both reached the upstream
    rows = _rows(tmp_path / "seam.jsonl")
    assert rows[0]["mandate_mode"] == "record-only"
    assert rows[0]["mandate_file_sha256"]
    out = [r for r in rows if r["evt"] == "mandate_outside"]
    assert len(out) == 1
    o = out[0]
    assert o["tool"] == "boom" and o["rule"] == "forbidden_acts"
    assert o["action"] == "forwarded" and o["rpc_id"] == "2"
    assert o["who"] == MANDATE["who"]
    assert end["mandate_inside"] == 1 and end["mandate_outside"] == 1
    assert "mandate_blocked" not in end
    assert verify_seam_log(tmp_path / "seam.jsonl").ok is True


def test_record_only_is_the_default(tmp_path, upstream, mandate_file):
    srv = HF.build_forward_server(upstream.url, ledger_path=tmp_path / "seam.jsonl",
                                  mandate_path=mandate_file).start()
    try:
        st, body = _post(srv, _call(1, "refund"))
        assert st == 200 and "error" not in json.loads(body)
    finally:
        srv.close()
    assert len(upstream.bodies) == 1


@pytest.mark.parametrize("kind", ["unreadable", "missing"])
def test_unreadable_mandate_record_only_rows_every_call_never_blocks(tmp_path, upstream,
                                                                     kind):
    p = tmp_path / "mandate.json"
    if kind == "unreadable":
        p.write_text("{nope", encoding="utf-8")
    srv = _serve(upstream, tmp_path, p)
    try:
        for i in range(3):
            st, body = _post(srv, _call(i, "echo", text=str(i)))
            assert st == 200 and json.loads(body)["result"]["content"][0]["text"] == str(i)
    finally:
        srv.close()
    rows = _rows(tmp_path / "seam.jsonl")
    assert rows[0]["mandate_status"] == kind
    cnl = [r for r in rows if r["evt"] == "mandate_could_not_look"]
    assert len(cnl) == 3
    assert all(r["action"] == "forwarded" for r in cnl)


def test_record_only_batch_rows_each_call(tmp_path, upstream, mandate_file):
    srv = _serve(upstream, tmp_path, mandate_file)
    try:
        st, body = _post(srv, [_call(1, "echo", text="a"), _call(2, "boom"),
                               _call(3, "nope")])
        assert st == 200 and len(json.loads(body)) == 3
    finally:
        srv.close()
    rows = _rows(tmp_path / "seam.jsonl")
    assert sorted(r["tool"] for r in rows if r["evt"] == "mandate_outside") == \
        ["boom", "nope"]


def test_record_only_oversize_body_is_forwarded_and_rowed_could_not_look(
        tmp_path, upstream, mandate_file):
    srv = _serve(upstream, tmp_path, mandate_file, max_frame=64)
    try:
        st, _ = _post(srv, _call(1, "echo", text="x" * 200))
        assert st == 200
    finally:
        srv.close()
    assert len(upstream.bodies) == 1
    rows = [r for r in _rows(tmp_path / "seam.jsonl") if r["evt"] == "mandate_could_not_look"]
    assert len(rows) == 1 and rows[0]["reason_word"] == "bounded"


def test_no_mandate_no_rows_and_no_mode(tmp_path, upstream):
    srv = _serve(upstream, tmp_path)
    try:
        _post(srv, _call(1, "boom"))
    finally:
        srv.close()
    rows = _rows(tmp_path / "seam.jsonl")
    assert "mandate_mode" not in rows[0]
    assert not [r for r in rows if r["evt"].startswith("mandate_")]


# -- enforce (opt-in) -------------------------------------------------------------

def test_enforce_outside_call_is_answered_here_and_never_forwarded(tmp_path, upstream,
                                                                   mandate_file):
    srv = _serve(upstream, tmp_path, mandate_file, enforce=True)
    try:
        st, body = _post(srv, _call(1, "echo", text="ok"))
        assert st == 200 and json.loads(body)["result"]["content"][0]["text"] == "ok"
        st, body = _post(srv, _call(2, "boom"))
        assert st == 200
        err = json.loads(body)["error"]
        assert err["code"] == -32001 and "mandate" in err["message"]
    finally:
        end = srv.close()
    assert len(upstream.bodies) == 1                  # only the inside call went up
    rows = _rows(tmp_path / "seam.jsonl")
    assert rows[0]["mandate_mode"] == "enforce"
    o = [r for r in rows if r["evt"] == "mandate_outside"]
    assert len(o) == 1 and o[0]["action"] == "blocked"
    calls = {r["rpc_id"]: r for r in rows if r["evt"] == "tool_call"}
    assert calls["2"]["status"] == "error"          # the attempt and the answer, paired
    assert end["mandate_blocked"] == 1
    assert verify_seam_log(tmp_path / "seam.jsonl").ok is True


def test_enforce_batch_with_one_outside_call_is_held_back_whole(tmp_path, upstream,
                                                                mandate_file):
    srv = _serve(upstream, tmp_path, mandate_file, enforce=True)
    try:
        st, body = _post(srv, [_call(1, "echo", text="a"), _call(2, "boom")])
        replies = json.loads(body)
    finally:
        srv.close()
    assert upstream.bodies == []
    assert isinstance(replies, list) and {r["id"] for r in replies} == {1, 2}


def test_enforce_oversize_body_is_413_and_rowed(tmp_path, upstream, mandate_file):
    srv = _serve(upstream, tmp_path, mandate_file, enforce=True, max_frame=64)
    try:
        st, _ = _post(srv, _call(1, "echo", text="x" * 200))
    finally:
        srv.close()
    assert st == 413 and upstream.bodies == []


@pytest.mark.parametrize("kind", ["unreadable", "missing"])
def test_enforce_unreadable_mandate_refuses_to_start(tmp_path, upstream, kind):
    p = tmp_path / "mandate.json"
    if kind == "unreadable":
        p.write_text("{nope", encoding="utf-8")
    with pytest.raises(HF.MandateUnreadable):
        HF.build_forward_server(upstream.url, ledger_path=tmp_path / "seam.jsonl",
                                mandate_path=p, mandate_enforce=True)
    rows = _rows(tmp_path / "seam.jsonl")
    assert [r["evt"] for r in rows] == ["session_begin", "session_end"]
    assert rows[-1]["exit_code"] == 3
    assert HF.run_http_forward(upstream.url, "127.0.0.1:0", tmp_path / "b.jsonl",
                               mandate_path=p, mandate_enforce=True) == 3


def test_enforce_without_a_mandate_is_a_usage_error(tmp_path, upstream):
    with pytest.raises(ValueError):
        HF.build_forward_server(upstream.url, ledger_path=tmp_path / "seam.jsonl",
                                mandate_enforce=True)


# -- wiring --------------------------------------------------------------------------

def test_gate_is_imported_lazily():
    code = ("import sys; import arcaeon.record.adapter.http_forward; "
            "print('arcaeon.record.adapter.mandate_gate' in sys.modules)")
    src = str(Path(__file__).resolve().parents[1] / "src")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env={**__import__("os").environ, "PYTHONPATH": src}, timeout=60)
    assert out.stdout.strip() == "False", out.stderr


def test_cli_accepts_mandate_with_http_forward(tmp_path):
    """--mandate with --http-forward is no longer a usage error; enforce on a
    missing mandate reaches the gate and exits 3 (COULD NOT LOOK)."""
    from arcaeon.record.adapter.proxy import main
    rc = main(["--ledger", str(tmp_path / "seam.jsonl"), "--http-forward",
               "http://127.0.0.1:9/mcp", "--mandate", str(tmp_path / "absent.json"),
               "--mandate-enforce"])
    assert rc == 3
