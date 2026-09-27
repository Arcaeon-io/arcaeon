"""K076: record which mandate was loaded, and any change to its file.

    pytest tests/test_mandate_loaded_row.py

A `mandate_loaded` row (file sha256) right after session_begin; swap the file
mid-session and the next judged call is preceded by a `mandate_changed` row
carrying both hashes. The gate keeps judging against what it loaded. Checked
on all three surfaces: stdio proxy (a live session held open across the swap),
http_forward and call_proxy.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from arcaeon.record.adapter._ledger import verify_seam_log

SRC = str(Path(__file__).resolve().parents[1] / "src")
ECHO = [sys.executable, "-m", "arcaeon.record.adapter._echo_server"]
FIRST = {"who": "loaded-agent", "allowed_acts": ["echo"]}
SECOND = {"who": "loaded-agent", "allowed_acts": ["search_*"]}


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _rows(path) -> list:
    return [json.loads(x) for x in Path(path).read_text(encoding="utf-8").splitlines()
            if x.strip()]


def _frame(i: int) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                       "params": {"name": "echo", "arguments": {"text": f"c{i}"}}}).encode()


def _check(rows, first_sha, second_sha):
    evts = [r["evt"] for r in rows]
    assert evts[0] == "session_begin" and evts[1] == "mandate_loaded", evts
    loaded = rows[1]
    assert loaded["mandate_file_sha256"] == first_sha
    assert loaded["mandate_status"] == "loaded" and loaded["mandate_mode"] == "record-only"
    changed = [r for r in rows if r["evt"] == "mandate_changed"]
    assert len(changed) == 1, evts
    c = changed[0]
    assert c["from_sha256"] == first_sha and c["to_sha256"] == second_sha
    assert c["judged_against_sha256"] == first_sha and c["file_status"] == "present"
    assert c["rpc_id"] == "2" and c["tool"] == "echo"
    # the change row comes before the call that noticed it is judged
    assert evts.index("mandate_changed") < len(evts) - 1
    # still judged against the loaded mandate: echo stays inside, no outside row
    assert not [r for r in rows if r["evt"] == "mandate_outside"]
    end = rows[-1]
    assert end["evt"] == "session_end" and end["mandate_changes"] == 1
    assert verify_seam_log(_LEDGER[0]).ok is True


_LEDGER: list = [None]


def _mandate(tmp_path) -> Path:
    p = tmp_path / "mandate.json"
    p.write_text(json.dumps(FIRST), encoding="utf-8")
    return p


def test_stdio_swap_mid_session(tmp_path):
    mandate = _mandate(tmp_path)
    first = _sha(mandate)
    ledger = tmp_path / "seam.jsonl"
    _LEDGER[0] = ledger
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    env.pop("ARCAEON_ADAPTER_SELFTEST_CORRUPT", None)
    p = subprocess.Popen([sys.executable, "-m", "arcaeon.record.adapter.proxy", "--ledger",
                          str(ledger), "--mandate", str(mandate), "--"] + ECHO,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env)
    try:
        p.stdin.write(_frame(1) + b"\n")
        p.stdin.flush()
        assert json.loads(p.stdout.readline())["id"] == 1
        # record-only judges a copy after forwarding; the reply to call 1 means
        # call 1 went out, and call 2 is written only after the swap
        mandate.write_text(json.dumps(SECOND), encoding="utf-8")
        second = _sha(mandate)
        p.stdin.write(_frame(2) + b"\n")
        p.stdin.flush()
        assert json.loads(p.stdout.readline())["id"] == 2
        p.stdin.close()
        p.wait(timeout=60)
    finally:
        if p.poll() is None:
            p.kill()
    _check(_rows(ledger), first, second)


class _Echo:
    def __init__(self):
        import http.server

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                body = json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {
                    "content": [{"type": "text", "text": "ok"}]}}).encode()
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


def _post(port, path, i):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    c.request("POST", path, body=_frame(i), headers={"Content-Type": "application/json"})
    reply = json.loads(c.getresponse().read())
    c.close()
    return reply


def test_http_forward_swap_mid_session(tmp_path):
    from arcaeon.record.adapter import http_forward as HF
    mandate = _mandate(tmp_path)
    first = _sha(mandate)
    ledger = tmp_path / "http.seam.jsonl"
    _LEDGER[0] = ledger
    up = _Echo()
    try:
        srv = HF.build_forward_server(up.url, ledger_path=ledger,
                                      mandate_path=mandate).start()
        try:
            assert _post(srv.port, "/", 1)["id"] == 1
            mandate.write_text(json.dumps(SECOND), encoding="utf-8")
            second = _sha(mandate)
            assert _post(srv.port, "/", 2)["id"] == 2
            time.sleep(0.2)          # record-only judges after forwarding
        finally:
            srv.close()
    finally:
        up.close()
    _check(_rows(ledger), first, second)


def test_call_proxy_swap_mid_session(tmp_path):
    from arcaeon.record.receipt import call_proxy
    mandate = _mandate(tmp_path)
    first = _sha(mandate)
    log = tmp_path / "call.mandate.jsonl"
    _LEDGER[0] = log
    up = _Echo()
    try:
        srv = call_proxy.build_server(
            listen="127.0.0.1:0", upstream=up.url.rsplit("/", 1)[0], seller="loaded",
            ledger_path=tmp_path / "calls.log.jsonl", witness=False,
            mandate_path=mandate, mandate_log=log)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            assert _post(srv.server_address[1], "/mcp", 1)["id"] == 1
            mandate.write_text(json.dumps(SECOND), encoding="utf-8")
            second = _sha(mandate)
            assert _post(srv.server_address[1], "/mcp", 2)["id"] == 2
            time.sleep(0.2)
        finally:
            srv.shutdown()
            srv.server_close()
            srv.mandate_close()
    finally:
        up.close()
    _check(_rows(log), first, second)


def test_file_deleted_mid_session_is_a_change_to_none(tmp_path):
    from arcaeon.record.adapter import mandate_gate
    from arcaeon.record.adapter.proxy import _MandateWatch
    from arcaeon.record.adapter.observer import SeamObserver
    mandate = _mandate(tmp_path)
    rows: list = []
    obs = SeamObserver(lambda r: rows.append(dict(r)) or r, server="t")
    w = _MandateWatch(mandate_gate.load(mandate), obs)
    obs.session_begin()
    mandate.unlink()
    w.judge({"id": 5, "method": "tools/call", "params": {"name": "echo"}})
    w.judge({"id": 6, "method": "tools/call", "params": {"name": "echo"}})
    changed = [r for r in rows if r.get("evt") == "mandate_changed"]
    assert len(changed) == 1                    # rowed once, not on every call
    assert changed[0].get("to_sha256") is None and changed[0]["file_status"] == "missing"


def test_no_change_no_row(tmp_path):
    from arcaeon.record.adapter import mandate_gate
    from arcaeon.record.adapter.proxy import _MandateWatch
    from arcaeon.record.adapter.observer import SeamObserver
    mandate = _mandate(tmp_path)
    rows: list = []
    obs = SeamObserver(lambda r: rows.append(dict(r)) or r, server="t")
    w = _MandateWatch(mandate_gate.load(mandate), obs)
    obs.session_begin()
    for i in range(3):
        w.judge({"id": i, "method": "tools/call", "params": {"name": "echo"}})
    assert [r.get("evt") for r in rows] == ["session_begin", "mandate_loaded"]


def test_nothing_loaded_no_loaded_row_and_a_later_file_is_a_change(tmp_path):
    from arcaeon.record.adapter import mandate_gate
    from arcaeon.record.adapter.proxy import _MandateWatch
    from arcaeon.record.adapter.observer import SeamObserver
    mandate = tmp_path / "later.json"
    rows: list = []
    obs = SeamObserver(lambda r: rows.append(dict(r)) or r, server="t")
    w = _MandateWatch(mandate_gate.load(mandate), obs)
    obs.session_begin()
    assert [r.get("evt") for r in rows] == ["session_begin"]
    mandate.write_text(json.dumps(FIRST), encoding="utf-8")
    v, _, _ = w.judge({"id": 1, "method": "tools/call", "params": {"name": "echo"}})
    assert v == "could_not_look"                 # still judged against what loaded
    changed = [r for r in rows if r.get("evt") == "mandate_changed"]
    assert len(changed) == 1 and changed[0].get("from_sha256") is None
    assert changed[0]["to_sha256"] == _sha(mandate)


@pytest.fixture(autouse=True)
def _arcaeon_home(tmp_path, monkeypatch):
    """A gated session appends its counts under ARCAEON_HOME (K077); keep a
    test's sessions out of the real ~/.arcaeon."""
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arc_home"))
