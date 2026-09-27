"""K07xR finding 1: a request the gate cannot parse is never a path around it.

    pytest tests/test_mandate_unparsed.py

Before: a body that was not JSON carried no tools/call the gate could see, so
it was forwarded with no row, even under enforce. Now, on every surface:
record-only forwards it and writes `mandate_could_not_look` with
`action: forwarded`, `judged_reason: unparsed`; enforce refuses it (the
JSON-RPC error a blocked call gets, id null) and writes the same row with
`action: blocked`. The stdio proxy under enforce keeps its standing
byte-identical contract for a non-JSON line and rows it as forwarded.
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

SRC = str(Path(__file__).resolve().parents[1] / "src")
ECHO = [sys.executable, "-m", "arcaeon.record.adapter._echo_server"]
MANDATE = {"who": "unparsed-agent", "allowed_acts": ["echo"]}
GARBAGE = b"{this is not json"


def _rows(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _unparsed_rows(rows) -> list:
    return [r for r in rows if r.get("evt") == "mandate_could_not_look"
            and r.get("judged_reason") == "unparsed"]


def _mandate(tmp_path) -> Path:
    p = tmp_path / "mandate.json"
    p.write_text(json.dumps(MANDATE), encoding="utf-8")
    return p


class _RawUpstream:
    """Loopback stub that answers ANY body, and counts the bodies it saw."""

    def __init__(self):
        seen = self.seen = []

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                seen.append(body)
                out = json.dumps({"jsonrpc": "2.0", "id": None,
                                  "result": {"upstream": "saw it"}}).encode()
                self.send_response_only(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/mcp"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _post(port: int, path: str, body: bytes) -> dict:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    c.request("POST", path, body=body, headers={"Content-Type": "application/json"})
    reply = json.loads(c.getresponse().read())
    c.close()
    return reply


# -- surfaces: each returns (upstream_saw_it, reply_to_agent, rows) --------------

def _http_forward(tmp_path, enforce):
    from arcaeon.record.adapter import http_forward as HF
    ledger = tmp_path / "http.seam.jsonl"
    up = _RawUpstream()
    try:
        srv = HF.build_forward_server(up.url, ledger_path=ledger,
                                      mandate_path=_mandate(tmp_path),
                                      mandate_enforce=enforce).start()
        try:
            reply = _post(srv.port, "/", GARBAGE)
        finally:
            srv.close()
    finally:
        up.close()
    return GARBAGE in up.seen, reply, _rows(ledger)


def _call_proxy(tmp_path, enforce):
    from arcaeon.record.receipt import call_proxy
    log = tmp_path / "call.mandate.jsonl"
    up = _RawUpstream()
    try:
        srv = call_proxy.build_server(
            listen="127.0.0.1:0", upstream=up.url.rsplit("/", 1)[0], seller="unparsed",
            ledger_path=tmp_path / "calls.log.jsonl", witness=False,
            mandate_path=_mandate(tmp_path), mandate_enforce=enforce, mandate_log=log)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            reply = _post(srv.server_address[1], "/mcp", GARBAGE)
        finally:
            srv.shutdown()
            srv.server_close()
            srv.mandate_close()
    finally:
        up.close()
    return GARBAGE in up.seen, reply, _rows(log)


def _stdio(tmp_path, enforce):
    ledger = tmp_path / "stdio.seam.jsonl"
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    env.pop("ARCAEON_ADAPTER_SELFTEST_CORRUPT", None)
    argv = [sys.executable, "-m", "arcaeon.record.adapter.proxy", "--ledger", str(ledger),
            "--mandate", str(_mandate(tmp_path))]
    if enforce:
        argv.append("--mandate-enforce")
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "after"}}}
    p = subprocess.run(argv + ["--"] + ECHO,
                       input=GARBAGE + b"\n" + json.dumps(call).encode() + b"\n",
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=120)
    replies = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
    # The echo server says nothing to garbage, so the only null-id reply can
    # be the gate's own refusal.
    refusal = next((r for r in replies if r.get("id") is None), None)
    after = next((r for r in replies if r.get("id") == 2), None)
    assert after is not None and "error" not in after, "a later good call was hurt"
    return refusal is None, refusal or after, _rows(ledger)


SURFACES = {"stdio_proxy": _stdio, "http_forward": _http_forward, "call_proxy": _call_proxy}


@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_record_only_forwards_unparsed_and_rows_it(tmp_path, surface):
    reached, reply, rows = SURFACES[surface](tmp_path, False)
    assert reached, f"{surface}: record-only withheld an unparsed body"
    assert "error" not in reply
    got = _unparsed_rows(rows)
    assert len(got) == 1, f"{surface}: no unparsed row"
    assert got[0]["action"] == "forwarded" and got[0]["verdict"] == "could_not_look"
    assert got[0]["reason_word"] == "unreadable"
    assert got[0]["mandate_mode"] == "record-only"


#: HTTP surfaces refuse an unparsed body under enforce. The stdio proxy keeps
#: its standing contract (a non-JSON line passes byte-identical under enforce,
#: tests/test_mandate_gate.py) and rows it instead: see the stdio test below.
REFUSING = ("http_forward", "call_proxy")


@pytest.mark.parametrize("surface", REFUSING)
def test_enforce_refuses_unparsed_and_rows_it(tmp_path, surface):
    reached, reply, rows = SURFACES[surface](tmp_path, True)
    assert not reached, f"{surface}: enforce forwarded an unparsed body"
    assert reply["id"] is None and reply["error"]["code"] == -32001
    assert reply["error"]["data"]["judged_reason"] == "unparsed"
    got = _unparsed_rows(rows)
    assert len(got) == 1, f"{surface}: no unparsed row"
    assert got[0]["action"] == "blocked" and got[0]["mandate_mode"] == "enforce"


def test_stdio_enforce_passes_unparsed_but_never_unrowed(tmp_path):
    reached, reply, rows = _stdio(tmp_path, True)
    assert reached and "error" not in reply
    got = _unparsed_rows(rows)
    assert len(got) == 1
    assert got[0]["action"] == "forwarded" and got[0]["mandate_mode"] == "enforce"


@pytest.fixture(autouse=True)
def _arcaeon_home(tmp_path, monkeypatch):
    """A gated session appends its counts under ARCAEON_HOME (K077); keep a
    test's sessions out of the real ~/.arcaeon."""
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arc_home"))
