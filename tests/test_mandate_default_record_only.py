"""K070 guard: record-only is the default on every surface that takes a mandate.

For each surface, a tools/call that FAILS the mandate check (outside the
mandate, or a mandate the gate could not read) must still reach the tool and
come back with the tool's own answer, and the ledger must carry the row that
names the failure. Only an explicit enforce flag may withhold a call.

    pytest tests/test_mandate_default_record_only.py

Each surface is one runner in SURFACES. A runner takes
(tmp_path, mandate_path, enforce) and returns a Result: the tool's answer text
(None when the call never reached the tool), the JSON-RPC error the agent got
(None when there was none), and the seam rows. K071 and K072 add their
surfaces here.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

SRC = str(Path(__file__).resolve().parents[1] / "src")
ECHO = [sys.executable, "-m", "arcaeon.record.adapter._echo_server"]

#: `echo` matches no allowed_acts pattern, so every guard call is OUTSIDE.
MANDATE = {"who": "guard-agent", "allowed_acts": ["search_*"], "forbidden_acts": ["refund"]}
CALL = {"name": "echo", "arguments": {"text": "guard"}}
FAIL_EVENTS = ("mandate_outside", "mandate_could_not_look")


@dataclass
class Result:
    answer: str | None
    error: dict | None
    rows: list


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    env.pop("ARCAEON_ADAPTER_SELFTEST_CORRUPT", None)
    return env


def _rows(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _answer(msg: dict) -> tuple[str | None, dict | None]:
    if "error" in msg:
        return None, msg["error"]
    content = (msg.get("result") or {}).get("content") or [{}]
    return content[0].get("text"), None


# -- surfaces -----------------------------------------------------------------

def _stdio(tmp_path: Path, mandate: Path, enforce: bool) -> Result:
    ledger = tmp_path / "stdio.seam.jsonl"
    frame = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": CALL}
    argv = [sys.executable, "-m", "arcaeon.record.adapter.proxy", "--ledger", str(ledger),
            "--mandate", str(mandate)]
    if enforce:
        argv.append("--mandate-enforce")
    p = subprocess.run(argv + ["--"] + ECHO, input=json.dumps(frame).encode() + b"\n",
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_env(),
                       timeout=120)
    replies = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
    if not replies:
        return Result(None, None, _rows(ledger))
    return Result(*_answer(replies[0]), _rows(ledger))


class _EchoUpstream:
    """Loopback HTTP JSON-RPC stub: answers a tools/call with its `text`."""

    def __init__(self):
        import http.server
        import threading

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                text = msg["params"]["arguments"]["text"]
                body = json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {
                    "content": [{"type": "text", "text": text}]}}).encode()
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


def _http_forward(tmp_path: Path, mandate: Path, enforce: bool) -> Result:
    import http.client
    from arcaeon.record.adapter import http_forward as HF
    ledger = tmp_path / "http.seam.jsonl"
    up = _EchoUpstream()
    try:
        try:
            srv = HF.build_forward_server(up.url, ledger_path=ledger, mandate_path=mandate,
                                          mandate_enforce=enforce).start()
        except HF.MandateUnreadable:
            return Result(None, None, _rows(ledger))
        try:
            frame = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": CALL}
            c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=30)
            c.request("POST", "/", body=json.dumps(frame).encode(),
                      headers={"Content-Type": "application/json"})
            reply = json.loads(c.getresponse().read())
            c.close()
        finally:
            srv.close()
    finally:
        up.close()
    return Result(*_answer(reply), _rows(ledger))


SURFACES = {
    "stdio_proxy": _stdio,
    "http_forward": _http_forward,   # K071
}

# Surfaces whose enforce mode refuses to start on an unreadable mandate
# (nothing reaches the tool, and there is no per-call reply to read).
ENFORCE_REFUSES_UNREADABLE = {"stdio_proxy", "http_forward"}


def _mandate(tmp_path: Path, kind: str) -> Path:
    p = tmp_path / "mandate.json"
    if kind == "outside":
        p.write_text(json.dumps(MANDATE), encoding="utf-8")
    elif kind == "unreadable":
        p.write_text("{not json", encoding="utf-8")
    else:                                   # missing: the path names no file
        p = tmp_path / "absent.json"
    return p


# -- the guard ----------------------------------------------------------------

@pytest.mark.parametrize("kind", ["outside", "unreadable", "missing"])
@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_failing_check_still_goes_through_when_enforce_is_off(tmp_path, surface, kind):
    r = SURFACES[surface](tmp_path, _mandate(tmp_path, kind), False)
    assert r.error is None, f"{surface}: record-only withheld a call: {r.error}"
    assert r.answer == "guard", f"{surface}: the tool's own answer never came back"
    failed = [x for x in r.rows if x.get("evt") in FAIL_EVENTS]
    assert len(failed) == 1, f"{surface}: expected one mandate row, got {r.rows}"
    row = failed[0]
    want = "mandate_outside" if kind == "outside" else "mandate_could_not_look"
    assert row["evt"] == want
    assert row["action"] == "forwarded"
    assert row["mandate_mode"] == "record-only"
    assert row["tool"] == "echo"


@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_record_only_is_named_in_the_first_row(tmp_path, surface):
    r = SURFACES[surface](tmp_path, _mandate(tmp_path, "outside"), False)
    begin = r.rows[0]
    assert begin["evt"] == "session_begin"
    assert begin["mandate_mode"] == "record-only"


@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_only_the_explicit_enforce_flag_withholds_a_call(tmp_path, surface):
    r = SURFACES[surface](tmp_path, _mandate(tmp_path, "outside"), True)
    assert r.answer is None, f"{surface}: enforce forwarded an outside call"
    assert r.error is not None and r.error["code"] == -32001
    blocked = [x for x in r.rows if x.get("evt") == "mandate_outside"]
    assert len(blocked) == 1 and blocked[0]["action"] == "blocked"
    assert blocked[0]["mandate_mode"] == "enforce"


@pytest.mark.parametrize("surface", sorted(ENFORCE_REFUSES_UNREADABLE & set(SURFACES)))
def test_enforce_on_an_unreadable_mandate_forwards_nothing(tmp_path, surface):
    r = SURFACES[surface](tmp_path, _mandate(tmp_path, "unreadable"), True)
    assert r.answer is None


def test_every_mandate_surface_is_in_the_guard():
    """A surface that grows a mandate parameter without joining SURFACES
    escapes this guard. The ones known to take one are listed here."""
    assert {"stdio_proxy", "http_forward"} <= set(SURFACES)
