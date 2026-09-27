"""A 401 drains the declared body before it answers (K148 reproduced the reset).

Without the drain, a POST whose body is still in flight when the 401 goes out
gets a connection reset on Windows (WinError 10053) instead of the answer.
"""
from __future__ import annotations

import io
import json
import socket
import threading
import time

import pytest

from arcaeon.serve import server as S

BODY = b'{"ledger": "l.jsonl", "fields": {"a": "' + b"y" * (200 * 1024) + b'"}}'


@pytest.fixture()
def srv(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arcaeon-home"))
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    server = S.make_server(port=0)
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(server,),
                         kwargs={"ready": ready, "out": io.StringIO()}, daemon=True)
    t.start()
    assert ready.wait(10)
    yield server
    server.shutdown()
    t.join(10)


def _raw_post(port: int) -> bytes:
    """Headers first, the 200 KB body a beat later, then read to close."""
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    try:
        s.sendall(b"POST /v1/log HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                  b"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n"
                  % (port, len(BODY)))
        time.sleep(0.05)
        s.sendall(BODY)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        s.close()


def test_a_200kb_post_without_a_token_gets_a_clean_401(srv):
    port = srv.server_address[1]
    for _ in range(5):
        raw = _raw_post(port)
        head, _, body = raw.partition(b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.") and b" 401 " in head.split(b"\r\n")[0], head
        assert "no token" in json.loads(body)["error"]
