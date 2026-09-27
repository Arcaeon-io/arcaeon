"""The socket guard (K143): loopback only, unless a test is marked `live`.

The root conftest refuses every non-loopback connect, sendto, bind and name
lookup in a test not marked `live`, and fails that test at teardown naming
the address in its call phase even when the code under test swallowed the
error. These tests
hold the parts; the last one runs a scratch session to show a swallowed
attempt still fails and a `live` test is skipped by default.
"""
from __future__ import annotations

import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("host", ["127.0.0.1", "127.8.9.10", "::1", "[::1]", "localhost",
                                  b"127.0.0.1"])
def test_loopback_hosts_are_allowed(socket_guard, host):
    assert socket_guard.is_loopback_host(host)


@pytest.mark.parametrize("host", ["", "0.0.0.0", "::", "10.0.0.1", "192.0.2.1",
                                  "witness.arcaeon.io", "example.invalid", None])
def test_other_hosts_are_not(socket_guard, host):
    assert not socket_guard.is_loopback_host(host)


def test_a_loopback_server_and_client_work():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        with socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=5) as s:
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            assert b"ok" in s.recv(1024) + s.recv(1024)
    finally:
        srv.shutdown()
        srv.server_close()


def _drain(guard):
    hits, guard.hits = guard.hits, []
    return hits


@pytest.mark.parametrize("call", [
    lambda: socket.create_connection(("192.0.2.1", 9), timeout=1),
    lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect_ex(("192.0.2.1", 9)),
    lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("192.0.2.1", 9)),
    lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).bind(("0.0.0.0", 0)),
    lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).bind(("", 0)),
    lambda: socket.getaddrinfo("witness.arcaeon.io", 443),
], ids=["connect", "connect_ex", "sendto", "bind-any", "bind-empty", "lookup"])
def test_a_non_loopback_attempt_is_refused_and_recorded(socket_guard, call):
    g = socket_guard.guard
    with pytest.raises(socket_guard.refused, match="K143"):
        call()
    hits = _drain(g)       # drained so this test itself does not fail at teardown
    assert len(hits) == 1, hits


def test_the_refusal_is_an_oserror_so_nothing_leaves_and_code_sees_a_down_network(socket_guard):
    assert issubclass(socket_guard.refused, OSError)
    import urllib.error
    import urllib.request
    with pytest.raises((urllib.error.URLError, OSError)):
        urllib.request.urlopen("http://192.0.2.1:9/", timeout=1)
    assert _drain(socket_guard.guard)


def test_the_live_marker_is_registered(pytestconfig):
    assert any(line.startswith("live:") for line in pytestconfig.getini("markers"))


def test_a_scratch_session_fails_a_swallowed_attempt_and_skips_live(tmp_path):
    """The real root conftest, copied into a scratch project: a test that
    swallows the refusal still fails by name, a loopback test passes, and a
    `live` test is skipped without -m live, with no unknown-marker warning."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "conftest.py").write_bytes((ROOT / "conftest.py").read_bytes())
    (proj / "tests").mkdir()
    (proj / "tests" / "test_scratch.py").write_text(
        "import socket\nimport pytest\n\n\n"
        "def test_swallows():\n"
        "    try:\n"
        "        socket.create_connection(('192.0.2.1', 9), timeout=1)\n"
        "    except OSError:\n"
        "        pass\n\n\n"
        "def test_loopback_lookup():\n"
        "    socket.getaddrinfo('127.0.0.1', 80)\n\n\n"
        "@pytest.mark.live\n"
        "def test_live():\n"
        "    raise AssertionError('a live test ran without -m live')\n",
        encoding="utf-8")
    env = {k: v for k, v in __import__("os").environ.items()}
    env["PYTHONPATH"] = str(ROOT / "src")
    env["ARCAEON_REAL_HOME_GUARD"] = "0"
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider",
                        "-W", "error::pytest.PytestUnknownMarkWarning", "tests"],
                       cwd=proj, env=env, capture_output=True, text=True, timeout=180)
    out = p.stdout + p.stderr
    assert p.returncode == 1, out
    assert "1 failed, 1 passed, 1 skipped" in out, out
    assert "192.0.2.1" in out and "socket guard (K143)" in out, out
    assert "-m live" in out, out
