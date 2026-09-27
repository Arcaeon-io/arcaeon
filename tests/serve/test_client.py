"""The stdlib Python client against a real server thread (K016)."""
from __future__ import annotations

import io
import json
import socket
import threading

import pytest

from arcaeon import client as C
from arcaeon.client import Client
from arcaeon.serve import routes as R
from arcaeon.serve import server as S


@pytest.fixture()
def home(tmp_path, monkeypatch):
    h = tmp_path / "arcaeon-home"
    monkeypatch.setenv("ARCAEON_HOME", str(h))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    return h


@pytest.fixture()
def root(tmp_path, home, monkeypatch):
    r = tmp_path / "served"
    r.mkdir()
    monkeypatch.chdir(tmp_path)
    return r


@pytest.fixture()
def srv(root):
    server = S.make_server(port=0, root=root)
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(server,),
                         kwargs={"ready": ready, "out": io.StringIO()}, daemon=True)
    t.start()
    assert ready.wait(10)
    yield server
    server.shutdown()
    t.join(10)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_every_route_but_the_dashboard_has_a_method():
    want = {(r.method, r.path) for r in R.ROUTES if r.path != "/"}
    assert set(C.ROUTE_METHODS.values()) == want
    for name in C.ROUTE_METHODS:
        assert callable(getattr(Client, name))


def test_default_client_reads_serve_json_and_token(srv, root):
    c = Client()
    assert c.url == srv.url and c.token
    assert c.health() == {"ok": True}
    assert c.log(ledger="l.jsonl", fields={"n": 1})["exit"] == 0
    assert c.log({"ledger": "l.jsonl"}, row={"n": 2})["exit"] == 0
    r = c.verify(ledger="l.jsonl")
    assert (r["verdict"], r["rows"], r["exit"]) == ("VERIFIED", 2, 0)
    assert "http_status" not in r
    assert c.openapi()["openapi"] == "3.1.0"
    assert isinstance(c.status(), dict)


def test_broken_and_could_not_look_come_back_as_dicts(srv, root):
    c = Client()
    for n in (1, 2):
        c.log(ledger="l.jsonl", fields={"n": n})
    p = root / "l.jsonl"
    data = bytearray(p.read_bytes())
    data[data.index(b'"n": 1') + 5] = ord("7")
    p.write_bytes(bytes(data))
    r = c.verify(ledger="l.jsonl")
    assert (r["verdict"], r["exit"]) == ("BROKEN", 1)
    r = c.verify(ledger="nope.jsonl")
    assert (r["verdict"], r["exit"]) == ("COULD NOT LOOK", 3)


def test_refusals_carry_http_status_and_never_exit_0(srv, root):
    r = Client(token="wrong").verify(ledger="l.jsonl")
    assert (r["http_status"], r["exit"]) == (401, 2)
    r = Client().verify(ledger="../out.jsonl")
    assert (r["http_status"], r["exit"]) == (400, 2)
    r = Client().call("GET", "/v1/nope")
    assert r["http_status"] == 404 and r["exit"] != 0


def test_the_token_is_not_in_the_repr(srv):
    c = Client()
    assert c.token not in repr(c)


def test_no_server_running_is_network_could_not_look(home):
    r = Client().verify(ledger="x.jsonl")
    assert r["reason_word"] == "network"
    assert (r["verdict"], r["exit"]) == ("COULD NOT LOOK", 3)


def test_refused_connection_is_network_never_an_exception(home):
    r = Client(url=f"http://127.0.0.1:{_free_port()}", token="t", timeout=5).verify(
        ledger="x.jsonl")
    assert (r["verdict"], r["exit"], r["reason_word"]) == ("COULD NOT LOOK", 3, "network")


def test_stale_serve_json_is_network(home):
    home.mkdir(parents=True)
    (home / "serve.json").write_text(json.dumps(
        {"pid": 1, "port": 1, "url": f"http://127.0.0.1:{_free_port()}"}), encoding="utf-8")
    assert Client(timeout=5).status()["reason_word"] == "network"


def test_a_reply_that_is_not_json_is_unreadable(home):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    s = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    try:
        r = Client(url=f"http://127.0.0.1:{s.server_address[1]}", token="t").verify(ledger="x")
    finally:
        s.shutdown()
        s.server_close()
        t.join(10)
    assert (r["verdict"], r["exit"], r["reason_word"]) == ("COULD NOT LOOK", 3, "unreadable")


# --- K016R: the serve token never leaves loopback -----------------------------------

class _FakeConn:
    """Stands in for http.client.HTTPConnection: records, never connects."""
    made: list = []

    def __init__(self, host, port, timeout=None):
        self.host = host
        _FakeConn.made.append(self)

    def request(self, method, path, body=None, headers=None):
        self.headers = dict(headers or {})

    def getresponse(self):
        class R:
            status = 200

            @staticmethod
            def read():
                return b'{"verdict": "VERIFIED", "exit": 0}'
        return R()

    def close(self):
        pass


@pytest.fixture()
def fake_conn(home, monkeypatch):
    home.mkdir(parents=True)
    (home / "serve.token").write_text("home-token-secret", encoding="utf-8")
    _FakeConn.made = []
    monkeypatch.setattr(C.http.client, "HTTPConnection", _FakeConn)
    return _FakeConn


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "[::1]", "127.0.0.9"])
def test_the_home_token_goes_to_loopback(fake_conn, host):
    assert Client(url=f"http://{host}:8787").verify(ledger="x")["exit"] == 0
    assert fake_conn.made[-1].headers["Authorization"] == "Bearer home-token-secret"


def test_the_home_token_never_goes_to_another_host(fake_conn):
    r = Client(url="http://example.invalid:8787", allow_insecure=True).verify(ledger="x")
    assert r["exit"] == 0
    assert "Authorization" not in fake_conn.made[-1].headers


def test_an_explicit_token_goes_where_the_caller_sends_it(fake_conn):
    Client(url="http://example.invalid:8787", token="mine",
           allow_insecure=True).verify(ledger="x")
    assert fake_conn.made[-1].headers["Authorization"] == "Bearer mine"


def test_plain_http_to_another_host_is_refused_unless_allowed(fake_conn):
    for tok in (None, "mine"):
        r = Client(url="http://example.invalid:8787", token=tok).verify(ledger="x")
        assert (r["exit"], r["reason_word"]) == (2, "insecure")
    assert fake_conn.made == []                      # nothing was sent at all
