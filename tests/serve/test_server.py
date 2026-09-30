"""The HTTP server (K004): loopback only, section 0's status codes, serve.json
for exactly as long as the server runs. Every request goes to a server this
test starts on 127.0.0.1, port 0."""
from __future__ import annotations

import http.client
import io
import json
import os
import subprocess
import sys
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from arcaeon.serve import MAX_BODY
from arcaeon.serve import cli as serve_cli
from arcaeon.serve import h_core as H
from arcaeon.serve import routes as R
from arcaeon.serve import server as S

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def home(tmp_path, monkeypatch):
    h = tmp_path / "arcaeon-home"
    monkeypatch.setenv("ARCAEON_HOME", str(h))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    return h


@pytest.fixture()
def srv(home):
    server = S.make_server(port=0, token=None, root=None)   # auth, fence: own tests
    ready, out = threading.Event(), io.StringIO()
    t = threading.Thread(target=S.run, args=(server,), kwargs={"ready": ready, "out": out},
                         daemon=True)
    t.start()
    assert ready.wait(10)
    server.printed = out
    yield server
    server.shutdown()
    t.join(10)


def call(server, method, path, body=None, *, raw: bytes | None = None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=30)
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
    h = {"Content-Type": "application/json", **(headers or {})}
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    payload = r.read()
    c.close()
    ctype = r.getheader("Content-Type", "")
    return r.status, (json.loads(payload) if "json" in ctype else payload), r


def _swap(monkeypatch, path: str, handler: str) -> None:
    """Point one declared route at another handler for this test only."""
    new = replace(R.find("POST", path), handler=handler)
    monkeypatch.setattr(R, "ROUTES", tuple(new if r.path == path else r for r in R.ROUTES))


# --- the three the item names -------------------------------------------------

def test_health_is_200_ok_true(srv):
    status, body, _ = call(srv, "GET", "/health")
    assert status == 200 and body == {"ok": True}


def test_an_11_mb_body_is_413(srv):
    status, body, _ = call(srv, "POST", "/v1/verify", raw=b"x" * (11 * 1024 * 1024))
    assert status == 413
    assert body["limit"] == MAX_BODY


def test_host_other_than_loopback_exits_2(capsys):
    assert serve_cli.main(["--host", "0.0.0.0"]) == 2
    assert "exposing the server is a deploy decision" in capsys.readouterr().err


def test_host_refused_from_the_command_line():
    p = subprocess.run([sys.executable, "-m", "arcaeon", "serve", "--host", "0.0.0.0"],
                       capture_output=True, text=True, timeout=60,
                       env=dict(os.environ, PYTHONPATH=str(ROOT / "src"), ARCAEON_JOURNAL="0"))
    assert p.returncode == 2
    assert "exposing the server is a deploy decision" in p.stderr


@pytest.mark.parametrize("host", ["0.0.0.0", "localhost", "::1", "192.168.1.5", ""])
def test_make_server_refuses_every_non_loopback_host(host):
    with pytest.raises(S.HostRefused):
        S.make_server(host, 0)


# --- the other status codes -----------------------------------------------------

def test_unknown_path_is_404(srv):
    status, body, _ = call(srv, "GET", "/v1/nothing")
    assert status == 404 and "no route" in body["error"]


def test_known_path_wrong_method_is_405_with_allow(srv):
    status, body, r = call(srv, "GET", "/v1/verify")
    assert status == 405 and body["allow"] == ["POST"]
    assert r.getheader("Allow") == "POST"


def test_not_json_is_400(srv):
    status, body, _ = call(srv, "POST", "/v1/log", raw=b"{not json")
    assert status == 400 and body["exit"] == 2


def test_schema_refusal_is_400_naming_the_field(srv):
    status, body, _ = call(srv, "POST", "/v1/log", {"fields": {"a": 1}})
    assert status == 400 and "'ledger'" in body["error"]


def test_a_declared_route_not_built_yet_is_404_saying_so(srv, monkeypatch):
    _swap(monkeypatch, "/v1/verify", "arcaeon.serve.no_such_mod:verify")
    status, body, _ = call(srv, "POST", "/v1/verify", {"ledger": "x.jsonl"})
    assert status == 404 and "not built" in body["error"]


def test_a_bad_host_header_is_400(srv):
    status, body, _ = call(srv, "GET", "/health", headers={"Host": "evil.example:80"})
    assert status == 400


# --- a verdict never rides in the HTTP status ------------------------------------

def test_verified_broken_and_could_not_look_are_all_200(srv, tmp_path, monkeypatch):
    _swap(monkeypatch, "/v1/verify", "arcaeon.serve.h_core:verify")
    led = tmp_path / "l.jsonl"
    for i in range(2):
        H.log({"ledger": str(led), "fields": {"i": i}})
    status, body, _ = call(srv, "POST", "/v1/verify", {"ledger": str(led)})
    assert (status, body["verdict"], body["exit"]) == (200, "VERIFIED", 0)
    led.write_text(led.read_text(encoding="utf-8").replace('"i": 0', '"i": 7'),
                   encoding="utf-8")
    status, body, _ = call(srv, "POST", "/v1/verify", {"ledger": str(led)})
    assert (status, body["verdict"], body["exit"]) == (200, "BROKEN", 1)
    status, body, _ = call(srv, "POST", "/v1/verify", {"ledger": str(tmp_path / "gone")})
    assert (status, body["exit"]) == (200, 3)


def test_a_handler_that_raises_is_could_not_look_in_a_200(srv, monkeypatch):
    def _boom(body):
        raise RuntimeError("a secret path")
    monkeypatch.setattr(S, "_boom_for_test", _boom, raising=False)
    _swap(monkeypatch, "/v1/verify", "arcaeon.serve.server:_boom_for_test")
    status, body, _ = call(srv, "POST", "/v1/verify", {"ledger": "x"})
    assert status == 200 and body["exit"] == 3
    assert "RuntimeError" in body["error"] and "secret" not in body["error"]


# --- the URL, the log line, serve.json ----------------------------------------------

def test_prints_the_url_on_start(srv):
    port = srv.server_address[1]
    assert f"listening on http://127.0.0.1:{port}" in srv.printed.getvalue()


def test_the_log_line_drops_the_query_and_never_prints_headers(srv, capsys):
    call(srv, "GET", "/health?t=s3cr3t", headers={"Authorization": "Bearer tok3n"})
    err = capsys.readouterr().err
    assert "GET /health 200" in err
    assert "s3cr3t" not in err and "tok3n" not in err


def test_serve_json_lives_exactly_as_long_as_the_server(home):
    server = S.make_server(port=0)
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(server,),
                         kwargs={"ready": ready, "out": io.StringIO()}, daemon=True)
    t.start()
    assert ready.wait(10)
    info = json.loads((home / "serve.json").read_text(encoding="utf-8"))
    assert info["pid"] == os.getpid() and info["port"] == server.server_address[1]
    server.shutdown()
    t.join(10)
    assert not (home / "serve.json").exists()


def test_serve_json_of_another_process_is_left_alone(home):
    home.mkdir(parents=True)
    other = {"pid": os.getpid() + 1, "port": 1}
    (home / "serve.json").write_text(json.dumps(other), encoding="utf-8")
    S.remove_serve_json()
    assert json.loads((home / "serve.json").read_text(encoding="utf-8")) == other


def test_a_taken_port_is_exit_3(home, capsys):
    busy = S.make_server(port=0)
    try:
        assert serve_cli.main(["--port", str(busy.server_address[1])]) == 3
        assert "cannot listen" in capsys.readouterr().err
    finally:
        busy.server_close()


def test_a_bad_port_is_usage_2():
    assert serve_cli.main(["--port", "70000"]) == 2


def test_the_real_command_serves_health_on_a_random_port(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), ARCAEON_JOURNAL="0",
               ARCAEON_HOME=str(tmp_path), PYTHONUNBUFFERED="1")
    p = subprocess.Popen([sys.executable, "-m", "arcaeon", "serve", "--port", "0"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    assert p.stdout is not None, "arcaeon serve spawned without a stdout pipe"
    try:
        line = p.stdout.readline()
        assert "listening on http://127.0.0.1:" in line, line
        port = int(line.split("127.0.0.1:")[1].split()[0])
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        c.request("GET", "/health")
        r = c.getresponse()
        assert r.status == 200 and json.loads(r.read()) == {"ok": True}
        c.close()
        assert json.loads((tmp_path / "serve.json").read_text(encoding="utf-8"))["port"] == port
    finally:
        p.kill()
        p.communicate(timeout=30)
