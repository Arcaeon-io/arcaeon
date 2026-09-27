"""Token auth (K005): serve.token is created on first run and reused; every
route but /health and /openapi.json needs it; the token never reaches the
request log, the journal or an error body."""
from __future__ import annotations

import http.client
import io
import json
import os
import stat
import sys
import threading
from dataclasses import replace

import pytest

from arcaeon.serve import auth
from arcaeon.serve import cli as serve_cli
from arcaeon.serve import routes as R
from arcaeon.serve import server as S


@pytest.fixture(autouse=True)
def status_built(monkeypatch):
    """/v1/status's own handler is K011's; point it at h_core.status here so a
    right token has a built route to reach."""
    new = replace(R.find("GET", "/v1/status"), handler="arcaeon.serve.h_core:status")
    monkeypatch.setattr(R, "ROUTES", tuple(new if r.path == "/v1/status" else r
                                           for r in R.ROUTES))


@pytest.fixture()
def home(tmp_path, monkeypatch):
    h = tmp_path / "arcaeon-home"
    monkeypatch.setenv("ARCAEON_HOME", str(h))
    monkeypatch.setenv("ARCAEON_JOURNAL", "1")     # on, so the grep below means something
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    return h


@pytest.fixture()
def srv(home):
    server = S.make_server(port=0)                 # the default: AUTO token
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(server,),
                         kwargs={"ready": ready, "out": io.StringIO()}, daemon=True)
    t.start()
    assert ready.wait(10)
    yield server
    server.shutdown()
    t.join(10)


def call(server, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=30)
    data = None if body is None else json.dumps(body).encode()
    c.request(method, path, body=data, headers={"Content-Type": "application/json",
                                                **(headers or {})})
    r = c.getresponse()
    payload = r.read()
    c.close()
    return r.status, json.loads(payload), r


# --- the token file ---------------------------------------------------------------

def test_first_run_creates_the_token_and_later_runs_reuse_it(home):
    assert not (home / "serve.token").exists()
    t1 = auth.load_or_create()
    assert (home / "serve.token").read_text(encoding="utf-8").strip() == t1
    assert len(t1) >= 40
    assert auth.load_or_create() == t1


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_the_token_file_is_owner_only(home):
    auth.load_or_create()
    mode = stat.S_IMODE(os.stat(home / "serve.token").st_mode)
    assert mode & 0o077 == 0


def test_an_empty_token_file_is_replaced(home):
    home.mkdir(parents=True)
    (home / "serve.token").write_text("", encoding="utf-8")
    t = auth.load_or_create()
    assert t and (home / "serve.token").read_text(encoding="utf-8").strip() == t


def test_print_token_prints_it_and_exits_0(home, capsys):
    assert serve_cli.main(["--print-token"]) == 0
    assert capsys.readouterr().out.strip() == auth.load_or_create()


# --- the three answers ----------------------------------------------------------------

def test_no_token_is_401(srv):
    status, body, r = call(srv, "GET", "/v1/status")
    assert status == 401 and "no token" in body["error"]
    assert r.getheader("WWW-Authenticate", "").startswith("Bearer")


def test_wrong_token_is_401(srv):
    status, body, _ = call(srv, "GET", "/v1/status", headers={"Authorization": "Bearer nope"})
    assert status == 401 and body == {"error": "wrong token"}


def test_right_token_is_200_bearer_and_header(srv):
    tok = auth.load_or_create()
    status, body, _ = call(srv, "GET", "/v1/status", headers={"Authorization": f"Bearer {tok}"})
    assert status == 200 and "exit" in body
    status, _, _ = call(srv, "GET", "/v1/status", headers={"X-Arcaeon-Token": tok})
    assert status == 200


def test_a_post_without_a_token_is_401_before_the_body_is_read(srv):
    status, _, _ = call(srv, "POST", "/v1/log", {"ledger": "l.jsonl", "fields": {"a": 1}})
    assert status == 401


def test_health_and_openapi_stay_open(srv):
    status, body, _ = call(srv, "GET", "/health")
    assert status == 200 and body == {"ok": True}
    status, _, _ = call(srv, "GET", "/openapi.json")
    assert status != 401          # open; 200 once K013 builds the document, 404 until then


def test_a_wrong_token_is_not_echoed(srv):
    status, body, _ = call(srv, "GET", "/v1/status",
                           headers={"X-Arcaeon-Token": "guess-Zq9w-guess"})
    assert status == 401 and "guess" not in json.dumps(body)


def test_token_is_nowhere_in_the_log_or_the_journal(srv, home, capsys):
    tok = auth.load_or_create()
    h = {"Authorization": f"Bearer {tok}"}
    call(srv, "GET", f"/v1/status?t={tok}", headers=h)
    call(srv, "GET", "/v1/status", headers={"Authorization": "Bearer " + tok[::-1]})
    call(srv, "GET", "/health", headers=h)
    captured = capsys.readouterr()
    log = captured.out + captured.err
    assert "/v1/status 200" in log and "/v1/status 401" in log
    assert tok not in log
    for p in home.rglob("*"):
        if p.is_file() and p.name != "serve.token":
            assert tok not in p.read_text(encoding="utf-8", errors="replace"), p.name


def test_a_server_with_token_none_serves_without_auth(home):
    server = S.make_server(port=0, token=None)
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(server,),
                         kwargs={"ready": ready, "out": io.StringIO()}, daemon=True)
    t.start()
    assert ready.wait(10)
    try:
        status, _, _ = call(server, "GET", "/v1/status")
        assert status == 200
    finally:
        server.shutdown()
        t.join(10)
