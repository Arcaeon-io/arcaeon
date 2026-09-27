"""POST /v1/log and /v1/verify over HTTP (K008), with the token (K005) and the
path fence (K006) on, the way `arcaeon serve` runs them."""
from __future__ import annotations

import http.client
import io
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from arcaeon.serve import auth
from arcaeon.serve import server as S

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arcaeon-home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    r = tmp_path / "served"
    r.mkdir()
    monkeypatch.chdir(tmp_path)          # the root is not the working directory
    return r


@pytest.fixture()
def srv(root):
    server = S.make_server(port=0, root=root)       # AUTO token, fenced to root
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(server,),
                         kwargs={"ready": ready, "out": io.StringIO()}, daemon=True)
    t.start()
    assert ready.wait(10)
    yield server
    server.shutdown()
    t.join(10)


def post(server, path, body, token=True):
    c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=30)
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {auth.load_or_create()}"
    c.request("POST", path, body=json.dumps(body).encode(), headers=h)
    r = c.getresponse()
    out = json.loads(r.read())
    c.close()
    return r.status, out


def test_two_logs_then_verify_is_verified_rows_2_exit_0(srv, root):
    s1, b1 = post(srv, "/v1/log", {"ledger": "l.jsonl", "fields": {"n": 1}})
    s2, b2 = post(srv, "/v1/log", {"ledger": "l.jsonl", "row": {"n": 2}})
    assert (s1, b1["exit"], s2, b2["exit"]) == (200, 0, 200, 0)
    assert b1["chain"] and b2["chain"] and b1["chain"] != b2["chain"]
    rows = (root / "l.jsonl").read_text(encoding="utf-8").splitlines()
    assert json.loads(rows[-1])["chain"] == b2["chain"]
    status, body = post(srv, "/v1/verify", {"ledger": "l.jsonl"})
    assert status == 200
    assert (body["verdict"], body["rows"], body["exit"]) == ("VERIFIED", 2, 0)


def test_edit_one_byte_and_verify_is_broken_exit_1(srv, root):
    for n in (1, 2):
        assert post(srv, "/v1/log", {"ledger": "l.jsonl", "fields": {"n": n}})[1]["exit"] == 0
    p = root / "l.jsonl"
    data = bytearray(p.read_bytes())
    at = data.index(b'"n": 1') + 5
    data[at] = ord("7")
    p.write_bytes(bytes(data))
    status, body = post(srv, "/v1/verify", {"ledger": "l.jsonl"})
    assert status == 200 and (body["verdict"], body["exit"]) == ("BROKEN", 1)


def test_fields_merge_over_the_row(srv, root):
    post(srv, "/v1/log", {"ledger": "m.jsonl", "row": {"a": 1, "b": 1}, "fields": {"b": 2}})
    row = json.loads((root / "m.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert (row["a"], row["b"]) == (1, 2)


def test_log_with_neither_row_nor_fields_is_400_usage(srv):
    status, body = post(srv, "/v1/log", {"ledger": "l.jsonl"})
    assert status == 400 and body["exit"] == 2


def test_log_outside_the_root_is_400_and_writes_nothing(srv, root, tmp_path):
    status, body = post(srv, "/v1/log", {"ledger": "../escape.jsonl", "fields": {"a": 1}})
    assert status == 400 and "outside the served root" in body["error"]
    assert not (tmp_path / "escape.jsonl").exists()


def test_log_without_the_token_is_401_and_writes_nothing(srv, root):
    status, _ = post(srv, "/v1/log", {"ledger": "l.jsonl", "fields": {"a": 1}}, token=False)
    assert status == 401
    assert not (root / "l.jsonl").exists()


def test_verify_over_http_equals_the_cli(srv, root):
    for n in (1, 2):
        post(srv, "/v1/log", {"ledger": "l.jsonl", "fields": {"n": n}})
    _, body = post(srv, "/v1/verify", {"ledger": "l.jsonl"})
    p = subprocess.run([sys.executable, "-m", "arcaeon", "verify", str(root / "l.jsonl")],
                       capture_output=True, text=True, timeout=120,
                       env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")})
    assert body == {**json.loads(p.stdout), "exit": p.returncode}


def test_verify_by_content_over_http(srv, root):
    for n in (1, 2):
        post(srv, "/v1/log", {"ledger": "l.jsonl", "fields": {"n": n}})
    text = (root / "l.jsonl").read_text(encoding="utf-8")
    _, body = post(srv, "/v1/verify", {"content": text})
    assert (body["verdict"], body["rows"], body["exit"]) == ("VERIFIED", 2, 0)
