"""Every HTTP call lands in the activity journal as serve:<route> (K015)."""
from __future__ import annotations

import http.client
import io
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from arcaeon import journal
from arcaeon.serve import auth
from arcaeon.serve import server as S

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def home(tmp_path, monkeypatch):
    h = tmp_path / "arcaeon-home"
    monkeypatch.setenv("ARCAEON_HOME", str(h))
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)
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


def call(server, method, path, body=None):
    c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=30)
    h = {"Content-Type": "application/json",
         "Authorization": f"Bearer {auth.load_or_create()}"}
    c.request(method, path, body=None if body is None else json.dumps(body).encode(),
              headers=h)
    r = c.getresponse()
    out = json.loads(r.read())
    c.close()
    return r.status, out


def _two_rows(server):
    for n in (1, 2):
        assert call(server, "POST", "/v1/log", {"ledger": "l.jsonl", "fields": {"n": n}})[0] == 200


def test_two_verifies_are_journaled_and_status_lists_them(srv, root, home):
    _two_rows(srv)
    for _ in range(2):
        status, body = call(srv, "POST", "/v1/verify", {"ledger": "l.jsonl"})
        assert (status, body["verdict"], body["exit"]) == (200, "VERIFIED", 0)
    rows = [r for r in journal.read() if r["verb"] == "serve:/v1/verify"]
    assert len(rows) == 2
    assert all(r["word"] == "VERIFIED" and r["exit"] == 0 for r in rows)
    want = journal.target_id(str((root / "l.jsonl").resolve()))
    assert all(r["target"] == want for r in rows)
    assert sum(r["verb"] == "serve:/v1/log" for r in journal.read()) == 2
    env = {**os.environ, "ARCAEON_HOME": str(home), "PYTHONPATH": str(ROOT / "src")}
    p = subprocess.run([sys.executable, "-m", "arcaeon", "status", "--json"], env=env,
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert "serve:/v1/verify" in json.loads(p.stdout)["last_run"]


def test_the_journal_carries_no_path_and_no_token(srv, root, home):
    _two_rows(srv)
    call(srv, "POST", "/v1/verify", {"ledger": "l.jsonl"})
    text = (home / journal.FILENAME).read_text(encoding="utf-8")
    assert "l.jsonl" not in text and "served" not in text
    assert auth.load_or_create() not in text


def test_open_routes_and_refusals_are_not_journaled(srv, root, home):
    assert call(srv, "GET", "/health")[0] == 200
    c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=30)
    c.request("POST", "/v1/verify", body=b"{}", headers={"Content-Type": "application/json"})
    assert c.getresponse().status == 401
    c.close()
    assert journal.read() == []


def test_content_in_and_could_not_look_are_journaled_with_their_word(srv, root):
    status, body = call(srv, "POST", "/v1/verify", {"ledger": "missing.jsonl"})
    assert status == 200 and body["exit"] == 3
    row = [r for r in journal.read() if r["verb"] == "serve:/v1/verify"][-1]
    assert (row["word"], row["exit"]) == (body["verdict"], 3)
    assert body.get("reason_word") and row["reason_word"] == body["reason_word"]  # K015b


def test_a_verdict_with_no_reason_word_adds_no_key(srv, root):
    _two_rows(srv)
    call(srv, "POST", "/v1/verify", {"ledger": "l.jsonl"})
    row = [r for r in journal.read() if r["verb"] == "serve:/v1/verify"][-1]
    assert "reason_word" not in row


def test_journal_off_writes_nothing(srv, root, home, monkeypatch):
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    _two_rows(srv)
    assert call(srv, "POST", "/v1/verify", {"ledger": "l.jsonl"})[1]["exit"] == 0
    assert not (home / journal.FILENAME).exists()


def test_a_journal_failure_never_changes_a_response(srv, root, monkeypatch):
    _two_rows(srv)
    good = call(srv, "POST", "/v1/verify", {"ledger": "l.jsonl"})

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(journal, "append", boom)
    assert call(srv, "POST", "/v1/verify", {"ledger": "l.jsonl"}) == good
    monkeypatch.setattr(journal, "word_for", boom)
    assert call(srv, "POST", "/v1/verify", {"ledger": "l.jsonl"}) == good
