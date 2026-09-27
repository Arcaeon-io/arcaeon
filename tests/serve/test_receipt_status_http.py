"""POST /v1/receipt/verify and GET /v1/status over HTTP (K011), token and
fence on."""
from __future__ import annotations

import http.client
import io
import json
import threading

import pytest

from arcaeon.record.receipt.core import build_receipt
from arcaeon.serve import auth
from arcaeon.serve import server as S


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arcaeon-home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
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
    c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=60)
    h = {"Authorization": f"Bearer {auth.load_or_create()}"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    out = json.loads(r.read())
    c.close()
    return r.status, out


def _receipt(root):
    rc = build_receipt("test", {"name": "one"}, [{"id": "c1", "result": "pass"}],
                       {"proves": ["a fixture"], "does_not_prove": ["anything else"]},
                       ledger_path=root / "receipts.jsonl", namespace="t",
                       witness=False, anchor=False)
    p = root / "r.json"
    p.write_text(json.dumps(rc, indent=1), encoding="utf-8")
    return p, rc


def test_a_good_receipt_verifies(srv, root):
    _receipt(root)
    status, body = call(srv, "POST", "/v1/receipt/verify", {"receipt": "r.json"})
    assert status == 200
    assert (body["ok"], body["verdict"], body["exit"]) == (True, "VERIFIED", 0)
    assert "reason" not in body


def test_one_body_field_changed_is_body_digest_mismatch(srv, root):
    p, rc = _receipt(root)
    rc["subject"]["name"] = "two"
    p.write_text(json.dumps(rc, indent=1), encoding="utf-8")
    status, body = call(srv, "POST", "/v1/receipt/verify", {"receipt": "r.json"})
    assert status == 200 and (body["verdict"], body["exit"]) == ("BROKEN", 1)
    assert body["reason"].startswith("body digest mismatch")


def test_receipt_by_content(srv, root):
    p, _ = _receipt(root)
    status, body = call(srv, "POST", "/v1/receipt/verify",
                        {"content": p.read_text(encoding="utf-8")})
    assert status == 200 and (body["verdict"], body["exit"]) == ("VERIFIED", 0)


def test_receipt_outside_the_root_is_400(srv):
    status, body = call(srv, "POST", "/v1/receipt/verify", {"receipt": "../r.json"})
    assert status == 400 and "outside the served root" in body["error"]


def test_status_without_a_key_says_not_checked(srv):
    status, body = call(srv, "GET", "/v1/status")
    assert status == 200 and body["exit"] == 0
    assert body["balance"] == "not checked, no key"
    assert body["balance_detail"] == {"checked": False, "reason": "not checked, no key"}
    assert "last_run" in body and "open_could_not_look" in body


def test_status_needs_the_token(srv):
    c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=30)
    c.request("GET", "/v1/status")
    r = c.getresponse()
    r.read()
    c.close()
    assert r.status == 401
