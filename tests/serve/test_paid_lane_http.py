"""/v1/pin (free, local) and the paid lane, /v1/pin remote and /v1/seal (K012).

The remote is monkeypatched to raise if called: no key refuses; a key
without --allow-paid refuses and the remote is never called; a key plus
--allow-paid calls the patched remote once. Nothing leaves the machine."""
from __future__ import annotations

import http.client
import io
import json
import threading

import pytest

import arcaeon.remote as remote
import arcaeon.remote.sealed_scan as sealed_scan
import arcaeon.remote.witness as witness
from arcaeon.remote.offers import upgrade_message
from arcaeon.serve import auth
from arcaeon.serve import h_pin
from arcaeon.serve import server as S

KEY = "test-key-not-real"


class Remote:
    def __init__(self):
        self.calls = []

    def boom(self, *a, **k):
        raise AssertionError("the remote was called")

    def pin(self, ns, rows, chain, key):
        self.calls.append(("pin", ns, rows, chain))
        return {"ok": True, "status": 201, "namespace": ns, "rows": rows, "chain": chain}

    def seal(self, record, **k):
        self.calls.append(("seal", k.get("namespace")))
        return {"sealed": True, "namespace": k.get("namespace") or "t", "pin": {"ok": True}}


@pytest.fixture()
def fake(monkeypatch):
    r = Remote()
    for mod, name in ((remote, "pin"), (remote, "renew"), (witness, "pin"),
                      (witness, "renew"), (witness, "_write"), (sealed_scan, "seal"),
                      (remote, "_request")):
        monkeypatch.setattr(mod, name, r.boom)
    return r


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arcaeon-home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    r = tmp_path / "served"
    r.mkdir()
    monkeypatch.chdir(tmp_path)
    return r


def _start(root, allow_paid):
    server = S.make_server(port=0, root=root, allow_paid=allow_paid)
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(server,),
                         kwargs={"ready": ready, "out": io.StringIO()}, daemon=True)
    t.start()
    assert ready.wait(10)
    return server, t


@pytest.fixture()
def srv(root):
    server, t = _start(root, False)
    yield server
    server.shutdown()
    t.join(10)


@pytest.fixture()
def paid_srv(root):
    server, t = _start(root, True)
    yield server
    server.shutdown()
    t.join(10)


def post(server, path, body):
    c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=60)
    c.request("POST", path, body=json.dumps(body).encode(),
              headers={"Content-Type": "application/json",
                       "Authorization": f"Bearer {auth.load_or_create()}"})
    r = c.getresponse()
    out = json.loads(r.read())
    c.close()
    return r.status, out


def _ledger(server):
    for n in (1, 2):
        assert post(server, "/v1/log", {"ledger": "l.jsonl", "fields": {"n": n}})[1]["exit"] == 0


def test_local_pin_is_free_and_lands_under_the_root(srv, root, fake):
    _ledger(srv)
    status, body = post(srv, "/v1/pin", {"ledger": "l.jsonl", "witness": "w.jsonl", "ns": "t"})
    assert status == 200 and (body["ok"], body["exit"]) == (True, 0), body
    assert body["namespace"] == "t" and body["pin"]["rows"] == 2
    assert (root / "w.jsonl").is_file()


def test_local_pin_witness_outside_the_root_is_400(srv, root, tmp_path, fake):
    _ledger(srv)
    status, body = post(srv, "/v1/pin", {"ledger": "l.jsonl", "witness": "../w.jsonl",
                                         "ns": "t"})
    assert status == 400 and "outside the served root" in body["error"]
    assert not (tmp_path / "w.jsonl").exists()


def test_local_pin_without_ns_is_400(srv, root, fake):
    _ledger(srv)
    status, body = post(srv, "/v1/pin", {"ledger": "l.jsonl", "witness": "w.jsonl"})
    assert status == 400 and body["exit"] == 2


@pytest.mark.parametrize("path,body,tool", [
    ("/v1/pin", {"ledger": "l.jsonl", "remote": True, "ns": "t"}, "witness_pin"),
    ("/v1/seal", {"path": "srv"}, "seal"),
])
def test_no_key_refuses_with_the_mcp_sentence(paid_srv, root, fake, path, body, tool):
    _ledger(paid_srv)
    status, got = post(paid_srv, path, body)
    assert status == 200 and (got["verdict"], got["exit"], got["refused"]) == (
        "COULD NOT LOOK", 3, True)
    assert got["reason"] == upgrade_message(tool)
    assert "no ARCAEON_KEY is set" in got["reason"] and fake.calls == []


@pytest.mark.parametrize("path,body", [
    ("/v1/pin", {"ledger": "l.jsonl", "remote": True, "ns": "t"}),
    ("/v1/seal", {"path": "srv"}),
])
def test_key_without_allow_paid_refuses_and_never_calls(srv, root, fake, monkeypatch,
                                                        path, body):
    _ledger(srv)
    monkeypatch.setenv("ARCAEON_KEY", KEY)
    status, got = post(srv, path, body)
    assert status == 200 and (got["exit"], got["refused"]) == (3, True)
    assert got["reason"] == h_pin.NOT_ALLOWED and fake.calls == []


def test_key_plus_allow_paid_pins_remote_once(paid_srv, root, fake, monkeypatch):
    _ledger(paid_srv)
    monkeypatch.setenv("ARCAEON_KEY", KEY)
    monkeypatch.setattr(remote, "pin", fake.pin)
    status, got = post(paid_srv, "/v1/pin", {"ledger": "l.jsonl", "remote": True, "ns": "t"})
    assert status == 200 and (got["ok"], got["exit"]) == (True, 0), got
    assert [c[:3] for c in fake.calls] == [("pin", "t", 2)]


def test_key_plus_allow_paid_seals_once(paid_srv, root, fake, monkeypatch):
    d = root / "srv"
    d.mkdir()
    (d / "server.py").write_text("def tool():\n    return 1\n", encoding="utf-8")
    monkeypatch.setenv("ARCAEON_KEY", KEY)
    monkeypatch.setattr(sealed_scan, "seal", fake.seal)
    status, got = post(paid_srv, "/v1/seal", {"path": "srv", "ns": "t"})
    assert status == 200 and "refused" not in got, got
    assert fake.calls == [("seal", "t")]


def test_the_body_cannot_grant_allow_paid(srv, root, fake, monkeypatch):
    _ledger(srv)
    monkeypatch.setenv("ARCAEON_KEY", KEY)
    status, got = post(srv, "/v1/pin", {"ledger": "l.jsonl", "remote": True, "ns": "t",
                                        "allow_paid": True, "_allow_paid": True})
    assert got["reason"] == h_pin.NOT_ALLOWED and fake.calls == []


def test_outside_a_request_the_paid_lane_is_refused(root, monkeypatch, fake):
    monkeypatch.setenv("ARCAEON_KEY", KEY)
    assert h_pin.paid_refusal("seal")["reason"] == h_pin.NOT_ALLOWED
