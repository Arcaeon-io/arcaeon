"""POST /v1/audit/verify and /v1/audit/export over HTTP (K010), token and
fence on: export writes the bundle inside the served root, and audit verify
on the bundle gives the verdict the CLI gives."""
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

from arcaeon.serve import auth
from arcaeon.serve import server as S

SRC = str(Path(__file__).resolve().parents[2] / "src")


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


def post(server, path, body):
    c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=60)
    c.request("POST", path, body=json.dumps(body).encode(),
              headers={"Content-Type": "application/json",
                       "Authorization": f"Bearer {auth.load_or_create()}"})
    r = c.getresponse()
    out = json.loads(r.read())
    c.close()
    return r.status, out


def cli(*args):
    env = {**os.environ, "PYTHONPATH": SRC}
    p = subprocess.run([sys.executable, "-m", "arcaeon", *args], capture_output=True,
                       text=True, encoding="utf-8", timeout=120, env=env)
    return p.returncode, p.stdout


def _ledger(srv):
    for n in (1, 2):
        assert post(srv, "/v1/log", {"ledger": "l.jsonl", "fields": {"n": n}})[1]["exit"] == 0


def test_export_then_verify_the_bundle_matches_the_cli(srv, root):
    _ledger(srv)
    status, body = post(srv, "/v1/audit/export", {"ledger": "l.jsonl", "out": "bundle"})
    assert status == 200 and body["exit"] == 0, body
    assert body["verdict"] == "VERIFIED"
    bundle = root / "bundle"
    assert (bundle / "records.jsonl").is_file() and (bundle / "integrity.json").is_file()
    assert Path(body["out"]) == bundle.resolve()

    status, got = post(srv, "/v1/audit/verify", {"path": "bundle"})
    rc, out = cli("audit", "verify", str(bundle / "records.jsonl"))
    assert status == 200
    assert (got["exit"], got["output"]) == (rc, out.rstrip("\n"))
    assert got["verdict"] == "VERIFIED" == out.split("\u2014")[0].strip()


def test_verify_a_tampered_bundle_is_fail_exit_1_like_the_cli(srv, root):
    _ledger(srv)
    post(srv, "/v1/audit/export", {"ledger": "l.jsonl", "out": "bundle"})
    rec = root / "bundle" / "records.jsonl"
    data = bytearray(rec.read_bytes())
    data[data.index(b'"n": 1') + 5] = ord("7")
    rec.write_bytes(bytes(data))
    status, got = post(srv, "/v1/audit/verify", {"path": "bundle"})
    rc, out = cli("audit", "verify", str(rec))
    assert status == 200 and (got["verdict"], got["exit"]) == ("FAIL", 1) and rc == 1
    assert got["output"] == out.rstrip("\n")


def test_export_of_a_tampered_ledger_is_exit_1_like_the_cli(srv, root):
    _ledger(srv)
    p = root / "l.jsonl"
    data = bytearray(p.read_bytes())
    data[data.index(b'"n": 1') + 5] = ord("7")
    p.write_bytes(bytes(data))
    status, got = post(srv, "/v1/audit/export", {"ledger": "l.jsonl", "out": "b1"})
    rc, out = cli("audit", "export", str(p), str(root / "b2"))
    assert status == 200 and got["exit"] == rc == 1
    assert got["verdict"] == out.split("Verdict:")[1].split()[0]


def test_verify_by_content(srv, root):
    _ledger(srv)
    text = (root / "l.jsonl").read_text(encoding="utf-8")
    status, got = post(srv, "/v1/audit/verify", {"content": text})
    assert status == 200 and (got["verdict"], got["exit"]) == ("VERIFIED", 0)


def test_export_out_outside_the_root_is_400_and_writes_nothing(srv, root, tmp_path):
    _ledger(srv)
    status, body = post(srv, "/v1/audit/export", {"ledger": "l.jsonl", "out": "../escaped"})
    assert status == 400 and "outside the served root" in body["error"]
    assert not (tmp_path / "escaped").exists()


def test_a_directory_that_is_not_a_bundle_is_400(srv, root):
    (root / "empty").mkdir()
    status, body = post(srv, "/v1/audit/verify", {"path": "empty"})
    assert status == 400 and body["exit"] == 2
