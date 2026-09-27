"""POST /v1/evidence-pack, /v1/evidence-pack/verify and /v1/export/aat over
HTTP (K069, the handler half), token and fence on. Each answer equals the
CLI's --json plus exit. No network: remote is checked by the argv it builds
and by a patched arcaeon.remote.check_head."""
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

import arcaeon.remote as remote
from arcaeon.record.ledger import Ledger
from arcaeon.serve import auth
from arcaeon.serve import h_core
from arcaeon.serve import h_evidence as HE
from arcaeon.serve import server as S

SRC = str(Path(__file__).resolve().parents[2] / "src")
ROWS = [
    {"ts": "2026-09-01T10:00:00Z", "system_id": "sys-a", "agent": "agent-a",
     "event": "system_start"},
    {"ts": "2026-09-01T11:00:00Z", "system_id": "sys-b", "agent": "agent-b",
     "event": "tool_call", "inputs": {"q": "lookup"}},
    {"ts": "2026-09-02T09:30:00Z", "system_id": "sys-a", "agent": "agent-a",
     "event": "decision", "decision": "escalate", "outputs": {"to": "desk"}},
]


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arcaeon-home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    r = tmp_path / "served"
    r.mkdir()
    lg = Ledger(r / "ledger.jsonl")
    for row in ROWS:
        lg.append(row)
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
    return p.returncode, json.loads(p.stdout)


def _drop_paths(d, root):
    """The pack folder differs between the HTTP build and the CLI build."""
    return json.loads(json.dumps(d).replace(json.dumps(str(root))[1:-1], "ROOT"))


def test_build_then_verify_matches_the_cli(srv, root):
    status, built = post(srv, "/v1/evidence-pack", {"ledger": "ledger.jsonl", "out": "pack"})
    assert status == 200 and built["exit"] == 0, built
    assert (root / "pack" / "manifest.json").is_file()
    status, got = post(srv, "/v1/evidence-pack/verify", {"pack": "pack"})
    rc, want = cli("evidence-pack", "verify", str(root / "pack"), "--json")
    assert status == 200 and got == {**want, "exit": rc}
    assert got["verdict"] and got["exit"] == rc


def test_build_equals_the_cli_build(srv, root):
    _, got = post(srv, "/v1/evidence-pack", {"ledger": "ledger.jsonl", "out": "p1",
                                             "agent": "agent-a"})
    rc, want = cli("evidence-pack", "--ledger", str(root / "ledger.jsonl"), "--out",
                   str(root / "p2"), "--agent", "agent-a", "--json")
    assert got["exit"] == rc
    a = _drop_paths(got, root)
    b = _drop_paths({**want, "exit": rc}, root)
    assert json.dumps(a).replace("p1", "pX") == json.dumps(b).replace("p2", "pX")


def test_verify_a_tampered_pack_is_not_green(srv, root):
    post(srv, "/v1/evidence-pack", {"ledger": "ledger.jsonl", "out": "pack"})
    m = root / "pack" / "records.jsonl"
    m.write_bytes(m.read_bytes().replace(b"escalate", b"ignore!!"))
    status, got = post(srv, "/v1/evidence-pack/verify", {"pack": "pack"})
    assert status == 200 and got["exit"] != 0 and got["verdict"] != "VERIFIED"


def test_export_aat_matches_the_cli(srv, root):
    status, got = post(srv, "/v1/export/aat", {"ledger": "ledger.jsonl", "out": "a1.jsonl"})
    rc, want = cli("export", str(root / "ledger.jsonl"), "--format", "agent-audit-trail",
                   "--out", str(root / "a2.jsonl"), "--json")
    assert status == 200 and got["exit"] == rc == 0, got
    assert (root / "a1.jsonl").read_bytes() == (root / "a2.jsonl").read_bytes()
    assert set(got) == set(want) | {"exit"}


def test_out_outside_the_root_is_400(srv, root, tmp_path):
    for path, body in (("/v1/evidence-pack", {"ledger": "ledger.jsonl", "out": "../p"}),
                       ("/v1/export/aat", {"ledger": "ledger.jsonl", "out": "../a.jsonl"}),
                       ("/v1/evidence-pack/verify", {"pack": "../../p"})):
        status, got = post(srv, path, body)
        assert status == 400 and "outside the served root" in got["error"], path
    assert not (tmp_path / "p").exists() and not (tmp_path / "a.jsonl").exists()


def test_verify_argv_carries_witness_namespace_and_remote(monkeypatch):
    seen = []
    monkeypatch.setattr(h_core, "run_verb",
                        lambda verb, argv: seen.append((verb, argv)) or (0, "{}", ""))
    HE.verify({"pack": "P", "witness": "W", "namespace": "N", "remote": True})
    HE.build({"ledger": "L", "out": "O", "since": "a", "until": "b", "formats": ["aat"]})
    assert seen[0] == ("evidence-pack", ["verify", "P", "--witness", "W", "--namespace", "N",
                                         "--remote", "--json"])
    assert seen[1] == ("evidence-pack", ["--ledger", "L", "--out", "O", "--from", "a",
                                         "--to", "b", "--format", "aat", "--json"])


def test_remote_true_reaches_only_the_patched_witness(srv, root, monkeypatch):
    monkeypatch.setattr(remote, "check_head",
                        lambda *a, **k: {"status": 0, "error": "patched: no network"})
    post(srv, "/v1/evidence-pack", {"ledger": "ledger.jsonl", "out": "pack"})
    status, got = post(srv, "/v1/evidence-pack/verify", {"pack": "pack", "remote": True})
    assert status == 200 and isinstance(got["exit"], int)


def test_bad_usage_is_400(srv):
    s1, _ = post(srv, "/v1/evidence-pack/verify", {"pack": "pack", "remote": "yes"})
    s2, _ = post(srv, "/v1/evidence-pack", {"ledger": "ledger.jsonl", "out": "p",
                                            "formats": ["nope"]})
    assert (s1, s2) == (400, 400)
