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


# --- K066 to K068 fields over HTTP: mandate, receipt (--readings), zip, built_at ---

STAMP = "2026-09-27T12:00:00Z"


def test_new_fields_reach_the_verb_argv(monkeypatch):
    seen = []
    monkeypatch.setattr(h_core, "run_verb",
                        lambda verb, argv: seen.append((verb, argv)) or (0, "{}", ""))
    HE.build({"ledger": "L", "out": "O", "mandate": "M", "receipt": "R", "zip": True,
              "built_at": STAMP})
    assert seen[0] == ("evidence-pack", ["--ledger", "L", "--out", "O", "--mandate", "M",
                                         "--readings", "R", "--built-at", STAMP, "--zip",
                                         "--json"])


def test_zip_built_twice_over_http_is_byte_identical_and_verifies(srv, root):
    import hashlib
    for out in ("z1", "z2"):
        status, got = post(srv, "/v1/evidence-pack", {"ledger": "ledger.jsonl", "out": out,
                                                     "zip": True, "built_at": STAMP})
        assert status == 200 and got["exit"] == 0, got
    a, b = (hashlib.sha256((root / f"{n}.zip").read_bytes()).hexdigest()
            for n in ("z1", "z2"))
    assert a == b == got["zip_sha256"]
    status, v = post(srv, "/v1/evidence-pack/verify", {"pack": "z1.zip"})
    rc, want = cli("evidence-pack", "verify", str(root / "z1.zip"), "--json")
    assert status == 200 and v["exit"] == rc == 0 and v == {**want, "exit": rc}


def test_mandate_and_receipt_over_http(srv, root):
    from arcaeon.record.receipt.core import build_receipt, save_receipt
    (root / "mandate.json").write_text('{"allowed_acts": ["echo"]}', encoding="utf-8")
    rc = build_receipt("second_read_compare", {"a": {"rows": 1}, "b": {"rows": 1}},
                       [{"name": "compare", "read": 1, "disagreed": 0}],
                       {"proves": ["the counts"], "does_not_prove": ["truth of a claim"]},
                       ledger_path=root / "receipts.jsonl", namespace="sr",
                       witness=False, anchor=False, issued_at=STAMP)
    save_receipt(rc, root / "compare.receipt.json")
    status, got = post(srv, "/v1/evidence-pack", {
        "ledger": "ledger.jsonl", "out": "pm", "mandate": "mandate.json",
        "receipt": "compare.receipt.json"})
    # this ledger holds no mandate_loaded row, so the mandate cannot be tied: exit 3
    assert status == 200 and got["exit"] == 3 and got["verdict"] == "COULD NOT LOOK", got
    assert got["readings"]["ok"] is True and got["mandate"]["counts"]["outside"] == 0
    assert (root / "pm" / "mandate_rows.json").is_file()
    assert (root / "pm" / "readings_receipt.json").is_file()
    status, v = post(srv, "/v1/evidence-pack/verify", {"pack": "pm"})
    assert status == 200 and v["exit"] == 3


def test_new_path_fields_are_fenced_and_unfenced_ones_refused(srv, root, tmp_path):
    (tmp_path / "outside.json").write_text("{}", encoding="utf-8")
    for body in ({"mandate": "../outside.json"}, {"receipt": "../outside.json"},
                 {"deal": "d-1", "buyer": "../b.jsonl"},
                 {"deal": "d-1", "seller": "../b.jsonl"},
                 {"receipt": "r.json", "readings_ledger": "../outside.json"}):
        status, got = post(srv, "/v1/evidence-pack",
                           {"ledger": "ledger.jsonl", "out": "pf", **body})
        assert status == 400 and "outside the served root" in got["error"], body
    status, got = post(srv, "/v1/evidence-pack",
                       {"ledger": "ledger.jsonl", "out": "pf", "readings": "r.json"})
    assert status == 400 and "not taken over HTTP" in got["error"]
    assert not (root / "pf").exists()


def test_deal_and_readings_ledger_reach_the_verb_argv_fenced(srv, root, monkeypatch):
    """K069b: buyer, seller and readings_ledger are fenced path fields now, so
    a deal with its tapes and the receipt's ledger are taken over HTTP."""
    seen = []
    monkeypatch.setattr(h_core, "run_verb",
                        lambda verb, argv: seen.append((verb, argv)) or (0, "{}", ""))
    status, got = post(srv, "/v1/evidence-pack", {
        "ledger": "ledger.jsonl", "out": "pd", "deal": "d-1", "buyer": "b.jsonl",
        "seller": "sub/s.jsonl", "receipt": "r.json", "readings_ledger": "r.ledger.jsonl"})
    assert status == 200 and got["exit"] == 0, got
    argv = seen[0][1]
    at = {flag: argv[argv.index(flag) + 1] for flag in
          ("--deal", "--buyer", "--seller", "--readings-ledger")}
    assert at["--deal"] == "d-1"
    for flag, rel in (("--buyer", "b.jsonl"), ("--seller", "sub/s.jsonl"),
                      ("--readings-ledger", "r.ledger.jsonl")):
        assert Path(at[flag]) == (root / rel).resolve(), flag


def test_zip_of_the_root_itself_is_refused(srv, root):
    status, got = post(srv, "/v1/evidence-pack", {"ledger": "ledger.jsonl", "out": ".",
                                                 "zip": True})
    assert status == 400, got
    assert not (root.parent / (root.name + ".zip")).exists()
    status, _ = post(srv, "/v1/evidence-pack", {"ledger": "ledger.jsonl", "out": "q",
                                               "zip": "yes"})
    assert status == 400
