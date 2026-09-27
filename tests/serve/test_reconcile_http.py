"""POST /v1/reconcile over HTTP (K009): two tapes, optional pin; MATCHED,
MISSING / ALTERED and COULD NOT LOOK all in a 200 body. `kind: "readings"`
dispatches to the readings compare (K035)."""
from __future__ import annotations

import http.client
import io
import json
import threading
from pathlib import Path

import pytest

from arcaeon.prove import readings as RD
from arcaeon.prove import readings_compare as RC
from arcaeon.prove.reconcile import TAPE_FORMAT
from arcaeon.record.ledger import Ledger, digest_json
from arcaeon.serve import auth
from arcaeon.serve import h_core as H
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


def post(server, body):
    c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=30)
    c.request("POST", "/v1/reconcile", body=json.dumps(body).encode(),
              headers={"Content-Type": "application/json",
                       "Authorization": f"Bearer {auth.load_or_create()}"})
    r = c.getresponse()
    out = json.loads(r.read())
    c.close()
    return r.status, out


def _tape(path: Path, side: str, n: int = 3, skip: int | None = None) -> Path:
    path.touch()
    lg = Ledger(path)
    for k in range(1, n + 1):
        if k == skip:
            continue
        lg.append({"evt": "tape_call", "tape": TAPE_FORMAT, "side": side, "ns": f"demo-{side}",
                   "idx": k, "tool": "echo",
                   "req": digest_json({"name": "echo", "arguments": {"text": f"c{k}"}}),
                   "resp": digest_json({"result": {"text": f"c{k}"}}), "status": "ok"})
    return path


def test_matched_tapes_are_matched_exit_0(srv, root):
    _tape(root / "agent.jsonl", "agent")
    _tape(root / "tool.jsonl", "tool")
    status, body = post(srv, {"tape_a": "agent.jsonl", "tape_b": "tool.jsonl"})
    assert status == 200 and (body["verdict"], body["exit"]) == ("MATCHED", 0)
    assert body["matched"] == 3


def test_kind_tapes_explicit_is_the_same(srv, root):
    _tape(root / "agent.jsonl", "agent")
    _tape(root / "tool.jsonl", "tool")
    _, plain = post(srv, {"tape_a": "agent.jsonl", "tape_b": "tool.jsonl"})
    _, explicit = post(srv, {"kind": "tapes", "tape_a": "agent.jsonl", "tape_b": "tool.jsonl"})
    assert plain == explicit


def test_one_tape_missing_is_could_not_look_exit_3_in_a_200(srv, root):
    _tape(root / "agent.jsonl", "agent")
    status, body = post(srv, {"tape_a": "agent.jsonl", "tape_b": "gone.jsonl"})
    assert status == 200
    assert (body["verdict"], body["exit"]) == ("COULD_NOT_LOOK", 3)


def test_a_call_missing_from_one_tape_is_exit_1(srv, root):
    _tape(root / "agent.jsonl", "agent")
    _tape(root / "tool.jsonl", "tool", skip=2)
    status, body = post(srv, {"tape_a": "agent.jsonl", "tape_b": "tool.jsonl"})
    assert status == 200 and body["exit"] == 1 and body["verdict"] in ("MISSING", "ALTERED")


def test_http_equals_h_core(srv, root):
    _tape(root / "agent.jsonl", "agent")
    _tape(root / "tool.jsonl", "tool", skip=3)
    _, over_http = post(srv, {"tape_a": "agent.jsonl", "tape_b": "tool.jsonl"})
    direct = H.reconcile({"tape_a": str(root / "agent.jsonl"), "tape_b": str(root / "tool.jsonl")})
    assert over_http == direct


def test_tapes_by_content(srv, root, tmp_path):
    a = _tape(tmp_path / "a.jsonl", "agent").read_text(encoding="utf-8")
    b = _tape(tmp_path / "b.jsonl", "tool").read_text(encoding="utf-8")
    status, body = post(srv, {"content_a": a, "content_b": b})
    assert status == 200 and (body["verdict"], body["exit"]) == ("MATCHED", 0)


def test_a_tape_outside_the_root_is_400(srv, root, tmp_path):
    _tape(root / "agent.jsonl", "agent")
    _tape(tmp_path / "tool.jsonl", "tool")
    status, body = post(srv, {"tape_a": "agent.jsonl", "tape_b": str(tmp_path / "tool.jsonl")})
    assert status == 400 and body["error"] == "`tape_b` is outside the served root"


def test_an_unknown_kind_is_400(srv):
    status, body = post(srv, {"kind": "cards", "tape_a": "a", "tape_b": "b"})
    assert status == 400 and body["exit"] == 2


# --- kind: readings ---------------------------------------------------------------

SENTENCE = "Does the claim state the dispatch time?"
RA = {"id": "reader-a", "provider": "acme", "model": "m-1", "endpoint_host": "127.0.0.1"}
RB = {"id": "reader-b", "provider": "other", "model": "m-2", "endpoint_host": "127.0.0.1"}


def _readings(path: Path, reader, pairs) -> Path:
    crit = RD.freeze_criterion(path, SENTENCE)["criterion_sha256"]
    for cid, word in pairs:
        RD.write_reading(path, RD.build_reading(claim_id=cid, claim_text=f"claim {cid}",
                                                criterion_sha256=crit, reader=reader,
                                                reading=word))
    return path


def test_kind_readings_is_the_compare_in_a_200(srv, root):
    a = _readings(root / "a.jsonl", RA, [("c1", "yes"), ("c2", "no")])
    b = _readings(root / "b.jsonl", RB, [("c1", "yes"), ("c2", "yes")])
    status, body = post(srv, {"kind": "readings", "tape_a": "a.jsonl", "tape_b": "b.jsonl"})
    assert status == 200 and (body["verdict"], body["exit"]) == ("COMPARED", 0)
    want = json.loads(json.dumps(RC.compare(str(a.resolve()), str(b.resolve()))))
    assert body == want


def test_kind_readings_missing_ledger_is_could_not_look_exit_3(srv, root):
    _readings(root / "a.jsonl", RA, [("c1", "yes")])
    status, body = post(srv, {"kind": "readings", "tape_a": "a.jsonl", "tape_b": "no.jsonl"})
    assert status == 200 and body["exit"] == 3


def test_kind_readings_by_content_hides_the_temporary_path(srv, root, tmp_path):
    a = _readings(tmp_path / "a.jsonl", RA, [("c1", "yes")]).read_text(encoding="utf-8")
    b = _readings(tmp_path / "b.jsonl", RB, [("c1", "no")]).read_text(encoding="utf-8")
    status, body = post(srv, {"kind": "readings", "content_a": a, "content_b": b})
    assert status == 200 and (body["verdict"], body["exit"]) == ("COMPARED", 0)
    assert "arcaeon-content-" not in json.dumps(body)


def test_kind_readings_with_a_pin_is_400(srv, root):
    status, body = post(srv, {"kind": "readings", "tape_a": "a.jsonl", "tape_b": "b.jsonl",
                              "pin": "p.jsonl"})
    assert status == 400 and body["exit"] == 2
