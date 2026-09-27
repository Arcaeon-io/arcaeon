"""Content-in mode (K007): every route that takes a path also takes `content`
(JSONL text) or `content_b64`, so an agent with no file access can still ask
for a check. A content check runs the same CLI verb as a path check, writes
nothing under the served root, and never shows the temporary path."""
from __future__ import annotations

import base64
import http.client
import io
import json
import os
import tempfile
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from arcaeon.serve import h_core as H
from arcaeon.serve import routes as R
from arcaeon.serve import server as S


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arcaeon-home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    r = tmp_path / "served"
    r.mkdir()
    monkeypatch.chdir(r)
    return r


def _text(root: Path, n: int = 3, name: str = "src.jsonl") -> str:
    """A good ledger's text, built in a scratch dir outside the root."""
    scratch = root.parent / "scratch"
    scratch.mkdir(exist_ok=True)
    p = scratch / name
    for i in range(n):
        assert H.log({"ledger": str(p), "fields": {"i": i}})["exit"] == 0
    return p.read_text(encoding="utf-8")


def _tampered(text: str) -> str:
    lines = text.splitlines()
    lines[0] = lines[0].replace('"i": 0', '"i": 9')
    return "\n".join(lines) + "\n"


def _listing(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


def _content_dirs() -> set[str]:
    return {d for d in os.listdir(tempfile.gettempdir()) if d.startswith("arcaeon-content-")}


# --- h_core -------------------------------------------------------------------------

def test_verify_by_content_of_a_good_ledger_is_verified(root):
    got = H.verify({"content": _text(root)})
    assert got["verdict"] == "VERIFIED" and got["exit"] == 0 and got["rows"] == 3


def test_verify_by_content_of_a_tampered_ledger_is_broken_naming_line_1(root):
    before = _listing(root)
    got = H.verify({"content": _tampered(_text(root))})
    assert got["verdict"] == "BROKEN" and got["exit"] == 1
    assert "line 1" in str(got["first_break"])
    assert _listing(root) == before


def test_content_and_path_give_the_same_answer(root):
    text = _tampered(_text(root))
    (root / "same.jsonl").write_text(text, encoding="utf-8")
    by_path = H.verify({"ledger": str(root / "same.jsonl")})
    by_content = H.verify({"content": text})
    assert by_content == by_path


def test_content_b64_is_the_same_as_content(root):
    text = _tampered(_text(root))
    b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
    assert H.verify({"content_b64": b64}) == H.verify({"content": text})


def test_verify_by_content_leaves_no_temporary_directory_behind(root):
    before = _content_dirs()
    H.verify({"content": _text(root)})
    H.verify({"content": "not json\n"})
    assert _content_dirs() == before


def test_the_temporary_path_never_reaches_the_answer(root):
    got = H.verify({"content": ""})                  # empty: COULD NOT LOOK names `where`
    assert got["exit"] == 3
    blob = json.dumps(got)
    assert "arcaeon-content-" not in blob and tempfile.gettempdir() not in blob
    assert H.CONTENT_LABEL in blob


def test_path_and_content_together_is_usage(root):
    got = H.verify({"ledger": "x.jsonl", "content": "{}\n"})
    assert got["exit"] == 2 and "not both" in got["error"]


def test_content_and_content_b64_together_is_usage(root):
    got = H.verify({"content": "{}\n", "content_b64": "e30K"})
    assert got["exit"] == 2 and "not both" in got["error"]


def test_bad_base64_is_usage(root):
    got = H.verify({"content_b64": "@@not base64@@"})
    assert got["exit"] == 2 and "not base64" in got["error"]


def test_neither_path_nor_content_is_usage_naming_both(root):
    got = H.verify({})
    assert got["exit"] == 2 and "'ledger'" in got["error"] and "content" in got["error"]


def _tapes(root: Path) -> tuple[str, str]:
    """An honest agent/tool tape pair's texts, built outside the root."""
    from arcaeon.prove.reconcile import TAPE_FORMAT
    from arcaeon.record.ledger import Ledger, digest_json
    scratch = root.parent / "scratch"
    scratch.mkdir(exist_ok=True)
    out = []
    for side in ("agent", "tool"):
        p = scratch / f"{side}.tape.jsonl"
        p.touch()
        lg = Ledger(p)
        for k in (1, 2, 3):
            lg.append({"evt": "tape_call", "tape": TAPE_FORMAT, "side": side,
                       "ns": f"demo-{side}", "idx": k, "tool": "echo",
                       "req": digest_json({"name": "echo", "arguments": {"text": f"c{k}"}}),
                       "resp": digest_json({"result": {"text": f"c{k}"}}), "status": "ok"})
        out.append(p.read_text(encoding="utf-8"))
    return out[0], out[1]


def test_reconcile_by_content_matches_reconcile_by_path(root):
    ta, tb = _tapes(root)
    (root / "a.jsonl").write_text(ta, encoding="utf-8")
    (root / "b.jsonl").write_text(tb, encoding="utf-8")
    by_path = H.reconcile({"tape_a": str(root / "a.jsonl"), "tape_b": str(root / "b.jsonl")})
    assert by_path["verdict"] == "MATCHED" and by_path["exit"] == 0
    before = _listing(root)
    by_content = H.reconcile({"content_a": ta,
                              "content_b_b64": base64.b64encode(tb.encode()).decode()})
    assert (by_content["verdict"], by_content["exit"]) == ("MATCHED", 0)
    assert by_content["matched"] == by_path["matched"] == 3
    assert _listing(root) == before
    assert "arcaeon-content-" not in json.dumps(by_content)


def test_reconcile_may_mix_a_path_and_content(root):
    ta, tb = _tapes(root)
    (root / "a.jsonl").write_text(ta, encoding="utf-8")
    got = H.reconcile({"tape_a": str(root / "a.jsonl"), "content_b": tb})
    assert (got["verdict"], got["exit"]) == ("MATCHED", 0)


def test_audit_verify_by_content_equals_by_path(root):
    text = _tampered(_text(root))
    (root / "audit.jsonl").write_text(text, encoding="utf-8")
    by_path = H.audit_verify({"path": str(root / "audit.jsonl")})
    by_content = H.audit_verify({"content": text})
    assert by_content["exit"] == by_path["exit"] != 0
    good = _text(root, name="good.jsonl")
    assert H.audit_verify({"content": good})["exit"] == 0


def test_receipt_verify_by_content_equals_by_path(root):
    (root / "r.json").write_text("{}", encoding="utf-8")
    by_path = H.receipt_verify({"receipt": str(root / "r.json")})
    by_content = H.receipt_verify({"content": "{}"})
    assert by_content["exit"] == by_path["exit"]
    assert by_content.get("ok") == by_path.get("ok")


# --- over HTTP ------------------------------------------------------------------------

@pytest.fixture()
def srv(root, monkeypatch):
    new = replace(R.find("POST", "/v1/verify"), handler="arcaeon.serve.h_core:verify")
    monkeypatch.setattr(R, "ROUTES", tuple(new if r.path == "/v1/verify" else r
                                           for r in R.ROUTES))
    server = S.make_server(port=0, token=None, root=root)
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(server,),
                         kwargs={"ready": ready, "out": io.StringIO()}, daemon=True)
    t.start()
    assert ready.wait(10)
    yield server
    server.shutdown()
    t.join(10)


def test_http_verify_by_content_is_broken_line_1_and_the_root_is_unchanged(srv, root):
    text = _tampered(_text(root))
    before = _listing(root)
    c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=30)
    c.request("POST", "/v1/verify", body=json.dumps({"content": text}).encode(),
              headers={"Content-Type": "application/json"})
    r = c.getresponse()
    body = json.loads(r.read())
    c.close()
    assert r.status == 200
    assert body["verdict"] == "BROKEN" and body["exit"] == 1
    assert "line 1" in str(body["first_break"])
    assert _listing(root) == before
