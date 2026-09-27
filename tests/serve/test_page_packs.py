"""The evidence pack page (K104): lists packs under the root, runs verify,
shows the three counts side by side. Headless: urllib plus html.parser over
a loopback server this test starts and stops."""
from __future__ import annotations

import json
import shutil

import pytest

from arcaeon import journal
from arcaeon.serve import h_core, h_evidence
from serve import _pages as P


def _build(root, ledger, out):
    res = h_evidence.build({"ledger": str(root / ledger), "out": str(root / out)})
    assert res["exit"] == 0, res


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    r = tmp_path / "root"
    (r / "packs").mkdir(parents=True)
    for i in range(3):
        res = h_core.log({"ledger": str(r / "l.jsonl"),
                          "fields": {"agent": "a", "t": f"2026-09-27T10:0{i}:00Z", "n": i}})
        assert res["exit"] == 0
    for name in ("good", "changed", "gone"):
        _build(r, "l.jsonl", f"packs/{name}")
    rec = r / "packs" / "changed" / "records.jsonl"
    rec.write_bytes(rec.read_bytes().replace(b'"n":1', b'"n":8').replace(b'"n": 1', b'"n": 8'))
    # OA1: a file the manifest lists is BROKEN when gone; the sidecar is not
    # listed, so its absence is the pack that stays COULD NOT LOOK
    (r / "packs" / "gone" / "manifest.sha256").unlink()
    _build(r, "l.jsonl", "../outside_pack")                  # built outside, via tmp
    return r


@pytest.fixture()
def root_outside_pack(root):
    return root.parent / "outside_pack"


@pytest.fixture()
def session(root):
    with P.running(root) as srv:
        yield srv, P.sign_in(srv)


def _result(text):
    tree = P.parse(text)
    blocks = P.by_class(tree, "verdict")
    assert len(blocks) == 1, text
    b = blocks[0]
    word = P.by_class(b, "verdict-word")[0].text()
    cells = {n.attrs["data-word"]: (int(n.text()), n.classes) for n in P.by_class(b, "count")}
    return word, b.classes, cells


def test_lists_packs_under_the_root_only(session):
    srv, ck = session
    r = P.get(srv, "/packs", cookie=ck)
    assert r.status == 200 and "default-src 'self'" in r.headers["Content-Security-Policy"]
    values = [n.attrs["value"] for n in P.by_tag(P.parse(r.text), "input")
              if n.attrs.get("name") == "pack"]
    assert values == ["packs/changed", "packs/gone", "packs/good"]
    assert "outside_pack" not in r.text


def test_a_good_pack_three_counts_side_by_side(session):
    srv, ck = session
    word, classes, cells = _result(P.post_form(srv, "/packs", {"pack": "packs/good"},
                                               cookie=ck).text)
    assert word == "VERIFIED" and "state-ok" in classes
    assert list(cells) == ["VERIFIED", "BROKEN", "COULD NOT LOOK"]    # one row, in order
    assert cells["VERIFIED"][0] > 0
    assert cells["BROKEN"][0] == 0 and cells["COULD NOT LOOK"][0] == 0


def test_a_changed_pack_is_broken(session):
    srv, ck = session
    word, classes, cells = _result(P.post_form(srv, "/packs", {"pack": "packs/changed"},
                                               cookie=ck).text)
    assert word == "BROKEN" and "state-bad" in classes and "state-ok" not in classes
    assert cells["BROKEN"][0] >= 1 and "state-bad" in cells["BROKEN"][1]


def test_a_pack_missing_a_file_is_could_not_look_never_ok(session, root):
    srv, ck = session
    r = P.post_form(srv, "/packs", {"pack": "packs/gone"}, cookie=ck)
    word, classes, cells = _result(r.text)
    assert word == "COULD NOT LOOK"
    assert "state-unknown" in classes and "state-ok" not in classes
    assert cells["COULD NOT LOOK"][0] >= 1
    assert "state-unknown" in cells["COULD NOT LOOK"][1]
    assert "missing" in r.text
    assert str(root) not in r.text


def test_the_counts_match_the_json_route(session):
    srv, ck = session
    api = P.request(srv, "/v1/evidence-pack/verify",
                    data=json.dumps({"pack": "packs/changed"}).encode(),
                    headers={"Authorization": f"Bearer {P.TOKEN}",
                             "Content-Type": "application/json"}, method="POST")
    body = json.loads(api.text)
    want = {"VERIFIED": 0, "BROKEN": 0, "COULD NOT LOOK": 0}
    for c in body["checks"]:
        want[c["verdict"] if c["verdict"] in ("VERIFIED", "BROKEN") else "COULD NOT LOOK"] += 1
    word, _, cells = _result(P.post_form(srv, "/packs", {"pack": "packs/changed"},
                                         cookie=ck).text)
    assert word == body["verdict"]
    assert {k: v[0] for k, v in cells.items()} == want


@pytest.mark.parametrize("path", ["../outside_pack", "packs/../../outside_pack"])
def test_a_pack_outside_the_root_is_refused(session, root_outside_pack, path):
    srv, ck = session
    assert root_outside_pack.is_dir()
    r = P.post_form(srv, "/packs", {"pack": path}, cookie=ck)
    assert r.status == 400 and "outside the folder" in r.text
    assert not P.by_class(P.parse(r.text), "count")


def test_an_outside_witness_is_refused(session):
    srv, ck = session
    r = P.post_form(srv, "/packs", {"pack": "packs/good", "witness": "../pins.jsonl"},
                    cookie=ck)
    assert r.status == 400 and "`witness`" in r.text


def test_needs_a_session(session):
    srv, _ = session
    assert P.get(srv, "/packs").status == 401
    assert P.post_form(srv, "/packs", {"pack": "packs/good"}).status == 401


def test_journaled_as_the_route(session):
    srv, ck = session
    P.post_form(srv, "/packs", {"pack": "packs/gone"}, cookie=ck)
    last = journal.read()[-1]
    assert last["verb"] == "serve:/v1/evidence-pack/verify" and last["exit"] == 3


def test_no_packs_says_so(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "home"))
    empty = tmp_path / "empty"
    empty.mkdir()
    with P.running(empty) as srv:
        assert "No evidence pack under the served root." in P.get(
            srv, "/packs", cookie=P.sign_in(srv)).text
    shutil.rmtree(empty)
