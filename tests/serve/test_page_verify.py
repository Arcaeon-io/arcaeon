"""The verify page (K103): pick a file under the root or paste a ledger.
COULD NOT LOOK carries the state-unknown class, never state-ok. Headless:
urllib plus html.parser over a loopback server this test starts and stops."""
from __future__ import annotations

import json

import pytest

from arcaeon import journal
from arcaeon.serve import h_core
from serve import _pages as P


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    r = tmp_path / "root"
    (r / "nested").mkdir(parents=True)
    for name in ("good.jsonl", "nested/bad.jsonl"):
        for i in range(3):
            res = h_core.log({"ledger": str(r / name), "fields": {"n": i, "word": "hello"}})
            assert res["exit"] == 0, res
    bad = r / "nested" / "bad.jsonl"
    bad.write_text(bad.read_text(encoding="utf-8").replace('"n": 1', '"n": 7', 1)
                   .replace('"n":1', '"n":7', 1), encoding="utf-8")
    (tmp_path / "outside.jsonl").write_text((r / "good.jsonl").read_text(encoding="utf-8"),
                                            encoding="utf-8")
    return r


@pytest.fixture()
def session(root):
    with P.running(root) as srv:
        yield srv, P.sign_in(srv)


def _verdict(text):
    blocks = P.by_class(P.parse(text), "verdict")
    assert len(blocks) == 1, text
    b = blocks[0]
    word = P.by_class(b, "verdict-word")[0].text()
    return word, b.classes


def test_get_lists_files_under_the_root(session):
    srv, ck = session
    r = P.get(srv, "/verify", cookie=ck)
    assert r.status == 200 and "default-src 'self'" in r.headers["Content-Security-Policy"]
    opts = [n.attrs.get("value") for n in P.by_tag(P.parse(r.text), "option")]
    assert opts == ["", "good.jsonl", "nested/bad.jsonl"]
    assert "outside.jsonl" not in r.text


def test_a_good_file_is_verified_state_ok(session):
    srv, ck = session
    r = P.post_form(srv, "/verify", {"ledger": "good.jsonl"}, cookie=ck)
    assert r.status == 200
    word, classes = _verdict(r.text)
    assert word == "VERIFIED" and "state-ok" in classes


def test_a_changed_file_is_broken_state_bad(session):
    srv, ck = session
    word, classes = _verdict(P.post_form(srv, "/verify", {"ledger": "nested/bad.jsonl"},
                                         cookie=ck).text)
    assert word == "BROKEN" and "state-bad" in classes and "state-ok" not in classes


def test_could_not_look_is_state_unknown_never_state_ok(session, root):
    srv, ck = session
    r = P.post_form(srv, "/verify", {"ledger": "nope.jsonl"}, cookie=ck)
    word, classes = _verdict(r.text)
    assert word == "COULD NOT LOOK"
    assert "state-unknown" in classes and "state-ok" not in classes
    assert "missing" in r.text and "it was not there at all" in r.text
    assert str(root) not in r.text                      # shown root-relative


def test_pasted_content_with_crlf(session, root):
    srv, ck = session
    text = (root / "good.jsonl").read_text(encoding="utf-8").replace("\n", "\r\n")
    word, classes = _verdict(P.post_form(srv, "/verify", {"content": text}, cookie=ck).text)
    assert word == "VERIFIED" and "state-ok" in classes


def test_pasted_rows_with_no_chain_are_could_not_look(session):
    srv, ck = session
    r = P.post_form(srv, "/verify", {"content": '{"a": 1}\n'}, cookie=ck)
    word, classes = _verdict(r.text)
    assert word == "COULD NOT LOOK" and "state-unknown" in classes
    assert "(content)" in r.text and "arcaeon-content-" not in r.text


@pytest.mark.parametrize("path", ["../outside.jsonl", "nested/../../outside.jsonl"])
def test_a_path_outside_the_root_is_refused_and_not_opened(session, root, path):
    srv, ck = session
    r = P.post_form(srv, "/verify", {"ledger": path}, cookie=ck)
    assert r.status == 400
    assert "outside the folder" in r.text
    assert not P.by_class(P.parse(r.text), "state-ok")


def test_an_absolute_path_outside_is_refused(session, root):
    srv, ck = session
    r = P.post_form(srv, "/verify", {"ledger": str(root.parent / "outside.jsonl")},
                    cookie=ck)
    assert r.status == 400 and "outside the folder" in r.text
    assert str(root.parent) not in r.text


def test_neither_or_both_is_refused(session):
    srv, ck = session
    assert P.post_form(srv, "/verify", {}, cookie=ck).status == 400
    assert P.post_form(srv, "/verify", {"ledger": "good.jsonl", "content": "{}"},
                       cookie=ck).status == 400


def test_the_page_needs_a_session(session):
    srv, _ = session
    assert P.post_form(srv, "/verify", {"ledger": "good.jsonl"}).status == 401
    assert P.get(srv, "/verify").status == 401


def test_a_page_check_is_journaled_as_the_route(session):
    srv, ck = session
    P.post_form(srv, "/verify", {"ledger": "nope.jsonl"}, cookie=ck)
    rows = journal.read()
    assert rows and rows[-1]["verb"] == "serve:/v1/verify" and rows[-1]["exit"] == 3


def test_the_json_route_gives_the_same_word(session):
    srv, ck = session
    r = P.request(srv, "/v1/verify", data=json.dumps({"ledger": "nested/bad.jsonl"}).encode(),
                  headers={"Authorization": f"Bearer {P.TOKEN}",
                           "Content-Type": "application/json"}, method="POST")
    page = P.post_form(srv, "/verify", {"ledger": "nested/bad.jsonl"}, cookie=ck).text
    assert json.loads(r.text)["verdict"] == _verdict(page)[0] == "BROKEN"
