"""The second-read page (K105): disagreements with both readings and both
reader ids, the two integers, "not yet informative" under twenty. Headless:
urllib plus html.parser over a loopback server this test starts and stops."""
from __future__ import annotations

import json

import pytest

from arcaeon import journal
from arcaeon.prove.readings_cli import submit
from arcaeon.serve.pages import readings as PR
from serve import _pages as P

CRITERION = "Does the claim say the delivery arrived on time?"


def _ledger(path, reader_id, provider, readings):
    for cid, word in readings:
        res = submit(path, reader_id=reader_id, provider=provider, claim_id=cid,
                     claim_text=f"claim text {cid}", reading=word, criterion_text=CRITERION)
        assert res["exit"] == 0, res


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    r = tmp_path / "root"
    (r / "reads").mkdir(parents=True)
    five_a = [("c1", "yes"), ("c2", "no"), ("c3", "yes"), ("c4", "no"), ("c5", "yes")]
    five_b = [("c1", "yes"), ("c2", "yes"), ("c3", "yes"), ("c4", "yes"), ("c5", "yes")]
    _ledger(r / "reads" / "a.jsonl", "reader-alpha", "vendor-one", five_a)
    _ledger(r / "reads" / "b.jsonl", "reader-beta", "vendor-two", five_b)
    _ledger(r / "reads" / "short.jsonl", "reader-gamma", "vendor-three", five_a[:3])
    many = [(f"m{i}", "yes" if i % 7 else "no") for i in range(22)]
    _ledger(r / "reads" / "many_a.jsonl", "reader-alpha", "vendor-one", many)
    _ledger(r / "reads" / "many_b.jsonl", "reader-beta", "vendor-two",
            [(c, "yes") for c, _ in many])
    broken = r / "reads" / "broken.jsonl"
    _ledger(broken, "reader-delta", "vendor-four", five_a)
    broken.write_bytes(broken.read_bytes().replace(b'"reading":"no"', b'"reading":"yes"', 1)
                       .replace(b'"reading": "no"', b'"reading": "yes"', 1))
    _ledger(tmp_path / "outside.jsonl", "reader-omega", "vendor-x", five_b)
    return r


@pytest.fixture()
def session(root):
    with P.running(root) as srv:
        yield srv, P.sign_in(srv)


def _compare(srv, ck, a, b):
    r = P.post_form(srv, "/readings", {"a": a, "b": b}, cookie=ck)
    tree = P.parse(r.text)
    blocks = P.by_class(tree, "verdict")
    assert len(blocks) == 1, r.text
    return r, tree, blocks[0]


def test_get_lists_ledgers_under_the_root_only(session):
    srv, ck = session
    r = P.get(srv, "/readings", cookie=ck)
    assert r.status == 200 and "default-src 'self'" in r.headers["Content-Security-Policy"]
    tree = P.parse(r.text)
    for side in ("a", "b"):
        sel = [n for n in P.by_tag(tree, "select") if n.attrs.get("name") == side]
        assert len(sel) == 1
        vals = [o.attrs["value"] for o in P.by_tag(sel[0], "option") if o.attrs["value"]]
        assert "reads/a.jsonl" in vals and "reads/b.jsonl" in vals
    assert "outside.jsonl" not in r.text
    assert 'href="/readings"' in r.text


def test_disagreements_both_readings_both_reader_ids_and_two_integers(session, root):
    srv, ck = session
    r, tree, block = _compare(srv, ck, "reads/a.jsonl", "reads/b.jsonl")
    assert r.status == 200
    assert P.by_class(block, "verdict-word")[0].text() == "COMPARED"
    assert "state-ok" in block.classes
    counts = {n.attrs["data-count"]: int(n.text()) for n in P.by_class(block, "count")}
    assert counts == {"disagreed": 2, "read": 5}
    assert "disagreed on 2 of the 5 claims" in P.by_class(block, "counts-sentence")[0].text()
    nyi = P.by_class(block, "not-yet-informative")
    assert len(nyi) == 1 and PR.NOT_YET in nyi[0].text() and "state-unknown" in nyi[0].classes
    rows = P.by_class(tree, "disagreed")
    got = {P.by_tag(x, "code")[0].text(): (
        P.by_class(x, "reading-a")[0].text(), P.by_class(x, "reader-a")[0].text(),
        P.by_class(x, "reading-b")[0].text(), P.by_class(x, "reader-b")[0].text())
        for x in rows}
    assert got == {"c2": ("no", "reader-alpha", "yes", "reader-beta"),
                   "c4": ("no", "reader-alpha", "yes", "reader-beta")}
    assert str(root) not in r.text and str(root).replace("\\", "/") not in r.text


def test_twenty_or_more_read_is_not_marked(session):
    srv, ck = session
    _r, _tree, block = _compare(srv, ck, "reads/many_a.jsonl", "reads/many_b.jsonl")
    counts = {n.attrs["data-count"]: int(n.text()) for n in P.by_class(block, "count")}
    assert counts == {"disagreed": 4, "read": 22}
    assert P.by_class(block, "not-yet-informative") == []
    assert PR.NOT_YET not in block.text()


def test_missing_claims_are_listed_not_hidden(session):
    srv, ck = session
    _r, tree, block = _compare(srv, ck, "reads/a.jsonl", "reads/short.jsonl")
    assert P.by_class(block, "verdict-word")[0].text() == "MISSING"
    assert "state-bad" in block.classes
    unmatched = P.by_class(tree, "unmatched")
    assert len(unmatched) == 1
    text = unmatched[0].text()
    assert "c4" in text and "c5" in text and "read only in ledger a" in text


def test_broken_ledger_counts_not_computed_never_green(session, root):
    srv, ck = session
    r, _tree, block = _compare(srv, ck, "reads/broken.jsonl", "reads/b.jsonl")
    assert P.by_class(block, "verdict-word")[0].text() == "BROKEN"
    assert "state-bad" in block.classes and "state-ok" not in block.classes
    assert P.by_class(block, "count") == []
    assert len(P.by_class(block, "counts-not-computed")) == 1
    assert str(root) not in r.text and str(root).replace("\\", "/") not in r.text


def test_same_reader_both_sides_is_could_not_look(session):
    srv, ck = session
    _r, _tree, block = _compare(srv, ck, "reads/a.jsonl", "reads/a.jsonl")
    assert P.by_class(block, "verdict-word")[0].text() == "COULD NOT LOOK"
    assert "state-unknown" in block.classes and "state-ok" not in block.classes


def test_outside_the_root_is_refused_and_journaled_calls_are_routes(session, root):
    srv, ck = session
    for bad in ("../outside.jsonl", str(root.parent / "outside.jsonl")):
        r = P.post_form(srv, "/readings", {"a": bad, "b": "reads/b.jsonl"}, cookie=ck)
        assert r.status == 400 and "outside the folder" in r.text
        assert "reader-omega" not in r.text
    _compare(srv, ck, "reads/a.jsonl", "reads/b.jsonl")
    verbs = [row.get("verb") for row in journal.read()]
    assert verbs.count("serve:/v1/second-read/compare") == 1


def test_needs_sign_in_and_both_sides(session):
    srv, ck = session
    assert P.get(srv, "/readings").status == 401
    assert P.post_form(srv, "/readings", {"a": "reads/a.jsonl", "b": "reads/b.jsonl"}
                       ).status == 401
    r = P.post_form(srv, "/readings", {"a": "reads/a.jsonl"}, cookie=ck)
    assert r.status == 400 and "Choose both" in r.text


def test_page_matches_the_json_route(session, root):
    srv, ck = session
    r = P.request(srv, "/v1/second-read/compare", method="POST",
                  data=json.dumps({"a": "reads/a.jsonl", "b": "reads/b.jsonl"}).encode(),
                  headers={"Authorization": f"Bearer {P.TOKEN}",
                           "Content-Type": "application/json"})
    doc = json.loads(r.text)
    _r, _tree, block = _compare(srv, ck, "reads/a.jsonl", "reads/b.jsonl")
    counts = {n.attrs["data-count"]: int(n.text()) for n in P.by_class(block, "count")}
    assert counts == {"disagreed": doc["summary"]["disagreed"], "read": doc["summary"]["read"]}
    assert P.by_class(block, "verdict-word")[0].text() == doc["verdict"]
