"""No-JavaScript fallback (K109): every page's verdict sentence is in the
server-rendered HTML. The pages are fetched with urllib (no script runs) and
read with html.parser; every verdict block must carry its word's sentence
from arcaeon.words, and the one script a page loads must add nothing a
reader needs. Loopback server the test starts and stops."""
from __future__ import annotations

import json
import re

import pytest

from arcaeon import words
from arcaeon.prove.readings_cli import submit
from arcaeon.record.adapter import mandate_gate
from arcaeon.record.adapter import proxy
from arcaeon.record.adapter._ledger import open_ledger
from arcaeon.record.adapter.observer import SeamObserver
from arcaeon.serve import dashboard as D
from arcaeon.serve import h_core, h_evidence
from serve import _pages as P


def _readings(path, reader_id, provider, pairs):
    for cid, word in pairs:
        assert submit(path, reader_id=reader_id, provider=provider, claim_id=cid,
                      claim_text=f"text {cid}", reading=word,
                      criterion_text="Is it on time?")["exit"] == 0


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    r = tmp_path / "root"
    r.mkdir()
    for i in range(3):
        assert h_core.log({"ledger": str(r / "good.jsonl"),
                           "fields": {"t": f"2026-09-27T10:0{i}:00Z", "n": i}})["exit"] == 0
    bad = r / "bad.jsonl"
    bad.write_bytes((r / "good.jsonl").read_bytes().replace(b'"n":1', b'"n":7')
                    .replace(b'"n": 1', b'"n": 7'))
    assert h_evidence.build({"ledger": str(r / "good.jsonl"),
                             "out": str(r / "pack")})["exit"] == 0
    _readings(r / "ra.jsonl", "reader-a", "vendor-a", [("c1", "yes"), ("c2", "no")])
    _readings(r / "rb.jsonl", "reader-b", "vendor-b", [("c1", "yes"), ("c2", "yes")])
    m = r / "mandate.json"
    m.write_text(json.dumps({"who": "agent", "allowed_acts": ["search_*"]}), encoding="utf-8")
    obs = SeamObserver(open_ledger(r / "seam.jsonl").append, server="stub", session="s1")
    watch = proxy._MandateWatch(mandate_gate.load(str(m)), obs, enforce=False)
    obs.session_begin()
    watch.observe(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": "refund", "arguments": {}}}).encode())
    obs.session_end(reason="eof", exit_code=0, **watch.session_end_fields())
    return r


#: (method, path, form, the verdict word the page must show)
CASES = [
    ("POST", "/verify", {"ledger": "good.jsonl"}, "VERIFIED"),
    ("POST", "/verify", {"ledger": "bad.jsonl"}, "BROKEN"),
    ("POST", "/verify", {"ledger": "nope.jsonl"}, "COULD NOT LOOK"),
    ("POST", "/packs", {"pack": "pack"}, "VERIFIED"),
    ("POST", "/readings", {"a": "ra.jsonl", "b": "rb.jsonl"}, "COMPARED"),
    ("POST", "/readings", {"a": "ra.jsonl", "b": "gone.jsonl"}, "COULD NOT LOOK"),
    ("POST", "/mandate", {"mandate": "mandate.json", "ledger": "seam.jsonl"}, "VERIFIED"),
    ("POST", "/mandate", {"mandate": "gone.json"}, "COULD NOT LOOK"),
]


def _fetch(srv, ck, method, path, form):
    if method == "GET":
        return P.get(srv, path, cookie=ck)
    return P.post_form(srv, path, form, cookie=ck)


def _check_scripts(tree, text):
    scripts = P.by_tag(tree, "script")
    assert [s.attrs.get("src") for s in scripts] == ["/static/app.js"]
    assert all("defer" in s.attrs for s in scripts)
    assert all(s.text() == "" for s in scripts), "no inline script"
    assert not re.search(r"\son[a-z]+\s*=", text), "no inline event handler"


@pytest.fixture()
def session(root):
    with P.running(root) as srv:
        yield srv, P.sign_in(srv)


@pytest.mark.parametrize("method,path,form,word", CASES,
                         ids=[f"{c[1]}-{c[3]}" for c in CASES])
def test_verdict_sentence_is_in_the_server_rendered_html(session, method, path, form, word):
    srv, ck = session
    r = _fetch(srv, ck, method, path, form)
    tree = P.parse(r.text)
    _check_scripts(tree, r.text)
    blocks = P.by_class(tree, "verdict")
    assert blocks, r.text
    shown = [(P.by_class(b, "verdict-word")[0].text(),
              P.by_class(b, "verdict-sentence")[0].text()) for b in blocks
             if P.by_class(b, "verdict-word") and "refusal" not in b.classes]
    assert (word, " ".join(words.sentence(word).split())) in shown, shown
    for w, s in shown:
        assert s, f"{w} has an empty sentence"
        assert s == " ".join(words.sentence(w).split())


def test_every_page_path_is_covered(session):
    """A new page that renders a verdict must be added to CASES (or the status
    and home checks below)."""
    covered = {c[1] for c in CASES} | {"/", "/status"}
    assert set(D.PAGES) <= covered, sorted(set(D.PAGES) - covered)


def test_status_headline_is_server_rendered(session):
    srv, ck = session
    P.post_form(srv, "/verify", {"ledger": "nope.jsonl"}, cookie=ck)
    r = P.get(srv, "/status", cookie=ck)
    tree = P.parse(r.text)
    _check_scripts(tree, r.text)
    head = P.by_class(tree, "headline")[0].text()
    assert head.startswith("You checked 1 file today.") and "could not be read" in head
    assert "state-ok" not in P.by_class(tree, "headline")[0].parent.classes


def test_home_reads_without_script(session):
    srv, ck = session
    r = P.get(srv, "/", cookie=ck)
    tree = P.parse(r.text)
    _check_scripts(tree, r.text)
    assert "COULD NOT LOOK is never green" in P.by_tag(tree, "main")[0].text()


def test_app_js_adds_no_content_and_fetches_nothing(session):
    srv, ck = session
    js = P.get(srv, "/static/app.js", cookie=ck).text
    for banned in ("fetch(", "XMLHttpRequest", "innerHTML", "outerHTML",
                   "insertAdjacent", "document.write", "WebSocket", "EventSource",
                   "import(", "http://", "https://"):
        assert banned not in js, banned
