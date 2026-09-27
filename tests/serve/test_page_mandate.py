"""The mandate page (K106): the mandate explained in sentences (K074) and the
last session's outside rows. The seam ledger is written by the proxy's own
observer and mandate watch, in process. Headless: urllib plus html.parser over
a loopback server this test starts and stops."""
from __future__ import annotations

import json

import pytest

from arcaeon import journal
from arcaeon.record.adapter import mandate_gate
from arcaeon.record.adapter import proxy
from arcaeon.record.adapter._ledger import open_ledger
from arcaeon.record.adapter.observer import SeamObserver
from arcaeon.record.mandate_cli import explain
from serve import _pages as P

MANDATE = {"who": "purchasing-agent", "allowed_acts": ["search_*", "get_quote"],
           "forbidden_acts": ["refund", "delete_*"]}


def _call(i, tool):
    return json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                       "params": {"name": tool, "arguments": {}}}).encode()


def _session(log, mandate, sid, tools, *, unparsed=False):
    obs = SeamObserver(log.append, server="stub", session=sid)
    watch = proxy._MandateWatch(mandate_gate.load(str(mandate)), obs, enforce=False)
    obs.session_begin()
    for i, tool in enumerate(tools):
        watch.observe(_call(i, tool))
    if unparsed:
        watch.record_unparsed("forwarded", "client stdin")
    obs.session_end(reason="eof", exit_code=0, **watch.session_end_fields())


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    r = tmp_path / "root"
    r.mkdir()
    m = r / "mandate.json"
    m.write_text(json.dumps(MANDATE), encoding="utf-8")
    (r / "bad_mandate.json").write_text(json.dumps({"allowed_acts": "search"}),
                                        encoding="utf-8")
    log = open_ledger(r / "seam.jsonl")
    _session(log, m, "session-one", ["search_web", "delete_everything"])
    _session(log, m, "session-two", ["search_web", "get_quote", "refund"], unparsed=True)
    (tmp_path / "outside.json").write_text(json.dumps(MANDATE), encoding="utf-8")
    return r


@pytest.fixture()
def session(root):
    with P.running(root) as srv:
        yield srv, P.sign_in(srv)


def test_get_shows_the_last_gated_session_counts(session, root):
    srv, ck = session
    r = P.get(srv, "/mandate", cookie=ck)
    assert r.status == 200 and "default-src 'self'" in r.headers["Content-Security-Policy"]
    tree = P.parse(r.text)
    last = P.by_class(tree, "last-session")
    assert len(last) == 1
    text = last[0].text()
    assert "2 inside, 1 outside, 1 COULD NOT LOOK" in text
    assert "state-bad" in last[0].classes and "state-ok" not in last[0].classes
    opts = [o.attrs["value"] for s in P.by_tag(tree, "select") if s.attrs["name"] == "mandate"
            for o in P.by_tag(s, "option") if o.attrs["value"]]
    assert opts == ["bad_mandate.json", "mandate.json"]
    assert "outside.json" not in r.text and 'href="/mandate"' in r.text


def test_explained_in_sentences_and_last_session_outside_rows(session, root):
    srv, ck = session
    r = P.post_form(srv, "/mandate", {"mandate": "mandate.json", "ledger": "seam.jsonl"},
                    cookie=ck)
    assert r.status == 200
    tree = P.parse(r.text)
    got = [li.text() for li in P.by_tag(P.by_class(tree, "mandate-sentences")[0], "li")]
    assert got == [" ".join(s.split()) for s in explain(MANDATE)]
    assert "This agent may call search_* and get_quote." in got
    blocks = P.by_class(tree, "verdict")
    assert len(blocks) == 1 and P.by_class(blocks[0], "verdict-word")[0].text() == "VERIFIED"
    assert "session-two" in P.by_class(tree, "session")[0].text()
    outside = P.by_class(tree, "outside-rows")
    assert len(outside) == 1
    tools = [P.by_tag(tr, "code")[0].text() for tr in P.by_tag(outside[0], "tr")
             if "state-bad" in tr.classes]
    assert tools == ["refund"]                       # the last session's only
    assert "delete_everything" not in r.text        # session one's is not shown
    cnl = P.by_class(tree, "cnl-rows")
    assert len(cnl) == 1
    rows = [tr for tr in P.by_tag(cnl[0], "tr") if "state-unknown" in tr.classes]
    assert len(rows) == 1 and "state-ok" not in rows[0].classes
    assert str(root) not in r.text and str(root).replace("\\", "/") not in r.text
    assert "serve:/v1/verify" in [row.get("verb") for row in journal.read()]


def test_a_changed_ledger_still_lists_rows_marked_unconfirmed(session, root):
    srv, ck = session
    led = root / "seam.jsonl"
    led.write_bytes(led.read_bytes().replace(b'"server": "stub"', b'"server": "stuB"', 1))
    r = P.post_form(srv, "/mandate", {"mandate": "mandate.json", "ledger": "seam.jsonl"},
                    cookie=ck)
    tree = P.parse(r.text)
    block = P.by_class(tree, "verdict")[0]
    assert P.by_class(block, "verdict-word")[0].text() == "BROKEN"
    assert "state-ok" not in block.classes
    assert len(P.by_class(tree, "unconfirmed")) == 1
    assert len(P.by_class(tree, "outside-rows")) == 1


def test_invalid_mandate_is_not_explained(session):
    srv, ck = session
    r = P.post_form(srv, "/mandate", {"mandate": "bad_mandate.json"}, cookie=ck)
    tree = P.parse(r.text)
    assert P.by_class(tree, "mandate-sentences") == []
    probs = P.by_class(tree, "mandate-problems")
    assert len(probs) == 1 and "allowed_acts" in probs[0].text()
    assert "state-ok" not in r.text.split("<main>", 1)[1].split('class="last-session', 1)[0]


def test_missing_mandate_is_could_not_look_never_green(session, root):
    srv, ck = session
    (root / "gone.json").write_text("{}", encoding="utf-8")
    (root / "gone.json").unlink()
    r = P.post_form(srv, "/mandate", {"mandate": "gone.json"}, cookie=ck)
    tree = P.parse(r.text)
    block = P.by_class(tree, "verdict")[0]
    assert P.by_class(block, "verdict-word")[0].text() == "COULD NOT LOOK"
    assert "state-unknown" in block.classes and "state-ok" not in block.classes
    assert str(root) not in r.text and str(root).replace("\\", "/") not in r.text


def test_outside_the_root_refused_and_sign_in_needed(session, root):
    srv, ck = session
    for bad in ("../outside.json", str(root.parent / "outside.json")):
        r = P.post_form(srv, "/mandate", {"mandate": bad}, cookie=ck)
        assert r.status == 400 and "outside the folder" in r.text
        assert "purchasing-agent" not in r.text
    r = P.post_form(srv, "/mandate", {"mandate": "mandate.json", "ledger": "../x.jsonl"},
                    cookie=ck)
    assert r.status == 400 and "outside the folder" in r.text
    assert P.get(srv, "/mandate").status == 401
    assert P.post_form(srv, "/mandate", {"mandate": "mandate.json"}).status == 401


def test_no_session_recorded_says_so(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "empty_home"))
    r0 = tmp_path / "r0"
    r0.mkdir()
    with P.running(r0) as srv:
        r = P.get(srv, "/mandate", cookie=P.sign_in(srv))
    last = P.by_class(P.parse(r.text), "last-session")[0]
    assert "No mandate-gated session recorded" in last.text()
    assert "state-ok" not in last.classes
