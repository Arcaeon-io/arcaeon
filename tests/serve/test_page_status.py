"""The status page (K102): today's checks as one sentence, rendered on the
server so it reads without JavaScript. Fixture journal in a temporary
ARCAEON_HOME; a loopback server this test starts and stops."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from arcaeon import journal
from arcaeon.serve.pages import status as ST
from serve import _pages as P

SENTENCE = "You checked 3 files today. One could not be read (missing)."


def _t(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture()
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("ARCAEON_HOME", str(h))
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    return h


@pytest.fixture()
def root(tmp_path):
    r = tmp_path / "root"
    r.mkdir()
    return r


def _write_journal(home, rows):
    with open(home / journal.FILENAME, "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def _fixture_rows():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    # Keep every "today" row on today's local date whatever the hour.
    local_midnight = datetime.now().astimezone().replace(hour=0, minute=0, second=0,
                                                         microsecond=0)
    t0 = max(now - timedelta(minutes=5), local_midnight.astimezone(timezone.utc))
    a, b, c = ("a" * 64), ("b" * 64), ("c" * 64)
    return [
        {"t": _t(now - timedelta(days=3)), "verb": "verify", "word": "COULD NOT LOOK",
         "exit": 3, "target": "d" * 64},                              # not today
        {"t": _t(t0), "verb": "log", "word": "OK", "exit": 0, "target": a},  # not a check
        {"t": _t(t0), "verb": "verify", "word": "VERIFIED", "exit": 0, "target": a},
        {"t": _t(t0), "verb": "serve:/v1/verify", "word": "VERIFIED", "exit": 0, "target": b},
        {"t": _t(t0), "verb": "verify", "word": "COULD NOT LOOK", "exit": 3, "target": c,
         "reason_word": "missing"},
        {"t": _t(t0), "verb": "status", "word": "OK", "exit": 0, "target": None},
    ]


def test_the_fixture_journal_gives_that_sentence(home, root):
    _write_journal(home, _fixture_rows())
    with P.running(root) as srv:
        cookie = P.sign_in(srv)
        r = P.get(srv, "/status", cookie=cookie)
    assert r.status == 200
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert SENTENCE in r.text                         # in the raw HTML: no JavaScript
    tree = P.parse(r.text)
    head = P.by_class(tree, "headline")
    assert [n.text() for n in head] == [SENTENCE]
    assert "state-unknown" in head[0].parent.classes and "state-ok" not in head[0].parent.classes


def test_open_could_not_look_is_shown_never_hidden(home, root):
    _write_journal(home, _fixture_rows())
    with P.running(root) as srv:
        tree = P.parse(P.get(srv, "/status", cookie=P.sign_in(srv)).text)
    count = P.by_class(tree, "open-count")
    # every open one, today's and the one from three days ago alike
    assert [n.text() for n in count] == ["Open COULD NOT LOOKs: 2"]
    assert "state-unknown" in count[0].classes
    rows = [n.text() for n in P.by_tag(tree, "tr") if "state-unknown" in n.classes]
    assert len(rows) == 2
    assert any("c" * 12 in r for r in rows) and any("d" * 12 in r for r in rows)
    cells = {n.text(): n.classes for n in P.by_tag(tree, "td")}
    assert "state-ok" not in cells["COULD NOT LOOK"]


def test_no_checks_today_is_not_a_pass(home, root):
    with P.running(root) as srv:
        r = P.get(srv, "/status", cookie=P.sign_in(srv))
    tree = P.parse(r.text)
    head = P.by_class(tree, "headline")[0]
    assert head.text() == "You have not checked any files today."
    assert "state-ok" not in head.parent.classes
    assert "No activity recorded yet." in r.text


def test_a_real_serve_call_shows_up(home, root):
    """A COULD NOT LOOK through the server's own route lands in the journal and
    on the page; the journal row carries no reason word, so none is claimed."""
    with P.running(root) as srv:
        r = P.request(srv, "/v1/verify", data=json.dumps({"ledger": "nope.jsonl"}).encode(),
                      headers={"Authorization": f"Bearer {P.TOKEN}",
                               "Content-Type": "application/json"}, method="POST")
        assert r.status == 200 and json.loads(r.text)["exit"] == 3
        page = P.get(srv, "/status", cookie=P.sign_in(srv)).text
    assert "You checked 1 file today. One could not be read." in page


def test_the_page_never_prints_a_path(home, root):
    _write_journal(home, _fixture_rows())
    with P.running(root) as srv:
        text = P.get(srv, "/status", cookie=P.sign_in(srv)).text
    for p in (str(home), str(home).replace("\\", "/"), str(root), journal.FILENAME):
        assert p not in text


def test_needs_a_session(home, root):
    with P.running(root) as srv:
        assert P.get(srv, "/status").status == 401


def test_headline_counts():
    today = datetime.now().astimezone().date()
    now = _t(datetime.now(timezone.utc))
    rows = [{"t": now, "verb": "verify", "exit": 0, "target": "x"},
            {"t": now, "verb": "verify", "exit": 3, "target": "x"}]   # newest wins
    c = ST.today_counts(rows, today)
    assert (c["files"], c["could_not_look"], c["good"]) == (1, 1, 0)
    rows.append({"t": now, "verb": "verify", "exit": 0, "target": "x"})
    assert ST.headline(ST.today_counts(rows, today)) == (
        "You checked 1 file today. Every one was checked to the end and held.", "ok")
    rows.append({"t": now, "verb": "reconcile", "exit": 1, "target": "y"})
    s, tone = ST.headline(ST.today_counts(rows, today))
    assert s == ("You checked 2 files today. One came back with a bad finding.") and tone == "bad"
