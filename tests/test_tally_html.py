# SPDX-License-Identifier: MIT
"""A14: the static tally page (`arcaeon tally html`). Facts columns only, the
sentence on every row, no score. Throwaway seeds in tmp_path; no network."""
from __future__ import annotations

import base64
import copy
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import exchange_log as X
from arcaeon.prove import tally as T
from arcaeon.prove import tally_html as H

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

NOW = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
HOSTILE = '<script>alert("x")</script>&\'"'


class Party:
    def __init__(self, tmp: Path, name: str):
        from arcaeon.prove.vet import receipts as R
        self.seed = secrets.token_bytes(32)
        self.key = tmp / f"{name}.key"
        self.key.write_text(base64.b64encode(self.seed).decode("ascii") + "\n", encoding="ascii")
        self.did = R.did_key(R.public_key_from_seed(self.seed))
        self.log = tmp / f"{name}.jsonl"


def _react(f, me, other, ex, word=V.VERIFIED, days=1.0):
    X.react(me.log, key_file=me.key, exchange_id=ex, counterparty=other.did, file=f,
            reaction=word, at=NOW - timedelta(days=days))


@pytest.fixture
def tally(tmp_path):
    f = tmp_path / "deliverable.csv"
    f.write_bytes(b"id,grade\n1,A\n")
    a, b, c = (Party(tmp_path, n) for n in "abc")
    for n in range(3):
        _react(f, a, b, f"ex-{n}", days=40 if n == 0 else 1)
        _react(f, b, a, f"ex-{n}", days=40 if n == 0 else 1)
    _react(f, c, a, "ex-c", V.BROKEN)
    _react(f, a, c, "ex-c")
    return T.build([a.log, b.log, c.log], now=NOW)


def _strings(o):
    if isinstance(o, dict):
        for v in o.values():
            yield from _strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _strings(v)
    elif isinstance(o, str) and len(o) > 3:
        yield o


class _Cells(HTMLParser):
    """tbody rows as lists of cell text, plus every tag and attribute seen."""

    def __init__(self):
        super().__init__()
        self.rows, self.tags, self.attrs, self._in_body, self._cell = [], [], [], False, None

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.extend(attrs)
        if tag == "tbody":
            self._in_body = True
        elif tag == "tr" and self._in_body:
            self.rows.append([])
        elif tag in ("td", "th") and self._in_body:
            self._cell = []

    def handle_endtag(self, tag):
        if tag == "tbody":
            self._in_body = False
        elif tag in ("td", "th") and self._cell is not None:
            self.rows[-1].append("".join(self._cell).strip())
            self._cell = None

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)


def _parse(page: str) -> _Cells:
    p = _Cells()
    p.feed(page)
    return p


def test_every_id_window_is_a_row_in_tally_order_with_the_sentence(tally):
    page = H.render_html(tally)
    p = _parse(page)
    names = [w["name"] for w in tally["windows"]]
    want = [(i["id"], n) for i in tally["ids"] for n in names]
    assert len(p.rows) == len(want) and want
    assert [(r[0], r[1]) for r in p.rows] == want
    for r in p.rows:
        assert r[-1] == T.SENTENCE


def test_columns_are_the_tally_facts_and_values_match_render(tally):
    p = _parse(H.render_html(tally))
    head = H.COLUMNS
    labels = [lab for lab, _ in T._ROWS]
    assert [c for c in head if c in labels] == labels
    for r, (i, n) in zip(p.rows, [(i, n) for i in tally["ids"]
                                  for n in [w["name"] for w in tally["windows"]]]):
        cells = dict(zip(head, r))
        for lab, fn in T._ROWS:
            assert cells[lab] == fn(i["windows"][n]), (lab, n)


def test_verdict_and_unrated_are_text(tally):
    page = H.render_html(tally)
    assert f"tally {tally['verdict']}: " in page
    p = _parse(page)
    unrated = [i for i in tally["ids"] if i["unrated"]]
    assert unrated
    col = H.COLUMNS.index("unrated")
    for r in p.rows:
        i = next(x for x in tally["ids"] if x["id"] == r[0])
        assert r[col] == ("unrated: " + "; ".join(i["unrated_because"]) if i["unrated"]
                          else "no")
    assert "BROKEN" in page


def test_no_score_rank_grade_or_colour(tally):
    page = H.render_html(tally)
    # what the page adds of its own: every value carried from the tally taken out
    strings = sorted({s for s in _strings(tally)}, key=len, reverse=True)
    own = page
    for s in strings:
        own = own.replace(H._e(s), "")
    own = own.lower()
    for word in ("score", "rank", "grade", "best", "worst", "rating", "%", "sort"):
        assert word not in own, word
    assert [c for c in H.COLUMNS if re.search("score|rank|grade|rating", c)] == []
    assert not re.search(r"color\s*:\s*(red|green|#)", page.split("</style>")[1])
    assert "class=\"good" not in page and "class=\"bad" not in page


def test_self_contained_no_script_no_fetch(tally):
    page = H.render_html(tally)
    p = _parse(page)
    assert "script" not in p.tags and "link" not in p.tags and "img" not in p.tags
    assert not any(k in ("src", "href") for k, _ in p.attrs)
    assert "http://" not in page and "https://" not in page and "@import" not in page
    assert page.startswith("<!doctype html>") and "<style>" in page


def test_hostile_alias_and_did_are_escaped(tally):
    t = copy.deepcopy(tally)
    t["ids"][0]["id"] = HOSTILE
    t["ids"][0]["unrated"], t["ids"][0]["unrated_because"] = True, [HOSTILE]
    t["aliases"] = [{"old": HOSTILE, "new": HOSTILE, "applied": False, "finding": HOSTILE}]
    t["chains"][0]["log"] = HOSTILE
    t["reason"] = HOSTILE
    page = H.render_html(t)
    assert "<script>" not in page and HOSTILE not in page
    assert "&lt;script&gt;" in page
    p = _parse(page)
    assert "script" not in p.tags
    assert p.rows[0][0] == HOSTILE        # the parser reads it back as text


def test_same_input_same_bytes(tally):
    assert H.render_html(tally) == H.render_html(copy.deepcopy(tally))


def test_cli_writes_one_file_and_refuses_to_overwrite(tally, tmp_path, capsys):
    src = tmp_path / "tally.json"
    src.write_text(json.dumps(tally), encoding="utf-8")
    out = tmp_path / "tally.html"
    assert cli.main(["tally", "html", str(src), "--out", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == H.render_html(tally)
    assert cli.main(["tally", "html", str(src), "--out", str(out)]) == 2
    capsys.readouterr()
    assert cli.main(["tally", "html", str(src)]) == 0
    assert capsys.readouterr().out.rstrip("\n") == H.render_html(tally).rstrip("\n")


@pytest.mark.parametrize("body", ["not json", "[1, 2]", '{"kind": "other"}',
                                  '{"kind": "arcaeon.tally/v1", "ids": "x"}'])
def test_cli_input_not_a_tally_is_could_not_look(tmp_path, body, capsys):
    src = tmp_path / "t.json"
    src.write_text(body, encoding="utf-8")
    out = tmp_path / "o.html"
    assert cli.main(["tally", "html", str(src), "--out", str(out)]) == 3
    assert not out.exists()
    assert cli.main(["tally", "html", str(tmp_path / "gone.json")]) == 3
    assert cli.main(["tally", "html"]) == 2
