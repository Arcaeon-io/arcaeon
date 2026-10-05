# SPDX-License-Identifier: MIT
"""L3-07a: the tally page shows WITHDRAWN as its own word and columns.

A reaction taken back by a signed exchange.withdraw row is counted apart in
the tally (`withdrawn` said / received). The text render prints those rows
only when a withdraw row is among the inputs; the HTML page now does the
same: its own columns, its own word in the per-ID notes, every value
escaped, and a page with no withdraw row is unchanged. Throwaway seeds in
tmp_path; no network."""
from __future__ import annotations

import base64
import copy
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

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
        seed = secrets.token_bytes(32)
        self.key = tmp / f"{name}.key"
        self.key.write_text(base64.b64encode(seed).decode("ascii") + "\n", encoding="ascii")
        self.did = R.did_key(R.public_key_from_seed(seed))
        self.log = tmp / f"{name}.jsonl"


def _rx(f, me, other, ex, word=V.VERIFIED, days=1.0, **kw):
    return X.react(me.log, key_file=me.key, exchange_id=ex, counterparty=other.did, file=f,
                   reaction=word, at=NOW - timedelta(days=days), **kw)


def _scene(tmp_path, withdraw=True):
    f = tmp_path / "deliverable.csv"
    f.write_bytes(b"id,grade\n1,A\n")
    a, b = Party(tmp_path, "a"), Party(tmp_path, "b")
    _rx(f, b, a, "e1")
    first = _rx(f, a, b, "e1")
    if withdraw:
        X.withdraw(a.log, key_file=a.key, row=first["row_digest"],
                   at=NOW - timedelta(hours=12), reason="sent the wrong file id")
    _rx(f, a, b, "e2")
    _rx(f, b, a, "e2")
    return T.build([a.log, b.log], now=NOW), a, b


def _head(page):
    thead = page.split("<thead>", 1)[1].split("</thead>", 1)[0]
    return [H.html.unescape(x) for x in re.findall(r"<th>(.*?)</th>", thead)]


def _rows(page):
    body = page.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    return [[H.html.unescape(c) for c in re.findall(r"<td[^>]*>(.*?)</td>", tr)]
            for tr in re.findall(r"<tr>(.*?)</tr>", body)]


def test_withdrawn_columns_and_word_are_on_the_page(tmp_path):
    r, a, b = _scene(tmp_path)
    page = H.render_html(r)
    head = _head(page)
    assert "withdrawn said" in head and "withdrawn received" in head
    assert head[-1] == "sentence"
    cols = {(row[0], row[1]): dict(zip(head, row)) for row in _rows(page)}
    assert cols[(a.did, "all")]["withdrawn said"] == "1"
    assert cols[(a.did, "all")]["withdrawn received"] == "0"
    assert cols[(b.did, "all")]["withdrawn received"] == "1"
    # its own word, per ID, in the notes
    assert f"{a.did}: WITHDRAWN: 1 reaction(s) this ID wrote were withdrawn" in page
    assert f"{b.did}: WITHDRAWN: 1 reaction(s) about this ID were withdrawn" in page
    # the definition is carried
    assert "withdrawn: reactions taken back entirely" in page


def test_withdrawn_values_are_escaped(tmp_path):
    r, a, _ = _scene(tmp_path)
    t = copy.deepcopy(r)
    i = next(x for x in t["ids"] if x["id"] == a.did)
    i["windows"]["all"]["withdrawn"]["said"] = HOSTILE
    page = H.render_html(t)
    assert "<script>" not in page
    assert H._e(HOSTILE) in page


def test_withdrawn_precedes_retracted_in_the_note(tmp_path):
    r, a, _ = _scene(tmp_path)
    t = copy.deepcopy(r)
    i = next(x for x in t["ids"] if x["id"] == a.did)
    i["windows"]["all"]["retracted"]["said"] = 1
    page = H.render_html(t)
    note = next(ln for ln in page.splitlines() if f"{a.did}: WITHDRAWN" in ln)
    assert "retracted" in note
    assert note.index("WITHDRAWN") < note.index("retracted")


def test_no_withdraw_row_page_is_unchanged(tmp_path):
    r, _, _ = _scene(tmp_path, withdraw=False)
    page = H.render_html(r)
    assert "withdrawn" not in page.lower()
    assert _head(page) == list(H.COLUMNS)
