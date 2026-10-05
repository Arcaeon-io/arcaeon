# SPDX-License-Identifier: MIT
"""L3-04: the operator register page (`arcaeon register page`), a static view
of the register chain (arcaeon.prove.register) with the chain's own verdict on
top. Keys here are TEST-ONLY: generated in the test and thrown away. No
network; files only under tmp_path."""
from __future__ import annotations

import copy
import json
import os
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser

import pytest

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

from arcaeon import cli  # noqa: E402
from arcaeon import verdict as V  # noqa: E402
from arcaeon.prove import register as G  # noqa: E402
from arcaeon.prove import register_page as P  # noqa: E402
from arcaeon.prove.vet import receipts as R  # noqa: E402

T0 = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)
D = timedelta(days=1)
A = "acct:operator-a@arcaeon.io"
B = "acct:operator-b@arcaeon.io"
HOSTILE = '<script>alert("x")</script>&\'"'
ENDPOINT = "https://witness-a.example/v1"


def _key():
    seed = os.urandom(32)
    return seed, R.did_key(R.public_key_from_seed(seed))


@pytest.fixture
def op():
    """The TEST-ONLY register operator key."""
    return _key()


@pytest.fixture
def reg(op):
    """operator-a: a key, a chain, a witness endpoint. operator-b: a key
    revoked for key_compromise, then a second key."""
    rows = G.new_register()
    _, ka = _key()
    _, kb = _key()
    _, kb2 = _key()
    G.add(rows, op[0], member=A, what="key", value=ka, at=T0)
    G.add(rows, op[0], member=A, what="chain", value="operator-a-main", at=T0)
    G.add(rows, op[0], member=A, what="witness_endpoint", value=ENDPOINT, at=T0)
    G.add(rows, op[0], member=B, what="key", value=kb, at=T0 + D)
    G.revoke(rows, op[0], member=B, what="key", digest=G.thing_digest("key", kb),
             reason="key_compromise", at=T0 + 3 * D, compromised_since=T0 + 2 * D)
    G.add(rows, op[0], member=B, what="key", value=kb2, at=T0 + 3 * D)
    return {"rows": rows, "ka": ka, "kb": kb, "kb2": kb2}


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.attrs, self.text = [], [], []
        self._stack = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.extend(attrs)
        self._stack.append((tag, dict(attrs)))

    def handle_endtag(self, tag):
        if self._stack:
            self._stack.pop()

    def handle_data(self, data):
        self.text.append(data)


def _parse(page):
    p = _Tags()
    p.feed(page)
    return p


def _banner(page):
    """The text of the first verdict paragraph."""
    start = page.index('<p class="verdict">')
    return page[start:page.index("</p>", start)]


# --- the page, verified --------------------------------------------------------------------

def test_verified_page_names_operators_keys_head_endpoints(op, reg):
    page = P.render_page(reg["rows"], operator_keys=[op[1]])
    chk = G.check_register(reg["rows"], operator_keys=[op[1]])
    assert "VERIFIED" in _banner(page)
    assert page.index('<p class="verdict">') < page.index("operator-a")
    for s in (A, B, reg["ka"], reg["kb"], reg["kb2"], "operator-a-main", ENDPOINT,
              chk["head"], G.thing_digest("key", reg["ka"]), op[1]):
        assert s in page, s
    assert "6 rows" in page
    assert "publishing cadence: not stated" in page


def test_revoked_key_is_shown_as_revoked_with_reason_and_compromised_since(op, reg):
    page = P.render_page(reg["rows"], operator_keys=[op[1]])
    line = next(ln for ln in page.splitlines() if reg["kb"] in ln and "<tr>" in ln)
    assert "REVOKED" in line and "key_compromise" in line
    assert "2026-10-08T12:00:00Z" in line and "2026-10-07T12:00:00Z" in line
    live = next(ln for ln in page.splitlines() if reg["kb2"] in ln and "<tr>" in ln)
    assert "REVOKED" not in live and "current" in live
    rev = page[page.index("<h2>Revocations</h2>"):]
    assert reg["kb"] in rev.split("</table>")[0]
    assert "compromised since" in rev.split("</table>")[0]


def test_cannot_tell_section_is_near_the_end(op, reg):
    page = P.render_page(reg["rows"], operator_keys=[op[1]])
    i = page.index("<h2>What this page cannot tell you</h2>")
    assert i > page.index("<h2>Revocations</h2>")
    tail = page[i:]
    assert "who they claim" in tail and "never copied" in tail
    assert "arcaeon register page" in tail


# --- escaping and static -------------------------------------------------------------------

def test_hostile_values_are_escaped(op):
    rows = G.new_register()
    _, k = _key()
    G.add(rows, op[0], member=A, what="key", value=k, at=T0)
    G.add(rows, op[0], member=A, what="chain", value=HOSTILE, at=T0)
    G.add(rows, op[0], member=A, what="witness_endpoint",
          value="https://w.example/<script>alert(1)</script>", at=T0)
    page = P.render_page(rows, operator_keys=[op[1], HOSTILE])
    assert "VERIFIED" in _banner(page)
    assert "<script" not in page and HOSTILE not in page
    assert "&lt;script&gt;" in page
    assert "script" not in _parse(page).tags


def test_hostile_operator_name_is_escaped_and_reads_broken(op):
    row = {k: None for k in G.SIGNED}
    row.update(kind=G.ROW_KIND, v=G.ROW_VERSION, event="add",
               member=f"acct:{HOSTILE}@arcaeon.io", what="chain", value="c",
               digest=G.thing_digest("chain", "c"), at="2026-10-05T12:00:00Z")
    G.sign_row(row, op[0])
    bad_event = copy.deepcopy(row)
    bad_event.update(member=A, event=HOSTILE)
    G.sign_row(bad_event, op[0])
    for rows in ([row], [bad_event]):
        page = P.render_page(rows, operator_keys=[op[1]])
        assert "BROKEN" in _banner(page)
        assert "<script" not in page and HOSTILE not in page
        assert "script" not in _parse(page).tags


def test_page_is_static_no_script_no_fetch(op, reg):
    page = P.render_page(reg["rows"], operator_keys=[op[1]])
    p = _parse(page)
    for tag in ("script", "link", "img", "iframe", "object", "embed", "a", "form", "base"):
        assert tag not in p.tags, tag
    names = {k for k, _ in p.attrs}
    assert not names & {"src", "href", "action", "srcset"}
    assert not any(k.startswith("on") for k in names)
    for s in ("@import", "url(", "@font-face", "http://"):
        assert s not in page, s
    assert page.startswith("<!doctype html>") and '<meta charset="utf-8">' in page


def test_same_register_same_bytes(op, reg):
    a = P.render_page(reg["rows"], operator_keys=[op[1]])
    b = P.render_page(copy.deepcopy(reg["rows"]), operator_keys=[op[1]])
    assert a == b
    assert a.encode("utf-8") == b.encode("utf-8")


# --- BROKEN, COULD NOT LOOK ---------------------------------------------------------------

def test_broken_chain_shows_broken_banner_and_no_rows_past_the_break(op, reg):
    rows = copy.deepcopy(reg["rows"])
    rows[3]["value"] = reg["kb2"]      # a changed row: its signature no longer verifies
    page = P.render_page(rows, operator_keys=[op[1]])
    assert "BROKEN" in _banner(page)
    assert "row 3" in _banner(page)
    assert "VERIFIED" not in page
    for s in (reg["kb"], reg["kb2"], "key_compromise", "REVOKED"):
        assert s not in page, s
    assert "<h2>Operators</h2>" not in page
    assert "<h2>What this page cannot tell you</h2>" in page


def test_dropped_row_is_broken(op, reg):
    rows = copy.deepcopy(reg["rows"])
    del rows[1]
    page = P.render_page(rows, operator_keys=[op[1]])
    assert "BROKEN" in _banner(page) and "operator-a-main" not in page


def test_signed_by_a_key_you_did_not_name_is_broken(op, reg):
    _, other = _key()
    page = P.render_page(reg["rows"], operator_keys=[other])
    assert "BROKEN" in _banner(page)
    assert reg["ka"] not in page and "<h2>Operators</h2>" not in page


def test_no_operator_key_named_is_could_not_look(reg):
    page = P.render_page(reg["rows"])
    assert "COULD NOT LOOK" in _banner(page)
    assert reg["ka"] not in page and "<h2>Operators</h2>" not in page


def test_empty_register_is_could_not_look(op):
    page = P.render_page([], operator_keys=[op[1]])
    assert "COULD NOT LOOK" in _banner(page)
    assert "no register rows" in page
    assert "<h2>Operators</h2>" not in page
    assert P.render_page([], operator_keys=[op[1]]) == page


# --- the CLI -----------------------------------------------------------------------------------

def _write(path, rows):
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows),
                    encoding="utf-8", newline="\n")
    return path


def test_cli_writes_the_page_and_refuses_to_overwrite(op, reg, tmp_path, capsys):
    src = _write(tmp_path / "register.jsonl", reg["rows"])
    out = tmp_path / "page.html"
    rc = cli.main(["register", "page", str(src), "--operator-key", op[1], "--out", str(out)])
    assert rc == V.EXIT_GOOD
    o = capsys.readouterr().out
    assert "VERIFIED" in o and "page.html" in o
    page = out.read_bytes()
    assert page == P.render_page(reg["rows"], operator_keys=[op[1]],
                                 source="register.jsonl").encode("utf-8")
    assert b"\r\n" not in page
    assert str(tmp_path).encode("utf-8") not in page
    assert cli.main(["register", "page", str(src), "--operator-key", op[1],
                     "--out", str(out)]) == V.EXIT_USAGE
    assert out.read_bytes() == page


def test_cli_same_register_same_bytes(op, reg, tmp_path):
    src = _write(tmp_path / "register.jsonl", reg["rows"])
    for n in ("one.html", "two.html"):
        assert cli.main(["register", "page", str(src), "--operator-key", op[1],
                         "--out", str(tmp_path / n)]) == V.EXIT_GOOD
    assert (tmp_path / "one.html").read_bytes() == (tmp_path / "two.html").read_bytes()


def test_cli_json_array_is_read_too(op, reg, tmp_path):
    src = tmp_path / "register.json"
    src.write_text(json.dumps(reg["rows"]), encoding="utf-8")
    out = tmp_path / "p.html"
    assert cli.main(["register", "page", str(src), "--operator-key", op[1],
                     "--out", str(out)]) == V.EXIT_GOOD


def test_cli_broken_writes_the_page_and_exits_1(op, reg, tmp_path, capsys):
    rows = copy.deepcopy(reg["rows"])
    rows[2]["at"] = "2026-10-05T12:00:01Z"
    src = _write(tmp_path / "register.jsonl", rows)
    out = tmp_path / "page.html"
    rc = cli.main(["register", "page", str(src), "--operator-key", op[1], "--out", str(out)])
    assert rc == V.EXIT_BAD
    assert "BROKEN" in capsys.readouterr().out
    assert "BROKEN" in _banner(out.read_text(encoding="utf-8"))


def test_cli_empty_register_writes_could_not_look_and_exits_3(op, tmp_path):
    src = tmp_path / "register.jsonl"
    src.write_bytes(b"")
    out = tmp_path / "page.html"
    rc = cli.main(["register", "page", str(src), "--operator-key", op[1], "--out", str(out)])
    assert rc == V.EXIT_COULD_NOT_LOOK
    assert "COULD NOT LOOK" in _banner(out.read_text(encoding="utf-8"))


@pytest.mark.parametrize("body", [b"not json\n", b"{\"a\": 1}\n{oops\n", b"\xff\xfe"])
def test_cli_unreadable_file_is_could_not_look_nothing_written(body, tmp_path, capsys):
    src = tmp_path / "register.jsonl"
    src.write_bytes(body)
    out = tmp_path / "page.html"
    assert cli.main(["register", "page", str(src), "--out", str(out)]) == V.EXIT_COULD_NOT_LOOK
    assert not out.exists()
    assert "COULD NOT LOOK" in capsys.readouterr().err


def test_cli_missing_file_and_bad_usage(tmp_path, capsys):
    assert cli.main(["register", "page", str(tmp_path / "nope.jsonl"),
                     "--out", str(tmp_path / "p.html")]) == V.EXIT_COULD_NOT_LOOK
    assert not (tmp_path / "p.html").exists()
    assert cli.main(["register", "page"]) == V.EXIT_USAGE
    assert cli.main(["register", "frob"]) == V.EXIT_USAGE
    assert cli.main(["register", "page", "a", "b"]) == V.EXIT_USAGE
    capsys.readouterr()
    assert cli.main(["register", "--help"]) == V.EXIT_GOOD
    assert capsys.readouterr().out.startswith("usage: arcaeon register page")


def test_cli_without_out_prints_the_page(op, reg, tmp_path, capsys):
    src = _write(tmp_path / "register.jsonl", reg["rows"])
    assert cli.main(["register", "page", str(src), "--operator-key", op[1]]) == V.EXIT_GOOD
    cap = capsys.readouterr()
    assert cap.out == P.render_page(reg["rows"], operator_keys=[op[1]], source="register.jsonl")
    assert "VERIFIED" in cap.err
