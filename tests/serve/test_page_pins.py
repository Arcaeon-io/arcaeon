"""The pins page: every pin in the pin files under the served root, with its
times and fingerprints, the pin file's own chain checked first, and one pin's
printable receipt with the command to check it yourself. A pin carries
fingerprints and times only, never a ledger's contents, so the page never
reads a ledger. Headless: urllib plus html.parser over a loopback server this
test starts and stops."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from arcaeon.record.ledger import Ledger
from arcaeon.record.ledger.witness import WitnessStore, publish_head
from arcaeon.serve import h_core
from arcaeon.serve.pages import common as C
from serve import _pages as P

#: Exactly the fields a pin carries (WitnessStore.record), as the page heads them.
PIN_COLUMNS = ["File", "Line", "Namespace", "Rows", "Chain",
               "Publisher's time (as_of)", "Witness's time (received_at)", ""]
SECRET = "the-ledger-content-that-must-never-show"


def _log(path, n):
    for i in range(n):
        res = h_core.log({"ledger": str(path), "fields": {"t": f"2026-09-27T10:0{i}:00Z",
                                                          "n": i, "note": SECRET}})
        assert res["exit"] == 0, res


def _pin(store, ns, ledger, later_s):
    """A pin whose witness clock reads `later_s` seconds from now (the witness
    refuses a publisher stamp from its own future)."""
    at = (datetime.now(timezone.utc) + timedelta(seconds=later_s)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return publish_head(store, ns, Ledger(str(ledger)), received_at=at)


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    r = tmp_path / "root"
    (r / "w").mkdir(parents=True)
    _log(r / "l.jsonl", 2)
    good = WitnessStore(r / "w" / "pins.jsonl")
    _pin(good, "team-a", r / "l.jsonl", 10)
    _log(r / "l.jsonl", 1)
    _pin(good, "team-a", r / "l.jsonl", 20)
    # an edited pin: the rows changed after it was recorded, so its own
    # digest no longer matches
    edited = r / "w" / "edited.jsonl"
    edited.write_bytes((r / "w" / "pins.jsonl").read_bytes())
    lines = edited.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["rows"] = 1
    edited.write_text("\n".join([json.dumps(first)] + lines[1:]) + "\n", encoding="utf-8")
    # a pin that fails the strict rules (rows 3.0): the file is unreadable
    (r / "w" / "loose.jsonl").write_text(
        json.dumps({"namespace": "x", "rows": 3.0, "chain": "genesis",
                    "as_of": None, "received_at": None}) + "\n", encoding="utf-8")
    # a pin file outside the root, never listed
    _pin(WitnessStore(tmp_path / "outside_pins.jsonl"), "outside", r / "l.jsonl",
         30)
    return r


@pytest.fixture()
def session(root):
    with P.running(root) as srv:
        yield srv, P.sign_in(srv)


def _files(tree):
    """{root-relative pin file: (verdict word, classes)} from the page."""
    out = {}
    for sec in P.by_class(tree, "pinfile"):
        name = sec.attrs["data-file"]
        b = P.by_class(sec, "verdict")[0]
        out[name] = (P.by_class(b, "verdict-word")[0].text(), b.classes)
    return out


def _pin_rows(tree):
    rows = []
    for table in P.by_class(tree, "pins"):
        for tr in P.by_tag(table, "tr")[1:]:
            rows.append([td.text() for td in P.by_tag(tr, "td")])
    return rows


def test_the_nav_names_the_pins_page():
    assert ("/pins", "Pins") in C.NAV_ITEMS


def test_lists_every_pin_file_under_the_root_only(session):
    srv, ck = session
    r = P.get(srv, "/pins", cookie=ck)
    assert r.status == 200 and "default-src 'self'" in r.headers["Content-Security-Policy"]
    files = _files(P.parse(r.text))
    assert sorted(files) == ["w/edited.jsonl", "w/loose.jsonl", "w/pins.jsonl"]
    assert "l.jsonl" not in files                      # a ledger is not a pin file
    assert "outside" not in r.text


def test_each_pin_shows_its_fields_and_fingerprints(session, root):
    srv, ck = session
    tree = P.parse(P.get(srv, "/pins", cookie=ck).text)
    heads = [th.text() for th in P.by_tag(P.by_class(tree, "pins")[0], "th")]
    assert heads == PIN_COLUMNS
    recs = WitnessStore(root / "w" / "pins.jsonl").history("team-a")
    rows = [row for row in _pin_rows(tree) if row[0] == "w/pins.jsonl"]
    assert [row[1:7] for row in rows] == [
        [str(i), "team-a", str(p["rows"]), p["chain"], p["as_of"] or "not recorded",
         p["received_at"]] for i, p in enumerate(recs, 1)]


def test_the_good_file_verifies_and_the_edited_one_is_broken(session):
    srv, ck = session
    files = _files(P.parse(P.get(srv, "/pins", cookie=ck).text))
    word, classes = files["w/pins.jsonl"]
    assert word == "VERIFIED" and "state-ok" in classes
    word, classes = files["w/edited.jsonl"]
    assert word == "BROKEN" and "state-bad" in classes and "state-ok" not in classes


def test_a_pin_failing_the_strict_rules_is_could_not_look_and_its_pins_are_not_listed(session):
    srv, ck = session
    r = P.get(srv, "/pins", cookie=ck)
    tree = P.parse(r.text)
    word, classes = _files(tree)["w/loose.jsonl"]
    assert word == "COULD NOT LOOK" and "state-unknown" in classes
    assert "state-ok" not in classes
    assert not [row for row in _pin_rows(tree) if row[0] == "w/loose.jsonl"]
    assert "strict pin rules" in r.text


def test_the_page_never_shows_a_ledgers_contents(session):
    srv, ck = session
    for path in ("/pins", "/pins?file=w/pins.jsonl&line=1"):
        r = P.get(srv, path, cookie=ck)
        assert r.status == 200 and P.by_class(P.parse(r.text), "pins")
        assert SECRET not in r.text


def test_the_page_says_a_pin_records_no_assistant(session):
    """A pin carries no assistant label and no assistant name, so the page
    names none and says so rather than invent one."""
    srv, ck = session
    text = " ".join(P.get(srv, "/pins", cookie=ck).text.split())
    assert "A pin records no assistant label and no assistant name" in text


def test_a_value_in_a_pin_is_escaped(session, root):
    store = WitnessStore(root / "w" / "html.jsonl")
    _pin(store, "<b>ns</b>", root / "l.jsonl", 30)
    srv, ck = session
    text = P.get(srv, "/pins", cookie=ck).text
    assert "<b>ns</b>" not in text and "&lt;b&gt;ns&lt;/b&gt;" in text


def test_one_pins_receipt_with_the_command_to_check_it(session, root):
    srv, ck = session
    r = P.get(srv, "/pins?file=w/pins.jsonl&line=2", cookie=ck)
    assert r.status == 200
    tree = P.parse(r.text)
    rec = WitnessStore(root / "w" / "pins.jsonl").history("team-a")[1]
    receipt = P.by_class(tree, "receipt")
    assert len(receipt) == 1
    fields = {dt.text(): dd.text() for dt, dd in zip(P.by_tag(receipt[0], "dt"),
                                                    P.by_tag(receipt[0], "dd"))}
    assert fields["Namespace"] == "team-a" and fields["Rows"] == str(rec["rows"])
    assert fields["Chain"] == rec["chain"] and fields["Pin digest (self)"] == rec["self"]
    assert fields["Witness's time (received_at)"] == rec["received_at"]
    cmd = P.by_class(tree, "check-yourself")[0].text()
    assert "arcaeon verify YOUR_LEDGER.jsonl --witness w/pins.jsonl --ns team-a" in cmd
    buttons = [b for b in P.by_tag(tree, "button") if "data-print" in b.attrs]
    assert len(buttons) == 1 and buttons[0].text() == "Print receipt"
    assert _files(tree)["w/pins.jsonl"][0] == "VERIFIED"


def test_a_receipt_from_a_broken_file_is_shown_broken(session):
    srv, ck = session
    tree = P.parse(P.get(srv, "/pins?file=w/edited.jsonl&line=1", cookie=ck).text)
    assert _files(tree)["w/edited.jsonl"][0] == "BROKEN"


@pytest.mark.parametrize("query", ["file=../outside_pins.jsonl&line=1",
                                   "file=w/../../outside_pins.jsonl&line=1"])
def test_a_file_outside_the_root_is_refused(session, query):
    srv, ck = session
    r = P.get(srv, "/pins?" + query, cookie=ck)
    assert r.status == 400 and "outside the folder" in r.text
    assert "outside" not in " ".join(c[0] for c in _pin_rows(P.parse(r.text)))
    assert '"outside"' not in r.text


@pytest.mark.parametrize("query,why", [
    ("file=w/pins.jsonl&line=9", "No pin on line 9"),
    ("file=w/pins.jsonl&line=x", "line must be a whole number"),
    ("file=w/pins.jsonl", "line must be a whole number"),
    ("file=l.jsonl&line=1", "is not a pin file"),
    ("file=w/loose.jsonl&line=1", "strict pin rules"),
    ("file=w/gone.jsonl&line=1", "is not a pin file"),
])
def test_a_receipt_that_cannot_be_shown_says_why(session, query, why):
    srv, ck = session
    r = P.get(srv, "/pins?" + query, cookie=ck)
    assert r.status == 400 and why in r.text
    assert not P.by_class(P.parse(r.text), "receipt")
