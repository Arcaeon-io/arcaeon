# SPDX-License-Identifier: MIT
"""A09: the tally chain's pin statement checked against the witness verifier's rules.

`tally_chain.pin_statement` says it reproduces the operator's v2 pin statement
field for field. The judge here is a FROZEN copy of the rules in the operator's
bridge/witness/verify_pins.py at commit 25a88340
(tests/fixtures/verify_pins_rules_25a88340.py), so this test never reads the
other repo. A statement tally_chain builds must pass every rule verify_pins
applies to a statement and its chain file; a tampered sample must fail both
sides. No network, no keys, no live pin: every file is in tmp_path."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest

from arcaeon import verdict as V
from arcaeon.prove import tally_chain as TC
from arcaeon.record import row as ROW
from arcaeon.record.ledger import Ledger

FIXTURE = Path(__file__).parent / "fixtures" / "verify_pins_rules_25a88340.py"
STATED = "2026-10-04T12:00:00+00:00"


def _load_vp():
    spec = importlib.util.spec_from_file_location("verify_pins_rules_25a88340", FIXTURE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


VP = _load_vp()


@pytest.fixture(autouse=True)
def _temp_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


def make_log(tmp_path: Path, n: int = 3) -> Path:
    log = tmp_path / "TALLY_CHAIN.jsonl"
    led = Ledger(log)
    for i in range(n):
        # non-ASCII on purpose: both sides hash with ensure_ascii=False
        led.append({"kind": "probe", "n": i, "note": "café ✓"})
    return log


def verify_pins_judges(raw: bytes, st: dict, statement_bytes: bytes) -> list[str]:
    """Every verify_pins rule a statement and its chain file must pass, as a
    list of failures (empty = verify_pins would accept this statement over this
    chain file): step 1 shape and canonical form, step 2 chain_values_sha256 /
    rows / tip over the values series, step 5 the recompute walk, the rows
    1..n values and the W18 LF-canonical file_sha256 of the pinned prefix."""
    bad = []
    why = VP._statement_problem(st)
    if why:
        return [f"shape: {why}"]
    if VP.canonical_bytes(st) != statement_bytes:
        bad.append("statement bytes are not canonical")
    walk = VP.walk_chain(raw)
    if walk["unparseable_row"] or walk["first_break_row"]:
        bad.append(f"walk breaks: {walk['unparseable_row'] or walk['first_break_row']}")
    vals, n = walk["values"], st["rows"]
    if len(vals) < n:
        return bad + ["TRUNCATED"]
    if VP.values_sha256(vals[:n]) != st["chain_values_sha256"]:
        bad.append("chain_values_sha256")
    if vals[n - 1] != st["tip"]:
        bad.append("tip")
    if st.get("file_sha256_of") != VP.FILE_SHA256_OF:
        bad.append("file_sha256_of")
    elif VP.lf_prefix_sha256(raw, walk, n) != st["file_sha256"]:
        bad.append("file_sha256 (re-serialized)")
    return bad


def tally_judges(tmp_path: Path, log: Path, st: dict) -> str:
    sp = tmp_path / f"statement-{TC.statement_sha256(st)[:12]}.json"
    sp.write_bytes(TC.statement_canonical(st).encode("utf-8"))
    return TC.verify(log, statement=sp)["statement"]["verdict"]


# --- the sample: the two agree -------------------------------------------------------------

def test_rule_constants_agree():
    assert TC.PIN_STATEMENT_FIELDS == VP.PIN_FIELDS
    assert TC.SHA256_OF == VP.FILE_SHA256_OF
    assert TC.LISTING_FIELD == VP.LISTING_FIELD
    assert TC.PIN_STATEMENT_KIND == 2


def test_chain_rule_agrees(tmp_path):
    log = make_log(tmp_path)
    prev = "genesis"
    for line in log.read_bytes().splitlines():
        obj = VP._loads(line.decode("utf-8"))
        claimed = obj.pop("chain")
        assert VP.chain_step(prev, obj) == claimed == ROW.chain(prev, obj)
        prev = claimed


def test_statement_agrees_on_sample(tmp_path):
    log = make_log(tmp_path)
    st = TC.pin_statement(log, stated_at=STATED)
    sbytes = TC.statement_canonical(st).encode("utf-8")
    assert sbytes == VP.canonical_bytes(st)
    assert TC.statement_sha256(st) == hashlib.sha256(VP.canonical_bytes(st)).hexdigest()
    assert VP._statement_problem(st) is None and TC._statement_problem(st) is None
    assert verify_pins_judges(log.read_bytes(), st, sbytes) == []
    assert tally_judges(tmp_path, log, st) == V.VERIFIED
    walk = VP.walk_chain(log.read_bytes())
    assert walk["values"] == TC._chain_values(TC._lines(TC._lf(log.read_bytes())))


def test_agree_on_a_crlf_checkout(tmp_path):
    log = make_log(tmp_path)
    st = TC.pin_statement(log, stated_at=STATED)
    log.write_bytes(log.read_bytes().replace(b"\n", b"\r\n"))
    assert verify_pins_judges(log.read_bytes(), st, VP.canonical_bytes(st)) == []
    assert tally_judges(tmp_path, log, st) == V.VERIFIED
    # and a statement built on the CRLF copy is the same statement
    assert TC.pin_statement(log, stated_at=STATED) == st


def test_agree_on_an_older_statement_after_appends(tmp_path):
    log = make_log(tmp_path, 2)
    st = TC.pin_statement(log, stated_at=STATED)
    Ledger(log).append({"kind": "probe", "n": 9, "note": "later"})
    assert verify_pins_judges(log.read_bytes(), st, VP.canonical_bytes(st)) == []
    assert tally_judges(tmp_path, log, st) == V.VERIFIED


def test_agree_with_prev_pin_and_listing_field_shape():
    st = {"chain": "arcaeon-tally", "chain_values_sha256": "a" * 64, "file_sha256": "b" * 64,
          "file_sha256_of": "lf", "prev_pin_sha256": "c" * 64, "rows": 1, "stated_at": STATED,
          "tip": "d" * 32, "v": 2}
    assert VP._statement_problem(st) is None and TC._statement_problem(st) is None
    st[TC.LISTING_FIELD] = "e" * 64
    assert VP._statement_problem(st) is None and TC._statement_problem(st) is None


# --- tampered samples: the two disagree with the sample, and agree with each other -----------

def test_reserialized_row_fails_both(tmp_path):
    log = make_log(tmp_path)
    st = TC.pin_statement(log, stated_at=STATED)
    lines = log.read_bytes().split(b"\n")
    lines[0] = lines[0].replace(b'", "', b'",  "', 1)    # same parse, same chain values
    log.write_bytes(b"\n".join(lines))
    assert VP.walk_chain(log.read_bytes())["first_break_row"] is None
    assert verify_pins_judges(log.read_bytes(), st, VP.canonical_bytes(st)) == \
        ["file_sha256 (re-serialized)"]
    assert tally_judges(tmp_path, log, st) == V.BROKEN


def test_edited_row_fails_both(tmp_path):
    log = make_log(tmp_path)
    st = TC.pin_statement(log, stated_at=STATED)
    log.write_bytes(log.read_bytes().replace(b'"n": 1', b'"n": 7', 1))
    assert any(b.startswith("walk breaks") for b in
               verify_pins_judges(log.read_bytes(), st, VP.canonical_bytes(st)))
    assert TC.verify(log)["verdict"] == V.BROKEN


@pytest.mark.parametrize("field,value,want", [
    ("tip", "0" * 32, "tip"),
    ("chain_values_sha256", "0" * 64, "chain_values_sha256"),
    ("file_sha256", "0" * 64, "file_sha256 (re-serialized)"),
])
def test_tampered_statement_fails_both(tmp_path, field, value, want):
    log = make_log(tmp_path)
    st = dict(TC.pin_statement(log, stated_at=STATED), **{field: value})
    assert want in verify_pins_judges(log.read_bytes(), st, VP.canonical_bytes(st))
    assert tally_judges(tmp_path, log, st) == V.BROKEN


@pytest.mark.parametrize("change", [
    {"file_sha256_of": "raw"}, {"v": 1}, {"rows": 0}, {"rows": True}, {"tip": "XYZ"},
    {"prev_pin_sha256": "short"}, {"extra": 1}, {"chain": ""},
])
def test_bad_shape_refused_by_both(tmp_path, change):
    log = make_log(tmp_path)
    st = dict(TC.pin_statement(log, stated_at=STATED), **change)
    assert VP._statement_problem(st) is not None
    assert TC._statement_problem(st) is not None


def test_non_canonical_statement_bytes_fail_verify_pins(tmp_path):
    log = make_log(tmp_path)
    st = TC.pin_statement(log, stated_at=STATED)
    pretty = __import__("json").dumps(st, indent=1).encode("utf-8")
    assert "statement bytes are not canonical" in verify_pins_judges(log.read_bytes(), st, pretty)


# --- the one place they genuinely disagree ---------------------------------------------------

@pytest.mark.xfail(strict=True, reason=(
    "MISMATCH (A09): a tally chain file holding blank lines after its last row. "
    "tally_chain.pin_statement sets file_sha256 = sha256 of the WHOLE LF-canonical file "
    "(trailing blank lines included); verify_pins (walk_chain ends + prefix_sha, 25a88340) "
    "and tally_chain's own _check_statement hash only the prefix through the end of row n. "
    "So verify_pins would call that statement BROKEN re-serialized. Not fixed here: "
    "changing either side's semantics is out of scope for A09."))
def test_trailing_blank_line_statement_agrees(tmp_path):
    log = make_log(tmp_path)
    log.write_bytes(log.read_bytes() + b"\n")
    st = TC.pin_statement(log, stated_at=STATED)
    assert verify_pins_judges(log.read_bytes(), st, VP.canonical_bytes(st)) == []
