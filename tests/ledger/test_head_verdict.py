# SPDX-License-Identifier: MIT
"""A head() over a BROKEN log must not look like a head() over a NEW one.

Found 2026-09-19. `head()` called `verify_file()` and threw the verdict away,
so a file containing the single line `{this is not a ledger row` produced
`Head(chain='genesis', rows=0, ...)` -- byte-identical to the head of a log
that had never been written to -- and `as_pin()` happily minted a publishable
genesis pin over it. In a tamper-evidence product, "the log is damaged" and
"the log is new" printing the same is the wrong default: the pin is the one
artefact that goes somewhere outside your control, so it is the last place a
silent downgrade belongs.

The fix: `Head` carries the verdict (`ok`, `first_break`), and every path that
MINTS A PUBLISHABLE PIN refuses when the verdict is red. `head()` itself still
returns -- it is a read, and readers (dashboards, `verify_against_witness`,
the MCP `head_hash`) must keep working on a damaged log; that is exactly when
they need to see it.

Run: python test_head_verdict.py
"""
import json
import tempfile
from pathlib import Path

import pytest

from arcaeon.record.ledger import (
    Head, Ledger, UnverifiedLedgerError, WitnessStore, publish_head,
)


def _three_row_log(d) -> Ledger:
    log = Ledger(Path(d) / "log.jsonl")
    for i in range(3):
        log.append({"tool": "search", "n": i})
    return log


# -- red verdicts: carried on the head, refused at the pin --------------------

def test_corrupt_file_head_is_red_and_refuses_to_pin():
    """The exact bug report: one unparseable line."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "corrupt.jsonl"
        p.write_text("{this is not a ledger row", encoding="utf-8")
        h = Ledger(p).head()
        assert h.ok is False, h
        assert h.first_break == "line 1: unparseable", h.first_break
        with pytest.raises(UnverifiedLedgerError) as e:
            h.as_pin()
        # The refusal must SAY what broke, or the caller has to go re-derive it.
        assert "line 1: unparseable" in str(e.value), str(e.value)
    print("PASS corrupt file -> head().ok is False, as_pin() refuses naming line 1")


def test_truncated_mid_row_head_is_red_and_refuses_to_pin():
    """A crash mid-append leaves a half-written final line. Same class, and the
    one most likely to happen by accident rather than by malice."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "torn.jsonl"
        log = Ledger(p)
        for i in range(3):
            log.append({"tool": "pay", "amount": i})
        raw = p.read_text(encoding="utf-8")
        lines = raw.split("\n")
        # Cut the last row in half -- valid JSON prefix, no closing brace.
        lines[2] = lines[2][: len(lines[2]) // 2]
        p.write_text("\n".join(lines), encoding="utf-8")
        h = Ledger(p).head()
        assert h.ok is False, h
        assert h.first_break == "line 3: unparseable", h.first_break
        with pytest.raises(UnverifiedLedgerError):
            h.as_pin()
    print("PASS truncated-mid-row -> head().ok is False, as_pin() refuses")


def test_mid_file_edit_head_is_red_and_refuses_to_pin():
    """The classic tamper: edit row 2, leave its stale chain. verify() has
    always caught this; head() used to publish over it anyway."""
    with tempfile.TemporaryDirectory() as d:
        log = _three_row_log(d)
        p = log.path
        lines = p.read_text(encoding="utf-8").split("\n")
        obj = json.loads(lines[1])
        obj["n"] = 999
        lines[1] = json.dumps(obj, ensure_ascii=False)
        p.write_text("\n".join(lines), encoding="utf-8")
        h = log.head()
        assert h.ok is False and h.first_break == "line 2: chain mismatch", h
        with pytest.raises(UnverifiedLedgerError):
            h.as_pin()
    print("PASS mid-file edit -> head().ok is False, as_pin() refuses")


def test_head_itself_does_not_raise_on_a_broken_log():
    """Deliberate: head() is a READ. Dashboards, verify_against_witness() and
    the MCP head_hash field all call it, and a damaged log is precisely when
    they must keep answering. Only the PIN refuses."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "corrupt.jsonl"
        p.write_text("{this is not a ledger row", encoding="utf-8")
        h = Ledger(p).head()            # must not raise
        assert h.rows == 0 and h.chain == "genesis"
    print("PASS head() still returns on a broken log (only as_pin refuses)")


# -- green verdicts: unchanged behaviour -------------------------------------

def test_clean_three_row_ledger_pins_exactly_as_before():
    with tempfile.TemporaryDirectory() as d:
        log = _three_row_log(d)
        h = log.head()
        assert h.ok is True and h.first_break is None, h
        # chain + rows + pin string are the pre-change contract, untouched.
        assert h.rows == 3, h.rows
        tail = json.loads(log.path.read_text(encoding="utf-8").strip()
                          .split("\n")[-1])["chain"]
        assert h.chain == tail, (h.chain, tail)
        pin = h.as_pin()
        assert pin == (f"arcaeon-ledger head chain={h.chain} rows=3 "
                       f"as_of={h.as_of}"), pin
    print("PASS clean 3-row ledger: ok True, chain/rows/pin string unchanged")


def test_brand_new_ledger_pins_as_genesis():
    """A log that does not exist yet is not a damaged log. verify_file() calls
    the missing file `ok=False, unreadable: [Errno 2]` and a zero-row file
    `ok=None` (0.5.8's "absence of evidence is not evidence"), so head() has to
    tell those two apart from damage itself -- otherwise the fix breaks every
    caller that pins before the first append."""
    with tempfile.TemporaryDirectory() as d:
        absent = Ledger(Path(d) / "never-written.jsonl")
        h = absent.head()
        assert h.ok is True and h.first_break is None, h
        assert h.chain == "genesis" and h.rows == 0, h
        assert h.as_pin() == (f"arcaeon-ledger head chain=genesis rows=0 "
                              f"as_of={h.as_of}")

        p = Path(d) / "touched.jsonl"
        p.write_text("", encoding="utf-8")
        h2 = Ledger(p).head()
        assert h2.ok is True and h2.chain == "genesis" and h2.rows == 0, h2
        h2.as_pin()                      # must not raise
    print("PASS brand-new ledger (absent and zero-byte) pins as genesis, ok True")


def test_head_construction_stays_backwards_compatible():
    """Existing callers build Head positionally and by keyword (the witness
    tests do both). New fields default to the green, so nothing downstream
    has to learn about them to keep working."""
    positional = Head("abc123", 7, "2026-09-19T00:00:00Z")
    keyword = Head(chain="abc123", rows=7, as_of="2026-09-19T00:00:00Z")
    assert positional == keyword
    assert positional.ok is True and positional.first_break is None
    assert positional.as_pin().startswith("arcaeon-ledger head chain=abc123 ")
    print("PASS Head(...) positional/keyword construction and equality unchanged")


# -- the other publish path ---------------------------------------------------

def test_publish_head_refuses_an_unverified_ledger():
    """publish_head() is the OTHER thing that mints a pin, and it writes it to
    a witness -- the harder one to retract. It already refused a zero-row pin;
    it must refuse a red one for the same reason."""
    with tempfile.TemporaryDirectory() as d:
        log = _three_row_log(d)
        store = WitnessStore(Path(d) / "witness.jsonl")
        publish_head(store, "ns", log)           # healthy: still works
        lines = log.path.read_text(encoding="utf-8").split("\n")
        obj = json.loads(lines[1])
        obj["n"] = 999
        lines[1] = json.dumps(obj, ensure_ascii=False)
        log.path.write_text("\n".join(lines), encoding="utf-8")
        with pytest.raises(UnverifiedLedgerError) as e:
            publish_head(store, "ns", log)
        assert "line 2: chain mismatch" in str(e.value), str(e.value)
    print("PASS publish_head() refuses to witness an unverified ledger")


def test_unverified_error_is_catchable_as_valueerror():
    """Callers that already wrap publish_head in `except ValueError` (the
    zero-row refusal is one) must not start seeing an uncaught exception."""
    assert issubclass(UnverifiedLedgerError, ValueError)
    print("PASS UnverifiedLedgerError is a ValueError (old handlers still catch)")


# -- the planted must-fail arm ------------------------------------------------

def test_regression_arm_old_head_had_no_verdict_and_pinned_over_damage():
    """PLANTED MUST-FAIL ARM. Every assertion here is false against the OLD
    head(), which is the point: it proves this file goes red without the fix
    rather than passing vacuously.

    Demonstrated by running this file on the pre-change code
    (`git stash` / checkout of arcaeon_ledger/__init__.py): the import of
    `UnverifiedLedgerError` fails outright (ImportError), `hasattr(head, 'ok')`
    is False, and `Ledger(corrupt).head().as_pin()` returns
    `arcaeon-ledger head chain=genesis rows=0 as_of=...` -- a clean genesis pin
    minted over a file whose verify() said `ok=False, first_break='line 1:
    unparseable'`. That transcript is in the branch's work notes.
    """
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "corrupt.jsonl"
        p.write_text("{this is not a ledger row", encoding="utf-8")
        h = Ledger(p).head()
        assert hasattr(h, "ok"), "OLD head(): Head carried no verdict at all"
        assert hasattr(h, "first_break"), "OLD head(): no first_break on Head"
        minted = None
        try:
            minted = h.as_pin()
        except UnverifiedLedgerError:
            pass
        assert minted is None, (
            "OLD head(): as_pin() minted a genesis pin over a damaged log -- %r"
            % minted)
    print("PASS regression arm (red against the old head(), green against the new)")


if __name__ == "__main__":
    test_corrupt_file_head_is_red_and_refuses_to_pin()
    test_truncated_mid_row_head_is_red_and_refuses_to_pin()
    test_mid_file_edit_head_is_red_and_refuses_to_pin()
    test_head_itself_does_not_raise_on_a_broken_log()
    test_clean_three_row_ledger_pins_exactly_as_before()
    test_brand_new_ledger_pins_as_genesis()
    test_head_construction_stays_backwards_compatible()
    test_publish_head_refuses_an_unverified_ledger()
    test_unverified_error_is_catchable_as_valueerror()
    test_regression_arm_old_head_had_no_verdict_and_pinned_over_damage()
    print("\nALL PASS - a head over a broken log no longer looks like a head "
          "over a new one, and no pin is minted over damage.")
