# SPDX-License-Identifier: MIT
"""Gaps the 2026-10-10 must-fail pass closed: each test here fails with one or
more planted defects (named in its docstring by mutant id) and passes on the
real code. None of them touches the code under test.

The pass aimed at one failure: a broken, edited or truncated record reading as
verified. Mutant ids and the full table are in the pass's report.
"""
import json

import pytest

from arcaeon.record.adapter import _ledger as adapter_ledger
from arcaeon.record.ledger import Ledger


# --- the adapter's FALLBACK verifier (no arcaeon-ledger importable) -------------
# tests/ledger/test_adapter_fallback_verify.py covers this path, but it imports
# `adapter.arcaeon_adapter`, which does not exist, so it is never collected.

@pytest.fixture
def fallback(monkeypatch):
    monkeypatch.setattr(adapter_ledger, "_HAVE_LEDGER", False)
    return adapter_ledger


def _fallback_log(tmp_path, fallback, n=3):
    log = tmp_path / "seam.jsonl"
    lg = fallback.open_ledger(str(log))
    for i in range(n):
        lg.append({"i": i})
    return log


def test_fallback_empty_seam_log_is_not_a_green(tmp_path, fallback):
    """F01, F06: an empty seam log checked nothing; ok is None and the verdict is falsy."""
    log = tmp_path / "seam.jsonl"
    log.write_text("", encoding="utf-8")
    v = fallback.verify_seam_log(str(log))
    assert v.ok is None and not v and v.verified_scope == "empty"


def test_fallback_one_edited_value_is_a_break(tmp_path, fallback):
    """F02, F04: one value edited after the write is one break, and one break is red."""
    log = _fallback_log(tmp_path, fallback)
    assert fallback.verify_seam_log(str(log)).ok is True
    lines = log.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[1])
    row["i"] = 41
    lines[1] = json.dumps(row)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    v = fallback.verify_seam_log(str(log))
    assert v.ok is False and v.breaks == 1 and v.first_break == "line 2: chain mismatch"


def test_fallback_unparseable_line_is_a_break(tmp_path, fallback):
    """F03: a torn or garbage line is counted as a break, not stepped over."""
    log = _fallback_log(tmp_path, fallback, n=1)
    with log.open("a", encoding="utf-8") as fh:
        fh.write('{"i": 1, "chain": \n')
    v = fallback.verify_seam_log(str(log))
    assert v.ok is False and v.breaks == 1 and "unparseable" in v.first_break


def test_fallback_unreadable_seam_log_is_not_verified(tmp_path, fallback):
    """F05: a path that cannot be read (here a directory) is never ok."""
    v = fallback.verify_seam_log(str(tmp_path))
    assert v.ok is False and not v


# --- verify_file ----------------------------------------------------------------

def test_a_row_the_chain_rule_cannot_hash_is_a_break_not_a_green(tmp_path, monkeypatch):
    """L07: the unhashable-row branch. On CPython 3.13 no file reaches it (every
    line json parses also hashes), so the fault is injected: when the chain rule
    raises on a row, the verdict is red and names the line, never ok."""
    import arcaeon.record.ledger as L
    p = tmp_path / "a.jsonl"
    for i in range(3):
        Ledger(p).append({"op": i})
    real = L._chain

    def chain(prev, obj):
        if obj.get("op") == 1:
            raise TypeError("planted: this row cannot be hashed")
        return real(prev, obj)

    monkeypatch.setattr(L, "_chain", chain)
    r = L.verify_file(p)
    assert r.ok is False and r.breaks == 1
    assert r.first_break == "line 2: unhashable row (TypeError)"


# --- Ledger.head ----------------------------------------------------------------

def test_head_of_a_bounded_log_carries_none_not_a_green(tmp_path):
    """L22: a log whose first row carries no chain verifies bounded (ok=None);
    its head must say the same, never ok=True. It still pins (bounded is not
    broken)."""
    p = tmp_path / "a.jsonl"
    p.write_text(json.dumps({"legacy": "row with no chain"}) + "\n", encoding="utf-8")
    Ledger(p).append({"op": 1})
    h = Ledger(p).head()
    assert h.ok is None and h.rows == 2
    assert "rows=2" in h.as_pin()


def test_head_of_a_path_that_cannot_be_read_is_red_not_a_fresh_genesis(tmp_path):
    """L24: only FileNotFoundError is the never-written state. A path under a
    regular file (stat raises NotADirectoryError) cannot be read; its head is
    red and refuses to pin instead of pinning a fresh genesis."""
    from arcaeon.record.ledger import UnverifiedLedgerError
    f = tmp_path / "a-file"
    f.write_text("not a directory", encoding="utf-8")
    h = Ledger(f / "ledger.jsonl").head()
    assert h.ok is False
    with pytest.raises(UnverifiedLedgerError):
        h.as_pin()


# --- the witness pin file -------------------------------------------------------

def test_witness_refuses_a_pin_one_row_below_its_high_water(tmp_path):
    """W03: a witness never goes backward, not even by one row: cut the last row
    off a pinned log and re-pin, and the pin is refused."""
    from arcaeon.record.ledger import WitnessStore, publish_head
    p, store = tmp_path / "a.jsonl", WitnessStore(tmp_path / "pins.jsonl")
    for i in range(5):
        Ledger(p).append({"op": i})
    publish_head(store, "ns", Ledger(p))
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
    p.write_text("".join(lines[:4]), encoding="utf-8")
    with pytest.raises(ValueError, match="monotonic violation"):
        publish_head(store, "ns", Ledger(p))
    assert store.latest("ns")["rows"] == 5
