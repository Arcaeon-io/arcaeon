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


def test_an_edited_only_pin_is_witness_broken_not_consistent(tmp_path):
    """W14: one pin in the file, edited to match a truncated log without
    recomputing its self digest: the witness fails its own chain, so no
    comparison runs and the verdict is witness_broken, never consistent."""
    from arcaeon.record.ledger import (WitnessStore, chain_at, publish_head,
                                       verify_against_witness)
    p, pins = tmp_path / "a.jsonl", tmp_path / "pins.jsonl"
    store = WitnessStore(pins)
    for i in range(5):
        Ledger(p).append({"op": i})
    publish_head(store, "ns", Ledger(p))
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
    p.write_text("".join(lines[:3]), encoding="utf-8")       # truncate to 3 rows
    pin = json.loads(pins.read_text(encoding="utf-8"))
    pin.update(rows=3, chain=chain_at(p, 3))                 # edit the pin to agree
    pins.write_text(json.dumps(pin) + "\n", encoding="utf-8")
    v = verify_against_witness(store, "ns", Ledger(p))
    assert v.verdict == "witness_broken" and not v


def test_a_pin_differing_only_in_its_last_hex_char_is_rewritten(tmp_path):
    """W19: the witnessed chain is compared in full. A properly recorded pin whose
    chain differs from the log's only in the final hex character is rewritten."""
    from arcaeon.record.ledger import Head, WitnessStore, verify_against_witness
    p = tmp_path / "a.jsonl"
    for i in range(3):
        Ledger(p).append({"op": i})
    real = Ledger(p).head()
    last = "0" if real.chain[-1] != "0" else "1"
    store = WitnessStore(tmp_path / "pins.jsonl")
    store.record("ns", Head(chain=real.chain[:-1] + last, rows=real.rows, as_of=real.as_of))
    assert store.verify()["ok"] is True
    assert verify_against_witness(store, "ns", Ledger(p)).verdict == "rewritten"


# --- reconcile ------------------------------------------------------------------

def _tape_pair(tmp_path, n=3):
    import arcaeon.prove.reconcile as R
    from arcaeon.record.ledger import digest_json
    paths = {}
    for side in ("agent", "tool"):
        p = tmp_path / f"{side}.tape.jsonl"
        lg = Ledger(p)
        for k in range(1, n + 1):
            lg.append({"evt": "tape_call", "tape": R.TAPE_FORMAT, "side": side,
                       "ns": f"demo-{side}", "idx": k, "tool": "echo",
                       "req": digest_json({"name": "echo", "arguments": {"n": k}}),
                       "resp": digest_json({"result": k}), "status": "ok"})
        paths[side] = p
    return paths["agent"], paths["tool"]


def test_reconcile_pin_head_is_compared_in_full(tmp_path):
    """C15: a pin whose chain differs from the tape's head only in its last hex
    character is ALTERED (head_differs), not an agreeing pin."""
    import arcaeon.prove.reconcile as R
    from arcaeon.record.ledger import chain_at
    a, t = _tape_pair(tmp_path)
    real = chain_at(a, 3)
    pin = tmp_path / "pin.json"
    pin.write_text(json.dumps({"side": "agent", "rows": 3,
                               "chain": real[:-1] + ("0" if real[-1] != "0" else "1")}),
                   encoding="utf-8")
    r = R.reconcile(a, t, pin_path=pin)
    assert r.verdict == R.ALTERED and r.pins_checked[0]["result"] == "head_differs"


def test_reconcile_with_a_missing_pin_file_could_not_look(tmp_path):
    """C17: --pin naming a file that is not there is COULD NOT LOOK (missing),
    never MATCHED over two agreeing tapes."""
    import arcaeon.prove.reconcile as R
    a, t = _tape_pair(tmp_path)
    assert R.reconcile(a, t).verdict == R.MATCHED
    r = R.reconcile(a, t, pin_path=tmp_path / "no-such-pin.json")
    assert r.verdict == R.COULD_NOT_LOOK and r.reason_word == "missing"


def test_reconcile_side_pin_is_held_against_a_tape_emptied_after_the_pin(tmp_path):
    """C19: both tapes emptied after the agent side pinned 3 calls. An empty tape
    names no side, so the agent pin is held against it: MISSING (the pin is the
    proof calls were removed), not COULD NOT LOOK over two empty tapes."""
    import arcaeon.prove.reconcile as R
    from arcaeon.record.ledger import chain_at
    a, t = _tape_pair(tmp_path)
    pin = tmp_path / "pin.json"
    pin.write_text(json.dumps({"side": "agent", "rows": 3, "chain": chain_at(a, 3)}),
                   encoding="utf-8")
    a.write_text("", encoding="utf-8")
    t.write_text("", encoding="utf-8")
    r = R.reconcile(a, t, pin_path=pin)
    assert r.verdict == R.MISSING


def test_reconcile_a_tape_that_mixes_sides_could_not_look(tmp_path):
    """C20: a chained tape whose rows say two different sides is refused (COULD
    NOT LOOK), never lined up as if it were one side's record."""
    import arcaeon.prove.reconcile as R
    a, t = _tape_pair(tmp_path)
    rows = [json.loads(x) for x in a.read_text(encoding="utf-8").splitlines()]
    a.unlink()
    for k, row in enumerate(rows):
        row.pop("chain")
        row.pop("ts")
        if k == 1:
            row["side"] = "tool"
        Ledger(a).append(row)
    r = R.reconcile(a, t)
    assert r.verdict == R.COULD_NOT_LOOK and "mixes sides" in r.reason


def test_reconcile_main_pin_with_no_path_exits_could_not_look(tmp_path, capsys):
    """C21: `reconcile a b --pin` with no path prints COULD_NOT_LOOK and exits 3."""
    import arcaeon.prove.reconcile as R
    a, t = _tape_pair(tmp_path)
    assert R.main([str(a), str(t), "--pin"]) == 3
    assert json.loads(capsys.readouterr().out)["verdict"] == R.COULD_NOT_LOOK


# --- receipts -------------------------------------------------------------------

def _receipt(tmp_path, ledger):
    from arcaeon.record.receipt.core import build_receipt
    return build_receipt("test", {"what": "x"}, [{"name": "c", "status": "pass"}],
                         {"proves": ["p"], "does_not_prove": ["q"]},
                         ledger_path=ledger, namespace="ns", witness=False, anchor=False)


def test_receipt_against_a_bounded_ledger_is_not_ok(tmp_path):
    """K05: the receipt's ledger has an unchained row the chain cannot speak for
    (verify ok=None). The ledger check is not 'consistent' and the receipt is not ok."""
    from arcaeon.record.receipt.core import verify_receipt
    led = tmp_path / "receipts.jsonl"
    led.write_text(json.dumps({"legacy": "no chain"}) + "\n", encoding="utf-8")
    rc = _receipt(tmp_path, led)
    res = verify_receipt(rc, ledger_path=led)
    assert res["body_digest_ok"] is True
    assert res["ledger"]["status"] != "consistent" and res["ok"] is False


def test_receipt_file_with_a_duplicate_key_is_never_ok(tmp_path):
    """K07: the receipt file carries a key twice. Even when the last-wins parse
    recomputes to its digest, verify_receipt(source_text=...) is not ok."""
    from arcaeon.record.receipt.core import verify_receipt
    rc = _receipt(tmp_path, tmp_path / "receipts.jsonl")
    text = json.dumps(rc)
    dup = text.replace('"kind": "test"', '"kind": "other", "kind": "test"', 1)
    assert dup != text
    res = verify_receipt(json.loads(dup), source_text=dup)
    assert res["body_digest_ok"] is True and res.get("duplicate_keys")
    assert res["ok"] is False
