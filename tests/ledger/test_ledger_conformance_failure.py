# SPDX-License-Identifier: MIT
"""Failure-conformance suite: does each verifier FAIL when handed a bad record?

Why this file exists. A peer study of the Sigstore ecosystem
(projects/online_business/PEER_STUDY_SIGSTORE_2026-09.md, section 6)
found that every high-impact public failure there was a VERIFIER saying
"verified" when it should have said "no", and that one such bug came back after
a refactor. Their conformance suite is phrased "does the client FAIL when given
a bad X", never "does it pass on a good one". A suite of happy paths cannot
tell a working checker from one that returns VERIFIED unconditionally.

So every test here feeds a verifier deliberately bad input and asserts the
answer is NOT the green one. "Not green" means, per verifier:

  verify_file / Ledger.verify   ok is not True and bool(result) is False
                                (False = broken, None = bounded/undetermined)
  WitnessStore.verify           ok is not True and bool(result) is False
  verify_against_witness        verdict != "consistent" and bool(v) is False
  Head.as_pin / publish_head    raise rather than mint a pin
  verify_artefact               never "live_match"; offline typed failures
                                never digest_ok / "digest_consistent"

BREAK-ARMS. For each verifier there is a test that swaps in a LYING verifier
(always green) and asserts the same checks raise on every case. If a check
ever stops catching the liar, the break-arm fails. A suite that has never been
watched failing against a lying verifier has not been shown to test anything.

KNOWN ACCEPTANCES are kept as tests and marked xfail(strict=True), each with a
reason naming whether it is a documented boundary of the design (a hash chain
alone cannot see it) or a finding. strict=True means that if a verifier starts
rejecting the case, the xfail turns into a failure and forces someone to
re-classify it, rather than silently passing.

Verifier code is NOT changed by this file. Run:
    py -m pytest test_conformance_failure.py -v
"""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import arcaeon.record.ledger as AL
from arcaeon.record.ledger import (Head, Ledger, UnverifiedLedgerError, VerifyResult,
                            authority, declare_break, publish_head)
from arcaeon.record.ledger import artefact as ART
from arcaeon.record.ledger import witness as W


# ---------------------------------------------------------------------------
# fixtures and helpers
# ---------------------------------------------------------------------------

N_ROWS = 6


def _mint(path: Path, n: int = N_ROWS) -> Ledger:
    log = Ledger(path)
    for i in range(n):
        auth = authority(f"agent-{i}", capability_version="v1") if i % 2 else None
        log.append({"tool": "search", "event": i, "result_ok": True,
                    "ts": f"2026-09-22T00:00:0{i}Z"}, authority=auth)
    return log


def _lines(p: Path) -> list[str]:
    return [ln for ln in p.read_text(encoding="utf-8").split("\n") if ln.strip()]


def _write(p: Path, lines: list[str], *, trailing: bool = True) -> None:
    p.write_text("\n".join(lines) + ("\n" if trailing else ""), encoding="utf-8")


def _edit_row(p: Path, idx: int, fn) -> None:
    ls = _lines(p)
    obj = json.loads(ls[idx])
    fn(obj)
    ls[idx] = json.dumps(obj, ensure_ascii=False)
    _write(p, ls)


def ledger_is_green(res: VerifyResult) -> bool:
    return res.ok is True or bool(res)


def _assert_ledger_rejects(p: Path, *, strict_too: bool = True) -> None:
    # Resolve the verifier through the module attribute AT CALL TIME, so the
    # break-arm's monkeypatch is what gets exercised.
    for strict in ((False, True) if strict_too else (False,)):
        res = AL.verify_file(p, strict=strict)
        assert not ledger_is_green(res), (
            f"verify_file(strict={strict}) said GREEN on bad input {p.name}: {res}")
        res2 = Ledger(p).verify(strict=strict)
        assert not ledger_is_green(res2), (
            f"Ledger.verify(strict={strict}) said GREEN on bad input {p.name}: {res2}")


# ---------------------------------------------------------------------------
# 1. LEDGER: verify_file / Ledger.verify
# ---------------------------------------------------------------------------
# Each builder writes a BAD ledger into dir `d` and returns its path.

def _b_tampered_payload(d):
    p = d / "l.jsonl"; _mint(p)
    _edit_row(p, 2, lambda o: o.__setitem__("event", "evil"))
    return p


def _b_tampered_ts(d):
    p = d / "l.jsonl"; _mint(p)
    _edit_row(p, 2, lambda o: o.__setitem__("ts", "2020-01-01T00:00:00Z"))
    return p


def _b_tampered_authority(d):
    # Preimage-coverage check (the /vow lesson: a field a reader assumes is
    # protected must actually be inside the hash). authority rides row 1.
    p = d / "l.jsonl"; _mint(p)
    _edit_row(p, 1, lambda o: o["authority"].__setitem__("principal", "root"))
    return p


def _b_added_field(d):
    p = d / "l.jsonl"; _mint(p)
    _edit_row(p, 3, lambda o: o.__setitem__("approved_by", "nobody"))
    return p


def _b_removed_field(d):
    p = d / "l.jsonl"; _mint(p)
    _edit_row(p, 3, lambda o: o.pop("result_ok"))
    return p


def _b_tampered_last_row(d):
    # The tail row has no successor; its own chain value is the only guard.
    p = d / "l.jsonl"; _mint(p)
    _edit_row(p, N_ROWS - 1, lambda o: o.__setitem__("result_ok", False))
    return p


def _b_chain_hex_flipped(d):
    p = d / "l.jsonl"; _mint(p)

    def flip(o):
        c = o["chain"]
        o["chain"] = c[:-1] + ("0" if c[-1] != "0" else "1")
    _edit_row(p, 2, flip)
    return p


def _b_chain_shortened(d):
    p = d / "l.jsonl"; _mint(p)
    _edit_row(p, 2, lambda o: o.__setitem__("chain", o["chain"][:16]))
    return p


def _b_chain_uppercased(d):
    p = d / "l.jsonl"; _mint(p)
    _edit_row(p, 2, lambda o: o.__setitem__("chain", o["chain"].upper()))
    return p


def _b_chain_null(d):
    p = d / "l.jsonl"; _mint(p)
    _edit_row(p, 3, lambda o: o.__setitem__("chain", None))
    return p


def _b_chain_non_string(d):
    p = d / "l.jsonl"; _mint(p)
    _edit_row(p, 3, lambda o: o.__setitem__("chain", 12345))
    return p


def _b_chain_removed_last(d):
    p = d / "l.jsonl"; _mint(p)
    _edit_row(p, N_ROWS - 1, lambda o: o.pop("chain"))
    return p


def _b_deleted_middle_row(d):
    p = d / "l.jsonl"; _mint(p)
    ls = _lines(p); del ls[2]; _write(p, ls)
    return p


def _b_deleted_first_row(d):
    p = d / "l.jsonl"; _mint(p)
    ls = _lines(p); del ls[0]; _write(p, ls)
    return p


def _b_reordered_rows(d):
    p = d / "l.jsonl"; _mint(p)
    ls = _lines(p); ls[2], ls[3] = ls[3], ls[2]; _write(p, ls)
    return p


def _b_reversed_file(d):
    p = d / "l.jsonl"; _mint(p)
    _write(p, list(reversed(_lines(p))))
    return p


def _b_duplicated_row(d):
    p = d / "l.jsonl"; _mint(p)
    ls = _lines(p); ls.insert(3, ls[2]); _write(p, ls)
    return p


def _b_replayed_last_row(d):
    p = d / "l.jsonl"; _mint(p)
    ls = _lines(p); ls.append(ls[-1]); _write(p, ls)
    return p


def _b_torn_tail(d):
    p = d / "l.jsonl"; _mint(p)
    raw = p.read_bytes().rstrip(b"\n")
    p.write_bytes(raw[: len(raw) - 20])          # cut inside the last row
    return p


def _b_truncated_mid_file(d):
    p = d / "l.jsonl"; _mint(p)
    raw = p.read_bytes()
    p.write_bytes(raw[: len(raw) // 2])          # arbitrary byte cut
    return p


def _b_unchained_row_after_chain(d):
    p = d / "l.jsonl"; _mint(p)
    ls = _lines(p); ls.insert(3, json.dumps({"tool": "search", "event": "x"})); _write(p, ls)
    return p


def _b_non_object_line(d):
    p = d / "l.jsonl"; _mint(p)
    ls = _lines(p); ls.insert(3, "[1, 2, 3]"); _write(p, ls)
    return p


def _b_scalar_line(d):
    p = d / "l.jsonl"; _mint(p)
    ls = _lines(p); ls.insert(3, "42"); _write(p, ls)
    return p


def _b_unparseable_line(d):
    p = d / "l.jsonl"; _mint(p)
    ls = _lines(p); ls.insert(3, "{not json"); _write(p, ls)
    return p


def _b_nesting_bomb(d):
    p = d / "l.jsonl"; _mint(p)
    ls = _lines(p); ls.insert(3, "[" * 200_000); _write(p, ls)
    return p


def _b_invalid_utf8(d):
    p = d / "l.jsonl"; _mint(p)
    raw = p.read_bytes()
    i = raw.index(b'"search"', len(raw) // 2)
    p.write_bytes(raw[:i + 1] + b"\xff\xfe" + raw[i + 3:])   # replace 2 bytes of a row
    return p


def _b_only_garbage(d):
    p = d / "l.jsonl"
    p.write_text("{not json\n", encoding="utf-8")
    return p


def _b_empty_file(d):
    p = d / "l.jsonl"; p.write_bytes(b"")
    return p


def _b_whitespace_only(d):
    p = d / "l.jsonl"; p.write_text("\n\n   \n\t\n", encoding="utf-8")
    return p


def _b_missing_file(d):
    return d / "never_written.jsonl"


def _b_directory_path(d):
    p = d / "a_directory.jsonl"; p.mkdir()
    return p


def _b_fabricated_prechain_prepend(d):
    # Fake "legacy" rows in front of a genuine chain. Non-strict must return
    # ok=None (bounded), never True; strict must return False.
    p = d / "l.jsonl"; _mint(p)
    fake = [json.dumps({"tool": "search", "event": f"fake-{i}"}) for i in range(3)]
    _write(p, fake + _lines(p))
    return p


def _b_all_unchained(d):
    p = d / "l.jsonl"
    _write(p, [json.dumps({"event": i}) for i in range(4)])
    return p


def _b_unchained_declaration_excuses_nothing(d):
    # A real break, plus a hand-echoed declaration WITHOUT a chain field.
    p = d / "l.jsonl"; _mint(p)
    ls = _lines(p); ls.insert(3, json.dumps({"tool": "oob"})); _write(p, ls)
    raw = ls[3].strip()
    import hashlib
    decl = {"op": "chain_break_declared", "orphan_line": 4,
            "orphan_sha256": hashlib.sha256(raw.encode()).hexdigest(), "why": "trust me"}
    ls.append(json.dumps(decl)); _write(p, ls)
    return p


def _b_declaration_wrong_sha(d):
    p = d / "l.jsonl"; _mint(p)
    ls = _lines(p); ls.insert(3, json.dumps({"tool": "oob"})); _write(p, ls)
    Ledger(p).append({"op": "chain_break_declared", "orphan_line": 4,
                      "orphan_sha256": "0" * 64, "why": "wrong bytes pinned"})
    return p


def _b_declared_then_orphan_edited(d):
    p = d / "l.jsonl"; _mint(p)
    ls = _lines(p); ls.insert(3, json.dumps({"tool": "oob"})); _write(p, ls)
    declare_break(p, 4, "incident: hand-appended")
    ls = _lines(p); ls[3] = json.dumps({"tool": "oob-EDITED"}); _write(p, ls)
    return p


def _b_honest_declared_break(d):
    # Correctly declared: must be BOUNDED (ok=None), never a full green.
    p = d / "l.jsonl"; _mint(p)
    ls = _lines(p); ls.insert(3, json.dumps({"tool": "oob"})); _write(p, ls)
    declare_break(p, 4, "incident: hand-appended", resume_prev=json.loads(ls[2])["chain"])
    return p


LEDGER_CASES = {
    "tampered_payload": _b_tampered_payload,
    "tampered_ts": _b_tampered_ts,
    "tampered_authority": _b_tampered_authority,
    "added_field": _b_added_field,
    "removed_field": _b_removed_field,
    "tampered_last_row": _b_tampered_last_row,
    "chain_hex_flipped": _b_chain_hex_flipped,
    "chain_shortened": _b_chain_shortened,
    "chain_uppercased": _b_chain_uppercased,
    "chain_null": _b_chain_null,
    "chain_non_string": _b_chain_non_string,
    "chain_removed_last_row": _b_chain_removed_last,
    "deleted_middle_row": _b_deleted_middle_row,
    "deleted_first_row": _b_deleted_first_row,
    "reordered_rows": _b_reordered_rows,
    "reversed_file": _b_reversed_file,
    "duplicated_row": _b_duplicated_row,
    "replayed_last_row": _b_replayed_last_row,
    "torn_tail": _b_torn_tail,
    "truncated_mid_file": _b_truncated_mid_file,
    "unchained_row_after_chain": _b_unchained_row_after_chain,
    "non_object_line": _b_non_object_line,
    "scalar_line": _b_scalar_line,
    "unparseable_line": _b_unparseable_line,
    "nesting_bomb": _b_nesting_bomb,
    "invalid_utf8": _b_invalid_utf8,
    "only_garbage": _b_only_garbage,
    "empty_file": _b_empty_file,
    "whitespace_only": _b_whitespace_only,
    "missing_file": _b_missing_file,
    "directory_path": _b_directory_path,
    "fabricated_prechain_prepend": _b_fabricated_prechain_prepend,
    "all_unchained": _b_all_unchained,
    "unchained_declaration_excuses_nothing": _b_unchained_declaration_excuses_nothing,
    "declaration_wrong_sha": _b_declaration_wrong_sha,
    "declared_then_orphan_edited": _b_declared_then_orphan_edited,
    "honest_declared_break_is_bounded_not_green": _b_honest_declared_break,
}


@pytest.mark.parametrize("case", sorted(LEDGER_CASES))
def test_ledger_rejects(case, tmp_path):
    _assert_ledger_rejects(LEDGER_CASES[case](tmp_path))


def test_ledger_rejects_the_red_ones_red(tmp_path):
    """Tamper cases must be RED (ok False), not merely bounded. A verifier that
    returned None for everything would pass test_ledger_rejects; this pins the
    red/bounded split for the cases that are unambiguous tampering."""
    must_be_red = ["tampered_payload", "tampered_authority", "deleted_middle_row",
                   "reordered_rows", "duplicated_row", "torn_tail",
                   "unchained_row_after_chain", "chain_hex_flipped",
                   "declaration_wrong_sha", "declared_then_orphan_edited",
                   "missing_file", "only_garbage"]
    for i, case in enumerate(must_be_red):
        d = tmp_path / str(i); d.mkdir()
        res = AL.verify_file(LEDGER_CASES[case](d))
        assert res.ok is False, f"{case}: expected ok=False, got {res}"
        assert res.first_break, f"{case}: a red verdict must name its break"


def test_ledger_tamper_does_not_cascade(tmp_path):
    p = _b_tampered_payload(tmp_path)
    assert AL.verify_file(p).breaks == 1


def test_head_carries_red_and_pin_refuses(tmp_path):
    p = _b_tampered_payload(tmp_path)
    h = Ledger(p).head()
    assert h.ok is False
    with pytest.raises(UnverifiedLedgerError):
        h.as_pin()
    store = W.WitnessStore(tmp_path / "w.jsonl")
    with pytest.raises(UnverifiedLedgerError):
        publish_head(store, "ns", Ledger(p))
    assert store.latest("ns") is None, "a refused publish must not land a pin"


def test_publish_refuses_empty_log(tmp_path):
    store = W.WitnessStore(tmp_path / "w.jsonl")
    p = tmp_path / "empty.jsonl"; p.write_bytes(b"")
    with pytest.raises(ValueError):
        publish_head(store, "ns", Ledger(p))


# --- known acceptances: kept, xfail(strict=True), reported -----------------

@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "DOCUMENTED BOUNDARY (module docstring 'Truncation'): cutting whole rows off "
    "the tail leaves a chain that verifies ok=True. A hash chain alone cannot see "
    "it; only an outside witness pin can (see test_witness_catches_truncation)."))
def test_ledger_whole_row_tail_truncation(tmp_path):
    p = tmp_path / "l.jsonl"; _mint(p)
    _write(p, _lines(p)[:-2])
    _assert_ledger_rejects(p)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "DOCUMENTED BOUNDARY ('Authorship'): a full re-mint from genesis with every "
    "chain recomputed verifies ok=True. Only an external head anchor defeats it "
    "(see test_witness_catches_remint)."))
def test_ledger_full_remint(tmp_path):
    p = tmp_path / "l.jsonl"; _mint(p)
    rows = [json.loads(ln) for ln in _lines(p)]
    p.unlink()
    log = Ledger(p)
    for r in rows:
        r.pop("chain"); r["event"] = f"rewritten-{r['event']}"
        log.append(r)
    _assert_ledger_rejects(p)


# FIXED 2026-09-22 (fix-false-yes-2026-09-22); formerly a strict xfail:
#   @pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
#       "FINDING (verify-side acceptance of tampered bytes): a duplicate key smuggled "
#       "INTO an honest row ahead of the real one -- {'event': 'evil', ..., 'event': 2} "
#       "-- verifies ok=True, because the chain is recomputed over Python's last-wins "
#       "parse. A first-wins reader (and several JSON libraries are) shows 'evil' "
#       "under a green verdict. The module docstring files this as a WRITE-side "
#       "boundary ('append() never produces one'), but the verifier is where it is "
#       "accepted: the line's bytes changed and the verdict stayed green."))
def test_ledger_duplicate_key_smuggle(tmp_path):
    p = tmp_path / "l.jsonl"; _mint(p)
    ls = _lines(p)
    assert ls[2].startswith("{")
    ls[2] = '{"event": "evil", ' + ls[2][1:]
    _write(p, ls)
    _assert_ledger_rejects(p)


# --- break-arm ------------------------------------------------------------

def _lying_verify_file(path, *, strict=False):
    return VerifyResult(ok=True, rows=1, chained=1)


@pytest.mark.parametrize("case", sorted(LEDGER_CASES))
def test_breakarm_ledger_suite_catches_lying_verifier(case, tmp_path, monkeypatch):
    p = LEDGER_CASES[case](tmp_path)
    monkeypatch.setattr(AL, "verify_file", _lying_verify_file)
    with pytest.raises(AssertionError):
        _assert_ledger_rejects(p)


def test_breakarm_pin_refusal_depends_on_verifier(tmp_path, monkeypatch):
    """If verify lies, publish_head mints a pin over a tampered log. The refusal
    test above would then fail -- proving it is testing the verdict, not luck."""
    p = _b_tampered_payload(tmp_path)
    monkeypatch.setattr(AL, "verify_file", _lying_verify_file)
    store = W.WitnessStore(tmp_path / "w.jsonl")
    publish_head(store, "ns", Ledger(p))          # no raise under the liar
    assert store.latest("ns") is not None


# ---------------------------------------------------------------------------
# 2. WITNESS STORE: WitnessStore.verify (the pin file's own chain)
# ---------------------------------------------------------------------------

def _store_with_pins(d, n=4) -> W.WitnessStore:
    store = W.WitnessStore(d / "w.jsonl")
    for i in range(1, n + 1):
        store.record("ns", Head(chain=f"{i:032x}", rows=i * 3, as_of="2026-09-22T00:00:00Z"))
    return store


def _edit_pin(store, idx, fn):
    ls = _lines(store.path)
    o = json.loads(ls[idx]); fn(o); ls[idx] = json.dumps(o)
    _write(store.path, ls)


def _s_edit_last_pin_rows(d):
    s = _store_with_pins(d); _edit_pin(s, -1, lambda o: o.__setitem__("rows", 999)); return s


def _s_edit_last_pin_chain(d):
    s = _store_with_pins(d); _edit_pin(s, -1, lambda o: o.__setitem__("chain", "f" * 32)); return s


def _s_edit_last_pin_drop_self(d):
    s = _store_with_pins(d)
    _edit_pin(s, -1, lambda o: (o.__setitem__("rows", 999), o.pop("self")))
    return s


def _s_edit_middle_pin(d):
    s = _store_with_pins(d); _edit_pin(s, 1, lambda o: o.__setitem__("rows", 1)); return s


def _s_edit_namespace(d):
    s = _store_with_pins(d); _edit_pin(s, 2, lambda o: o.__setitem__("namespace", "other")); return s


def _s_delete_middle_pin(d):
    s = _store_with_pins(d); ls = _lines(s.path); del ls[1]; _write(s.path, ls); return s


def _s_delete_first_pin(d):
    s = _store_with_pins(d); ls = _lines(s.path); del ls[0]; _write(s.path, ls); return s


def _s_reorder_pins(d):
    s = _store_with_pins(d); ls = _lines(s.path); ls[1], ls[2] = ls[2], ls[1]
    _write(s.path, ls); return s


def _s_duplicate_pin(d):
    s = _store_with_pins(d); ls = _lines(s.path); ls.insert(2, ls[1]); _write(s.path, ls); return s


def _s_unchained_after_chain(d):
    s = _store_with_pins(d); _edit_pin(s, 2, lambda o: o.pop("prev")); return s


def _s_forged_prev(d):
    s = _store_with_pins(d); _edit_pin(s, 2, lambda o: o.__setitem__("prev", "0" * 32)); return s


def _s_unparseable_line(d):
    s = _store_with_pins(d); ls = _lines(s.path); ls.insert(2, "{nope"); _write(s.path, ls); return s


def _s_non_object_line(d):
    s = _store_with_pins(d); ls = _lines(s.path); ls.insert(2, "[]"); _write(s.path, ls); return s


def _s_nesting_bomb(d):
    s = _store_with_pins(d); ls = _lines(s.path); ls.insert(2, "[" * 200_000)
    _write(s.path, ls); return s


def _s_torn_tail(d):
    s = _store_with_pins(d); raw = s.path.read_bytes().rstrip(b"\n")
    s.path.write_bytes(raw[:-15]); return s


def _s_empty(d):
    s = W.WitnessStore(d / "w.jsonl"); s.path.write_bytes(b""); return s


def _s_missing(d):
    return W.WitnessStore(d / "never.jsonl")


def _s_all_legacy(d):
    s = W.WitnessStore(d / "w.jsonl")
    _write(s.path, [json.dumps({"namespace": "ns", "rows": 3, "chain": "a" * 32})])
    return s


STORE_CASES = {
    "edit_last_pin_rows": _s_edit_last_pin_rows,
    "edit_last_pin_chain": _s_edit_last_pin_chain,
    "edit_last_pin_and_drop_self": _s_edit_last_pin_drop_self,
    "edit_middle_pin": _s_edit_middle_pin,
    "edit_namespace": _s_edit_namespace,
    "delete_middle_pin": _s_delete_middle_pin,
    "delete_first_pin": _s_delete_first_pin,
    "reorder_pins": _s_reorder_pins,
    "duplicate_pin": _s_duplicate_pin,
    "unchained_pin_after_chain": _s_unchained_after_chain,
    "forged_prev": _s_forged_prev,
    "unparseable_line": _s_unparseable_line,
    "non_object_line": _s_non_object_line,
    "nesting_bomb": _s_nesting_bomb,
    "torn_tail": _s_torn_tail,
    "empty_store": _s_empty,
    "missing_store": _s_missing,
    "all_legacy_unchained": _s_all_legacy,
}


def _assert_store_rejects(store) -> None:
    v = W.WitnessStore.verify(store)
    assert not (v.get("ok") is True or bool(v)), f"WitnessStore.verify said GREEN: {v}"


@pytest.mark.parametrize("case", sorted(STORE_CASES))
def test_witness_store_rejects(case, tmp_path):
    _assert_store_rejects(STORE_CASES[case](tmp_path))


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "DOCUMENTED BOUNDARY (WitnessStore docstring 'WHAT THE CHAIN STILL DOES NOT "
    "DO'): editing the LAST pin and recomputing its `self` digest verifies "
    "ok=True -- no successor links forward from the tail. Anyone with write "
    "access to the store can do this; the protection is host independence."))
def test_witness_store_tail_edit_with_recomputed_self(tmp_path):
    s = _store_with_pins(tmp_path)

    def forge(o):
        o["rows"] = 999
        o["self"] = W.WitnessStore._digest_record(o)
    _edit_pin(s, -1, forge)
    _assert_store_rejects(s)


def test_witness_store_refuses_backward_pin(tmp_path):
    s = _store_with_pins(tmp_path)
    with pytest.raises(ValueError):
        s.record("ns", Head(chain="a" * 32, rows=1, as_of="2026-09-22T00:00:00Z"))


def test_witness_store_refuses_future_stamp(tmp_path):
    s = W.WitnessStore(tmp_path / "w.jsonl")
    with pytest.raises(ValueError):
        s.record("ns", Head(chain="a" * 32, rows=3, as_of="2026-09-22T01:00:00Z"),
                 received_at="2026-09-22T00:00:00Z")
    with pytest.raises(ValueError):
        s.record("ns", Head(chain="a" * 32, rows=3, as_of="not-a-time"),
                 received_at="2026-09-22T00:00:00Z")


@pytest.mark.parametrize("case", sorted(STORE_CASES))
def test_breakarm_store_suite_catches_lying_verifier(case, tmp_path, monkeypatch):
    s = STORE_CASES[case](tmp_path)
    monkeypatch.setattr(W.WitnessStore, "verify",
                        lambda self: W.WitnessVerify(ok=True, pins=1, chained=1,
                                                     unchained=0, breaks=0, first_break=None))
    with pytest.raises(AssertionError):
        _assert_store_rejects(s)


# ---------------------------------------------------------------------------
# 3. OUTSIDE CHECK: verify_against_witness
# ---------------------------------------------------------------------------
# Each builder returns (store, namespace, ledger) that must NOT be "consistent".

def _pinned(d, n=N_ROWS):
    log = _mint(d / "l.jsonl", n)
    store = W.WitnessStore(d / "w.jsonl")
    publish_head(store, "ns", log)
    return store, log


def _a_truncated(d):
    store, log = _pinned(d)
    _write(log.path, _lines(log.path)[:-2])
    return store, "ns", log


def _a_remint(d):
    store, log = _pinned(d)
    rows = [json.loads(ln) for ln in _lines(log.path)]
    log.path.unlink()
    for r in rows:
        r.pop("chain"); r["event"] = f"rewritten-{r['event']}"
        log.append(r)
    return store, "ns", log


def _a_remint_same_length_last_row_only(d):
    store, log = _pinned(d)
    ls = _lines(log.path)
    last = json.loads(ls[-1]); last.pop("chain"); last["result_ok"] = False
    _write(log.path, ls[:-1])
    log.append(last)
    return store, "ns", log


def _a_local_tampered(d):
    store, log = _pinned(d)
    _edit_row(log.path, 2, lambda o: o.__setitem__("event", "evil"))
    return store, "ns", log


def _a_witness_tampered(d):
    store, log = _pinned(d)
    store.record("ns", Head(chain="b" * 32, rows=N_ROWS, as_of="2026-09-22T00:00:00Z"))
    _edit_pin(store, 0, lambda o: o.__setitem__("rows", 1))
    return store, "ns", log


def _a_no_pin(d):
    log = _mint(d / "l.jsonl")
    return W.WitnessStore(d / "w.jsonl"), "ns", log


def _a_wrong_namespace(d):
    store, log = _pinned(d)
    return store, "someone-else", log


def _a_zero_row_pin(d):
    log = _mint(d / "l.jsonl")
    store = W.WitnessStore(d / "w.jsonl")
    store.record("ns", Head(chain="genesis", rows=0, as_of="2026-09-22T00:00:00Z"))
    return store, "ns", log


def _a_non_int_rows_pin(d):
    log = _mint(d / "l.jsonl")
    store = W.WitnessStore(d / "w.jsonl")
    store.record("ns", Head(chain=log.head().chain, rows="6", as_of="2026-09-22T00:00:00Z"))
    return store, "ns", log


def _a_forged_pin_chain(d):
    log = _mint(d / "l.jsonl")
    store = W.WitnessStore(d / "w.jsonl")
    store.record("ns", Head(chain="c" * 32, rows=N_ROWS, as_of="2026-09-22T00:00:00Z"))
    return store, "ns", log


def _a_pin_ahead_of_log(d):
    log = _mint(d / "l.jsonl")
    store = W.WitnessStore(d / "w.jsonl")
    store.record("ns", Head(chain=log.head().chain, rows=N_ROWS + 5,
                            as_of="2026-09-22T00:00:00Z"))
    return store, "ns", log


def _a_log_deleted(d):
    store, log = _pinned(d)
    log.path.unlink()
    return store, "ns", log


def _a_log_emptied(d):
    store, log = _pinned(d)
    log.path.write_bytes(b"")
    return store, "ns", log


class _RemoteStoreNoVerify:
    """Hosted-client shape: exposes only latest(). Returns a forged pin."""
    def __init__(self, pin):
        self._pin = pin

    def latest(self, namespace):
        return self._pin


def _a_remote_forged_pin(d):
    log = _mint(d / "l.jsonl")
    return (_RemoteStoreNoVerify({"namespace": "ns", "rows": N_ROWS, "chain": "d" * 32}),
            "ns", log)


def _a_remote_pin_garbage(d):
    log = _mint(d / "l.jsonl")
    return _RemoteStoreNoVerify({"rows": None, "chain": None}), "ns", log


def _a_remote_pin_bool_rows(d):
    # bool is an int subclass in Python; rows=False must not act like a 0 that
    # slips past, nor like a valid count.
    log = _mint(d / "l.jsonl")
    return _RemoteStoreNoVerify({"rows": False, "chain": "genesis"}), "ns", log


AGAINST_CASES = {
    "truncated_log": _a_truncated,
    "reminted_log": _a_remint,
    "last_row_rewritten_and_rechained": _a_remint_same_length_last_row_only,
    "local_log_tampered": _a_local_tampered,
    "witness_file_tampered": _a_witness_tampered,
    "no_pin": _a_no_pin,
    "wrong_namespace": _a_wrong_namespace,
    "zero_row_pin": _a_zero_row_pin,
    "non_int_rows_pin": _a_non_int_rows_pin,
    "forged_pin_chain": _a_forged_pin_chain,
    "pin_ahead_of_log": _a_pin_ahead_of_log,
    "log_deleted": _a_log_deleted,
    "log_emptied": _a_log_emptied,
    "remote_store_forged_pin": _a_remote_forged_pin,
    "remote_store_garbage_pin": _a_remote_pin_garbage,
    "remote_store_bool_rows_pin": _a_remote_pin_bool_rows,
}


def _assert_against_rejects(store, ns, log) -> None:
    v = W.verify_against_witness(store, ns, log)
    assert v.verdict != "consistent" and not bool(v), (
        f"verify_against_witness said CONSISTENT on bad input: {v}")


@pytest.mark.parametrize("case", sorted(AGAINST_CASES))
def test_against_witness_rejects(case, tmp_path):
    _assert_against_rejects(*AGAINST_CASES[case](tmp_path))


def test_witness_catches_truncation(tmp_path):
    assert W.verify_against_witness(*_a_truncated(tmp_path)).verdict == "truncated"


def test_witness_catches_remint(tmp_path):
    assert W.verify_against_witness(*_a_remint(tmp_path)).verdict == "rewritten"


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "DOCUMENTED BOUNDARY (witness docstring: 'a pin constrains nothing about rows "
    "appended after it was taken'): with a STALE pin at row 6, rows 7..10 can be "
    "rewritten and re-chained and the verdict is 'consistent' (truthy, detail "
    "'has grown 4 row(s)'). The max gap between pins is the security parameter."))
def test_against_witness_stale_pin_post_pin_rewrite(tmp_path):
    store, log = _pinned(tmp_path)
    for i in range(4):
        log.append({"tool": "search", "event": 100 + i})
    ls = _lines(log.path)
    keep, tail = ls[:N_ROWS], [json.loads(x) for x in ls[N_ROWS:]]
    _write(log.path, keep)
    for r in tail:
        r.pop("chain"); r["event"] = "rewritten"
        log.append(r)
    _assert_against_rejects(store, "ns", log)


@pytest.mark.parametrize("case", sorted(AGAINST_CASES))
def test_breakarm_against_suite_catches_lying_verifier(case, tmp_path, monkeypatch):
    args = AGAINST_CASES[case](tmp_path)
    monkeypatch.setattr(W, "verify_against_witness",
                        lambda *a, **k: W.WitnessVerdict("consistent", "liar"))
    with pytest.raises(AssertionError):
        _assert_against_rejects(*args)


# ---------------------------------------------------------------------------
# 4. ARTEFACT: verify_artefact
# ---------------------------------------------------------------------------

def _good_url_artefact(body=b"the page as fetched"):
    import hashlib
    h = hashlib.sha256(body).hexdigest()
    return {"subject": {"name": "https://example.invalid/page", "digest": {"sha256": h}},
            "recipe": "sha256:raw-bytes:v1", "digest": f"sha256:raw-bytes:v1:{h}"}


def _mut(fn):
    a = _good_url_artefact(); fn(a); return a


ARTEFACT_OFFLINE_CASES = {
    "not_a_dict": lambda: ["not", "a", "dict"],
    "missing_digest": lambda: _mut(lambda a: a.pop("digest")),
    "digest_not_string": lambda: _mut(lambda a: a.__setitem__("digest", 12)),
    "digest_three_parts": lambda: _mut(lambda a: a.__setitem__("digest", "sha256:raw-bytes:abc")),
    "unknown_algorithm": lambda: _mut(lambda a: a.__setitem__(
        "digest", a["digest"].replace("sha256:", "md5:", 1))),
    "unknown_recipe": lambda: _mut(lambda a: a.__setitem__(
        "digest", a["digest"].replace("raw-bytes", "raw-bytez"))),
    "unknown_recipe_version": lambda: _mut(lambda a: a.__setitem__(
        "digest", a["digest"].replace(":v1:", ":v9:"))),
    "hex_too_short": lambda: _mut(lambda a: a.__setitem__("digest", a["digest"][:-2])),
    "hex_not_hex": lambda: _mut(lambda a: a.__setitem__("digest", a["digest"][:-2] + "zz")),
    "subject_digest_mismatch": lambda: _mut(lambda a: a["subject"]["digest"].__setitem__(
        "sha256", "0" * 64)),
    "subject_not_object": lambda: _mut(lambda a: a.__setitem__("subject", "x")),
    "subject_sha_not_string": lambda: _mut(lambda a: a["subject"]["digest"].__setitem__(
        "sha256", 5)),
}


def _assert_artefact_offline_rejects(a) -> None:
    out = ART.verify_artefact(a)
    assert out["digest_ok"] is False and out["verdict"] not in (
        "digest_consistent", "live_match"), f"verify_artefact accepted bad artefact: {out}"
    assert out["reason"] in ART.FAILURE_REASONS, out


@pytest.mark.parametrize("case", sorted(ARTEFACT_OFFLINE_CASES))
def test_artefact_offline_rejects(case):
    _assert_artefact_offline_rejects(ARTEFACT_OFFLINE_CASES[case]())


class _FakeResp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _patch_fetch(monkeypatch, body=None, exc=None):
    def fake(req, timeout=30):
        if exc is not None:
            raise exc
        return _FakeResp(body)
    monkeypatch.setattr(ART.urllib.request, "urlopen", fake)


@pytest.mark.parametrize("scenario", ["content_changed", "fetch_failed", "over_cap"])
def test_artefact_refetch_never_live_match_on_bad_content(scenario, monkeypatch):
    a = _good_url_artefact()
    if scenario == "content_changed":
        _patch_fetch(monkeypatch, body=b"the page, TAMPERED")
        out = ART.verify_artefact(a, refetch=True)
    elif scenario == "fetch_failed":
        _patch_fetch(monkeypatch, exc=OSError("network down"))
        out = ART.verify_artefact(a, refetch=True)
    else:
        _patch_fetch(monkeypatch, body=b"x" * 64)
        out = ART.verify_artefact(a, refetch=True, fetch_cap=10)
    assert out["verdict"] != "live_match", out


def test_artefact_refetch_happy_path_sanity(monkeypatch):
    """One positive control, so the refetch rejections above are shown to be
    about the content and not a refetch path that never matches anything."""
    _patch_fetch(monkeypatch, body=b"the page as fetched")
    assert ART.verify_artefact(_good_url_artefact(), refetch=True)["verdict"] == "live_match"


@pytest.mark.parametrize("case", sorted(ARTEFACT_OFFLINE_CASES))
def test_breakarm_artefact_suite_catches_lying_verifier(case, monkeypatch):
    a = ARTEFACT_OFFLINE_CASES[case]()
    monkeypatch.setattr(ART, "verify_artefact", lambda *x, **k: {
        "verdict": "digest_consistent", "digest_ok": True, "reason": None,
        "recipe": "sha256:raw-bytes:v1", "refetch": "skipped", "notes": []})
    with pytest.raises(AssertionError):
        _assert_artefact_offline_rejects(a)


# ---------------------------------------------------------------------------
# positive controls: the fixtures themselves are honest before mutation
# ---------------------------------------------------------------------------

def test_positive_control_fixtures_are_green(tmp_path):
    """Without this, every rejection above could be an artefact of a broken
    fixture (a mint that never verified), and the suite would prove nothing."""
    log = _mint(tmp_path / "l.jsonl")
    assert AL.verify_file(log.path).ok is True
    assert AL.verify_file(log.path, strict=True).ok is True
    (tmp_path / "s").mkdir()
    s = _store_with_pins(tmp_path / "s")
    assert s.verify().get("ok") is True
    d = tmp_path / "a"; d.mkdir()
    store, log2 = _pinned(d)
    assert W.verify_against_witness(store, "ns", log2).verdict == "consistent"
    assert ART.verify_artefact(_good_url_artefact())["verdict"] == "digest_consistent"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
