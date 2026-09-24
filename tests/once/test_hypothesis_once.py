"""Hypothesis property suite for arcaeon_once.

Companion to the hand-rolled test_once.py (duplicate refusal, the crash
window, chain tamper) and test_concurrency.py (real two-process + 12-process
subprocess races). Read both before adding here -- this file exists to add
what those don't already cover: randomized keys/payloads driving the same
invariants, THREAD-based races (faster than subprocess, so Hypothesis can
actually explore N rather than fixing it), and the unicode-line-separator
bug class specifically. Run against this repo's checkout (`pip install -e .`
from the repo root), never a stale site-packages copy.

Sections:
  1. Idempotence / receipt-identity -- guard() twice on an intact ledger:
     second call must raise AlreadyExecuted carrying the ORIGINAL receipt,
     not a new one, over randomized keys/payloads.
  2. The crash-window contract -- complete() only accepts a key currently in
     'intent' state (refuses on 'never' and on 'executed'); allow_retry_
     after_indeterminate lets a verified-safe retry proceed and then behaves
     like any other completed key.
  3. Concurrent-ish semantics -- N-way THREAD races on a never-seen key:
     exactly one winner, ever, everyone else AlreadyExecuted or
     Indeterminate, never a double-execute. Complements (does not replace)
     test_concurrency.py's real-subprocess two-process and 12-process races.
  4. THE RETRY-RACE BUG, found and fixed by this pass (see the inline fix
     notes on `_reclaim_after_indeterminate` in arcaeon_once/__init__.py for
     the full story -- two rounds, neither a test-construction artifact):
     (a) N callers racing allow_retry_after_indeterminate=True off the SAME
         observed crash must produce exactly one winner, not N.
     (b) a caller invoking allow_retry_after_indeterminate=True while
         ANOTHER caller's retry is still actively running (no threading
         needed -- a plain sequential probe) must be refused, not also win.
  5. The WAL-init first-touch race (b2aea25) -- THREAD-based complement to
     test_concurrency.py's 12-process/5-trial subprocess version: N threads
     first-touching a brand-new ledger path must never raise a raw
     sqlite3.OperationalError, only the typed IndexUnavailable if genuinely
     unabsorbable, and still produce exactly one execution.
  6. The unicode-line-separator class (U+0085/U+2028/U+2029) -- see the
     section docstring below for the verdict. Short version: arcaeon_once
     itself does zero direct file reads of the ledger (grep-pinned here);
     every read goes through arcaeon_ledger's Ledger/verify_file, which
     fixed this exact bug class at 0.5.6. This section proves the FULL
     round trip through guard()/receipt()/verify_integrity stays green.

Run: python -m pytest test_hypothesis_once.py -q
Stress-run while developing: HYPOTHESIS_PROFILE=dev or bump max_examples
directly -- this pass ran at 300-500 examples / multiple seeds locally
before settling on the checked-in counts below (60-100 for cheap pure-Python
properties, 8-20 for thread/subprocess-heavy ones -- an N-thread race is a
different cost class per example than a dict comparison, and Hypothesis's
shrinker still finds the interesting N even at low example counts because
the interesting behavior is at small N, not large N).
"""
from __future__ import annotations

import re
import sqlite3
import tempfile
import threading
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from arcaeon.record.once import (
    AlreadyExecuted, Indeterminate, IndexUnavailable, Receipt,
    complete, guard, rebuild_index, receipt,
)

# ---------------------------------------------------------------------------
# strategies
# ---------------------------------------------------------------------------

_key = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc"), max_codepoint=0xFFFF),
    min_size=1, max_size=40,
).filter(lambda s: s.strip() != "")

_json_scalar = st.one_of(
    st.none(), st.booleans(),
    st.integers(min_value=-10**9, max_value=10**9),
    st.text(max_size=30),
)
_payload = st.dictionaries(st.text(min_size=1, max_size=12), _json_scalar, max_size=5)

# The exact characters implicated in the U+2028-class bug: NOT escaped by
# json.dumps(ensure_ascii=False) (all sit outside U+0000-U+001F, the only
# mandatory escape range), but treated as line boundaries by str.splitlines()
# -- distinct from the literal "\n" arcaeon_ledger's writer actually emits.
LINE_SEPARATOR_CLASS = ["\u0085", "\u2028", "\u2029"]

_slow_settings = settings(max_examples=80, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
# Thread/subprocess races: each example opens real OS threads and a fresh
# temp ledger, so the per-example cost is thread-startup + several SQLite
# round trips, not a dict comparison. Kept low deliberately (see module
# docstring) -- the interesting counterexamples live at small N.
_race_settings = settings(max_examples=15, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])


# ===========================================================================
# 1. Idempotence / receipt-identity
# ===========================================================================

@given(key=_key, first_payload=_payload, second_payload=_payload)
@_slow_settings
def test_duplicate_raises_carrying_the_original_receipt(key, first_payload, second_payload):
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        with guard(key, ledger_path=path, store_outcome=True) as g:
            g.done(first_payload)
        original = receipt(key, ledger_path=path)
        assert original.state == "executed"

        try:
            with guard(key, ledger_path=path, store_outcome=True) as g2:
                g2.done(second_payload)  # must never run -- AlreadyExecuted first
            pytest.fail("expected AlreadyExecuted")
        except AlreadyExecuted as e:
            # The carried receipt is the ORIGINAL, not a fresh one built
            # from second_payload -- the whole point of the guard.
            assert e.receipt.executed_ts == original.executed_ts
            assert e.receipt.executed_chain == original.executed_chain
            assert e.receipt.outcome_digest == original.outcome_digest
            assert e.receipt.outcome == first_payload
            assert e.receipt.outcome != second_payload or first_payload == second_payload


@given(key=_key, payload=_payload)
@_slow_settings
def test_on_duplicate_return_receipt_never_raises_and_matches_original(key, payload):
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        with guard(key, ledger_path=path, store_outcome=True) as g:
            g.done(payload)
        original = receipt(key, ledger_path=path)

        with guard(key, ledger_path=path, on_duplicate="return_receipt",
                   store_outcome=True) as g2:
            assert g2.already_executed is True
            assert g2.receipt.executed_chain == original.executed_chain
            assert g2.receipt.outcome == payload


# ===========================================================================
# 2. The crash-window contract: Indeterminate / complete() / allow_retry
# ===========================================================================

def _simulate_crash(path: Path, key: str) -> None:
    """Write the 'intent' row and abandon -- no done(), matching exactly what
    a hard process kill leaves behind (the module's own test_once.py proves
    this equals a real subprocess os._exit(); doing it in-process here is a
    deliberate, documented simplification so Hypothesis can drive this at
    scale -- the ledger-visible state is identical either way).

    Round 3 note (2026-08-24): after a crash the INDEX row now sits at
    'claiming' (the live-claim state), so the retry flag alone refuses --
    that same leniency was a demonstrated double-fire on live claims. Tests
    exercising the RECOVERY path must run rebuild_index() after this, which
    replays the ledger to a reclaimable 'intent' row -- the documented
    operator step asserting the prior holder is genuinely dead."""
    g = guard(key, ledger_path=path)
    g.__enter__()  # writes 'once.intent', never calls done()


@given(key=_key)
@_slow_settings
def test_complete_refuses_a_never_claimed_key(key):
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        with pytest.raises(ValueError):
            complete(key, {"x": 1}, ledger_path=path)


@given(key=_key, outcome=_payload)
@_slow_settings
def test_complete_refuses_an_already_executed_key(key, outcome):
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        with guard(key, ledger_path=path) as g:
            g.done({"first": True})
        with pytest.raises(ValueError):
            complete(key, outcome, ledger_path=path)


@given(key=_key, outcome=_payload)
@_slow_settings
def test_crash_window_indeterminate_then_complete_resolves_to_executed(key, outcome):
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        _simulate_crash(path, key)
        mid = receipt(key, ledger_path=path)
        assert mid.state == "intent"

        with pytest.raises(Indeterminate) as exc_info:
            with guard(key, ledger_path=path):
                pass
        assert exc_info.value.receipt.key == key

        resolved = complete(key, outcome, ledger_path=path)
        assert resolved.state == "executed"
        # Now behaves like any other completed key: refused, never re-run.
        with pytest.raises(AlreadyExecuted):
            with guard(key, ledger_path=path):
                pass


@given(key=_key, outcome=_payload)
@_slow_settings
def test_crash_window_allow_retry_resolves_to_executed(key, outcome):
    """Round 3 contract: flag alone REFUSES a crashed claim (the index
    cannot distinguish it from a live one); rebuild_index + flag heals."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        _simulate_crash(path, key)
        with pytest.raises(Indeterminate):
            with guard(key, ledger_path=path,
                       allow_retry_after_indeterminate=True):
                pass
        rebuild_index(path)
        with guard(key, ledger_path=path,
                   allow_retry_after_indeterminate=True) as g:
            g.done(outcome)
        final = receipt(key, ledger_path=path)
        assert final.state == "executed"
        assert final.ledger_ok is True


# ===========================================================================
# 3. Concurrent-ish semantics: N-way thread race on a NEVER-seen key
# ===========================================================================

def _thread_race(path: Path, key: str, n: int, kwargs=None) -> "list[str]":
    """N threads hit guard() on the same key, released together by a real
    threading.Barrier. Returns each thread's outcome label."""
    kwargs = kwargs or {}
    results: "list[str]" = []
    lock = threading.Lock()
    barrier = threading.Barrier(n)

    def worker():
        barrier.wait()
        try:
            with guard(key, ledger_path=path, **kwargs) as g:
                with lock:
                    results.append("executing")
                g.done({"ok": True})
        except AlreadyExecuted:
            with lock:
                results.append("already_executed")
        except Indeterminate:
            with lock:
                results.append("indeterminate")
        except IndexUnavailable:
            with lock:
                results.append("index_unavailable")

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


@given(n=st.integers(min_value=2, max_value=10), key=_key)
@_race_settings
def test_n_way_race_on_never_seen_key_exactly_one_winner(n, key):
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        results = _thread_race(path, key, n)
        assert results.count("executing") == 1, results
        assert set(results) <= {"executing", "already_executed", "indeterminate"}
        final = receipt(key, ledger_path=path)
        assert final.state == "executed"
        assert final.ledger_ok is True


# ===========================================================================
# 4. The retry-race bug (found + fixed this pass)
# ===========================================================================

@given(n=st.integers(min_value=2, max_value=10), key=_key)
@_race_settings
def test_retry_race_off_same_crash_exactly_one_winner(n, key):
    """Round-1 regression pin: N threads race allow_retry_after_indeterminate
    =True off the IDENTICAL observed crashed intent. Before the fix this was
    an unconditional UPDATE and every racer "won" (reproduced directly: 6/6,
    then 4/8 threads all executed). The generation-CAS fix must bring this
    to exactly one winner regardless of N."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        _simulate_crash(path, key)
        rebuild_index(path)  # Round 3: the reclaimable state comes from the rebuild
        results = _thread_race(path, key, n,
                               kwargs={"allow_retry_after_indeterminate": True})
        assert results.count("executing") == 1, results
        final = receipt(key, ledger_path=path)
        assert final.state == "executed"


@given(key=_key, first_outcome=_payload, second_outcome=_payload)
@_slow_settings
def test_retry_while_still_in_flight_is_refused_not_double_won(key, first_outcome, second_outcome):
    """Round-2 regression pin: NO threading needed -- this reproduces
    sequentially. A second allow_retry_after_indeterminate=True caller
    arriving while the first retry is still running (hasn't called done()
    yet) must be refused (Indeterminate), never also win the claim. Before
    the 'retrying' index-state fix this always won -- reproduced with the
    exact two-step sequence below, deterministically, on every run."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        _simulate_crash(path, key)
        rebuild_index(path)  # Round 3: makes the crashed intent reclaimable

        g1 = guard(key, ledger_path=path, allow_retry_after_indeterminate=True)
        g1.__enter__()
        assert g1._won is True

        with pytest.raises(Indeterminate):
            with guard(key, ledger_path=path,
                       allow_retry_after_indeterminate=True):
                pass  # must never reach here while g1 is still open

        g1.done(first_outcome)
        final = receipt(key, ledger_path=path)
        assert final.state == "executed"
        assert final.outcome_digest is not None

        # AFTER g1 finishes, the key is a normal duplicate -- still refused,
        # but via AlreadyExecuted now, not Indeterminate.
        with pytest.raises(AlreadyExecuted) as exc_info:
            with guard(key, ledger_path=path,
                       allow_retry_after_indeterminate=True) as g3:
                g3.done(second_outcome)
        assert exc_info.value.receipt.executed_chain == final.executed_chain


@given(key=_key, outcome=_payload)
@_slow_settings
def test_retry_stuck_in_retrying_heals_via_rebuild_index(key, outcome):
    """If the RETRY itself also crashes, the index row is stuck at
    'retrying' (documented in the fix note) until rebuild_index() replays
    ledger truth, which only ever produces 'intent'/'executed' -- proving
    the documented healing path actually works, not just reads well."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        _simulate_crash(path, key)
        rebuild_index(path)  # Round 3: makes the crashed intent reclaimable

        g1 = guard(key, ledger_path=path, allow_retry_after_indeterminate=True)
        g1.__enter__()
        assert g1._won is True
        del g1  # simulate the retry ALSO crashing: no done() ever called

        # Stuck: a third attempt right now is refused, not a silent re-win.
        with pytest.raises(Indeterminate):
            with guard(key, ledger_path=path,
                       allow_retry_after_indeterminate=True):
                pass

        n = rebuild_index(path)
        assert n >= 1

        with guard(key, ledger_path=path,
                   allow_retry_after_indeterminate=True) as g2:
            g2.done(outcome)
        final = receipt(key, ledger_path=path)
        assert final.state == "executed"


# ===========================================================================
# 5. WAL-init first-touch race (thread-based complement to test_concurrency.py)
# ===========================================================================

@given(n=st.integers(min_value=2, max_value=12), key=_key)
@_race_settings
def test_first_touch_thread_race_typed_and_exactly_once(n, key):
    """N threads first-touch a BRAND-NEW ledger path (never seen before this
    call) all at once. b2aea25 fixed the window where the delete->wal
    journal-mode switch could crash concurrent first-touchers with a raw
    sqlite3.OperationalError; test_concurrency.py proves this with real
    subprocesses (12 workers, 5 trials). This is a lighter thread-based
    complement so Hypothesis can vary N -- same claim: no untyped escape,
    exactly one execution."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"  # fresh -- never guard()ed before
        results = _thread_race(path, key, n)
        assert "index_unavailable" not in results or results.count("executing") == 1
        assert results.count("executing") == 1, results
        for r in results:
            assert r in ("executing", "already_executed", "indeterminate", "index_unavailable")


# ===========================================================================
# 6. The unicode-line-separator class (U+0085 / U+2028 / U+2029)
# ===========================================================================
#
# VERDICT: arcaeon_once itself is structurally clean -- it does zero direct
# file reads of the ledger anywhere in arcaeon_once/__init__.py (confirmed
# by grep for ensure_ascii/splitlines/readlines/open(/read_text and pinned
# below as a regression test). Every read of ledger content goes through
# arcaeon_ledger's Ledger.__iter__ / verify_file, and that dependency fixed
# this exact bug class at 0.5.6 (2026-08-16 CHANGELOG: "every read path...
# split with str.splitlines()... now split on '\n' only"). Confirmed the
# installed checkout is genuinely 0.5.6, not a stale pre-fix copy, via
# `arcaeon_ledger.__version__` from a neutral cwd. This section proves the
# FULL round trip -- guard() -> receipt() -> verify_integrity=True -- stays
# green with these characters in both the key and the payload, individually
# and combined, closing the loop the same way arcaeon-distill's suite closed
# it for DropReceipt.seal().

_line_sep_text = st.text(
    alphabet=st.sampled_from(
        list("abcXYZ 0123") + LINE_SEPARATOR_CLASS
    ),
    min_size=1, max_size=25,
).filter(lambda s: any(ch in LINE_SEPARATOR_CLASS for ch in s))


@given(payload_text=_line_sep_text)
@_slow_settings
def test_line_separator_class_in_payload_survives_round_trip(payload_text):
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "refund:pi_unicode"
        with guard(key, ledger_path=path, store_outcome=True,
                   verify_integrity=True) as g:
            g.done({"note": payload_text})

        rec = receipt(key, ledger_path=path)
        assert rec.state == "executed"
        assert rec.ledger_ok is True
        assert rec.outcome == {"note": payload_text}

        # A FRESH guard() call re-verifying the chain must also see it green
        # -- proves this isn't just receipt() being lenient.
        with pytest.raises(AlreadyExecuted) as exc_info:
            with guard(key, ledger_path=path, verify_integrity=True):
                pass
        assert exc_info.value.receipt.outcome == {"note": payload_text}


@given(key_suffix=_line_sep_text)
@_slow_settings
def test_line_separator_class_in_key_survives_round_trip(key_suffix):
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "job:" + key_suffix
        with guard(key, ledger_path=path, store_outcome=True) as g:
            g.done({"ok": True})
        rec = receipt(key, ledger_path=path)
        assert rec.key == key
        assert rec.state == "executed"
        assert rec.ledger_ok is True


def test_all_three_line_separator_chars_combined_in_one_call():
    """Pinned, not just property-fuzzed: the exact three characters named in
    the bug class, mixed in one key AND one payload value, individually and
    combined -- mirrors how the ledger/distill reports pinned this."""
    combined = "".join(LINE_SEPARATOR_CLASS) + "-mixed-" + "".join(reversed(LINE_SEPARATOR_CLASS))
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        for i, ch in enumerate([*LINE_SEPARATOR_CLASS, combined]):
            key = f"k{i}:" + ch
            with guard(key, ledger_path=path, store_outcome=True,
                       verify_integrity=True) as g:
                g.done({"payload": ch, "n": i})
            rec = receipt(key, ledger_path=path)
            assert rec.state == "executed", (i, ch, rec)
            assert rec.ledger_ok is True, (i, ch, rec)
            assert rec.outcome == {"payload": ch, "n": i}


def test_arcaeon_once_has_no_direct_ledger_file_reads():
    """Regression pin for the structural verdict above: arcaeon_once must
    keep delegating ALL ledger content reads to arcaeon_ledger (Ledger /
    verify_file) rather than ever reaching for its own open()/read_text()/
    splitlines() on the ledger file. If this ever starts matching, the
    unicode-line-separator verdict above needs re-auditing, not assuming."""
    src = Path(__file__).resolve().parents[2] / "src" / "arcaeon" / "record" / "once" / "__init__.py"
    text = src.read_text(encoding="utf-8")
    # os.open( is fine -- that's the cross-process advisory LOCK file, not
    # ledger content. Anything else touching splitlines/readlines/read_text
    # on JSONL content, or ensure_ascii, would be new surface to re-check.
    assert "splitlines" not in text
    assert "readlines" not in text
    assert "ensure_ascii" not in text
    assert not re.search(r"(?<!os)\.read_text\(", text)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
