"""`reclaim()` driven through every verdict its liveness probe can return.

`test_once.py` covers reclaim against REAL processes: this pid as a live
holder, a hard-exited subprocess as a dead one. What it cannot do is force
the probe to say a particular thing about a holder that is in a particular
state, which is the only way to prove the DECISION is wired to the probe
rather than to some accident of the fixture. The README admitted this at
0.2.0 ("mutation-checked by hand ... not an automated test"). This file is
that test, automated.

Every case plants the SAME fixture: a claim on `key` held by THIS process
(a row in `'claiming'` state with a real lease: this pid, this host). The
holder is genuinely alive throughout. Only the probe's verdict changes:

  alive (True)      -> HolderAlive, row untouched, holder still owns it
  dead  (False)     -> row rewritten to 'intent'; the retry flag now wins it
  unknown (None)    -> LivenessUnknown, row untouched (documented: None is
                       treated exactly like True, fail closed)
  probe RAISES      -> exception propagates, row untouched (see the test's
                       docstring for why this is the pinned behaviour)

Plus the must-miss arm: with the probe forced to "dead" for the target
key's holder, a DIFFERENT key's live claim in the same ledger is NOT
reclaimed, because reclaim is single-key by construction.

The probe is patched at `arcaeon_once._pid_alive`, the name `reclaim()`
resolves at call time; each fake records the pid it was asked about so the
test can also prove the probe was consulted with the lease's pid and not
skipped.
"""
from __future__ import annotations

import contextlib
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

import arcaeon.record.once
from arcaeon.record.once import (
    HolderAlive, Indeterminate, LivenessUnknown,
    guard, receipt, reclaim,
)


def _index_row(path: Path, key: str) -> tuple:
    con = sqlite3.connect(str(path) + ".idx.sqlite3")
    try:
        return con.execute(
            "SELECT state, holder_pid, holder_host, generation "
            "FROM once_state WHERE key=?", (key,)).fetchone()
    finally:
        con.close()


@contextlib.contextmanager
def _live_claim(path: Path, key: str):
    """A claim held by this process for the duration of the block. The row
    is 'claiming' with a lease naming this pid and host, exactly what
    reclaim() reads before it probes."""
    g = guard(key, ledger_path=path)
    g.__enter__()
    try:
        row = _index_row(path, key)
        assert row is not None and row[0] == "claiming", row
        assert row[1] == os.getpid()
        yield g
    finally:
        with contextlib.suppress(Exception):
            g.done({"status": "cleanup"})


def _fake_probe(verdict, asked: list):
    """A stand-in for _pid_alive that records the pid it was asked about and
    returns (or raises) `verdict`."""
    def probe(pid):
        asked.append(pid)
        if isinstance(verdict, BaseException):
            raise verdict
        return verdict
    return probe


def test_probe_alive_refuses_and_leaves_the_claim_untouched(monkeypatch):
    """Probe says ALIVE -> HolderAlive. The row is byte-for-byte what it was
    (state, lease, generation) and the holder finishes its work normally."""
    asked: list = []
    monkeypatch.setattr(arcaeon.record.once, "_pid_alive", _fake_probe(True, asked))
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "mock:probe-alive"
        with _live_claim(path, key) as g:
            before = _index_row(path, key)
            with pytest.raises(HolderAlive) as ei:
                reclaim(key, ledger_path=path)
            assert ei.value.key == key
            assert ei.value.holder_pid == os.getpid()
            assert asked == [os.getpid()], "probe not consulted with the lease pid"
            assert _index_row(path, key) == before, "refusal changed the row"
            g.done({"status": "finished"})
        assert receipt(key, ledger_path=path).state == "executed"


def test_probe_dead_frees_the_key_for_the_retry_flag(monkeypatch):
    """Probe says DEAD -> the row alone is rewritten to 'intent' with the
    lease cleared and the generation bumped, and the documented retry path
    (`guard(..., allow_retry_after_indeterminate=True)`) now wins the key.

    The holder is in fact alive (this process); the point is that reclaim
    believes the probe, so the probe is the only thing standing between a
    live claim and a double-fire. That is the mutation the README described
    as hand-checked at 0.2.0."""
    asked: list = []
    monkeypatch.setattr(arcaeon.record.once, "_pid_alive", _fake_probe(False, asked))
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "mock:probe-dead"
        with _live_claim(path, key):
            before = _index_row(path, key)
            r = reclaim(key, ledger_path=path)
            assert r.state == "intent", r
            assert asked == [os.getpid()]
            after = _index_row(path, key)
            assert after[0] == "intent"
            assert after[1] is None and after[2] is None, "lease not cleared"
            assert after[3] == before[3] + 1, "generation not bumped"
            # The freed key is retryable through the documented flag.
            with guard(key, ledger_path=path,
                       allow_retry_after_indeterminate=True) as g2:
                g2.done({"status": "retried-after-mock-reclaim"})
            assert receipt(key, ledger_path=path).state == "executed"


def test_probe_unknown_refuses_with_liveness_unknown(monkeypatch):
    """Probe returns None (could not decide) -> LivenessUnknown, not
    HolderAlive, and nothing changes. `_pid_alive`'s contract says callers
    treat None exactly like True for safety decisions; this pins reclaim()
    to that contract."""
    asked: list = []
    monkeypatch.setattr(arcaeon.record.once, "_pid_alive", _fake_probe(None, asked))
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "mock:probe-unknown"
        with _live_claim(path, key) as g:
            before = _index_row(path, key)
            with pytest.raises(LivenessUnknown) as ei:
                reclaim(key, ledger_path=path)
            assert not isinstance(ei.value, HolderAlive)
            assert str(os.getpid()) in str(ei.value)
            assert asked == [os.getpid()]
            assert _index_row(path, key) == before, "refusal changed the row"
            g.done({"status": "finished"})
        assert receipt(key, ledger_path=path).state == "executed"


def test_probe_raising_does_not_reclaim(monkeypatch):
    """Probe RAISES (a crash inside the syscall wrapper, or, since the probe
    is synchronous and has no timeout of its own, the nearest thing to a
    timeout: an unexpected error surfacing from it).

    reclaim() does not document this arm: `_pid_alive` is specified as
    three-valued and its own body catches what it expects (POSIX OSError,
    every Exception on Windows), so a raise here is outside the contract.
    The behaviour pinned is the SAFE one, and it is what the code does today
    without a special case: the exception propagates out of reclaim()
    unchanged (it is not converted to LivenessUnknown, the caller sees the
    real error), the open BEGIN IMMEDIATE transaction is discarded when the
    connection closes, the row is untouched, the index lock is released so
    the next call is not wedged, and the retry flag still refuses the key.
    Do NOT reclaim is the property; the exception type is incidental and a
    future release may choose to type it, at which point this test should
    be updated to the typed error rather than weakened."""
    asked: list = []
    boom = RuntimeError("probe blew up mid-syscall")
    monkeypatch.setattr(arcaeon.record.once, "_pid_alive", _fake_probe(boom, asked))
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "mock:probe-raises"
        with _live_claim(path, key) as g:
            before = _index_row(path, key)
            with pytest.raises(RuntimeError, match="probe blew up"):
                reclaim(key, ledger_path=path)
            assert asked == [os.getpid()]
            assert _index_row(path, key) == before, "a raising probe changed the row"
            # Lock released: a follow-up index write is not wedged, and the
            # retry flag still refuses because the claim is still 'claiming'.
            with pytest.raises(Indeterminate):
                with guard(key, ledger_path=path,
                           allow_retry_after_indeterminate=True):
                    raise AssertionError("retry flag stole a claim after "
                                         "a raising probe")
            g.done({"status": "finished"})
        assert receipt(key, ledger_path=path).state == "executed"


def test_must_miss_dead_verdict_frees_only_the_target_key(monkeypatch):
    """THE MUST-MISS ARM. Two live claims by this process on two keys. The
    probe is forced to "dead" for everything it is asked. reclaim(target)
    must free the target and nothing else: the bystander key's row is
    untouched, the probe was asked about the target's holder exactly once
    and never about the bystander, and the bystander stays unstealable."""
    asked: list = []
    monkeypatch.setattr(arcaeon.record.once, "_pid_alive", _fake_probe(False, asked))
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        target, bystander = "mock:target", "mock:bystander"
        with _live_claim(path, target), _live_claim(path, bystander) as by:
            by_before = _index_row(path, bystander)
            r = reclaim(target, ledger_path=path)
            assert r.state == "intent"
            assert len(asked) == 1, f"probe consulted {len(asked)} times"
            assert _index_row(path, bystander) == by_before, (
                "reclaim of one key touched a different key's row")
            with pytest.raises(Indeterminate):
                with guard(bystander, ledger_path=path,
                           allow_retry_after_indeterminate=True):
                    raise AssertionError("bystander claim became stealable")
            assert receipt(target, ledger_path=path).state == "intent"
            assert _index_row(path, target)[0] == "intent"
            by.done({"status": "still-mine"})
        assert receipt(bystander, ledger_path=path).state == "executed"


def test_probe_is_not_consulted_when_the_lease_cannot_be_used(monkeypatch):
    """Ordering guard: a foreign-host lease is refused BEFORE the probe runs.
    A probe that would say "dead" must not be reached, because a pid from
    another machine means nothing here. If the probe is ever asked, the
    host check has moved below it and this fails."""
    asked: list = []
    monkeypatch.setattr(arcaeon.record.once, "_pid_alive", _fake_probe(False, asked))
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "mock:foreign-host"
        with _live_claim(path, key) as g:
            con = sqlite3.connect(str(path) + ".idx.sqlite3")
            con.execute("UPDATE once_state SET holder_host='elsewhere' "
                        "WHERE key=?", (key,))
            con.commit(); con.close()
            with pytest.raises(LivenessUnknown, match="host"):
                reclaim(key, ledger_path=path)
            assert asked == [], "probe consulted despite an unusable lease"
            assert _index_row(path, key)[0] == "claiming"
            g.done({"status": "finished"})


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
