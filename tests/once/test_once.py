"""Core correctness tests for arcaeon_once.

Run: python test_once.py    (or: pytest test_once.py)

Covers: duplicate refused with original receipt returned, the crash window
(a real subprocess hard-exits between claim and complete -> Indeterminate on
the next call, not silently resolved either way), and chain tamper on an
executed record being detected. The concurrent two-process race lives in
`test_concurrency.py`, mirroring how arcaeon-meter split its own suite.
"""
from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from arcaeon.record.ledger import Ledger
from arcaeon.record.once import (
    AlreadyExecuted, GuardContext, HolderAlive, Indeterminate,
    LivenessUnknown, Receipt, TamperDetected,
    complete, guard, rebuild_index, receipt, reclaim,
)

# -- duplicate refusal --------------------------------------------------


def test_duplicate_raises_with_original_receipt():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "refund:pi_1"
        with guard(key, ledger_path=path) as g:
            g.done({"refund_id": "re_abc", "amount": 4900})
        first = receipt(key, ledger_path=path)
        assert first.state == "executed"

        try:
            with guard(key, ledger_path=path) as g2:
                g2.done({"refund_id": "re_SHOULD_NOT_HAPPEN"})
            assert False, "expected AlreadyExecuted"
        except AlreadyExecuted as e:
            assert e.receipt.key == key
            assert e.receipt.executed_chain == first.executed_chain
            assert e.receipt.executed_ts == first.executed_ts
    print("PASS duplicate call raises AlreadyExecuted carrying the ORIGINAL receipt")


def test_duplicate_return_receipt_mode_skips_without_raising():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "email:welcome:user42"
        with guard(key, ledger_path=path) as g:
            g.done({"sent": True})

        with guard(key, ledger_path=path, on_duplicate="return_receipt") as g2:
            assert g2.already_executed is True
            assert g2.receipt.state == "executed"
            # caller is expected to check already_executed and skip the effect;
            # calling done() here would be a programmer error, not attempted.
    print("PASS on_duplicate='return_receipt' signals duplicate without raising")


def test_decorator_form_refuses_second_call():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        calls = []

        @guard("job:static-key", ledger_path=path)
        def do_job():
            calls.append(1)
            return {"ok": True}

        do_job()
        try:
            do_job()
            assert False, "expected AlreadyExecuted"
        except AlreadyExecuted:
            pass
        assert calls == [1], f"side effect ran {len(calls)} times, expected 1"
    print("PASS decorator form: second call refused, side effect ran exactly once")


def test_decorator_form_dynamic_key():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        calls = []

        @guard(lambda job_id: f"job:{job_id}", ledger_path=path)
        def do_job(job_id):
            calls.append(job_id)
            return {"job_id": job_id}

        do_job("A")
        do_job("B")  # distinct key -> distinct execution, not refused
        try:
            do_job("A")
            assert False, "expected AlreadyExecuted for repeated key"
        except AlreadyExecuted:
            pass
        assert calls == ["A", "B"]
    print("PASS decorator with per-call key: distinct keys both run, repeat refused")


# -- crash-window honesty ------------------------------------------------

_CRASH_WORKER = r"""
import sys
from arcaeon.record.once import guard
ledger_path, key = sys.argv[1], sys.argv[2]
g = guard(key, ledger_path=ledger_path)
g.__enter__()          # writes the 'intent' row -- the claim is real
# simulate the side effect "happening" here, then a hard crash: os._exit
# skips __exit__, skips done(), skips any cleanup -- exactly what a SIGKILL
# or a host power-loss would do. No 'executed' row is ever written.
import os
os._exit(1)
"""


def test_crash_window_leaves_typed_indeterminate():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "deploy:build-4471"

        proc = subprocess.run(
            [sys.executable, "-c", _CRASH_WORKER, str(path), key],
            capture_output=True, text=True, timeout=30)
        assert proc.returncode == 1, (proc.stdout, proc.stderr)

        mid = receipt(key, ledger_path=path)
        assert mid.state == "intent", mid
        assert mid.ledger_ok is True  # the ledger itself is NOT tampered, just incomplete

        try:
            with guard(key, ledger_path=path):
                pass
            assert False, "expected Indeterminate"
        except Indeterminate as e:
            assert e.receipt.state == "intent"
            assert e.receipt.key == key

        # Resolution path 1: caller manually confirmed the deploy DID land.
        resolved = complete(key, {"status": "confirmed-by-hand"}, ledger_path=path)
        assert resolved.state == "executed"
        # Now it behaves like any other completed key -- refused, not re-run.
        try:
            with guard(key, ledger_path=path):
                pass
            assert False, "expected AlreadyExecuted after manual completion"
        except AlreadyExecuted:
            pass
    print("PASS crash-window (hard process exit before done()) -> typed Indeterminate, "
          "refused by default, resolvable via complete()")


def test_crash_window_allow_retry_override():
    """UPDATED for the Round 3 contract (2026-08-24): the flag alone no
    longer heals a crashed ORDINARY claim -- the same leniency was a live
    double-fire (the index could not tell a crashed intent from a running
    one). Resolution path 2 is now: rebuild_index() (the ledger replay
    proves the state and produces a reclaimable 'intent' row), THEN the
    flag. Same recovery already documented for a stuck 'retrying' row."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "deploy:build-9001"
        proc = subprocess.run(
            [sys.executable, "-c", _CRASH_WORKER, str(path), key],
            capture_output=True, text=True, timeout=30)
        assert proc.returncode == 1

        # Resolution path 2: caller manually confirmed it did NOT land ->
        # rebuild the index from the ledger, then retry with the flag.
        rebuild_index(path)
        with guard(key, ledger_path=path,
                   allow_retry_after_indeterminate=True) as g:
            g.done({"status": "retried-and-succeeded"})
        final = receipt(key, ledger_path=path)
        assert final.state == "executed"
        assert final.outcome_digest is not None
    print("PASS rebuild_index + allow_retry_after_indeterminate heals a verified-dead crash")


# -- tamper detection ------------------------------------------------------


def test_chain_tamper_on_executed_row_is_detected():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "refund:pi_tamper"
        with guard(key, ledger_path=path, store_outcome=True) as g:
            g.done({"refund_id": "re_original", "amount": 100})

        clean = receipt(key, ledger_path=path)
        assert clean.ledger_ok is True
        assert clean.state == "executed"

        # Attacker deletes the executed row to re-enable a re-fire.
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2  # intent + executed
        path.write_text(lines[0] + "\n", encoding="utf-8")  # drop the executed row

        truncated = receipt(key, ledger_path=path)
        assert truncated.state == "intent"  # the executed claim is just... gone
        # Ledger's OWN verify() still reports ok=True here -- truncation of the
        # tail is arcaeon-ledger's documented non-proof (needs external
        # witnessing to catch), stated rather than hidden. What we DO catch
        # here is guard() refusing to treat "no executed row" as anything but
        # unresolved -- a second guard() call does NOT get a free re-fire, it
        # gets Indeterminate:
        try:
            with guard(key, ledger_path=path):
                pass
            assert False, "expected Indeterminate, not a silent re-fire"
        except Indeterminate:
            pass

        # Now the in-place tamper case: edit a byte instead of truncating.
        with guard(key + ":inplace", ledger_path=path, store_outcome=True) as g2:
            g2.done({"refund_id": "re_inplace", "amount": 200})
        text = path.read_text(encoding="utf-8")
        tampered = text.replace("re_inplace", "re_HACKED!!", 1)
        path.write_text(tampered, encoding="utf-8")
        broken = receipt(key + ":inplace", ledger_path=path)
        assert broken.ledger_ok is False
        assert broken.ledger_first_break is not None
    print("PASS in-place chain tamper on an executed row is detected "
          "(ledger_ok=False); tail-drop degrades to a safe refusal, not a re-fire")


def test_verify_integrity_refuses_on_tampered_ledger():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "refund:pi_verify"
        with guard(key, ledger_path=path, store_outcome=True) as g:
            g.done({"refund_id": "re_x"})
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace("re_x", "re_Y", 1), encoding="utf-8")

        try:
            with guard("refund:pi_other", ledger_path=path, verify_integrity=True):
                pass
            assert False, "expected TamperDetected"
        except TamperDetected as e:
            assert e.verify_result.ok is False
    print("PASS verify_integrity=True refuses ANY new claim on a tampered ledger")


def test_retry_flag_cannot_steal_a_live_ordinary_claim_sequential():
    """Round 3 (adversarial audit 2026-08-24, HIGH -- a REAL double-fire):
    an ordinary guard() winner's index row sat at state='intent',
    generation=0, indistinguishable from a CRASHED intent, so a second
    caller with allow_retry_after_indeterminate=True CASed on the LIVE
    claim and also won -- the guarded effect ran twice with no crash
    anywhere. The ordinary claim now occupies its own live state
    ('claiming'), which the reclaim CAS never matches."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "refund:order-31337"
        fired = []

        g1 = guard(key, ledger_path=path)
        g1.__enter__()
        fired.append("g1")
        assert g1._won is True

        g2 = guard(key, ledger_path=path, allow_retry_after_indeterminate=True)
        try:
            g2.__enter__()
            if g2._won:
                fired.append("g2")
            assert not g2._won, (
                "the retry flag stole a LIVE ordinary claim -- effect fired "
                "%d times: %r" % (len(fired), fired))
            assert g2.already_executed or True
        except (Indeterminate, AlreadyExecuted):
            pass  # honest refusal -- exactly what the fix requires
        assert fired == ["g1"], fired

        g1.done({"status": "refunded"})
        final = receipt(key, ledger_path=path)
        assert final.state == "executed"
    print("PASS a live ordinary claim cannot be stolen by the retry flag (sequential)")


def test_retry_flag_race_on_fresh_key_fires_effect_exactly_once():
    """The concurrent half of Round 3: N threads race a FRESH key, some
    carrying the retry flag. Before the fix, 5/10 trials double-fired.
    The guarded effect must run exactly once, every trial."""
    import threading
    for trial in range(6):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ops.log.jsonl"
            key = "deploy:race-%d" % trial
            fired = []
            lock = threading.Lock()
            barrier = threading.Barrier(6)

            def worker(i):
                barrier.wait()
                try:
                    g = guard(key, ledger_path=path,
                              allow_retry_after_indeterminate=(i % 2 == 0))
                    g.__enter__()
                    if g._won:
                        with lock:
                            fired.append(i)
                        g.done({"worker": i})
                except (Indeterminate, AlreadyExecuted):
                    pass

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=60)
            assert len(fired) == 1, (
                "trial %d: the guarded effect ran %d times (workers %r) -- "
                "at-most-once violated" % (trial, len(fired), fired))
    print("PASS 6 trials x 6 racing threads (mixed retry flags): exactly one execution each")


def test_rebuild_index_warns_when_it_downgrades_a_live_claim():
    """Round 3 review (2026-08-24): rebuild_index() replays the ledger, which
    cannot distinguish a live claim from a crashed one (both are one intent
    row), so it downgrades every in-flight 'claiming' row to reclaimable
    'intent'. Run on a live system this makes live claims stealable -- the
    fix is documentation + quiescence, but rebuild must at least WARN when it
    downgrades in-flight rows, so an operator who did it by mistake gets a
    signal instead of a silent stolen claim."""
    import warnings
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "deploy:live-during-rebuild"

        g1 = guard(key, ledger_path=path)  # a LIVE claim, state 'claiming'
        g1.__enter__()
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                rebuild_index(path)
            downgrades = [w for w in caught
                          if "in-flight-looking claim" in str(w.message)]
            assert downgrades, (
                "rebuild_index downgraded a live claim to reclaimable with NO "
                "warning -- a silent stolen-claim window")
            assert "1 in-flight" in str(downgrades[0].message)
        finally:
            # The claim is now 'intent' post-rebuild; complete it to close out.
            with contextlib.suppress(Exception):
                g1.done({"status": "done"})

    # Green control: rebuild on an IDLE system (only executed keys) warns NOT.
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        with guard("done-key", ledger_path=path) as g:
            g.done({"ok": True})
        with warnings.catch_warnings(record=True) as caught2:
            warnings.simplefilter("always")
            rebuild_index(path)
        assert not [w for w in caught2 if "in-flight-looking claim" in str(w.message)], (
            "rebuild warned on an idle system with no in-flight claims -- false positive")
    print("PASS rebuild_index warns when downgrading a live claim; silent on an idle system")


def test_crashed_ordinary_claim_heals_via_rebuild_then_retry_flag():
    """The deliberate contract change that rides with Round 3: after a
    genuine crash of an ORDINARY claim, the index row is stuck at
    'claiming' and the retry flag alone no longer heals it (that same
    leniency was the double-fire). The documented recovery -- exactly the
    one already documented for a stuck 'retrying' row -- is
    rebuild_index() (ledger replay produces 'intent') and THEN the flag."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "deploy:crashed-77"
        proc = subprocess.run(
            [sys.executable, "-c", _CRASH_WORKER, str(path), key],
            capture_output=True, text=True, timeout=30)
        assert proc.returncode == 1

        # The flag alone must now refuse (the row is 'claiming'; the CAS
        # requires 'intent'; nothing proves the prior holder is dead).
        try:
            with guard(key, ledger_path=path,
                       allow_retry_after_indeterminate=True):
                assert False, "flag alone healed a crashed ordinary claim -- the Round 3 leniency is back"
        except Indeterminate:
            pass

        # The documented path: rebuild (replays ledger -> 'intent'), then flag.
        rebuild_index(path)
        with guard(key, ledger_path=path,
                   allow_retry_after_indeterminate=True) as g:
            g.done({"status": "retried-after-rebuild"})
        final = receipt(key, ledger_path=path)
        assert final.state == "executed"
    print("PASS crashed ordinary claim: flag alone refuses; rebuild_index + flag heals")


# -- single-key reclaim (0.2.0): the deep fix behind the 8/24 quiesce rule --


def test_reclaim_refuses_a_live_holder():
    """THE PLANTED RED. A claim held by a RUNNING process (this one) must
    refuse reclaim with HolderAlive -- freeing it would authorise the exact
    double-fire the 8/24 audit demonstrated. Nothing may change on refusal:
    the live claim keeps working afterward."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "deploy:live-holder"
        g = guard(key, ledger_path=path)
        g.__enter__()          # live claim, holder pid = THIS process
        try:
            try:
                reclaim(key, ledger_path=path)
                assert False, ("reclaim freed a LIVE claim -- the double-fire "
                               "door is open again")
            except HolderAlive as e:
                assert e.key == key
                assert e.holder_pid == __import__("os").getpid()
            # Refusal changed nothing: the live holder still owns the claim.
            g.done({"status": "finished-after-refused-reclaim"})
            assert receipt(key, ledger_path=path).state == "executed"
        finally:
            with contextlib.suppress(Exception):
                g.done({"status": "cleanup"})
    print("PASS reclaim refuses a live holder (HolderAlive), claim unharmed")


def test_reclaim_frees_a_dead_holder_without_touching_live_claims():
    """The green half, plus the property that makes reclaim better than
    rebuild_index: a PROVABLY DEAD holder's key is freed for the retry flag
    with NO rebuild and NO quiesce -- a live claim on a DIFFERENT key in the
    same ledger is untouched throughout."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        dead_key, live_key = "deploy:crashed-dead", "deploy:still-running"

        live = guard(live_key, ledger_path=path)
        live.__enter__()       # a live claim that must survive the reclaim

        proc = subprocess.run(
            [sys.executable, "-c", _CRASH_WORKER, str(path), dead_key],
            capture_output=True, text=True, timeout=30)
        assert proc.returncode == 1

        # The flag alone still refuses (row is 'claiming'; Round 3 contract).
        try:
            with guard(dead_key, ledger_path=path,
                       allow_retry_after_indeterminate=True):
                assert False, "flag alone healed a crashed claim"
        except Indeterminate:
            pass

        # reclaim: holder pid provably dead -> that key alone is freed.
        r = reclaim(dead_key, ledger_path=path)
        assert r.state == "intent", r
        with guard(dead_key, ledger_path=path,
                   allow_retry_after_indeterminate=True) as g:
            g.done({"status": "retried-after-reclaim"})
        assert receipt(dead_key, ledger_path=path).state == "executed"

        # The live claim was never downgraded: its holder finishes normally,
        # and no second caller could have stolen it mid-reclaim.
        try:
            with guard(live_key, ledger_path=path,
                       allow_retry_after_indeterminate=True):
                assert False, ("reclaim of a DIFFERENT key made the live "
                               "claim stealable")
        except Indeterminate:
            pass
        live.done({"status": "still-mine"})
        assert receipt(live_key, ledger_path=path).state == "executed"
    print("PASS reclaim frees a dead holder's key alone; live claims untouched")


def test_reclaim_refuses_indeterminate_rows_with_a_distinct_error():
    """THE SECOND PLANTED RED. A row without a liveness lease (pre-0.2.0
    vintage), or leased on a different host, is INDETERMINATE -- reclaim must
    refuse with LivenessUnknown (distinct from HolderAlive) and point the
    operator at the old quiesce -> rebuild_index path."""
    import sqlite3
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"

        # Legacy row: crash a claim, then strip its lease -- byte-for-byte
        # what a pre-0.2.0 index row looks like after the column migration.
        key = "deploy:legacy-no-lease"
        proc = subprocess.run(
            [sys.executable, "-c", _CRASH_WORKER, str(path), key],
            capture_output=True, text=True, timeout=30)
        assert proc.returncode == 1
        con = sqlite3.connect(str(path) + ".idx.sqlite3")
        con.execute("UPDATE once_state SET holder_pid=NULL, holder_host=NULL, "
                    "holder_ts=NULL WHERE key=?", (key,))
        con.commit(); con.close()
        try:
            reclaim(key, ledger_path=path)
            assert False, "reclaimed a row whose holder is UNPROVABLE"
        except LivenessUnknown as e:
            assert not isinstance(e, HolderAlive)
            assert "rebuild_index" in str(e), (
                "the refusal must tell the operator the quiesce-path "
                "recovery, got: " + str(e))
            assert "lease" in e.reason

        # Foreign-host lease: same indeterminacy, same refusal.
        key2 = "deploy:leased-elsewhere"
        proc2 = subprocess.run(
            [sys.executable, "-c", _CRASH_WORKER, str(path), key2],
            capture_output=True, text=True, timeout=30)
        assert proc2.returncode == 1
        con = sqlite3.connect(str(path) + ".idx.sqlite3")
        con.execute("UPDATE once_state SET holder_host='some-other-machine' "
                    "WHERE key=?", (key2,))
        con.commit(); con.close()
        try:
            reclaim(key2, ledger_path=path)
            assert False, "reclaimed a claim leased on another host"
        except LivenessUnknown as e:
            assert "host" in str(e)

        # And the trivial refusals are ValueError, not silent passes.
        done_key = "deploy:already-done"
        with guard(done_key, ledger_path=path) as g:
            g.done({"ok": True})
        for bad in (done_key, "deploy:never-claimed"):
            try:
                reclaim(bad, ledger_path=path)
                assert False, f"reclaim({bad!r}) did not refuse"
            except ValueError:
                pass
    print("PASS reclaim refuses indeterminate/legacy rows with LivenessUnknown "
          "(quiesce path named), foreign-host leases refused, executed/never "
          "refuse with ValueError")


def test_pre_0_2_0_index_migrates_lease_columns_in_place():
    """Backward compatibility: an index file created by 0.1.x (no lease
    columns) must keep working -- the columns are ALTER-ed on at first touch,
    old rows read as legacy (lease NULL -> LivenessUnknown on reclaim), and
    new claims carry a lease."""
    import sqlite3
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        idx = Path(str(path) + ".idx.sqlite3")

        # Build the index exactly as 0.1.2 did: no lease columns, plus a
        # crashed-looking legacy row.
        con = sqlite3.connect(str(idx))
        con.execute(
            "CREATE TABLE once_state (key TEXT PRIMARY KEY, state TEXT NOT NULL,"
            " intent_ts TEXT, executed_ts TEXT, outcome_digest TEXT,"
            " intent_chain TEXT, executed_chain TEXT,"
            " generation INTEGER NOT NULL DEFAULT 0)")
        con.execute("INSERT INTO once_state (key, state, intent_ts, generation)"
                    " VALUES ('old:crashed', 'claiming', '2026-08-01T00:00:00Z', 0)")
        con.commit(); con.close()
        Ledger(path).append({"event": "once.intent", "key": "old:crashed"})

        # A new guard() against the legacy index must work (migration runs),
        # and its claim must carry a lease.
        with guard("new:key", ledger_path=path) as g:
            g.done({"ok": True})
        con = sqlite3.connect(str(idx))
        cols = {r[1] for r in con.execute("PRAGMA table_info(once_state)")}
        assert {"holder_pid", "holder_host", "holder_ts"} <= cols, cols
        legacy = con.execute("SELECT holder_pid FROM once_state "
                             "WHERE key='old:crashed'").fetchone()
        assert legacy == (None,), legacy      # old row untouched, lease NULL
        con.close()

        # The legacy row is refusable-but-recoverable exactly as documented.
        try:
            reclaim("old:crashed", ledger_path=path)
            assert False, "reclaimed a legacy row with no lease"
        except LivenessUnknown:
            pass
        rebuild_index(path)                   # the documented quiesce path
        with guard("old:crashed", ledger_path=path,
                   allow_retry_after_indeterminate=True) as g:
            g.done({"status": "healed-the-old-way"})
        assert receipt("old:crashed", ledger_path=path).state == "executed"
    print("PASS pre-0.2.0 index migrates in place; legacy rows refuse reclaim "
          "and heal via the quiesce path")


def test_reclaim_heals_a_claim_that_died_before_its_ledger_intent():
    """Audit 2026-08-24 Finding 2's stuck shape: a holder that dies between
    winning the INDEX claim and appending its LEDGER intent row leaves an
    index row with no ledger trace -- guard() reports Indeterminate while
    receipt() honestly says never, and complete() is a dead end. With the
    holder provably dead, reclaim deletes the orphan row so a PLAIN guard()
    claims the key fresh."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        key = "deploy:index-claim-only"
        # Touch the ledger so the index path exists, then die between the
        # index claim and the ledger append (the F2 window, forced).
        worker = r"""
import sys
from pathlib import Path
import arcaeon.record.once
from arcaeon.record.once import _claim, _default_index_path, _init_index
from arcaeon.record.ledger import Ledger
ledger_path, key = Path(sys.argv[1]), sys.argv[2]
Ledger(ledger_path).append({"event": "once.touch"})
db = _default_index_path(ledger_path)
_init_index(db)
assert _claim(db, key)
import os; os._exit(1)     # dead before the once.intent append
"""
        proc = subprocess.run(
            [sys.executable, "-c", worker, str(path), key],
            capture_output=True, text=True, timeout=30)
        assert proc.returncode == 1, (proc.stdout, proc.stderr)

        assert receipt(key, ledger_path=path).state == "never"
        try:
            with guard(key, ledger_path=path):
                assert False, "orphan index row let a claim through unguarded"
        except Indeterminate:
            pass

        r = reclaim(key, ledger_path=path)
        assert r.state == "never", r          # orphan row deleted outright
        with guard(key, ledger_path=path) as g:   # PLAIN guard, no flag
            g.done({"status": "fresh-after-orphan-reclaim"})
        assert receipt(key, ledger_path=path).state == "executed"
    print("PASS reclaim deletes a dead orphan index row (Finding 2); plain "
          "guard() claims fresh")




# -- the three-valued ledger verdict ----------------------------------------

def test_receipt_over_a_bounded_ledger_is_falsy_not_a_crash():
    """arcaeon-ledger's verdict is THREE-valued: ok=True (every row checked),
    ok=None (no fault found, but the scan did not cover every row -- falsy on
    purpose), ok=False (a real break). `Receipt` took that straight into a
    field DECLARED `bool` and then wrote

        return self.state == "executed" and self.ledger_ok

    which evaluates to `None` on the bounded case -- and Python rejects a
    non-bool from `__bool__`. So `if receipt(...):`, the documented way to
    read a receipt, raised TypeError against any ledger carrying an unchained
    pre-chain row (a shared ops log, a legacy header line) or a declared
    break. A receipt that cannot be truth-tested is not a receipt.

    Also pins the coverage distinction the receipt could not previously make:
    `ledger_first_break` is None for a CLEAN ledger and None for a BOUNDED
    one, so it cannot tell them apart. `ledger_verified_scope` can.
    """
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "shared_ops.log.jsonl"
        key = "refund:pi_bounded"

        # An ordinary shape: one unchained row at the top of a shared log
        # (a legacy header, another tool's line) before arcaeon_once ever
        # appends. verify_file tolerates it and reports the scan as BOUNDED.
        path.write_text(
            json.dumps({"event": "note", "msg": "legacy header row"}) + "\n",
            encoding="utf-8")

        with guard(key, ledger_path=path) as g:
            g.done({"refund_id": "re_bounded"})

        rec = receipt(key, ledger_path=path)
        assert rec.state == "executed"
        assert rec.ledger_ok is None, (
            "expected the bounded three-valued verdict, got "
            f"{rec.ledger_ok!r}")
        assert bool(rec) is False, (
            "a bounded scan is not a proof and must not read as success")
        assert rec.ledger_verified_scope == "bounded_prechain_skipped"
        assert rec.ledger_first_break is None
        d = rec.to_dict()
        assert d["ledger_verified_scope"] == "bounded_prechain_skipped"
        assert d["ledger_breaks"] == 0

        # Control: a ledger with NO pre-chain row is fully covered, truthy,
        # and says so in-band.
        clean_path = Path(td) / "clean.log.jsonl"
        with guard(key, ledger_path=clean_path) as g2:
            g2.done({"refund_id": "re_clean"})
        clean = receipt(key, ledger_path=clean_path)
        assert clean.ledger_ok is True
        assert clean.ledger_verified_scope == "full"
        assert bool(clean) is True
    print("PASS a bounded ledger verdict reads FALSY and names its scope; "
          "only a full-scope clean scan is truthy")


def test_guard_verifies_the_chain_once_per_entry_not_twice():
    """`verify_integrity=True` used to verify the whole chain, then call
    `receipt()`, which verified the whole chain again -- two full O(rows)
    scans per claim, on the hot path of a side effect."""
    import arcaeon.record.once as _once
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        with guard("seed", ledger_path=path) as g:
            g.done({"n": 1})

        calls = []
        real = _once.verify_file
        _once.verify_file = lambda *a, **k: (calls.append(1), real(*a, **k))[1]
        try:
            g2 = guard("second", ledger_path=path, verify_integrity=True)
            g2.__enter__()
        finally:
            _once.verify_file = real
        assert len(calls) == 1, (
            f"guard().__enter__() ran verify_file {len(calls)} times; the "
            "chain scan is the expensive half and one pass serves both the "
            "tamper gate and the state derivation")
    print("PASS guard() entry verifies the chain exactly once")


# -- audit 2026-09-01 regressions ---------------------------------------


def test_foreign_non_object_ledger_line_is_skipped_not_a_crash():
    """A shared ledger can carry lines that are valid JSON but not objects
    (`[1, 2]`, `"note"`). 0.2.1 did `row.get("key")` on every parsed line
    and guard()/receipt()/rebuild_index() all died with AttributeError."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "shared.jsonl"
        path.write_text('[1, 2]\n"just a note"\n', encoding="utf-8")
        with guard("k", ledger_path=path) as g:
            g.done({"ok": 1})
        assert receipt("k", ledger_path=path).state == "executed"
        assert rebuild_index(path) == 1
    print("PASS foreign non-object ledger lines are skipped")


def test_store_outcome_with_non_json_outcome_stores_the_repr_form():
    """_outcome_digest already fell back to digest_json({"repr": ...}) for a
    non-serialisable outcome, but store_outcome=True then put the RAW object
    in the row and the append raised TypeError from done() -- after the
    effect had run, leaving the key stuck at 'intent'. Stored value and
    digest must be taken over the same form."""
    from arcaeon.record.ledger import digest_json

    class Obj:
        def __repr__(self):
            return "<Obj>"

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        with guard("c", ledger_path=path, store_outcome=True) as g:
            g.done(Obj())
        rec = receipt("c", ledger_path=path)
        assert rec.state == "executed"
        assert rec.outcome == {"repr": "<Obj>"}
        assert rec.outcome_digest == digest_json(rec.outcome)
        # a plain JSON outcome is still stored verbatim
        with guard("d", ledger_path=path, store_outcome=True) as g:
            g.done({"n": 1})
        assert receipt("d", ledger_path=path).outcome == {"n": 1}
    print("PASS store_outcome stores the same JSON-safe form it digested")


def test_lone_surrogate_key_is_a_typed_valueerror_before_any_write():
    """0.2.1 let a lone surrogate in the key reach sqlite's parameter
    binding and escape as a bare UnicodeEncodeError from inside _claim."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        for call in (lambda: guard("k\udc80", ledger_path=path).__enter__(),
                     lambda: complete("k\udc80", ledger_path=path),
                     lambda: reclaim("k\udc80", ledger_path=path)):
            try:
                call()
                assert False, "expected ValueError"
            except ValueError as e:
                assert "lone surrogate" in str(e)
        assert not path.exists()
    print("PASS lone-surrogate key is refused with a typed ValueError")


def test_complete_index_unavailable_reports_ledger_committed_truthfully():
    """complete() appended the executed row and only THEN opened the index;
    when the index could not be opened the IndexUnavailable it raised said
    ledger_committed=False ('no ledger row was written') while the executed
    row already sat in the chain. The receipt must not contradict the
    exception in either direction."""
    import arcaeon.record.once as _once
    from arcaeon.record.once import IndexUnavailable, _default_index_path

    @contextlib.contextmanager
    def dead_lock(lock_path):
        raise IndexUnavailable(lock_path, "acquire the index setup lock",
                               cause=OSError("simulated contention"))
        yield  # pragma: no cover

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ops.log.jsonl"
        g = guard("d", ledger_path=path)
        g.__enter__()
        _default_index_path(path).unlink()
        real = _once._index_setup_lock
        _once._index_setup_lock = dead_lock
        try:
            complete("d", {"ok": 1}, ledger_path=path)
            assert False, "expected IndexUnavailable"
        except IndexUnavailable as e:
            state = receipt("d", ledger_path=path).state
            assert e.ledger_committed == (state == "executed"), (
                f"exception says ledger_committed={e.ledger_committed} but "
                f"the ledger says {state!r}")
            assert state == "intent"
        finally:
            _once._index_setup_lock = real
    print("PASS complete() IndexUnavailable.ledger_committed matches the ledger")


def test_dunder_version_matches_pyproject():
    import tomllib
    import arcaeon.record.once
    declared = tomllib.loads(
        (Path(__file__).parent / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    assert arcaeon.record.once.__version__ == declared, (
        f"arcaeon_once.__version__={arcaeon.record.once.__version__!r} but "
        f"pyproject.toml declares {declared!r}")
    print("PASS __version__ matches pyproject")


if __name__ == "__main__":
    test_duplicate_raises_with_original_receipt()
    test_duplicate_return_receipt_mode_skips_without_raising()
    test_decorator_form_refuses_second_call()
    test_decorator_form_dynamic_key()
    test_crash_window_leaves_typed_indeterminate()
    test_crash_window_allow_retry_override()
    test_chain_tamper_on_executed_row_is_detected()
    test_verify_integrity_refuses_on_tampered_ledger()
    test_retry_flag_cannot_steal_a_live_ordinary_claim_sequential()
    test_retry_flag_race_on_fresh_key_fires_effect_exactly_once()
    test_rebuild_index_warns_when_it_downgrades_a_live_claim()
    test_crashed_ordinary_claim_heals_via_rebuild_then_retry_flag()
    test_reclaim_refuses_a_live_holder()
    test_reclaim_frees_a_dead_holder_without_touching_live_claims()
    test_reclaim_refuses_indeterminate_rows_with_a_distinct_error()
    test_pre_0_2_0_index_migrates_lease_columns_in_place()
    test_reclaim_heals_a_claim_that_died_before_its_ledger_intent()
    test_receipt_over_a_bounded_ledger_is_falsy_not_a_crash()
    test_guard_verifies_the_chain_once_per_entry_not_twice()
    test_foreign_non_object_ledger_line_is_skipped_not_a_crash()
    test_store_outcome_with_non_json_outcome_stores_the_repr_form()
    test_lone_surrogate_key_is_a_typed_valueerror_before_any_write()
    test_complete_index_unavailable_reports_ledger_committed_truthfully()
    test_dunder_version_matches_pyproject()
    print("ALL PASS")
