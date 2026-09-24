"""Concurrency sanity for arcaeon_once -- two real OS processes race the SAME
idempotency key. Claim under test: exactly one of them executes the guarded
side effect, ever, no matter how tight the race. (Mirrors the two-process
pattern in arcaeon-meter's own test_concurrency.py -- real processes, not
threads under a comforting mock.)

Run: python test_concurrency.py
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from pathlib import Path

from arcaeon.record.once import receipt

WORKER = r"""
import sys, time
from arcaeon.record.once import guard, AlreadyExecuted, Indeterminate

ledger_path, key, effect_path, barrier_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

# Crude barrier: both workers spin-wait for the file to exist so they hit the
# claim as close to simultaneously as this OS/filesystem allows.
open(barrier_path + f".{sys.argv[5]}", "w").close()
deadline = time.time() + 10
while time.time() < deadline:
    if all((barrier_path + f".{i}") and __import__("os").path.exists(barrier_path + f".{i}")
           for i in ("0", "1")):
        break
    time.sleep(0.01)

executed = False
outcome = "unknown"
try:
    with guard(key, ledger_path=ledger_path) as g:
        # the guarded "side effect": append our pid to a shared file --
        # if this runs twice, the file will show two lines.
        with open(effect_path, "a", encoding="utf-8") as fh:
            fh.write(f"{sys.argv[5]}\n")
        executed = True
        g.done({"worker": sys.argv[5]})
        outcome = "executed"
except AlreadyExecuted:
    outcome = "already_executed"
except Indeterminate:
    outcome = "indeterminate"

print(f"executed={executed} outcome={outcome}")
"""


def _run_race(key: str, ledger_path: Path, effect_path: Path) -> "list[str]":
    # Derived from effect_path, which is per-trial, NOT from ledger_path, which
    # is shared across trials. It used to be the shared one: the barrier files
    # (`<stem>.barrier.0` / `.1`) are never cleaned up, so from trial 1 onward
    # both workers found them already present and sailed straight past the
    # wait. Four of the five "repeated races" were therefore not synchronized
    # at all -- a contention test with no contention cannot fail for the
    # reason it claims to.
    barrier_path = effect_path.with_suffix(".barrier")
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", WORKER, str(ledger_path), key,
             str(effect_path), str(barrier_path), str(i)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for i in (0, 1)
    ]
    outputs = []
    for p in procs:
        out, err = p.communicate(timeout=30)
        assert p.returncode == 0, f"worker crashed: {err}"
        outputs.append(out.strip())
    return outputs


def test_two_processes_race_same_key_exactly_one_executes():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        ledger_path = td / "race.log.jsonl"
        effect_path = td / "effect.txt"
        key = "refund:pi_race"

        outputs = _run_race(key, ledger_path, effect_path)
        print("worker outputs:", outputs)

        executed_count = sum(1 for o in outputs if "executed=True" in o)
        assert executed_count == 1, (
            f"expected exactly 1 execution, got {executed_count}: {outputs}")

        effect_lines = (effect_path.read_text(encoding="utf-8").splitlines()
                        if effect_path.exists() else [])
        assert len(effect_lines) == 1, (
            f"side effect ran {len(effect_lines)} times, expected 1: {effect_lines}")

        final = receipt(key, ledger_path=ledger_path)
        assert final.state == "executed"
        assert final.ledger_ok is True
    print("PASS two OS processes racing the same key -> exactly one execution, "
          "one AlreadyExecuted/Indeterminate refusal, ledger stays intact")


def test_many_repeated_races_stay_exactly_one():
    """A single race could get lucky. Repeat it several times with fresh
    keys to make sure the atomicity holds under repeated trials, not once."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        ledger_path = td / "race_repeat.log.jsonl"
        for trial in range(5):
            effect_path = td / f"effect_{trial}.txt"
            key = f"refund:pi_race_{trial}"
            outputs = _run_race(key, ledger_path, effect_path)
            executed_count = sum(1 for o in outputs if "executed=True" in o)
            assert executed_count == 1, (
                f"trial {trial}: expected exactly 1 execution, got "
                f"{executed_count}: {outputs}")
            # Assert the SIDE EFFECT too, not only what the workers reported
            # about themselves: the file is the thing a double-fire actually
            # damages.
            effect_lines = (effect_path.read_text(encoding="utf-8").splitlines()
                            if effect_path.exists() else [])
            assert len(effect_lines) == 1, (
                f"trial {trial}: side effect ran {len(effect_lines)} times: "
                f"{effect_lines}")
    print("PASS 5 repeated races (fresh key each trial, shared ledger) -> "
          "exactly one execution every time")


# -- the first-touch init race ---------------------------------------------
# Regression test for the 2026-08-14 WAL-init race. The concurrency index is
# created lazily on the first `guard()` call; switching a brand-new SQLite
# file from `delete` to `wal` journal mode needs a momentary EXCLUSIVE lock
# and does NOT honour busy_timeout (measured: gave up after 0.003s against a
# 15s timeout). Many processes first-touching the SAME fresh index at once
# used to collide there and crash out of `guard().__enter__()` with a naked
# `sqlite3.OperationalError: database is locked`.
#
# The claim under test is BOTH halves:
#   (1) exactly-once still holds (it always did -- the crash landed before any
#       claim row, so it failed safe), and
#   (2) nobody gets an untyped exception out of `__enter__` -- every outcome is
#       one of this library's documented typed outcomes.
#
# Determinism comes from a two-phase start barrier. Each worker imports the
# library, signals ready, and waits for a `go` file; the parent writes that
# file -- carrying an absolute release timestamp -- only ONCE every worker has
# armed. Workers then BUSY-SPIN (no sleep) to that instant, landing all N on
# the journal-mode switch within the same millisecond.
#
# The release time is chosen AFTER everyone is armed on purpose: a fixed
# wall-clock lead picked up front is a guess about process-startup cost, and
# on a loaded machine that guess is wrong (observed: 9/10 and even 0/10
# workers armed in time). A barrier whose own timing can lose is a flaky
# test, and a flaky test is exactly what this whole exercise exists to kill.

INIT_RACE_WORKER = r"""
import os, sys, time, traceback

# Import BEFORE the barrier so module-import cost can't skew the alignment.
from arcaeon.record.once import guard, AlreadyExecuted, Indeterminate, IndexUnavailable

ledger_path, key, effect_path, ready_dir, go_path, wid = sys.argv[1:7]

open(os.path.join(ready_dir, wid), "w").close()   # "I am loaded and armed"

deadline = time.time() + 120
release_at = None
while release_at is None:                         # wait for the parent's go
    try:
        with open(go_path, "r") as fh:
            release_at = float(fh.read().strip())
    except (OSError, ValueError):
        if time.time() > deadline:
            print("executed=False outcome=BARRIER_TIMEOUT")
            sys.exit(4)
        time.sleep(0.001)

while time.time() < release_at:                   # busy-spin: sub-ms alignment
    pass

executed = False
outcome = "unknown"
try:
    with guard(key, ledger_path=ledger_path) as g:
        with open(effect_path, "a", encoding="utf-8") as fh:
            fh.write(wid + "\n")
        executed = True
        g.done({"worker": wid})
        outcome = "executed"
except AlreadyExecuted:
    outcome = "already_executed"
except Indeterminate:
    outcome = "indeterminate"
except IndexUnavailable:
    # A TYPED, documented outcome: the index could not be brought up under
    # contention. Fails safe (no claim, no effect) and is an outcome the
    # caller can catch by name -- unlike a naked OperationalError.
    outcome = "index_unavailable"
except Exception:
    # Anything reaching here is the defect: an untyped escape from __enter__.
    traceback.print_exc()
    print("executed=%s outcome=UNTYPED_ESCAPE" % executed)
    sys.exit(3)

print("executed=%s outcome=%s" % (executed, outcome))
"""


def _run_init_race(td: Path, trial: int, workers: int = 12) -> "list[str]":
    """N processes first-touch a FRESH index (fresh dir per trial) at once."""
    trial_dir = td / f"init_race_{trial}"
    ready_dir = trial_dir / "ready"
    ready_dir.mkdir(parents=True)
    ledger_path = trial_dir / "race.log.jsonl"
    effect_path = trial_dir / "effect.txt"
    go_path = trial_dir / "go"
    key = "deploy:svc-init-race"

    procs = [
        subprocess.Popen(
            [sys.executable, "-c", INIT_RACE_WORKER, str(ledger_path), key,
             str(effect_path), str(ready_dir), str(go_path), str(i)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for i in range(workers)
    ]
    # Everyone must be loaded and waiting before the release instant is even
    # chosen, otherwise the "race" is really a stagger and proves nothing.
    arm_deadline = time.time() + 120
    while len(list(ready_dir.iterdir())) < workers:
        assert time.time() < arm_deadline, (
            f"trial {trial}: only {len(list(ready_dir.iterdir()))}/{workers} "
            "workers armed within 120s -- barrier did not hold")
        time.sleep(0.005)
    # Written atomically (tmp + rename) so no worker can read a half-written
    # timestamp and release early.
    tmp = go_path.with_suffix(".tmp")
    tmp.write_text(repr(time.time() + 0.5))
    tmp.replace(go_path)

    results = []
    for i, p in enumerate(procs):
        out, err = p.communicate(timeout=60)
        results.append((i, p.returncode, out.strip(), err.strip()))

    crashed = [(i, err) for i, rc, out, err in results if rc != 0]
    assert not crashed, (
        f"trial {trial}: {len(crashed)}/{workers} workers escaped "
        "guard().__enter__() with an UNTYPED exception:\n" +
        "\n".join(f"  worker {i}:\n{err}" for i, err in crashed))

    outputs = [out for _, _, out, _ in results]
    executed_count = sum(1 for o in outputs if "executed=True" in o)
    assert executed_count == 1, (
        f"trial {trial}: expected exactly 1 execution, got "
        f"{executed_count}: {outputs}")
    effect_lines = (effect_path.read_text(encoding="utf-8").splitlines()
                    if effect_path.exists() else [])
    assert len(effect_lines) == 1, (
        f"trial {trial}: side effect ran {len(effect_lines)} times: {effect_lines}")
    assert receipt(key, ledger_path=ledger_path).state == "executed"
    return outputs


def test_first_touch_index_race_is_typed_and_exactly_once():
    # 5 trials, not 1: the crash window is the sub-millisecond during which
    # the FIRST process creates the database and flips its journal mode, so a
    # single trial can miss it by luck. Measured against the pre-fix code with
    # this exact barrier, per-trial reproduction ran roughly 20-100% and
    # run-level reproduction (any trial red) hit every attempt.
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        for trial in range(5):
            outputs = _run_init_race(td, trial)
            summary = {}
            for o in outputs:
                summary[o] = summary.get(o, 0) + 1
            print(f"  trial {trial}: {summary}")
    print("PASS 12 processes barrier-released onto a FRESH index, 5 trials -> "
          "exactly one execution each, zero untyped OperationalError escapes")


if __name__ == "__main__":
    test_two_processes_race_same_key_exactly_one_executes()
    test_many_repeated_races_stay_exactly_one()
    test_first_touch_index_race_is_typed_and_exactly_once()
    print("ALL PASS")
