"""arcaeon_once — executed-once receipts for non-idempotent agent side effects.

Agents retry. Refunds, deploys, and outbound emails do not want to be retried.
`arcaeon_once` wraps a non-idempotent side effect with an idempotency key: it
refuses to re-run a key that already executed, and hands back the original
tamper-evident receipt instead — built on `arcaeon-ledger`'s hash chain, so
nobody can quietly delete the record to enable a re-fire.

    from arcaeon.record.once import guard

    with guard(f"refund:{charge_id}", ledger_path="ops.log.jsonl") as g:
        result = stripe.Refund.create(charge=charge_id)
        g.done(result)

Call it again with the same key and it raises `AlreadyExecuted` (carrying the
original receipt) instead of refunding twice.

THE NON-PROOF, STATED UP FRONT BECAUSE IT IS THE POINT. This library gives you
**at-most-once-or-flagged**, not exactly-once. Exactly-once over a real,
non-transactional side effect (an HTTP call to a payment processor, a `kubectl
apply`) is not achievable by any wrapper running in the same process as the
effect: if the process dies between the effect executing and the record being
written, nobody -- this library included -- can know from the outside whether
the effect happened. Anyone selling you "exactly-once" over that boundary is
selling you a story. What we actually give you:

  - **at-most-once** when nothing crashes: a second call with the same key,
    while the ledger is intact, is refused -- period.
  - **-or-flagged** when something crashes mid-effect: the key comes back
    `Indeterminate`, a typed, refuse-by-default outcome, instead of a silent
    double-fire OR a silent skip. You verify manually (check the payment
    processor, check the deploy) and either `complete()` it (it did happen)
    or retry with `allow_retry_after_indeterminate=True` (it didn't).

CRASH-WINDOW DESIGN, not hidden. Every guarded call is two-phase in the
ledger: an `once.intent` row is appended BEFORE the effect runs, an
`once.executed` row is appended AFTER (with `guard.done(outcome)` or the
module-level `complete()`). A key with an `intent` row and no matching
`executed` row means: something started and we don't know if it finished.
That state is `Indeterminate` and is refused by default -- never silently
treated as "safe to retry" and never silently treated as "must have worked."

TAMPER-EVIDENCE, not tamper-prevention. Every intent/executed row is appended
to an `arcaeon-ledger` hash chain, so deleting an inconvenient `executed` row
to enable a re-fire breaks the chain and `receipt()` reports it.

What `guard()` does with that, stated precisely (this paragraph used to claim
the chain was NOT verified on every call; the code was the honest one): every
`guard()` entry derives the key's state through `receipt()`, and `receipt()`
runs a full `verify_file()` -- so the O(rows) scan happens on every call
whether you ask for it or not. `verify_integrity=True` does not add the scan;
it adds ENFORCEMENT. Without it the verdict is computed and then discarded,
so a claim against an already-broken chain proceeds on the ledger's face
value. (It still fails safe in the shape that matters: a deleted `executed`
row reads as an unresolved intent, which is `Indeterminate` -- a refusal, not
a re-fire. And the verdict is not thrown away everywhere -- it rides on the
`Receipt` those exceptions carry, as `ledger_ok` / `ledger_verified_scope` /
`ledger_breaks`.) Or call `arcaeon_once.receipt()` /
`arcaeon_ledger.verify_file()` on your own cadence. Tamper caught late is
still tamper caught; tamper never checked is a receipt you shouldn't trust.

THE VERDICT IS THREE-VALUED, and the receipt carries its own coverage.
`ledger_ok is True` with `ledger_verified_scope == "full"` means every row was
checked. `ledger_ok is None` with a `bounded_*` scope means no fault was found
but the scan did not cover everything -- falsy on purpose, because "verified
within scope" is not verified. `ledger_ok is False` is a real break, counted
in `ledger_breaks` (not just named in `ledger_first_break`, which reports the
first fault and thereby teaches its reader there is exactly one).

CONCURRENCY. Two processes racing the same key: the claim is a single SQLite
`BEGIN IMMEDIATE` transaction against a small index file next to the ledger
(same pattern `arcaeon-meter` uses for its usage counter) -- exactly one
process wins the claim, ever, cross-process. The loser gets `AlreadyExecuted`
or `Indeterminate` depending on timing, never a green light to also execute.
That index is a performance/concurrency accelerator, not the source of truth
-- `receipt()` always reads the ledger itself, and `rebuild_index()` replays
the ledger into a fresh index if the index file is ever lost. Losing the index
loses speed, not correctness.

The index is created lazily on first use, and that creation is serialized by a
cross-process file lock: switching a brand-new SQLite file into WAL journal
mode needs a momentary EXCLUSIVE lock that does NOT honour `busy_timeout`, so
N processes first-touching the same fresh ledger at once would otherwise
collide. If contention still cannot be absorbed, you get `IndexUnavailable` --
typed, documented, raised BEFORE any claim or ledger row, never a raw
`sqlite3.OperationalError` leaking out of `guard()`. Nothing that comes out of
this library is an untyped surprise.

Zero required dependencies beyond `arcaeon-ledger` (stdlib + sqlite3 otherwise). MIT.
"""
from __future__ import annotations

import contextlib
import functools
import os
import socket
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from arcaeon.record.ledger import Ledger, verify_file, digest_json

try:                      # POSIX advisory locks
    import fcntl as _fcntl
except ImportError:       # pragma: no cover - platform dependent
    _fcntl = None
try:                      # Windows byte-range locks
    import msvcrt as _msvcrt
except ImportError:       # pragma: no cover - platform dependent
    _msvcrt = None

__version__ = "0.2.3"
__all__ = [
    "guard", "receipt", "complete", "rebuild_index", "reclaim",
    "Receipt", "GuardContext",
    "AlreadyExecuted", "Indeterminate", "TamperDetected", "IndexUnavailable",
    "HolderAlive", "LivenessUnknown",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _outcome_form(outcome: Any) -> Any:
    """The JSON-safe form of an outcome: the value itself when the ledger can
    serialise it, else ``{"repr": repr(outcome)}``.  Used for BOTH the digest
    and the stored ``outcome`` row field so the two never disagree (0.2.1
    digested the repr fallback but then tried to store the raw object, and
    ``done()`` blew up with TypeError after the effect had already run)."""
    try:
        digest_json(outcome)
    except (TypeError, ValueError):
        # Not JSON-serializable as-is (a custom object, NaN, a lone surrogate)
        # -- fall back to its repr rather than fail the whole guard over an
        # unhashable outcome.
        return {"repr": repr(outcome)}
    return outcome


def _outcome_digest(outcome: Any) -> Optional[str]:
    """Self-describing digest of an outcome value, or None for no outcome."""
    if outcome is None:
        return None
    return digest_json(_outcome_form(outcome))


def _check_key(key: str) -> None:
    """Reject keys the ledger/index cannot carry, with a typed error, BEFORE
    any claim or row is attempted.  A lone surrogate code point escaped
    sqlite's parameter binding as a bare UnicodeEncodeError in 0.2.1."""
    if not isinstance(key, str):
        return
    try:
        key.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("key contains a lone surrogate code point; "
                         "it cannot be stored in the ledger") from None


def _default_index_path(ledger_path: Path) -> Path:
    return Path(str(ledger_path) + ".idx.sqlite3")


# -- the SQLite concurrency index -------------------------------------------
# A small, rebuildable accelerator so a `guard()` claim is a single atomic
# cross-process transaction instead of an O(rows) ledger scan on every call.
# The ledger remains the source of truth; see `rebuild_index()`.

_INDEX_TIMEOUT = 15.0                 # seconds; matches the sqlite busy_timeout
_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS once_state ("
    " key TEXT PRIMARY KEY,"
    " state TEXT NOT NULL,"            # 'claiming' | 'intent' | 'retrying' | 'executed'
    " intent_ts TEXT,"
    " executed_ts TEXT,"
    " outcome_digest TEXT,"
    " intent_chain TEXT,"
    " executed_chain TEXT,"
    " generation INTEGER NOT NULL DEFAULT 0,"
    # Liveness lease (0.2.0): who holds a live claim, written at claim time,
    # so `reclaim(key)` can PROVE a crashed holder dead instead of forcing a
    # global quiesce + rebuild_index(). NULL on rows written before 0.2.0
    # (and on rows produced by rebuild_index's replay) -- reclaim REFUSES
    # those with LivenessUnknown rather than guessing. Fail closed.
    " holder_pid INTEGER,"
    " holder_host TEXT,"
    " holder_ts TEXT)")

# Columns added after 0.1.x, ALTER-ed onto an existing index in place so a
# pre-0.2.0 index file keeps working without a rebuild (its old rows simply
# carry NULL lease fields, which reclaim() refuses -- see LivenessUnknown).
_LEASE_COLUMNS = (
    ("holder_pid", "INTEGER"),
    ("holder_host", "TEXT"),
    ("holder_ts", "TEXT"),
)

_HOSTNAME = socket.gethostname()

# Per-process memo of index files whose journal mode has already been settled,
# so the hot path never re-reads the pragma. Correctness never depends on it:
# the table check below still runs every time, and a missing table always falls
# through to the locked setup path.
_WAL_SETTLED: "set[str]" = set()


def _connect(db_path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(db_path), timeout=_INDEX_TIMEOUT,
                          isolation_level=None)
    con.execute("PRAGMA busy_timeout=15000")
    return con


@contextlib.contextmanager
def _index_setup_lock(lock_path: Path):
    """Cross-process exclusive lock around FIRST-TIME index setup.

    Yields True when a real OS lock is held, False when the platform offers no
    lock primitive at all (then the caller degrades to best-effort, which is
    slower under contention but never less correct -- see `_set_wal`).

    Why a file lock rather than just retrying the pragma: switching a SQLite
    database from `delete` to `wal` journal mode needs a momentary EXCLUSIVE
    database lock, and that acquisition does NOT honour `busy_timeout` -- it
    gives up in milliseconds. Retrying alone turns a hard failure into a
    thundering herd; serializing the setup means the switch is attempted ONCE,
    by one process, with everyone else waiting outside the database entirely.
    """
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + _INDEX_TIMEOUT
        delay = 0.001
        while True:
            try:
                if _msvcrt is not None:
                    _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
                elif _fcntl is not None:
                    _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                else:                      # pragma: no cover - exotic platform
                    yield False
                    return
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise IndexUnavailable(
                        lock_path, "acquire the index setup lock",
                        cause=exc) from exc
                time.sleep(delay)
                delay = min(delay * 2, 0.05)
        try:
            yield True
        finally:
            try:
                if _msvcrt is not None:
                    _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)
                else:
                    _fcntl.flock(fd, _fcntl.LOCK_UN)
            except OSError:                # pragma: no cover - best effort
                pass
    finally:
        os.close(fd)


def _index_is_usable(db_path: Path) -> bool:
    """Lock-free hot-path check: does the index already exist, carry its
    table, and sit in a settled journal mode? Read-only -- it takes no
    exclusive lock, so concurrent callers cannot collide here."""
    if not db_path.exists():
        return False
    try:
        con = _connect(db_path)
    except sqlite3.Error:
        return False
    try:
        # Probing the newest schema column (not `SELECT 1`) makes this check
        # double as the migration trigger: a pre-0.2.0 index -- table present
        # but no liveness-lease columns -- fails here and falls through to
        # the locked setup path, where `_migrate_lease_columns` ALTERs the
        # missing columns on in place.
        con.execute("SELECT holder_pid FROM once_state LIMIT 1").fetchone()
    except sqlite3.Error:
        return False
    else:
        if str(db_path) in _WAL_SETTLED:
            return True
        try:
            mode = con.execute("PRAGMA journal_mode").fetchone()
        except sqlite3.Error:
            return False
        if mode and str(mode[0]).lower() == "wal":
            _WAL_SETTLED.add(str(db_path))
            return True
        return False
    finally:
        con.close()


def _set_wal(con: sqlite3.Connection, db_path: Path) -> None:
    """Best-effort switch into WAL journal mode, bounded and never fatal.

    WAL is a concurrency OPTIMISATION here, not the safety mechanism -- the
    actual race serialization is `BEGIN IMMEDIATE` in `_claim`, which DOES
    honour `busy_timeout`. So a database that stubbornly stays in `delete`
    mode is slower under load, never less correct, and must not take down a
    guarded side effect. Called under `_index_setup_lock`, where in practice
    nothing is competing for the exclusive lock and it succeeds first try."""
    try:
        mode = con.execute("PRAGMA journal_mode").fetchone()
        if mode and str(mode[0]).lower() == "wal":
            _WAL_SETTLED.add(str(db_path))
            return
    except sqlite3.Error:
        pass
    deadline = time.monotonic() + _INDEX_TIMEOUT
    delay = 0.002
    while True:
        try:
            row = con.execute("PRAGMA journal_mode=WAL").fetchone()
            if row and str(row[0]).lower() == "wal":
                break
        except sqlite3.OperationalError:
            pass
        if time.monotonic() >= deadline:
            break                          # stay in `delete`: slower, not wrong
        time.sleep(delay)
        delay = min(delay * 2, 0.05)
    _WAL_SETTLED.add(str(db_path))


def _init_index(db_path: Path) -> None:
    """Ensure the concurrency index exists and is ready to serve claims.

    Runs on every `guard()` entry, so it has two paths:

    * HOT PATH -- a lock-free, read-only check (`_index_is_usable`). Once the
      index exists this costs one open + one SELECT and takes no exclusive
      lock, so N concurrent callers cannot collide.
    * FIRST-TOUCH PATH -- serialized behind a cross-process file lock, so the
      one-time `delete`->`wal` journal-mode switch happens ONCE rather than N
      times simultaneously. This is the fix for the 2026-08-14 race in which
      concurrent first use crashed out of `guard().__enter__()` with a naked
      `sqlite3.OperationalError: database is locked`.

    Any residual contention this cannot absorb surfaces as `IndexUnavailable`
    -- typed, documented, and raised before any claim or ledger row is
    written, so it fails safe.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if _index_is_usable(db_path):
        return
    with _index_setup_lock(Path(str(db_path) + ".init.lock")) as locked:
        # Double-checked: another process may have finished the setup while we
        # were queued on the lock.
        if locked and _index_is_usable(db_path):
            return
        try:
            con = _connect(db_path)
        except sqlite3.Error as exc:
            raise IndexUnavailable(
                db_path, "open the concurrency index", cause=exc) from exc
        try:
            _set_wal(con, db_path)
            _run_with_retry(lambda: con.execute(_SCHEMA), db_path,
                            "create the concurrency index table")
            _migrate_lease_columns(con, db_path)
        finally:
            con.close()


def _migrate_lease_columns(con: sqlite3.Connection, db_path: Path) -> None:
    """Backward-compatible, in-place migration: ALTER the 0.2.0 liveness-lease
    columns onto a pre-0.2.0 index. Runs only on the serialized first-touch
    setup path (`_index_is_usable` fails its column probe on a legacy index,
    which routes it here under the setup lock). Existing rows keep NULL lease
    fields -- `reclaim()` refuses those with `LivenessUnknown` rather than
    guessing about a holder nobody recorded."""
    cols = {r[1] for r in con.execute("PRAGMA table_info(once_state)")}
    for name, decl in _LEASE_COLUMNS:
        if name not in cols:
            _run_with_retry(
                lambda n=name, d=decl: con.execute(
                    f"ALTER TABLE once_state ADD COLUMN {n} {d}"),
                db_path, f"add the {name} liveness column to the index")


def _run_with_retry(fn: Callable[[], Any], db_path: Path, what: str,
                    ledger_committed: bool = False) -> Any:
    """Run a SQLite statement, retrying transient lock contention within the
    index timeout, then converting anything left into `IndexUnavailable`.

    The point is the conversion: no caller of this library should ever have to
    catch `sqlite3.OperationalError` leaking out of `guard()`. Contention is a
    real outcome; it just has to be a NAMED one."""
    deadline = time.monotonic() + _INDEX_TIMEOUT
    delay = 0.002
    while True:
        try:
            return fn()
        except sqlite3.OperationalError as exc:
            if time.monotonic() >= deadline:
                raise IndexUnavailable(
                    db_path, what, cause=exc,
                    ledger_committed=ledger_committed) from exc
            time.sleep(delay)
            delay = min(delay * 2, 0.05)
        except sqlite3.Error as exc:
            raise IndexUnavailable(
                db_path, what, cause=exc,
                ledger_committed=ledger_committed) from exc


@contextlib.contextmanager
def _index_txn(db_path: Path, what: str, ledger_committed: bool = False):
    """A connection to the index whose SQLite errors surface as the typed
    `IndexUnavailable` instead of a raw `sqlite3.OperationalError`."""
    try:
        con = _connect(db_path)
    except sqlite3.Error as exc:
        raise IndexUnavailable(db_path, what, cause=exc,
                               ledger_committed=ledger_committed) from exc
    try:
        yield con
    except sqlite3.Error as exc:
        with contextlib.suppress(sqlite3.Error):
            con.execute("ROLLBACK")
        raise IndexUnavailable(db_path, what, cause=exc,
                               ledger_committed=ledger_committed) from exc
    finally:
        con.close()


def _claim(db_path: Path, key: str) -> bool:
    """Atomically claim `key` IF the index has never seen it. Returns True
    iff this call is the one that gets to write the fresh `intent` row.

    This is pure race serialization for the "nobody has this key yet"
    boundary -- it is NOT consulted as a source of truth for existing state
    (see `_enter_for_key`, which always re-derives state from the ledger
    itself). A `BEGIN IMMEDIATE` takes a write lock before reading, so two
    processes racing this function serialize: the second one's SELECT runs
    only after the first has committed, and sees the row the first inserted.
    Exactly one caller, ever, gets back True for a given key.
    """
    what = "claim the key in the concurrency index"
    with _index_txn(db_path, what) as con:
        _run_with_retry(lambda: con.execute("BEGIN IMMEDIATE"), db_path, what)
        row = con.execute(
            "SELECT 1 FROM once_state WHERE key=?", (key,)).fetchone()
        if row is not None:
            con.execute("ROLLBACK")
            return False
        # 'claiming', not 'intent' (audit 2026-08-24, Finding 1 — a REAL
        # double-execution): an ordinary winner's row used to sit at
        # 'intent', generation=0 — byte-indistinguishable from a CRASHED
        # intent — so a second caller with allow_retry_after_indeterminate
        # CASed on it and ALSO won while the first was mid-effect (5/10
        # concurrent trials double-fired the guarded effect). 'claiming'
        # marks a LIVE in-process claim: the reclaim CAS requires 'intent'
        # specifically, so it now matches only rows produced by
        # rebuild_index()'s ledger replay — an operator action asserting the
        # prior holder is dead — never a claim that is running right now.
        # Same recovery contract the 'retrying' state already documents.
        # The liveness lease (0.2.0): pid + host + timestamp of the claimant,
        # written atomically WITH the claim, so a later `reclaim(key)` can
        # check whether this holder is still alive instead of demanding a
        # global quiesce to prove it.
        con.execute(
            "INSERT INTO once_state (key, state, intent_ts, generation, "
            "holder_pid, holder_host, holder_ts) "
            "VALUES (?, 'claiming', ?, 0, ?, ?, ?)",
            (key, _now_iso(), os.getpid(), _HOSTNAME, _now_iso()))
        con.execute("COMMIT")
        return True


def _mark_executed(db_path: Path, key: str, outcome_digest: Optional[str],
                    chain: str) -> None:
    # `ledger_committed=True`: by the time this runs, the `once.executed` row
    # is already durable in the ledger -- the source of truth. A failure here
    # leaves the accelerator stale, not the record wrong, and says so.
    what = "record the executed row in the concurrency index"
    with _index_txn(db_path, what, ledger_committed=True) as con:
        _run_with_retry(lambda: con.execute("BEGIN IMMEDIATE"), db_path, what,
                        ledger_committed=True)
        con.execute(
            "UPDATE once_state SET state='executed', executed_ts=?, "
            "outcome_digest=?, executed_chain=?, "
            "holder_pid=NULL, holder_host=NULL, holder_ts=NULL WHERE key=?",
            (_now_iso(), outcome_digest, chain, key))
        con.execute("COMMIT")


def _read_generation(db_path: Path, key: str) -> int:
    """Read-only lookup of the index's current `generation` counter for
    `key` -- the optimistic-concurrency token `_reclaim_after_indeterminate`
    CASes on. A missing row reads as 0, matching the schema's own DEFAULT."""
    what = "read the generation counter in the concurrency index"
    with _index_txn(db_path, what) as con:
        row = con.execute(
            "SELECT generation FROM once_state WHERE key=?", (key,)).fetchone()
        return row[0] if row is not None else 0


def _reclaim_after_indeterminate(db_path: Path, key: str,
                                  expected_generation: int) -> bool:
    """Explicit, caller-asserted override: "I manually verified this is safe
    to retry." Bumps the generation counter and resets the index to a fresh
    'intent' claim. Never called automatically -- only via
    `allow_retry_after_indeterminate=True`, which is itself opt-in.

    Returns True iff THIS call is the one that wins the reclaim.

    FIX (property-test pass, 2026-08-16), TWO ROUNDS -- both reproduced
    directly before being closed, neither was a test-construction artifact:

    Round 1 -- simultaneous racers. This used to be an unconditional UPDATE,
    so N callers racing `allow_retry_after_indeterminate=True` on the SAME
    indeterminate key all "won" and all ran the guarded side effect --
    reproduced directly, 6/6 (later 4/8) threads all executed. A first fix
    attempt CASed on the observed `intent_ts` instead, and STILL let
    multiple racers through: `_now_iso()` only has second resolution, so the
    winner's "new" timestamp is frequently identical to the stale one a
    same-second loser is comparing against, and the WHERE clause matches
    anyway. `generation` doesn't have that problem -- it is an exact
    integer, incremented by exactly one winner per value. The caller reads
    `expected_generation` via `_read_generation` BEFORE racing; the UPDATE
    below only succeeds for whichever transaction reaches the write lock
    while `generation` still equals that observed value.

    Round 2 -- a SEQUENTIAL second caller, no threading needed. The
    generation CAS alone only stops racers who all observed the SAME stale
    generation. It did nothing for a caller who legitimately reads the
    CURRENT generation *after* another reclaim has already won and is still
    running (hasn't called `done()` yet) -- reproduced with a plain two-step
    script, no timing race at all: `g1 = guard(..., allow_retry_after_
    indeterminate=True); g1.__enter__()` (wins), then a fresh `g2 = guard(
    ..., allow_retry_after_indeterminate=True); g2.__enter__()` called
    *before* `g1.done()` ALSO won -- because nothing distinguished "this
    intent is abandoned" from "this intent is somebody's active claim right
    now." Closed by adding a THIRD index state, `'retrying'`, entered only
    by a winning reclaim and left only by `_mark_executed` (via `done()`) --
    the CAS below requires `state='intent'` specifically, so a second
    caller arriving while a retry is genuinely in flight sees `'retrying'`,
    matches zero rows, and loses honestly instead of also winning. If the
    retry ITSELF then also crashes, the row is stuck at `'retrying'` and
    unreclaimable until `rebuild_index()` is run -- documented deliberately,
    not silently: replaying the ledger only ever produces `'intent'` or
    `'executed'` (it has no `'retrying'` concept), so a rebuild heals a
    stuck retry back to a reclaimable `'intent'` row, matching the
    module docstring's existing "losing the index loses speed, not
    correctness" promise and its existing crash-recovery instructions.

    Every losing racer re-derives from the ledger and gets `Indeterminate`
    (or `AlreadyExecuted` if the winner finished in the meantime) --
    same as a `_claim()` loss on a never-seen key, never a silent green
    light to also execute.

    Round 3 -- adversarial audit 2026-08-24, and it is the same disease as
    Round 2 one state over. The Round 2 fix protected a live RECLAIM
    (state='retrying'), but an ORDINARY `_claim()` winner still sat at
    `state='intent'`, `generation=0` -- byte-indistinguishable from a
    crashed intent -- so a caller with the retry flag CASed on the LIVE
    ordinary claim and also won: reproduced both sequentially (two-step
    script) and under a pure thread race on a fresh key (5/10 trials
    double-fired the guarded effect, no crash involved). Closed by giving
    the ordinary claim its own live state, `'claiming'` (entered by
    `_claim`, left by `_mark_executed`), which this CAS -- still requiring
    `state='intent'` -- matches never. CONTRACT CHANGE, deliberate and
    loud: after a genuine crash of an ordinary claim, the index row is
    stuck at `'claiming'` and the retry flag alone no longer heals it; run
    `rebuild_index()` first (the ledger replay produces `'intent'`, which
    the flag then reclaims) -- exactly the recovery already documented for
    a stuck `'retrying'` row. The flag's assertion is "the prior holder is
    dead"; the rebuild is the step that makes that assertion checkable
    against the ledger instead of taking the caller's word while the prior
    holder may be mid-effect. At-most-once outranks recovery convenience.
    """
    what = "reclaim the indeterminate key in the concurrency index"
    with _index_txn(db_path, what) as con:
        _run_with_retry(lambda: con.execute("BEGIN IMMEDIATE"), db_path, what)
        # The winning reclaim becomes the new live holder, so its lease is
        # written here exactly as `_claim` writes one -- a crashed RETRY is
        # then just as provably-dead to `reclaim(key)` as a crashed claim.
        cur = con.execute(
            "UPDATE once_state SET state='retrying', intent_ts=?, "
            "generation=generation+1, holder_pid=?, holder_host=?, holder_ts=? "
            "WHERE key=? AND state='intent' AND generation=?",
            (_now_iso(), os.getpid(), _HOSTNAME, _now_iso(),
             key, expected_generation))
        won = cur.rowcount == 1
        con.execute("COMMIT")
        return won


def rebuild_index(ledger_path: "str | Path",
                   state_db: "str | Path | None" = None) -> int:
    """Rebuild the SQLite concurrency index by replaying the ledger.

    The ledger (hash-chained JSONL) is the source of truth; the index is a
    disposable performance/concurrency accelerator. If the index file is
    lost, corrupted, or you simply don't trust it, this rebuilds it from
    scratch by replaying every `once.intent` / `once.executed` row in order.
    Returns the number of distinct keys indexed.

    QUIESCE FIRST -- this is a maintenance/recovery operation, NOT a routine
    step, and it is UNSAFE to run while guarded work is in flight (audit
    2026-08-24, Round 3 review). The reason is the same hard fact this whole
    package is built around: a live claim and a crashed one are byte-
    identical in durable state -- both are a single `once.intent` ledger row
    with no `once.executed`. So the replay CANNOT tell them apart, and it
    rewrites BOTH to the reclaimable `'intent'` state. That is exactly what
    you want for a genuinely crashed claim (it becomes reclaimable via
    `allow_retry_after_indeterminate=True`), and exactly what you do NOT want
    for a claim that is running right now -- a concurrent retry-flagged
    caller could then also win it and double-fire the effect. Run this only
    when no `guard()` block is active anywhere against this ledger. When it
    downgrades any in-flight-looking (`'claiming'`/`'retrying'`) rows from a
    prior index, it WARNS with the count, so an operator who ran it on a live
    system by mistake gets a signal instead of a silent stolen claim.

    Recovery decision tree, so rebuild is never reached by reflex:
      - Crashed key, effect DID land  -> `complete(key, ...)`. No rebuild.
      - Crashed key, effect did NOT land -> quiesce, THEN rebuild_index(),
        THEN `guard(key, allow_retry_after_indeterminate=True)`.
      - Index file merely lost/corrupt, system otherwise idle -> rebuild_index().

    Restores CORRECTNESS (duplicate refusal resumes working); does not
    reconstruct the exact claim timing of a race in flight when the index was
    lost -- an inherent limit of any rebuild-from-log approach.
    """
    ledger_path = Path(ledger_path)
    db_path = Path(state_db) if state_db else _default_index_path(ledger_path)
    # Count in-flight-looking rows in the OLD index before destroying it, so a
    # rebuild run against a live system can WARN rather than silently convert
    # every live claim to stealable (Round 3 review).
    live_before = 0
    if db_path.exists():
        try:
            with _index_txn(db_path, "count in-flight rows before rebuild") as con:
                r = con.execute(
                    "SELECT COUNT(*) FROM once_state "
                    "WHERE state IN ('claiming', 'retrying')").fetchone()
                live_before = r[0] if r else 0
        except Exception:
            live_before = 0  # unreadable old index -> nothing to warn about
    if live_before:
        import warnings as _warnings
        _warnings.warn(
            f"rebuild_index() is downgrading {live_before} in-flight-looking "
            f"claim(s) ('claiming'/'retrying') to the reclaimable 'intent' "
            f"state. If any guard() block is ACTIVE against this ledger right "
            f"now, that claim is now stealable and its effect can double-fire "
            f"-- rebuild_index requires quiescence (see its docstring). If the "
            f"system is idle and these are genuine crash remnants, this is the "
            f"intended healing.", stacklevel=2)
    if db_path.exists():
        db_path.unlink()
    for sidecar in ("-wal", "-shm"):       # never let an orphaned WAL survive
        stale = Path(str(db_path) + sidecar)
        if stale.exists():
            stale.unlink()
    _WAL_SETTLED.discard(str(db_path))
    _init_index(db_path)
    seen: "dict[str, dict]" = {}
    for row in Ledger(ledger_path):
        if not isinstance(row, dict):
            # A shared ledger may carry foreign non-object lines (`[1, 2]`,
            # `"note"`); they are not once rows, not a crash.
            continue
        key = row.get("key")
        if key is None:
            continue
        event = row.get("event")
        if event == "once.intent":
            seen[key] = {"state": "intent", "intent_ts": row.get("ts"),
                         "intent_chain": row.get("chain")}
        elif event == "once.executed":
            entry = seen.setdefault(key, {})
            entry.update({"state": "executed", "executed_ts": row.get("ts"),
                          "executed_chain": row.get("chain"),
                          "outcome_digest": row.get("outcome_digest")})
    what = "replay the ledger into a fresh concurrency index"
    with _index_txn(db_path, what) as con:
        _run_with_retry(lambda: con.execute("BEGIN IMMEDIATE"), db_path, what)
        for key, s in seen.items():
            con.execute(
                "INSERT INTO once_state (key, state, intent_ts, executed_ts, "
                "outcome_digest, intent_chain, executed_chain, generation) "
                "VALUES (?,?,?,?,?,?,?,0)",
                (key, s.get("state"), s.get("intent_ts"), s.get("executed_ts"),
                 s.get("outcome_digest"), s.get("intent_chain"),
                 s.get("executed_chain")))
        con.execute("COMMIT")
    return len(seen)


def _pid_alive(pid: Any) -> "bool | None":
    """Three-valued liveness probe for a recorded holder pid, ON THIS HOST.

    Returns True (provably running), False (provably not running), or None
    (could not determine). Callers must treat None exactly like True for
    safety decisions -- indeterminate is refuse, fail closed.

    Windows: NEVER `os.kill(pid, 0)` here -- on Windows any signal value
    other than the two CTRL events is delivered via TerminateProcess, i.e.
    "checking" liveness would KILL the process being checked. The probe is
    OpenProcess with the weakest query right instead:
      - ERROR_INVALID_PARAMETER (87): no such pid -> dead.
      - ERROR_ACCESS_DENIED (5): the pid exists (we just can't open it) ->
        alive as far as this decision is concerned.
      - handle obtained: GetExitCodeProcess, STILL_ACTIVE (259) -> alive,
        anything else -> exited (a handle can outlive the process).
    POSIX: `os.kill(pid, 0)` -- ProcessLookupError -> dead, PermissionError
    -> exists -> alive, success -> alive.

    PID-REUSE CAVEAT, stated: a dead holder's pid can be recycled by an
    unrelated process, in which case this reads "alive" and `reclaim()`
    refuses a key it could in principle have freed. That error lands on the
    SAFE side only -- a pid cannot be reused while its owner still runs, so
    reuse can cause a false REFUSAL (fall back to the quiesce path), never
    a false reclaim of a live claim.
    """
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return None
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                err = ctypes.get_last_error()
                if err == 87:          # ERROR_INVALID_PARAMETER: no such pid
                    return False
                if err == 5:           # ERROR_ACCESS_DENIED: exists
                    return True
                return None
            try:
                code = ctypes.c_ulong()
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                    return None
                return code.value == 259   # STILL_ACTIVE
            finally:
                kernel32.CloseHandle(handle)
        except Exception:              # pragma: no cover - defensive
            return None
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:                    # pragma: no cover - exotic errno
        return None


def reclaim(key: "str | Callable", *, ledger_path: "str | Path",
            state_db: "str | Path | None" = None) -> Receipt:
    """Free ONE crashed key for retry -- the targeted, no-quiesce alternative
    to `rebuild_index()`, and strictly safer: it frees the key only when the
    recorded holder is PROVABLY dead, where the rebuild takes your word that
    the whole system is idle.

    What it does, atomically for this key alone:
      1. Reads the key's index row and its liveness lease (holder pid + host
         + timestamp, written at claim time since 0.2.0).
      2. Probes the holder pid ON THIS HOST. Three outcomes:
         - provably DEAD -> the row alone is rewritten to the reclaimable
           `'intent'` state (generation bumped), and
           `guard(key, allow_retry_after_indeterminate=True)` will now win
           it. No other key's row is touched; live claims elsewhere are
           never downgraded; no quiesce required.
         - provably ALIVE (including this process) -> `HolderAlive`. The
           claim is somebody's active work; reclaiming it is the exact
           double-fire this library exists to refuse.
         - INDETERMINATE -> `LivenessUnknown`. No lease on the row (written
           before 0.2.0, or produced by `rebuild_index`'s replay, which has
           no holder to record), a lease from a DIFFERENT host (a pid is
           only meaningful on the machine that issued it), or a probe that
           could not decide. Fail closed: use the documented quiesce ->
           `rebuild_index()` path instead, where quiescence is what proves
           deadness.
      3. Special case, healed on the way through: a holder that died between
         winning the index claim and appending its ledger `intent` row
         (audit 2026-08-24 Finding 2) leaves an index row with NO ledger
         trace. With the holder provably dead, that row is deleted outright
         so a plain `guard()` can claim the key fresh.

    Raises `ValueError` when there is nothing to reclaim (the key already
    executed -- that's `receipt()`'s territory). A row already sitting at
    `'intent'` is already reclaimable; that's a no-op success.

    Returns the post-reclaim ledger `Receipt` (state `'intent'`, or
    `'never'` for the Finding-2 delete case).
    """
    key = str(key)
    _check_key(key)
    ledger_path = Path(ledger_path)
    db_path = Path(state_db) if state_db else _default_index_path(ledger_path)
    _init_index(db_path)
    rec = receipt(key, ledger_path=ledger_path)
    if rec.state == "executed":
        raise ValueError(
            f"nothing to reclaim: key {key!r} already executed at "
            f"{rec.executed_ts} -- inspect it via receipt(), don't re-fire it")
    what = "reclaim the single key in the concurrency index"
    with _index_txn(db_path, what) as con:
        _run_with_retry(lambda: con.execute("BEGIN IMMEDIATE"), db_path, what)
        row = con.execute(
            "SELECT state, holder_pid, holder_host, holder_ts "
            "FROM once_state WHERE key=?", (key,)).fetchone()
        if row is None:
            con.execute("ROLLBACK")
            if rec.state == "never":
                raise ValueError(
                    f"nothing to reclaim: key {key!r} has never been claimed")
            raise LivenessUnknown(
                key, "the concurrency index has no row for this key (index "
                "lost or replaced since the claim), so there is no liveness "
                "lease to check")
        state, holder_pid, holder_host, holder_ts = row
        if state == "executed":
            con.execute("ROLLBACK")
            raise ValueError(
                f"nothing to reclaim: key {key!r} is recorded executed in "
                "the index -- inspect it via receipt()")
        if state == "intent":
            # Already in the reclaimable state (rebuild_index replay, or a
            # prior successful reclaim). Nothing to prove, nothing to change.
            con.execute("ROLLBACK")
            return rec
        if holder_pid is None or holder_host is None:
            con.execute("ROLLBACK")
            raise LivenessUnknown(
                key, "this claim carries no liveness lease (row written by a "
                "pre-0.2.0 release), so the holder cannot be proven dead")
        if holder_host != _HOSTNAME:
            con.execute("ROLLBACK")
            raise LivenessUnknown(
                key, f"the claim was taken on host {holder_host!r} and this "
                f"is {_HOSTNAME!r} -- a pid is only meaningful on the "
                "machine that issued it")
        alive = _pid_alive(holder_pid)
        if alive is True:
            con.execute("ROLLBACK")
            raise HolderAlive(key, holder_pid, holder_ts)
        if alive is None:
            con.execute("ROLLBACK")
            raise LivenessUnknown(
                key, f"could not determine whether holder pid {holder_pid} "
                "is alive")
        # Provably dead. Rewrite THIS key's row alone.
        if rec.state == "never":
            # Died between the index claim and the ledger intent append: the
            # ledger has no trace, so the honest healing is a fresh start.
            con.execute("DELETE FROM once_state WHERE key=?", (key,))
        else:
            con.execute(
                "UPDATE once_state SET state='intent', "
                "generation=generation+1, "
                "holder_pid=NULL, holder_host=NULL, holder_ts=NULL "
                "WHERE key=?", (key,))
        con.execute("COMMIT")
    return receipt(key, ledger_path=ledger_path)


# -- receipts -----------------------------------------------------------

@dataclass
class Receipt:
    """The tamper-evident state of one idempotency key, read from the ledger
    itself (not the SQLite index) -- this is the thing you'd hand to an
    auditor or a skeptical teammate."""
    key: str
    state: str = "never"          # "never" | "intent" | "executed"
    intent_ts: Optional[str] = None
    intent_chain: Optional[str] = None
    executed_ts: Optional[str] = None
    executed_chain: Optional[str] = None
    outcome_digest: Optional[str] = None
    outcome: Any = None           # only populated if store_outcome=True was used
    ledger_path: Optional[str] = None
    # THREE-VALUED, straight through from arcaeon_ledger's own verdict (0.5.7+):
    #   True  -- every row in the chain was checked and it holds. Full green.
    #   None  -- no fault FOUND, but the scan did not cover every row (unchained
    #            pre-chain rows skipped, or a break excused by a declaration).
    #            Falsy on purpose. "Verified within scope" is not verified.
    #   False -- a real break.
    # Defaults to None, not True: a verdict field that defaults to the
    # reassuring value hands out a green nobody computed.
    ledger_ok: Optional[bool] = None
    ledger_first_break: Optional[str] = None
    # `first_break` names the FIRST fault and nothing else, which teaches its
    # reader there is exactly one. These two carry the rest: how many breaks
    # the walker actually counted, and what the scan covered. None when the
    # installed arcaeon-ledger predates those fields.
    ledger_verified_scope: Optional[str] = None
    ledger_breaks: Optional[int] = None

    def __bool__(self) -> bool:
        """Truthy only for a clean, FULLY-verified, executed record.

        `ledger_ok is None` ("no fault found, but the scan was bounded") is
        NOT a green and never has been -- but until 0.2.1 the expression here
        was `... and self.ledger_ok`, which RETURNS None on that case, and
        Python rejects a non-bool from `__bool__`. So `if receipt(...):`
        raised `TypeError: __bool__ should return bool, returned NoneType`
        against any ledger carrying pre-chain rows or a declared break --
        the documented way to use this API, crashing instead of answering.
        """
        return self.state == "executed" and self.ledger_ok is True

    def to_dict(self) -> dict:
        return {
            "key": self.key, "state": self.state,
            "intent_ts": self.intent_ts, "intent_chain": self.intent_chain,
            "executed_ts": self.executed_ts, "executed_chain": self.executed_chain,
            "outcome_digest": self.outcome_digest, "outcome": self.outcome,
            "ledger_path": self.ledger_path, "ledger_ok": self.ledger_ok,
            "ledger_first_break": self.ledger_first_break,
            "ledger_verified_scope": self.ledger_verified_scope,
            "ledger_breaks": self.ledger_breaks,
        }


def receipt(key: "str | Callable", *, ledger_path: "str | Path") -> Receipt:
    """The tamper-evident proof of a key's state, read directly from the
    hash chain (never from the SQLite index, which is only a concurrency
    accelerator). Runs a full `verify_file` so a tampered ledger is flagged
    on the receipt rather than silently trusted.

    The chain verdict on the returned `Receipt` is THREE-valued and carries
    its own coverage: `ledger_ok is True` with `ledger_verified_scope ==
    "full"` is the only clean bill; `ledger_ok is None` with a `bounded_*`
    scope means no fault was found but not every row was checked (falsy on
    purpose); `ledger_ok is False` is a real break, whose count is
    `ledger_breaks` and whose first instance is `ledger_first_break`. Reading
    only `first_break` teaches you there is exactly one fault, which is not
    something this function ever claimed.
    """
    return _receipt_with_vr(str(key), Path(ledger_path))[0]


def _receipt_with_vr(key: str, ledger_path: Path):
    """`receipt()`, plus the raw `VerifyResult` it was derived from.

    Exists because `guard()` needs BOTH, and `verify_file` is the expensive
    half (O(rows)). Before 0.2.1, `guard(..., verify_integrity=True)` verified
    the whole chain, then called `receipt()`, which verified the whole chain
    AGAIN -- two full scans per claim. One scan, both consumers.
    """
    vr = verify_file(ledger_path)
    rec = Receipt(key=key, ledger_path=str(ledger_path),
                  ledger_ok=vr.ok, ledger_first_break=vr.first_break,
                  # getattr, not attribute access. The declared floor is
                  # 0.5.7 (where the three-valued verdict and `verified_scope`
                  # arrived, which is what makes this package's own "only a
                  # full scan is a green" statement true) -- but a floor is a
                  # promise about what a resolver installs, not a guarantee
                  # about what is on the machine. Absent -> None, which reads
                  # as "unknown", which is exactly what it is.
                  ledger_verified_scope=getattr(vr, "verified_scope", None),
                  ledger_breaks=getattr(vr, "breaks", None))
    for row in Ledger(ledger_path):
        if not isinstance(row, dict) or row.get("key") != key:
            continue
        event = row.get("event")
        if event == "once.intent":
            rec.state = "intent"
            rec.intent_ts = row.get("ts")
            rec.intent_chain = row.get("chain")
            rec.executed_ts = None
            rec.executed_chain = None
            rec.outcome_digest = None
            rec.outcome = None
        elif event == "once.executed":
            rec.state = "executed"
            rec.executed_ts = row.get("ts")
            rec.executed_chain = row.get("chain")
            rec.outcome_digest = row.get("outcome_digest")
            rec.outcome = row.get("outcome")
    return rec, vr


def complete(key: "str | Callable", outcome: Any = None, *,
             ledger_path: "str | Path", state_db: "str | Path | None" = None,
             store_outcome: bool = False) -> Receipt:
    """Mark `key` executed directly, without an open `guard()` context.

    This is the crash-recovery path: a process died mid-effect leaving an
    `intent`-only (indeterminate) record; you checked the real system (the
    payment processor, the deploy target) by hand and confirmed the effect
    DID complete. Rather than forcing a re-execution via
    `allow_retry_after_indeterminate`, record what actually happened.

    Refuses (`ValueError`) unless the key is currently in `intent` state --
    you can't complete a key nobody claimed, and you can't complete one
    that's already executed (that actually-already-happened case is exactly
    what `receipt()` / `AlreadyExecuted` is for).
    """
    key = str(key)
    _check_key(key)
    ledger_path = Path(ledger_path)
    rec = receipt(key, ledger_path=ledger_path)
    if rec.state != "intent":
        raise ValueError(
            f"cannot complete key {key!r}: currently in state {rec.state!r} "
            "(expected 'intent' -- claim it with guard() first, or check "
            "whether it's already executed via receipt())")
    digest = _outcome_digest(outcome)
    row: "dict[str, Any]" = {"event": "once.executed", "key": key,
                              "outcome_digest": digest}
    if store_outcome:
        # Store the same JSON-safe form the digest was taken over, so the
        # stored value and its digest agree and a non-serialisable outcome
        # cannot fail the append after the effect already ran.
        row["outcome"] = _outcome_form(outcome)
    # Open/create the index BEFORE the ledger append.  If the index cannot
    # be opened at all, the IndexUnavailable raised here truthfully carries
    # ledger_committed=False; opening it after the append made the message
    # say "no ledger row was written" while the executed row already sat in
    # the chain (audit 2026-09-01).
    db_path = Path(state_db) if state_db else _default_index_path(ledger_path)
    _init_index(db_path)
    chain = Ledger(ledger_path).append(row)
    _mark_executed(db_path, key, digest, chain)
    return receipt(key, ledger_path=ledger_path)


# -- typed outcomes -------------------------------------------------------

class AlreadyExecuted(Exception):
    """Raised (default) when `key` already has an `executed` record. Carries
    the original tamper-evident `.receipt` -- inspect it instead of
    re-running the side effect."""

    def __init__(self, receipt: Receipt):
        self.receipt = receipt
        super().__init__(
            f"key {receipt.key!r} already executed at {receipt.executed_ts} "
            f"(chain={receipt.executed_chain}) -- refusing to run it again")


class Indeterminate(Exception):
    """Raised (default) when `key` has an unresolved `intent` record and no
    matching `executed` record -- the process that claimed it may have
    crashed mid-effect, or may still be running right now. This is the
    honest "we don't know" outcome: refuse by default, never guess.

    Resolve by checking the real system, then either `complete(key, ...)`
    (it did happen) or `guard(key, allow_retry_after_indeterminate=True)`
    (it didn't, safe to retry -- an explicit, caller-asserted override).
    If the flag refuses because the crashed claim still occupies the index
    (`'claiming'`/`'retrying'`), `reclaim(key, ...)` verifies the holder is
    dead and frees that one key -- no quiesce, no rebuild."""

    def __init__(self, receipt: Receipt):
        self.receipt = receipt
        super().__init__(
            f"key {receipt.key!r} has an unresolved intent (since "
            f"{receipt.intent_ts}, chain={receipt.intent_chain}) with no "
            "executed record -- verify manually whether the side effect "
            "actually ran before retrying (arcaeon_once.complete(key, ...) "
            "if it did; if it didn't, reclaim(key, ...) to free the crashed "
            "claim, then guard(key, allow_retry_after_indeterminate=True))")


class HolderAlive(Exception):
    """Raised by `reclaim(key)` when the claim's recorded holder process is
    PROVABLY RUNNING right now. This claim is somebody's active work, not a
    crash remnant -- reclaiming it would authorise the exact double-fire this
    library exists to refuse. Nothing was changed.

    Attributes: `.key`, `.holder_pid`, `.holder_ts` (when the lease was
    written)."""

    def __init__(self, key: str, holder_pid: int, holder_ts: Optional[str]):
        self.key = key
        self.holder_pid = holder_pid
        self.holder_ts = holder_ts
        super().__init__(
            f"refusing to reclaim key {key!r}: its holder (pid {holder_pid}, "
            f"lease written {holder_ts}) is ALIVE on this host -- the claim "
            "is active work, not a crash remnant. If that process is wedged "
            "rather than working, stop it first, then reclaim.")


class LivenessUnknown(Exception):
    """Raised by `reclaim(key)` when the holder's deadness CANNOT BE PROVEN:
    the row carries no liveness lease (written by a pre-0.2.0 release, or by
    `rebuild_index`'s replay), the lease names a different host (a pid is
    only meaningful on the machine that issued it), or the pid probe itself
    could not decide. Indeterminate is refuse -- fail closed; nothing was
    changed.

    The recovery for this case is the pre-0.2.0 one, where quiescence is
    what proves deadness: stop all guard() work against this ledger, run
    `rebuild_index()`, then `guard(key,
    allow_retry_after_indeterminate=True)`.

    Attributes: `.key`, `.reason`."""

    def __init__(self, key: str, reason: str):
        self.key = key
        self.reason = reason
        super().__init__(
            f"cannot reclaim key {key!r}: {reason}. Refusing (indeterminate "
            "= refuse). Use the quiesce path instead: stop all guard() work "
            "against this ledger, rebuild_index(), then guard(key, "
            "allow_retry_after_indeterminate=True).")


class IndexUnavailable(Exception):
    """Raised when the SQLite concurrency index cannot be brought up, locked,
    or written -- e.g. many processes first-touching a brand-new index in the
    same instant, a stuck lock on the index file, or a read-only directory.

    This is the TYPED form of what used to escape `guard().__enter__()` as a
    naked `sqlite3.OperationalError: database is locked`. Contention is a real
    outcome; the contract is only that it has a NAME you can catch, like every
    other outcome in this library.

    It fails SAFE. Everywhere but one, it is raised before any claim row and
    before any ledger row is written -- no side effect was authorised, and
    retrying the guarded call is safe as far as this library is concerned
    (the key was never claimed).

    THE ONE EXCEPTION, stated on the instance as `.ledger_committed`: when
    raised from `guard.done()` / `complete()`, the `once.executed` row is
    ALREADY durable in the ledger and only the index accelerator is stale.
    Duplicate refusal keeps working regardless -- `receipt()` reads the ledger
    and never the index -- and `rebuild_index()` resyncs the accelerator.
    Do NOT re-run the side effect on this one; it recorded.

    Attributes: `.db_path`, `.operation`, `.cause` (the underlying
    `sqlite3.Error`), `.ledger_committed`.
    """

    def __init__(self, db_path: "str | Path", operation: str, *,
                 cause: Optional[BaseException] = None,
                 ledger_committed: bool = False):
        self.db_path = str(db_path)
        self.operation = operation
        self.cause = cause
        self.ledger_committed = ledger_committed
        tail = (" -- the executed row IS committed to the ledger (the source "
                "of truth); only the index accelerator is stale, so duplicate "
                "refusal still works and rebuild_index() resyncs it. Do not "
                "re-run the side effect."
                if ledger_committed else
                " -- no claim and no ledger row were written, so nothing was "
                "authorised to run")
        super().__init__(
            f"concurrency index unavailable, could not {operation} at "
            f"{self.db_path}: {cause}{tail}")


class TamperDetected(Exception):
    """Raised by `guard(..., verify_integrity=True)` when the ledger's hash
    chain does not verify -- refuses to make ANY claim (executed or not)
    about a key when the record itself can't be trusted."""

    def __init__(self, verify_result):
        self.verify_result = verify_result
        scope = getattr(verify_result, "verified_scope", None)
        if verify_result.ok is None:
            # Not a break -- a BOUNDED scan. Saying "chain broken: None" here
            # (which is what this message used to say) is a lie in both halves.
            detail = (f"the chain verified within a BOUNDED scope "
                      f"({scope!r}) -- no fault was found, but not every row "
                      f"was checked, so this is not a green to extend")
        else:
            detail = f"first break: {verify_result.first_break}"
            n = getattr(verify_result, "breaks", None)
            if isinstance(n, int) and n > 1:
                # A result object that reports only the first fault teaches
                # its reader there is exactly one fault.
                detail += f" (and {n - 1} more -- {n} breaks in total)"
            if scope and scope != "full":
                detail += f"; scanned scope: {scope!r}"
        super().__init__(
            f"ledger chain not verified, refusing to trust or extend it: "
            f"{detail}")


# -- the guard --------------------------------------------------------------

class GuardContext:
    """Context manager / decorator returned by `guard()`. See module docstring."""

    def __init__(self, key_spec: "str | Callable", *, ledger_path: Path,
                 state_db: "Path | None", on_duplicate: str,
                 allow_retry_after_indeterminate: bool,
                 verify_integrity: bool, store_outcome: bool):
        if on_duplicate not in ("raise", "return_receipt"):
            raise ValueError(
                "on_duplicate must be 'raise' or 'return_receipt', "
                f"got {on_duplicate!r}")
        self._key_spec = key_spec
        self.ledger_path = Path(ledger_path)
        self.state_db = state_db or _default_index_path(self.ledger_path)
        self.on_duplicate = on_duplicate
        self.allow_retry_after_indeterminate = allow_retry_after_indeterminate
        self.verify_integrity = verify_integrity
        self.store_outcome = store_outcome

        self.key: Optional[str] = None
        self.already_executed = False
        self.receipt: Optional[Receipt] = None
        self._won = False
        self._completed = False

    # -- context manager ----------------------------------------------------
    def __enter__(self) -> "GuardContext":
        if callable(self._key_spec):
            raise TypeError(
                "guard(key_fn) with a callable key is decorator-only "
                "(the key needs the call's arguments to resolve). Use it as "
                "`@guard(key_fn)` on a function, or resolve the key yourself "
                "and pass a plain string to guard() for `with` usage.")
        self.key = str(self._key_spec)
        self._enter_for_key(self.key)
        return self

    def _enter_for_key(self, key: str) -> None:
        # FIX (property-test pass, 2026-08-16): a ledger path that has never
        # been touched (this is the FIRST guard() call ever made against it)
        # used to raise TamperDetected unconditionally, because
        # arcaeon_ledger.verify_file() returns ok=False with
        # first_break="unreadable: ..." for a genuinely-missing file -- a
        # DELIBERATE distinction from a broken one (arcaeon-ledger's 0.5.4
        # CHANGELOG: "A never-created path returns ok=False... an explicitly
        # -created zero-byte file returns ok=True" -- callers are told to
        # branch on first_break, not just ok). arcaeon_once wasn't making
        # that distinction, so any caller who conscientiously always passes
        # verify_integrity=True (the docstring's own recommended "stronger
        # guarantee") got a confusing TamperDetected on their very first
        # call, on a file that was never written to, let alone tampered.
        # Reproduced directly: guard(key, ledger_path=<never-created path>,
        # verify_integrity=True) always raised, 100% of the time. A missing
        # file has nothing to verify -- fixed by skipping the chain check
        # (not the tamper check's meaning) when the path doesn't exist yet;
        # an existing-but-broken ledger is unaffected and still raises.
        # ONE chain verification per entry, shared by the tamper gate and the
        # state derivation below (it used to be two full O(rows) scans).
        # `vr.ok is not True` is the same gate the old `not vr.ok` was: a
        # bounded verdict (ok=None) is not a green to extend a chain on.
        _check_key(key)
        rec, vr = _receipt_with_vr(key, self.ledger_path)
        if self.verify_integrity and self.ledger_path.exists() and vr.ok is not True:
            raise TamperDetected(vr)
        _init_index(self.state_db)
        # The ledger is ALWAYS the source of truth for existing state -- an
        # out-of-band edit to the ledger file (a dropped row, a tampered
        # byte) must be reflected here even though the SQLite index wasn't
        # touched. The index is consulted only below, to serialize the race
        # on a key nobody has claimed yet. (`rec` is the one derived above,
        # from the single verify pass.)
        if rec.state == "executed":
            self._resolve_duplicate(rec)
            return
        if rec.state == "intent":
            self._resolve_indeterminate(rec)
            return
        # rec.state == "never": race to claim it via the SQLite index.
        if _claim(self.state_db, key):
            Ledger(self.ledger_path).append({"event": "once.intent", "key": key})
            self._won = True
            return
        # Lost the race -- someone else's insert landed first. Re-derive from
        # the ledger to find out what they did (they may not have finished
        # writing their `intent` row yet; that's still an honest "unresolved,
        # try again shortly," never a green light for us to also proceed).
        rec2 = receipt(key, ledger_path=self.ledger_path)
        if rec2.state == "executed":
            self._resolve_duplicate(rec2)
        else:
            self._resolve_indeterminate(rec2)

    def _resolve_duplicate(self, rec: Receipt) -> None:
        if self.on_duplicate == "return_receipt":
            self.already_executed = True
            self.receipt = rec
            return
        raise AlreadyExecuted(rec)

    def _resolve_indeterminate(self, rec: Receipt) -> None:
        if self.allow_retry_after_indeterminate:
            # CAS on the generation counter observed just before racing --
            # see the fix note on `_reclaim_after_indeterminate`. Only the
            # one racer whose observed generation still matches the live row
            # wins; everyone else re-derives from the ledger below instead
            # of also proceeding to run the guarded effect.
            observed_generation = _read_generation(self.state_db, rec.key)
            if _reclaim_after_indeterminate(self.state_db, rec.key, observed_generation):
                Ledger(self.ledger_path).append(
                    {"event": "once.intent", "key": rec.key,
                     "retry_of_indeterminate": True})
                self._won = True
                return
            rec2 = receipt(rec.key, ledger_path=self.ledger_path)
            if rec2.state == "executed":
                self._resolve_duplicate(rec2)
            else:
                # Someone else's reclaim is in flight (or already lost their
                # own race further down the line). Still an honest "don't
                # know yet" -- never a silent green light to also execute.
                raise Indeterminate(rec2)
            return
        raise Indeterminate(rec)

    def done(self, outcome: Any = None, *,
             store_outcome: "bool | None" = None) -> Receipt:
        """Mark the guarded side effect as successfully executed. Required --
        the effect is only recorded EXECUTED when you explicitly say so; a
        `with` block that exits (cleanly OR via exception) without calling
        `done()` leaves the `intent` record dangling on purpose. See the
        module docstring's crash-window section for why that's the honest
        default rather than a bug."""
        if not self._won:
            raise RuntimeError(
                "done() called without owning the execution claim for this "
                "key (guard() didn't win it -- check .already_executed)")
        so = self.store_outcome if store_outcome is None else store_outcome
        self.receipt = complete(self.key, outcome, ledger_path=self.ledger_path,
                                state_db=self.state_db, store_outcome=so)
        self._completed = True
        return self.receipt

    def __exit__(self, exc_type, exc, tb) -> bool:
        # Deliberately does nothing on exception or silent fall-through: only
        # `done()` writes the executed record. See module docstring.
        return False

    # -- decorator ------------------------------------------------------
    def __call__(self, fn: Callable) -> Callable:
        key_spec = self._key_spec

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            key = key_spec(*args, **kwargs) if callable(key_spec) else str(key_spec)
            g = GuardContext(
                key, ledger_path=self.ledger_path, state_db=self.state_db,
                on_duplicate=self.on_duplicate,
                allow_retry_after_indeterminate=self.allow_retry_after_indeterminate,
                verify_integrity=self.verify_integrity,
                store_outcome=self.store_outcome)
            g.key = key
            g._enter_for_key(key)
            if g.already_executed:
                return g.receipt
            result = fn(*args, **kwargs)   # an exception here leaves intent dangling
            g.done(result)
            return result
        wrapper.__wrapped_guard__ = self  # introspection hook, not part of the API contract
        return wrapper


def guard(key: "str | Callable", *, ledger_path: "str | Path | None" = None,
          state_db: "str | Path | None" = None, on_duplicate: str = "raise",
          allow_retry_after_indeterminate: bool = False,
          verify_integrity: bool = False,
          store_outcome: bool = False) -> GuardContext:
    """Guard a non-idempotent side effect against duplicate execution.

    `key`: the idempotency key (a string), or -- decorator use only -- a
      `callable(*args, **kwargs) -> str` resolving the key from the call.
    `ledger_path`: the hash-chained JSONL to record into. Default
      `"once.log.jsonl"` in the current directory.
    `on_duplicate`: `"raise"` (default) -- raise `AlreadyExecuted` with the
      original receipt attached. `"return_receipt"` -- `__enter__` (or the
      decorator) returns without executing; check `.already_executed` /
      `.receipt`, or for the decorator, the wrapped call returns the
      `Receipt` object directly instead of calling the wrapped function.
    `allow_retry_after_indeterminate`: explicit override for a key stuck in
      `intent` state -- "I manually verified this is safe to retry."
      Default False (refuse). Not a substitute for checking; it's how you
      tell the library what you found.
    `verify_integrity`: run a full ledger chain verification before claiming
      (O(rows), off by default for hot-path speed). Raises `TamperDetected`
      if the chain doesn't verify.
    `store_outcome`: also store the raw outcome value (not just its digest)
      in the executed row, so a duplicate call with `on_duplicate=
      "return_receipt"` can hand back the actual prior result via
      `receipt.outcome`, not just its digest. Off by default (privacy/size
      discipline -- see `bind_artefact` in `arcaeon-ledger` for the same
      philosophy).
    """
    if ledger_path is None:
        ledger_path = "once.log.jsonl"
    return GuardContext(
        key, ledger_path=Path(ledger_path),
        state_db=Path(state_db) if state_db else None,
        on_duplicate=on_duplicate,
        allow_retry_after_indeterminate=allow_retry_after_indeterminate,
        verify_integrity=verify_integrity, store_outcome=store_outcome)
