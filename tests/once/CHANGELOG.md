# Changelog

## Unreleased (2026-09-04) -- the reclaim probe gets its mocked test

### Added

- **`test_reclaim_probe_mock.py` (six cases).** The README had said since
  0.2.0 that the probe-forced-to-"dead" mutation was checked by hand and not
  automated. It is automated now: one planted live claim (this pid, this
  host), `_pid_alive` patched to return alive / dead / unknown / raise. Alive
  and unknown refuse with the typed error and leave the row byte-identical;
  dead rewrites the row to `'intent'` (lease cleared, generation bumped) and
  the retry flag wins it; a raising probe propagates unchanged, the row is
  untouched and the index lock is released (pinned as the safe behaviour;
  reclaim() does not document that arm and the test docstring says so). A
  must-miss arm proves a dead verdict frees ONLY the target key, never a
  bystander's live claim, and the probe is consulted exactly once. An
  ordering arm proves a foreign-host lease is refused before the probe runs.
  Observed on the side, not asserted: after a mocked-dead reclaim and a
  successful retry, the original holder's late `done()` is refused with
  `ValueError` and the ledger holds exactly one `once.executed` row.
  README status line updated (50 -> 56 cases). Not yet published.

## 0.2.3 — 2026-09-02 (the MCP server leaves its own call record)

### Fixed

- **The stdio loop died on a line of invalid UTF-8, and answered several other
  hostile lines with silence.** Found by `scripts/mcp_stdio_fuzz.py`, which
  sends one hostile JSON-RPC line to a FRESH server process per case, against
  the PUBLISHED package. Two defects, both already solved in arcaeon-ledger
  0.7.3 and ported here:

  1. `for line in sys.stdin` decodes as text, so bytes that are not UTF-8 raise
     `UnicodeDecodeError` from the **for statement itself**, outside every `try`
     below it. The process died: `invalid_utf8_bytes -> traceback, exit 1`.
     stdin is now reconfigured with `errors="replace"`, so the line fails as a
     parse error in words, like any other bad line.
  2. Lines that could not be parsed, and JSON that parsed but was not an object
     (a bare array, string, number, `null`), were skipped in **silence**. The
     previous release stopped the crash by returning `None`, and silence looked
     like a fix. It is not: a caller that sent a request with an id and got
     nothing back waits forever. A hang is a quieter version of the same
     defect. JSON-RPC 2.0 answers a parse error with `-32700` and a non-object
     request with `-32600`, both carrying a null id, and that is what happens
     now.

  The hostile line is never echoed into the error message: a 100k-deep line
  quoted back is a 100k-deep message, which is the same denial of service one
  hop later.

  Battery: 23/23 cases now meet the bar on this server, matching
  arcaeon-ledger. The tests that asserted the old silence were updated rather
  than deleted - what they exist to prove, that a valid call sent AFTER a
  hostile line still gets answered, is unchanged and still asserted.

### Added

- **A tamper-evident call record for the MCP server (OWASP MCP08).**
  arcaeon-mcp-vet 0.0.16's `audit-record` check, run against this package
  with the other four of ours before the registry sample, graded
  `mcp_server.py` gate 0 of 4: a `tools/call` left nothing behind on any
  tool-handling path. (The package's own once-ledger records CLAIMS by key; it never recorded which MCP tool was called with what, so a `complete` on an unknown key or a refused `claim` left no trace.) Now every `tools/call`, success or
  refusal, appends one hash-chained row to `$ARCAEON_CALL_RECORD` (default
  `./once.calls.jsonl`): tool name, the server's own UTC timestamp, sha256
  of the canonical arguments (always), the arguments inline under 4 KB,
  outcome, and the error text on a refused call. Written AFTER the tool runs
  so the row carries the outcome; a call whose record cannot be written is
  answered as an error, never as if it had been logged.
  `python -m arcaeon_once.mcp_server --verify-calls [path]` walks the chain and
  exits 1 on a break.
- **`arcaeon_once/_ledger.py`**, stdlib only, so the zero-dependency pitch stands.
  Same chain format as arcaeon-ledger (`sha256(prev + json.dumps(row minus
  chain, sort_keys=True))[:32]`, genesis `"genesis"`); the suite proves a
  record written here verifies under `arcaeon_ledger.verify_file` when that
  package is present (skips cleanly when it is not). One record format
  across our five servers, not a fork of one. Identical module to
  arcaeon-distill 0.1.7's.

### Measured

- mcp-vet grade of `mcp_server.py` before: gate 0. After: gate 4. Mutant
  check: deleting the single `_record_call(...)` line drops it back to gate
  0, so the grade tracks the record, not the imports. Honest note: mcp-vet
  awards tamper-evidence on the ledger-module import, the same rule any
  stranger importing a ledger library gets.

### Limits stated

- Single-writer: no cross-process lock on the call record. Two servers
  pointed at one file can fork the chain; `--verify-calls` will say so.
- The record proves the server said what it did, not that the tool's work
  was correct.

Suite +4.

## 0.2.2 — 2026-09-01 (sell-code audit: three ways to kill the MCP server, one lie in an exception, three crashes on odd input)

Pre-sale audit pass over the whole package, every finding reproduced before
it was touched. Nothing here changes what the guard promises; every item is a
place where the code fell over, or said something untrue, on input a normal
user or a misbehaving client can produce. **Published to PyPI 2026-09-02.**

- **FIXED (MCP server death, three inputs):** the stdio loop is supposed to
  outlive one bad line. It did not. (1) A JSON array or scalar where a
  message object was expected (`[1,2]`) hit `msg.get("id")` and the process
  died with AttributeError, so every later request from the client went
  unanswered. (2) A non-object `params` (`"params": [1]`) hit
  `params.get("name")` OUTSIDE the per-call try block — same death.
  (3) A line nested past the JSON parser's depth (`[[[[...` 100k deep)
  raised RecursionError, which is not the ValueError the loop caught. Now:
  non-object messages are skipped, non-object `params`/`arguments` are
  treated as empty (the call returns an `isError` result), and
  RecursionError is skipped like any other unparseable line.
- **FIXED (exception that contradicted the ledger):** `complete()` appended
  the `once.executed` row and only THEN opened the SQLite index. If the index
  could not be opened, the `IndexUnavailable` it raised carried
  `ledger_committed=False` and said "no ledger row was written" — while the
  executed row already sat in the chain and `receipt()` said `executed`.
  Through the MCP tool that surfaced as `retryable: true` on a key that had
  in fact completed. The index is now opened before the append, so the flag
  is true in both directions. Regression test asserts
  `exc.ledger_committed == (receipt(key).state == "executed")`.
- **FIXED (crash on a shared ledger):** a ledger line that is valid JSON but
  not an object (`[1, 2]`, `"note"` — a shared file with other writers) made
  `guard()`, `receipt()` and `rebuild_index()` die with
  `AttributeError: 'list' object has no attribute 'get'`. Such lines are not
  once rows; they are now skipped.
- **FIXED (`done()` failing after the effect ran):** `_outcome_digest`
  already fell back to `digest_json({"repr": repr(outcome)})` for an outcome
  the ledger cannot serialise, precisely so a custom return value would not
  fail the guard. `store_outcome=True` bypassed that: it put the RAW object
  in the row and the append raised TypeError from `done()` — after the side
  effect had executed, leaving the key stuck at `intent`. Both the digest
  and the stored value now use the same JSON-safe form, so they agree.
- **FIXED (untyped error on a bad key):** a key containing a lone surrogate
  code point escaped as a bare `UnicodeEncodeError` from inside sqlite's
  parameter binding. `guard()`, `complete()` and `reclaim()` now refuse it
  up front with `ValueError("key contains a lone surrogate code point ...")`
  before any index row or ledger row is attempted.
- Tests: 37 → 46. New `test_mcp_server.py` (4, driving the real stdio
  process) plus five in `test_once.py`, including a `__version__` ==
  `pyproject.toml` pin so a half-bumped release cannot ship again.
- Noted, not fixed (out of this package's hands): a line nested past the
  parser's depth INSIDE the ledger file raises RecursionError from
  arcaeon-ledger's reader, not from here.

## 0.2.1 — 2026-08-28 (the three-valued ledger verdict: `bool(receipt)` crashed instead of answering)

Audit pass over the money/idempotence packages. One live defect, one honest
gap, one wasted scan.

- **FIXED (crash on a documented API path): `bool(receipt(...))` raised
  `TypeError: __bool__ should return bool, returned NoneType`.**
  `arcaeon_ledger.verify_file()` has been three-valued since 0.5.7 — `True`
  (every row checked), `None` (no fault found, but the scan did not cover
  every row: unchained pre-chain rows skipped, or a break excused by a
  `chain_break_declared` row), `False` (a real break). `Receipt` took that
  straight into a field DECLARED `bool` and then wrote
  `return self.state == "executed" and self.ledger_ok`, which evaluates to
  `None` on the bounded case — and Python rejects a non-bool from
  `__bool__`. So `if receipt(...):` — the usage the README documents — blew
  up against any shared ops log carrying one unchained header row. Nothing
  in the wild could have depended on a truthy answer there, because there
  was no answer: it crashed. Now `... and self.ledger_ok is True`, which is
  also the honest verdict — a bounded scan is not a proof, so it is not a
  green.
- **FIXED (a verdict that could not describe its own coverage).** `Receipt`
  surfaced `ledger_ok` and `ledger_first_break` and nothing else, so a CLEAN
  ledger and a BOUNDED one were indistinguishable on the receipt
  (`first_break` is `None` in both). Two additive fields now carry the rest:
  **`ledger_verified_scope`** (`"full"` / `"bounded_prechain_skipped"` /
  `"bounded_declared_break"` / …) and **`ledger_breaks`** (the walker's total
  count — `first_break` names the first fault and thereby teaches its reader
  there is exactly one). Both are in `to_dict()`; both read `None` against an
  arcaeon-ledger older than the fields, which is what "unknown" should look
  like. `TamperDetected`'s message and the MCP server's `verify` payload
  carry them too — the message used to read "ledger chain broken … : None"
  on the bounded case, a lie in both halves.
- **CHANGED (default): `Receipt.ledger_ok` now defaults to `None`, not
  `True`.** A verdict field whose default is the reassuring value hands out a
  green nobody computed. Every `Receipt` this package constructs sets the
  field explicitly, so this is only visible to code building a bare
  `Receipt()` by hand. `arcaeon_once.cli receipt` likewise exits 0 only on
  `ledger_ok is True`.
- **FIXED (redundant work on the side-effect hot path): `guard()` verified
  the whole chain TWICE per entry** when `verify_integrity=True` — once
  directly, then again inside the `receipt()` call that derives the key's
  state. New private `_receipt_with_vr()` does one pass and hands both
  consumers the result. The tamper gate is byte-for-byte the same decision
  (`vr.ok is not True` where it was `not vr.ok`; identical for all three
  values).
- **Docs corrected against the code:** the README claimed `guard()` "does not
  re-verify the whole chain on every call by default." It always did —
  `receipt()` runs `verify_file` unconditionally — it simply discarded the
  verdict unless you asked. Stated plainly now, along with what
  `verify_integrity=True` actually adds (enforcement, not the scan). The
  first-touch race test's worker count said "ten" and is twelve.
- Tests: `test_receipt_over_a_bounded_ledger_is_falsy_not_a_crash` (watched
  failing with the TypeError before the fix) and
  `test_guard_verifies_the_chain_once_per_entry_not_twice` (watched failing
  at 2 scans). Nothing previously exercised `bool(receipt)` at all.
- **Test fix: `test_many_repeated_races_stay_exactly_one` was only racing on
  its first trial.** Its start barrier was derived from the SHARED ledger
  path, and the barrier files are never cleaned up — so from trial 1 onward
  both workers found them already present and skipped the wait entirely. Four
  of five "repeated races" were unsynchronized. The barrier is now per-trial,
  and the test asserts the side-effect FILE (the thing a double-fire actually
  damages), not just what each worker reported about itself.
- Hygiene: dropped unused imports (`dataclasses.field`, `typing.Union`,
  `pathlib.Path` in `mcp_server`, `complete` in `selftest`).

## 0.2.0 — 2026-08-28 (single-key `reclaim`: the deep fix the 0.1.2 quiesce rule was standing in for)

0.1.2 closed the live-claim-steal double-fire by contract: a crashed
ordinary claim could only be healed by a GLOBAL `rebuild_index()`, which is
quiesce-first because the ledger cannot tell a live claim from a dead one —
so recovering one crashed key meant stopping every guarded workload against
that ledger. Honest, documented, and operationally miserable. This release
ships the fix that was boarded that night.

- **New operation: `reclaim(key, *, ledger_path, state_db=None)`** — frees
  ONE crashed key, atomically, no quiesce, and only after PROVING the
  claim's holder process is dead. Provably dead → that key's index row alone
  is rewritten to the reclaimable `'intent'` state (generation bumped) and
  the retry flag then works; provably alive → refuses with the new typed
  **`HolderAlive`** (nothing changed — that claim is running work, and
  freeing it is the exact 8/24 double-fire); can't prove either →
  refuses with the new typed **`LivenessUnknown`**, whose message names the
  fallback (quiesce → `rebuild_index()` → flag). **Indeterminate = refuse;
  fail closed.** Live claims on OTHER keys are never touched — the property
  `rebuild_index()` could not offer.
- **Liveness lease in the concurrency index (schema addition, migrated in
  place).** The 0.1.x schema had no way to check a holder's liveness — the
  row said `'claiming'` and nothing else, which is WHY recovery needed
  quiescence. Every claim (ordinary `_claim` and a winning flag-reclaim
  alike) now writes `holder_pid` + `holder_host` + `holder_ts` atomically
  with the claim; `done()`/`complete()` clear them. A pre-0.2.0 index file
  keeps working: the columns are `ALTER TABLE`-d on at first touch (the
  hot-path usability probe doubles as the migration trigger), old rows keep
  NULL leases, and `reclaim` refuses those with `LivenessUnknown` until
  healed once via the quiesce path. The ledger format is UNCHANGED — the
  lease lives only in the rebuildable index, so the hash chain and every
  existing receipt verify exactly as before.
- **The pid probe is fail-closed and Windows-safe.** On Windows the probe is
  `OpenProcess`/`GetExitCodeProcess` — NEVER `os.kill(pid, 0)`, which on
  Windows delivers TerminateProcess (checking liveness by killing the
  patient). On POSIX it is signal-0. Pid reuse is stated, not hidden: a
  recycled pid reads "alive" and causes a false REFUSAL (fall back to
  quiesce), never a false reclaim — a pid cannot be recycled while its owner
  runs. A lease from a different hostname refuses (`LivenessUnknown`): a pid
  is only meaningful on the machine that issued it, so cross-host ledgers
  keep the quiesce path.
- **Audit Finding 2 (8/24, disclosed then) healed on the same path:** a
  holder that died between winning the index claim and appending its ledger
  `once.intent` row left `guard()` saying Indeterminate while `receipt()`
  said never, with `complete()` a dead end. `reclaim` on that orphan (holder
  provably dead, ledger has no trace) deletes the index row outright so a
  PLAIN `guard()` claims the key fresh.
- **CLI: new `reclaim` command** (`arcaeon-once reclaim <ledger> <key>`) —
  prints the post-reclaim receipt on success; a refusal prints the typed
  reason and exits nonzero. MCP surface deliberately unchanged: reclaim is
  an operator action, same posture as keeping `rebuild_index` off MCP.
- **Tests (5 new in `test_once.py`, all green with the planted reds
  demonstrated):** a LIVE holder (the test's own pid) refuses with
  `HolderAlive` and the claim finishes unharmed; a dead holder's key is
  freed while a live claim on another key in the same ledger stays
  untouched; a lease-less legacy row and a foreign-host lease both refuse
  with `LivenessUnknown` naming the quiesce path (and executed/never-claimed
  keys refuse with `ValueError`); a 0.1.x-schema index migrates in place;
  the Finding-2 orphan heals to a plain fresh claim. Mutation-verified:
  forcing the liveness probe to report "dead" makes `reclaim` steal the
  planted live claim — exactly what the red test exists to catch.
- Version 0.1.2 → 0.2.0 (minor: new public operation + two new exception
  types + index schema addition). `Indeterminate`'s message now points at
  `reclaim` as the didn't-land recovery. README recovery table rewritten
  around the single-key path, quiesce demoted to the fallback.

## 0.1.2 — 2026-08-24 (Round 3: the retry flag could steal a LIVE claim — a real double-execution, fixed)

Adversarial audit finding (HIGH), reproduced both sequentially and under a
pure thread race (5/10 trials double-fired the guarded effect, no crash
involved), directly contradicting 0.1.1's own fix claim. The Round 2 fix
protected a live RECLAIM (state='retrying') but an ORDINARY guard() winner
still sat at state='intent', generation=0 — byte-indistinguishable from a
CRASHED intent — so a second caller with
`allow_retry_after_indeterminate=True` CASed on the live claim and also
won. The guarded effect ran twice; the receipt afterward read
`executed, ledger_ok=True` over a double-fire.

**Fix:** the ordinary claim now occupies its own live index state,
`'claiming'` (entered by `_claim`, left by `done()`), which the reclaim CAS
— still requiring `'intent'` — never matches. A live claim can no longer
be stolen, sequentially or raced (regression tests for both, plus a 6×6
mixed-flag race pinned to exactly-one-execution).

**DELIBERATE CONTRACT CHANGE, stated loudly:** after a genuine crash of an
ordinary claim, the index row is stuck at `'claiming'` and the retry flag
ALONE no longer heals it. The documented recovery — identical to the one
already documented for a stuck `'retrying'` row — is `rebuild_index()`
(the ledger replay produces a reclaimable `'intent'` row) and THEN the
flag. The flag's assertion is "the prior holder is dead"; the rebuild is
what makes that assertion checkable against the ledger instead of taking
the caller's word while the prior holder may be mid-effect. At-most-once
outranks recovery convenience. All crash-recovery tests updated to the
documented path; suites: core 11, hypothesis 15, concurrency 3 — all green.
Mutation-verified: reverting `'claiming'` to `'intent'` reproduces the
exact double-fire the audit demonstrated.

**Pre-publish independent review caught the fix's own tail (same sitting):**
the contract change shipped in the code but the DOCS still described the old
flag-alone recovery — a user or MCP agent following the shipped words either
could not recover a crashed key or, worse, could reproduce the exact
double-fire this release kills by running `rebuild_index()` on a LIVE system
(the replay downgrades every in-flight 'claiming' row to reclaimable, because
a live claim and a crashed one are indistinguishable in the ledger). Fixed
before publish: README rewritten with the recovery table and the quiesce-first
rule; the MCP flag description now states the flag no longer heals a crash and
that recovery is an out-of-band `rebuild_index` (no rebuild action over MCP, on
purpose); and `rebuild_index()` now WARNS loudly when it downgrades in-flight
rows, so an operator who ran it on a live system gets a signal instead of a
silent stolen claim (mutation-verified). The deeper fix — a targeted
single-key reclaim that never touches live claims, or a liveness lease so the
replay can tell live from dead — is boarded for a later release; tonight's fix
is honest quiescence, documented and signalled.

Known, disclosed, not yet fixed (audit Findings 2-3, MEDIUM/LOW): a crash
between the index claim and the ledger intent-append leaves guard()
reporting Indeterminate while receipt() honestly says never, and the
Indeterminate message's complete() suggestion is a dead end for that
sub-case (rebuild_index() heals it); the CLI receipt exit code conflates
ledger-absent with ledger-broken. Next release.

## 0.1.1 — 2026-08-16

Same treatment as the 5 prior `arcaeon-*` packages this run: a `hypothesis`
suite (`test_hypothesis_once.py`, new) added alongside the existing
hand-rolled `test_once.py` / `test_concurrency.py`. Found and fixed two real
bugs, both genuine double-execution / false-refusal defects, neither a
test-construction artifact — verified by hand before trusting either.

- **HIGH — `allow_retry_after_indeterminate=True` let MULTIPLE callers win
  the same reclaim, in two distinct ways.** (1) N callers racing the flag
  simultaneously off the SAME observed crashed intent previously ALL won
  (an unconditional `UPDATE`, no atomicity at all) — reproduced directly at
  6/6 and 4/8 threads executing. (2) even with no threading, a SECOND caller
  invoking the flag while a FIRST caller's retry was still actively running
  (hadn't called `done()` yet) ALSO won — reproduced with a plain two-step
  sequential script, 100% of the time, no timing race needed. Both silently
  broke the "-or-flagged" half of the library's own headline contract: a
  genuine double-fire, not a flagged one. Fixed with a real compare-and-swap
  on the SQLite index's `generation` counter (closes case 1) plus a new
  index-only `'retrying'` state entered only by a winning reclaim and left
  only by `done()`/`complete()` (closes case 2) — see the inline fix note on
  `_reclaim_after_indeterminate` in `arcaeon_once/__init__.py` for the full
  before/after story, including a first CAS attempt (keyed on `intent_ts`)
  that looked right and still wasn't (second-resolution timestamps collide
  under real racing). If the retry ITSELF also crashes, the row is stuck at
  `'retrying'` until `rebuild_index()` is run — documented, not silent:
  replaying the ledger only ever produces `'intent'`/`'executed'`, so a
  rebuild heals a stuck retry back to reclaimable, and this healing path is
  now covered by a test, not just asserted.
- **MEDIUM — `verify_integrity=True` raised `TamperDetected` on a ledger
  path that had never been written to at all.** `arcaeon_ledger.verify_file()`
  deliberately returns `ok=False` with a distinguishing `first_break=
  "unreadable: ..."` for a genuinely-missing file (its own 0.5.4 CHANGELOG:
  callers should branch on `first_break`, not just `ok`) — `arcaeon_once`
  wasn't making that distinction, so the FIRST-EVER `guard()` call against a
  fresh ledger path with `verify_integrity=True` (the docstring's own
  recommended "stronger guarantee") always raised, on a file that was never
  tampered because it never existed. Fixed by skipping the chain check when
  the ledger path doesn't exist yet; an existing-but-broken ledger is
  unaffected and still raises exactly as before.
- **New: `test_hypothesis_once.py`** — idempotence/receipt-identity over
  randomized keys/payloads, the crash-window contract (`complete()` /
  `allow_retry_after_indeterminate`), N-way THREAD races (never-seen key,
  retry-off-same-crash, first-touch WAL-init) as a faster complement to
  `test_concurrency.py`'s real-subprocess races, and an end-to-end
  unicode-line-separator (U+0085/U+2028/U+2029) round trip through
  `guard()`/`receipt()`/`verify_integrity=True`.
- **Dependency floor raised: `arcaeon-ledger>=0.5.2` → `>=0.5.6`.** 0.5.6 is
  the release that fixed `arcaeon_ledger`'s own `splitlines()`-vs-
  `ensure_ascii=False` false-mismatch bug on the U+0085/U+2028/U+2029
  unicode-line-separator class (found the same night, in the sibling
  package) — `arcaeon_once` chains every claim/executed row through
  `arcaeon_ledger`, so it inherits that correctness floor rather than
  merely being compatible with it.
- Test count: `test_once.py` 8/8, plus the new `test_hypothesis_once.py`
  (15 tests, includes the N-way thread races and the unicode-line-separator
  round trip) — 23 total, all passing. `test_concurrency.py` (real
  multi-process races, ~5 min) is unchanged and still green, run separately
  from the fast suite.

## 0.1.0 — the WAL-init race, found and fixed BEFORE first publish (2026-08-14)

The hold below did its job. The race is fixed, the fix is signed off, the gate
was run and passed **20/20 consecutive full-suite runs with zero flakes**
(`test_once.py` + `test_concurrency.py` + `selftest`, 283s), `dist/` was
rebuilt from the fixed source, and `ArcaeonOncePyPIRetry` is re-enabled for
14:10 on 8/15. Nothing was ever published from the raced code — PyPI returned
404 for the project at fix time — so this folds into 0.1.0 rather than
minting a 0.1.1 whose predecessor never existed.

**What changed:**

- **First-touch index setup is serialized by a cross-process file lock**
  (`msvcrt` byte-range on Windows, `fcntl.flock` on POSIX). The one-time
  `delete`→`wal` journal-mode switch now happens ONCE, by one process, with
  everybody else queued *outside the database* — instead of N processes
  simultaneously fighting for an exclusive lock that ignores `busy_timeout`.
- **The hot path takes no exclusive lock at all.** `_init_index()` now starts
  with a lock-free, read-only check (file exists + table present + journal
  mode settled) and returns immediately once the index is up. Only genuine
  first touch reaches the locked setup path, double-checked on the way in.
- **WAL is treated as what it actually is — an optimisation, not the safety
  mechanism.** The real race serialization is `BEGIN IMMEDIATE`, which *does*
  honour `busy_timeout`. So the WAL switch is bounded-retry and best-effort:
  an index stuck in `delete` mode is slower under load, never less correct,
  and must not take down a guarded side effect.
- **New typed outcome: `IndexUnavailable`.** Every SQLite path in the index
  (`_init_index`, `_claim`, `_mark_executed`, `_reclaim_after_indeterminate`,
  `rebuild_index`) now converts residual `sqlite3.Error` into this documented
  exception after a bounded retry. Nothing untyped escapes `guard()` any
  more. It fails safe — raised before any claim row and any ledger row.
  The single documented nuance rides on the instance as `.ledger_committed`:
  raised from `done()`/`complete()`, the executed row is already durable in
  the ledger and only the accelerator is stale (duplicate refusal still
  works, `rebuild_index()` resyncs). Don't re-run the effect on that one.
- **`rebuild_index()` now removes orphaned `-wal`/`-shm` sidecars** before
  recreating the index, so a stale WAL can't outlive the database it belonged
  to.

**New regression test** —
`test_first_touch_index_race_is_typed_and_exactly_once`, 5 trials × 12
processes. Workers import the library, signal ready, and wait on a `go` file;
the parent writes it — carrying an absolute release timestamp — only once
every worker has armed, and workers then BUSY-SPIN to that instant, so all
twelve land on the journal-mode switch inside the same millisecond.

The release time is chosen AFTER everyone arms on purpose. The first version
of this test guessed a fixed 3-second lead up front, and on a loaded machine
that guess was wrong: a gate run caught it arming 9/10 and then 0/10 workers.
That test was itself flaky, which is precisely the disease under treatment —
so the barrier was rebuilt rather than papered over with a longer sleep.

Reproduction measured against the pre-fix code (the check that the test isn't
vacuous — a regression test that can't fail on the buggy code proves nothing):
**19 of 30 workers crashed** with exactly the traceback below under the first
barrier, and 2–8 of 30–80 workers under the final one, with run-level
reproduction — at least one trial red — in every attempt. Five trials, not
one, because the crash window is the sub-millisecond in which the first
process creates the database and flips its journal mode, and a single trial
can miss it by luck.

On the fixed code: 0 crashes, every outcome typed, exactly one execution per
trial, across 20 consecutive full-suite runs including three where the
machine was loaded enough to double the runtime.

## Superseded — the hold that produced the fix (2026-08-14 QA sweep)

_Kept as the audit trail. Every claim below was true when written; the
"Candidate fix" is what got implemented, plus the file lock and the typed
outcome._

**The 0.1.0 PyPI publish was held back, and the `ArcaeonOncePyPIRetry` scheduled
task that would have shipped it unattended at 14:10 on 8/15 is DISABLED.**
Re-arm with `schtasks /change /tn "ArcaeonOncePyPIRetry" /enable` once the item
below is signed off. The task publishes unconditionally — it has no test gate —
and 14:10 falls inside a work shift, so nobody would have been watching.

**Why:** `test_concurrency.py` fails roughly 30% of runs, always the same way:

```
File "arcaeon_once\__init__.py", line 438, in _enter_for_key
    _init_index(self.state_db)
File "arcaeon_once\__init__.py", line 119, in _init_index
    con.execute("PRAGMA journal_mode=WAL")
sqlite3.OperationalError: database is locked
```

`_init_index()` runs on every `guard()` entry and unconditionally re-issues
`PRAGMA journal_mode=WAL`. The first-time `delete`→`wal` switch needs an
EXCLUSIVE lock and does **not** honour `busy_timeout` — measured: the pragma
gave up after 0.003s against a 15s timeout. Two processes first-touching the
same ledger at once collide there, and one crashes out of
`guard().__enter__()` with an untyped `OperationalError` instead of one of this
library's typed outcomes.

**What is NOT broken:** the exactly-once guarantee holds. The crash lands before
any intent or claim row is written, so it fails safe — no double-fire. 120
concurrent claims and 40 barrier-synchronised races each produced exactly one
winner. This is an availability defect, not a correctness one.

**Why it still blocks the release:** `README.md` sells this exact test as the
proof — "Verified with two real OS processes hammering the same key" — and that
proof is red a third of the time. Shipping a reliability library whose own
advertised evidence is flaky is the wrong first impression, and PyPI version
numbers cannot be reused.

**Candidate fix** (shape verified in a scratch copy, deliberately NOT applied):
read `PRAGMA journal_mode` first and only switch when it is not already `wal`,
tolerating `OperationalError` on the switch — WAL is a concurrency optimisation,
and the real serialization comes from `BEGIN IMMEDIATE`. It touches the
concurrency core of an exactly-once library, so it wants a sign-off plus 20+
consecutive green suite runs before the publish is re-armed.

## 0.1.0 — initial release contents (2026-08-14)

- `guard(key, *, ledger_path=None, on_duplicate="raise", allow_retry_after_indeterminate=False, verify_integrity=False, store_outcome=False)` — context manager / decorator around a non-idempotent side effect, backed by an `arcaeon-ledger` hash chain.
- Two-phase `once.intent` / `once.executed` ledger rows: a crash between them leaves the key `Indeterminate` (typed, refuse-by-default) instead of silently assumed either way.
- `AlreadyExecuted`, `Indeterminate`, `TamperDetected` — typed, structured refusals, never a silent pass.
- `receipt(key, ledger_path=...)` — the tamper-evident state of a key, read straight from the hash chain.
- `complete(key, outcome, ledger_path=...)` — crash-recovery path: mark a key executed after manually confirming the effect actually ran.
- `rebuild_index(ledger_path)` — replay the ledger into a fresh SQLite concurrency index if the index file is lost.
- SQLite `BEGIN IMMEDIATE` race serialization on brand-new keys (same pattern as `arcaeon-meter`'s usage counter); every other decision is re-derived fresh from the ledger, so an out-of-band ledger edit is reflected immediately.
- MCP server (`arcaeon_once.mcp_server`) — one tool, `guard_side_effect`, with `claim`/`complete` actions mirroring the library's own two-phase design across the MCP boundary.
- CLI (`arcaeon_once.cli`) — `receipt` and `rebuild-index` commands.
- Tests: duplicate refusal, crash-window indeterminacy (real subprocess hard-exit via `os._exit`), chain tamper detection (in-place edit and tail-drop), and a real two-OS-process concurrency race (`test_concurrency.py`).
- `python -m arcaeon_once.selftest` — golden outcome-digest vector + planted-tamper fixture, runnable on any machine.
