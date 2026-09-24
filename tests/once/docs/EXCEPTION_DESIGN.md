# EXCEPTION_DESIGN — the `arcaeon-once` exception-subclass design (F2)

**Status:** DESIGN ONLY. No code in this repo changes with this document.
**Origin:** board item F2 (SUNDAY_DAYLIGHT_PACK_2026-08-16, section F): *"Consider
splitting `IndexUnavailable` into `RetrySafe` / `EffectRecorded` subclasses so the
exception TYPE carries the safe-to-retry signal (a caller matching on type alone can
currently double-execute). 'The field name does the lying,' one layer up.
Design-first, 0.2.0-scale — not a rushed change."*
**Verified against:** `arcaeon_once/__init__.py` at version 0.1.1 (line numbers below
are from that file as of 2026-08-17).

---

## 0. The premise, checked first

The broad form of the F2 premise — "error signaling uses broad/generic exceptions;
a caller can't distinguish already-executed vs lock-contention vs tamper-detected" —
is **mostly wrong, and the code deserves credit for it**. The library already ships
four distinct, documented, exported exception types (`AlreadyExecuted`,
`Indeterminate`, `TamperDetected`, `IndexUnavailable`), each carrying structured
payload (`.receipt`, `.verify_result`, `.db_path`/`.operation`/`.cause`/
`.ledger_committed`). Those four failure classes ARE distinguishable by `except`
clause today.

What survives scrutiny is a **narrower, real** set of three gaps:

1. **No common base class.** All four types subclass `Exception` directly. A caller
   who wants "anything this library signals" must enumerate all four or catch bare
   `Exception`.
2. **The one safety-critical distinction rides on a field, not a type.**
   `IndexUnavailable` means two OPPOSITE things depending on `.ledger_committed`:
   *retry the whole guarded call, nothing happened* vs *do NOT re-run, the effect is
   recorded*. `except IndexUnavailable: retry()` — the natural reading of the type
   name — double-executes in the `ledger_committed=True` case. This is the genuine
   F2 finding.
3. **One state-dependent refusal is a bare `ValueError`.** `complete()` refuses
   with `ValueError` when the key isn't in `intent` state — that fires on runtime
   ledger state, not on a programming mistake, and a caller (e.g. bulk crash-recovery
   tooling) can't catch it without also swallowing every other `ValueError`.

Everything else raised in this package is a legitimate stdlib usage error
(bad argument value, wrong call shape, API misuse) and should stay stdlib-typed.

---

## 1. Current exception surface (every raise site, verified from code)

All raise sites live in `arcaeon_once/__init__.py`. `cli.py`, `mcp_server.py`, and
`selftest.py` contain **zero** `raise` statements (verified by grep 2026-08-17);
`mcp_server.py` only catches (see §1.3).

### 1.1 The four typed library outcomes (10 raise sites)

| # | Location | Type | Trigger | Message (abridged) |
|---|----------|------|---------|--------------------|
| 1 | `_index_setup_lock`, line 187 | `IndexUnavailable` (`ledger_committed=False` implicit) | timeout acquiring the first-touch index setup file lock | "concurrency index unavailable, could not acquire the index setup lock at {path}: {cause} -- no claim and no ledger row were written..." |
| 2 | `_init_index`, line 296 | `IndexUnavailable` (`False` implicit) | `sqlite3.Error` opening the index db on first-touch setup | "...could not open the concurrency index at {path}..." |
| 3 | `_run_with_retry`, line 321 | `IndexUnavailable` (`ledger_committed` **parameterized**) | `sqlite3.OperationalError` still failing at the 15 s deadline | "...could not {what} at {path}..." + tail chosen by `ledger_committed` |
| 4 | `_run_with_retry`, line 327 | `IndexUnavailable` (parameterized) | any other `sqlite3.Error` (no retry) | same shape as #3 |
| 5 | `_index_txn`, line 339 | `IndexUnavailable` (parameterized) | `sqlite3.Error` connecting to the index | same shape as #3 |
| 6 | `_index_txn`, line 346 | `IndexUnavailable` (parameterized) | `sqlite3.Error` inside an index transaction (after ROLLBACK attempt) | same shape as #3 |
| 7 | `_enter_for_key`, line 783 | `TamperDetected` | `verify_integrity=True` and the existing ledger's chain does not verify | "ledger chain broken, refusing to trust or extend it: {first_break}" |
| 8 | `_resolve_duplicate`, line 817 | `AlreadyExecuted` | key already has an `executed` record and `on_duplicate="raise"` | "key {k!r} already executed at {ts} (chain=...) -- refusing to run it again" |
| 9 | `_resolve_indeterminate`, line 840 | `Indeterminate` | reclaim race lost (`allow_retry_after_indeterminate=True` but another reclaim is in flight / won) | "key {k!r} has an unresolved intent... verify manually..." |
| 10 | `_resolve_indeterminate`, line 842 | `Indeterminate` | key has unresolved `intent`, no override flag (the default refuse) | same as #9 |

`ledger_committed` provenance (verified): only `_mark_executed` (line 385/386)
passes `ledger_committed=True` into `_index_txn`/`_run_with_retry`, and
`_mark_executed` is reached only via `complete()` — i.e. via `guard.done()` or the
module-level crash-recovery `complete()`. Every other `IndexUnavailable` path is
`ledger_committed=False`: raised **before** any claim row or ledger row exists.
So the retry-safe / effect-recorded partition is already crisp at raise time —
it just isn't expressed in the type.

### 1.2 Stdlib-typed raises (4 sites)

| # | Location | Type | Trigger | Character |
|---|----------|------|---------|-----------|
| 11 | `complete()`, line 614 | `ValueError` | key not currently in `intent` state (either `never` or already `executed`) | **state-dependent refusal**, not a usage bug — the odd one out |
| 12 | `GuardContext.__init__`, line 732 | `ValueError` | `on_duplicate` not in `("raise", "return_receipt")` | usage error, correctly stdlib |
| 13 | `GuardContext.__enter__`, line 752 | `TypeError` | callable key used in `with` form (decorator-only feature) | usage error, correctly stdlib |
| 14 | `GuardContext.done()`, line 853 | `RuntimeError` | `done()` called without owning the execution claim | usage error, correctly stdlib |

**Total: 14 raise sites.** Also worth stating for honesty: exceptions from the
`arcaeon_ledger` layer (e.g. `OSError` on an unwritable ledger path, whatever
`Ledger.append` raises) propagate through `guard()` **untyped by this package** —
the module docstring's "nothing that comes out of this library is an untyped
surprise" is true of the index/claim machinery, not of ledger-file I/O. See §5
for why that stays out of scope here.

### 1.3 In-repo consumers of the current surface

- `mcp_server.py` lines 121–138: catches all four types individually on `claim`,
  maps each to a `reason` string; already exposes `retryable: True` for
  `IndexUnavailable` on the claim path (correct — claim-path is always
  retry-safe).
- `mcp_server.py` lines 148–158: on `complete`, catches `ValueError` (site #11)
  into a generic `{"error": str(e)}` blob, and catches `IndexUnavailable`
  branching on `.ledger_committed` — the field-based dance this design removes
  the need for.
- Tests (`test_once.py`, `test_hypothesis_once.py`, `test_concurrency.py`) catch
  by the four public names.

---

## 2. The problem cases — what a caller cannot express today

**P1 — "retry vs don't-you-dare" is invisible to `except`.**
An agent harness wraps every guarded side effect with generic contention
handling: `except IndexUnavailable: backoff_and_retry()`. That is exactly right
for sites #1–#6 with `ledger_committed=False` (nothing was authorized) and
exactly wrong when the same type arrives from `done()` with
`ledger_committed=True` (the refund POSTED; the executed row is durable; only the
accelerator is stale). The wrong branch re-runs a refund. The library's own
docstring has to shout "Do NOT re-run the side effect on this one" precisely
because the type system doesn't. A caller must remember to check a boolean
attribute that nothing forces them to read. *What the caller wants:* two catch
clauses — one that retries, one that treats the effect as recorded and schedules
`rebuild_index()`.

**P2 — no "anything from this library" catch.**
An ops wrapper wants: "if `arcaeon_once` signaled ANY typed outcome, log it
structured and route it; if anything else blew up, that's a bug — crash loudly."
Today that's `except (AlreadyExecuted, Indeterminate, TamperDetected,
IndexUnavailable)` — a four-way tuple that silently goes stale if a fifth type
is ever added (as `IndexUnavailable` itself was, in 0.1.0: any pre-0.1.0-style
tuple missed it). *What the caller wants:* `except OnceError`.

**P3 — `complete()`'s refusal is uncatchable precisely.**
Bulk crash-recovery tooling loops over indeterminate keys calling `complete()`.
A key that a colleague already completed raises `ValueError` — indistinguishable
by type from a `ValueError` the caller's own argument-handling might raise, and
carrying no structured payload (no receipt, no state). `mcp_server.py` line 148
demonstrates the ceiling: all it can do is stringify. *What the caller wants:*
catch the state-refusal specifically, read `exc.receipt.state`, and branch
`never` (claim it first) vs `executed` (fine, someone beat me — idempotent skip).

Sites #12/#13/#14 are NOT problem cases: they are call-shape/programming errors,
raised deterministically on misuse, and stdlib types are the right convention.

---

## 3. Proposed hierarchy

Names follow the package's own vocabulary (index / retry-safe / effect-recorded /
receipt / state — all words already used in docstrings and the CHANGELOG; the
board note's `RetrySafe` / `EffectRecorded` stems are kept, prefixed to stay
self-describing outside an `arcaeon_once.` namespace).

```
Exception
└── OnceError                                   # NEW - base for every typed outcome
    ├── AlreadyExecuted                         # existing type, re-parented
    ├── Indeterminate                           # existing type, re-parented
    ├── TamperDetected                          # existing type, re-parented
    ├── IndexUnavailable                        # existing type, re-parented; becomes abstract-ish base
    │   ├── IndexRetrySafe                      # NEW - ledger_committed=False: nothing claimed,
    │   │                                       #       nothing written, retrying the call is safe
    │   └── IndexEffectRecorded                 # NEW - ledger_committed=True: executed row IS durable
    │                                           #       in the ledger; do NOT re-run; rebuild_index()
    └── CompletionStateError(OnceError, ValueError)   # NEW - complete() refusal, site #11;
                                                      #       dual-inherits ValueError for back-compat;
                                                      #       carries .receipt
```

### 3.1 Raise-site mapping

| Site(s) | Today | Proposed |
|---------|-------|----------|
| #1, #2 | `IndexUnavailable` (implicitly retry-safe) | `IndexRetrySafe` |
| #3–#6 with `ledger_committed=False` | `IndexUnavailable` | `IndexRetrySafe` |
| #3–#6 with `ledger_committed=True` (only reachable via `_mark_executed`, i.e. `done()`/`complete()`) | `IndexUnavailable` | `IndexEffectRecorded` |
| #7 | `TamperDetected` | unchanged type, new parent `OnceError` |
| #8 | `AlreadyExecuted` | unchanged type, new parent `OnceError` |
| #9, #10 | `Indeterminate` | unchanged type, new parent `OnceError` |
| #11 | `ValueError` | `CompletionStateError` (still caught by `except ValueError`) |
| #12, #13, #14 | `ValueError` / `TypeError` / `RuntimeError` | **unchanged** — usage errors stay stdlib |

Implementation shape for the split: `_run_with_retry` / `_index_txn` /
`_index_setup_lock` / `_init_index` pick the subclass from the
`ledger_committed` flag they already receive (a one-line
`cls = IndexEffectRecorded if ledger_committed else IndexRetrySafe`). The
`.ledger_committed` attribute is **kept** on both subclasses (redundant with the
type, harmless, and existing field-readers keep working). Constructor signature
of `IndexUnavailable` is unchanged; direct instantiation of the base remains
legal (nothing in-package will raise the bare base after the change).

`CompletionStateError` carries the `Receipt` (`.receipt`) that `complete()`
already computed at line 612 before refusing — the message keeps its current
text so string-matching callers (there shouldn't be any, but) see no change.

### 3.2 Back-compat rule — what keeps working, what breaks

Keeps working, by construction:
- `except AlreadyExecuted` / `Indeterminate` / `TamperDetected` — same classes,
  only their parent changes. Every existing catch is unaffected.
- `except IndexUnavailable` — still catches both new subclasses. The
  `mcp_server.py` handlers keep working untouched (they can be *simplified*
  later, see §4, but don't have to change).
- `except ValueError` around `complete()` — still catches
  `CompletionStateError` via dual inheritance. `mcp_server.py` line 148 keeps
  working untouched.
- `.ledger_committed`, `.db_path`, `.operation`, `.cause`, `.receipt`,
  `.verify_result` — all attributes preserved.
- All exception message strings preserved verbatim.

Breaks, stated exactly:
- **Exact-type identity checks** on the paths that now raise subclasses:
  `type(exc) is IndexUnavailable` becomes False (it's now one of the two
  subclasses), and `type(exc) is ValueError` for site #11 becomes False.
  Grep of this repo (library, CLI, MCP server, all three test files) finds
  **zero** exact-type checks — everything catches via `except`, which is
  subclass-tolerant. No known external dependents yet (package published
  2026-08-15; no reverse-dependencies on PyPI as of this design). So the break
  set is: hypothetical downstream code doing `type(e) is ...`, an anti-pattern
  we accept breaking, and we say so in the CHANGELOG.
- Nothing else. No signature changes, no removed names, no message changes.

---

## 4. Migration plan

Two releases, one deprecation window, no forced churn.

**Release A — 0.1.2 (additive; "one minor release introducing the hierarchy"):**
- Add `OnceError`, `IndexRetrySafe`, `IndexEffectRecorded`,
  `CompletionStateError`; re-parent the four existing types; switch the 7
  affected raise sites (#1–#6, #11) to the precise subclasses per §3.1.
- Export all new names in `__all__`; docstrings on each class state the recovery
  contract in one line (retry-safe: "retrying the guarded call is safe — nothing
  was claimed"; effect-recorded: "the effect IS recorded — do not re-run;
  `rebuild_index()` resyncs the accelerator").
- Old names are NOT renamed, so no aliases are needed; `IndexUnavailable`
  itself becomes the deprecated-to-*catch-alone* name: catching it still works
  and will keep working, but README + docstrings direct new code at the
  subclasses. (A `DeprecationWarning` cannot be emitted for an `except` clause —
  Python offers no hook — so this deprecation is documentation-and-CHANGELOG
  level, stated honestly rather than pretending a warning exists.)
- README "API surface" section gains the exception table; the crash-window
  example switches its `except IndexUnavailable` guidance to the two-clause
  form of P1.
- Tests: every raise site asserted for its precise type; a regression test that
  `except IndexUnavailable` and `except ValueError` (site #11) still catch;
  hypothesis suites re-run unchanged.

**Deprecation window:** the remainder of the 0.1.x line, minimum 30 days or two
releases, whichever is longer. During the window nothing is removed — the window
exists so the CHANGELOG entry and README table have time to reach any early
adopters before 0.2.0's docs stop describing the old idioms.

**Release B — 0.2.0 (cleanup; no removals that break catches):**
- `mcp_server.py` handlers simplified to dispatch on the new types
  (`IndexEffectRecorded` → `{"completed": true, retryable: false}` branch;
  `CompletionStateError` → structured `{"reason": "completion_state",
  "state": e.receipt.state}` instead of the stringified blob) — wire-format
  additions only, existing fields preserved.
- Decision point, resolved by evidence at 0.2.0 time: if a reverse-dependency
  search still shows no external `except ValueError` reliance on site #11,
  KEEP the dual inheritance anyway (it costs nothing and breaking it buys
  nothing). Dropping `ValueError` from `CompletionStateError.__bases__` is
  explicitly NOT planned; it would break silent catchers for zero gain.
- Remove the transitional "new in 0.1.2" framing from docs; the hierarchy is
  simply the exception surface.
- `IndexUnavailable` stays permanently as the catch-both intermediate — it is
  a useful level of the hierarchy ("index trouble, either flavor"), not a
  legacy shim, so it is never removed.

---

## 5. Explicitly OUT of scope

- **Any behavior change to the execution guarantees.** At-most-once-or-flagged
  semantics, the two-phase intent/executed ledger protocol, refuse-by-default on
  `Indeterminate`, the generation-CAS reclaim, the `'retrying'` index state,
  claim serialization via `BEGIN IMMEDIATE`, fail-safe ordering (index errors
  before any claim/ledger row except the documented `done()`/`complete()` case)
  — none of it moves. This design changes only *which class object* travels on
  already-existing raise paths, plus one new attribute (`.receipt` on the
  `complete()` refusal).
- **When exceptions are raised.** No raise site is added, removed, or moved; no
  condition changes.
- **Typing ledger-file I/O.** Wrapping `arcaeon_ledger` / `OSError` failures in
  a hypothetical `LedgerUnavailable(OnceError)` was considered and deferred:
  unlike everything in §3 it would CHANGE the observed type of existing
  failures (an `except OSError` today would stop catching), i.e. it is not
  subclass-compatible, and it needs its own crash-window analysis (an append
  that fails after fsync?). Separate design if ever.
- **Usage errors #12–#14.** `ValueError`/`TypeError`/`RuntimeError` on
  malformed calls stay stdlib — they signal programmer mistakes, not runtime
  outcomes, and typing them under `OnceError` would wrongly invite catching
  them in recovery logic.
- **MCP wire-format changes** beyond the additive 0.2.0 fields listed in §4.
- **Version bumps, code edits, or publishes accompanying this document.** This
  file is the entire deliverable.
