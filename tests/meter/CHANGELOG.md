# Changelog — arcaeon-meter

## 0.1.7 — 2026-09-01 (0.1.6's month check let a non-ASCII month through; three crashes on odd input; a mint the meter would never honor)

Sell-code audit ordered by the owner, every finding reproduced before it was
touched. Published to PyPI 2026-09-02. Tests: 55 -> 62.

- **FIXED: the 0.1.6 month check still accepted a month spelled in non-ASCII
  digits, and answered the same confident-zero invoice it was written to
  refuse.** `_MONTH_RE` was `\d{4}-...`; in a str pattern `\d` matches every
  Unicode decimal digit, so `export(month="٢٠٢٦-08")` (Arabic-Indic 2026)
  passed the check, matched zero rows, and returned the complete roster at
  `used: 0` with no warning — the exact defect 0.1.6's entry says is closed.
  The meter only ever writes ASCII digits; the check now allows only
  `[0-9]`. Test: `test_month_with_non_ascii_digits_is_refused_not_a_zero_invoice`,
  watched failing before the fix.
- **FIXED: a keys file nested past the JSON parser's depth crashed `check()`
  with a `RecursionError`, and the ASGI middleware with a 500.** `check()`
  maps `(ValueError, OSError, UnicodeDecodeError)` from the read path to the
  typed `keys_unreadable` denial the README promises for "a parse failure";
  `RecursionError` is none of those and walked straight out. `keys.load()`
  now reports it as the `ValueError` it is (naming the path, "nested too
  deep to parse"), so `check()` denies `keys_unreadable`, the middleware
  answers 401 with the reason in the body, and the migration path fails
  loud as before. Test:
  `test_deeply_nested_keys_file_is_keys_unreadable_not_a_recursion_error`.
- **FIXED: one hand-edited keys entry that is not an object crashed the
  invoice run while the meter kept authorizing.** With
  `"keys": {"<hash>": "oops"}`, `check()` denied that one key `unknown_key`
  (guarded since 0.1.1, pinned by two tests) but `export()` and `usage()`
  died with `AttributeError: 'str' object has no attribute 'get'` and
  `list_keys()` (so `keys list`) with a dict-update `ValueError` — the file
  was readable for spending and unreadable for billing. The verdict
  `check()` already gives is now given everywhere: `usage()` raises the
  documented `KeyError` (unknown key); `export()` bills the rest of the
  roster and `warnings.warn`s naming the malformed entries and any counts
  recorded under them (same pattern as the orphan warning — said out loud,
  never dropped); `list_keys()` returns the entry as
  `{key_id, key_hash, malformed: True}` and `keys list` prints it as
  `MALFORMED ENTRY` so it can be found and fixed. `check()`'s behaviour is
  unchanged. Test: `test_non_dict_entry_does_not_crash_export_usage_or_list_keys`,
  watched failing before the fix.
- **FIXED: `usage()` and `revoke_key()` raised a raw `UnicodeEncodeError` on
  a lone-surrogate secret instead of the documented `KeyError`.** `check()`
  has typed that input as `malformed_key` since 0.1.1; the two lookup paths
  still called `key_hash()` unguarded. Both now raise `KeyError` ("not
  encodable text (lone surrogate)"). Reachable from any wire that hands a
  JSON string to `usage()`, and from the CLI, where it printed a traceback.
  Test: `test_lone_surrogate_secret_is_a_keyerror_in_usage_and_revoke`.
- **FIXED: `add_key()` minted keys the meter would never honor.**
  `monthly_cap=-5`, `100.0`, `True`, `"100"` were written verbatim and the
  mint reported success (`keys add --cap -5` printed a secret); every call
  on that key then denied `no_cap_configured`, visible only from the
  customer's side. The writer now applies the reader's own `_valid_cap`
  (None, a non-negative int, or `"plan"`) and raises `ValueError` before the
  file is touched. Test: `test_add_key_refuses_a_cap_the_meter_would_not_honor`.
- **FIXED: the CLI printed a traceback for the package's own typed
  refusals.** Only `KeyError` was caught; `--month 2026-8` on `usage` /
  `export`, a refused `--cap`, and a keys file that is not a keys file
  (`keys list`, `export`, `revoke`) all escaped as stacks. `main()` now maps
  `KeyError` and `ValueError` to `error: <message>` on stderr, exit 1. Test:
  `test_cli_typed_errors_exit_1_without_a_traceback`.
- **ADDED test: `__version__` == `pyproject.toml` == `--version`**
  (`test_dunder_version_matches_pyproject_and_cli`). No drift found at 0.1.6;
  the pin keeps it that way.
- **Noted, not changed (contract call for the owner):** the ASGI middleware
  answers `keys_unreadable` with **401**, the same status as a bad key. The
  fault is server-side (the roster cannot be read); a 401 tells the caller
  their key is wrong. The body names the reason honestly. A 503 would be the
  truthful status, but that changes the HTTP contract the README documents,
  so it is left as-is and flagged.

## 0.1.6 — 2026-08-28 (an invoice run against a keys file that does not exist came back clean)

Audit pass over the money/idempotence packages.

- **FIXED: `export()` minted a clean, empty invoice for a keys file that does
  not exist.** `_load_keys()` returns an empty roster for a missing file *by
  design* — that is the fail-closed behaviour `check()` depends on, and it is
  correct there. At invoice time it is the opposite of correct: a mistyped
  path, an unmounted volume, or a container rebuilt without the persistent
  path produced `[]`, byte-identical to a genuine month with no customers.
  The 0.1.4 orphan warning could not catch it either, because `Meter()`
  creates a fresh counts database next to the bad path, so there were no
  orphan rows to disagree with the roster. Nothing on any surface said a
  word. `export()` now warns, naming the path, when the keys file does not
  exist; an existing-but-empty roster (a legitimate fresh install) stays
  quiet. Test: `test_export_against_a_nonexistent_keys_file_warns_instead_of_a_clean_invoice`,
  watched failing before the fix.
- **FIXED (a wrong month key answered a confident zero) — BEHAVIOUR CHANGE,
  new `ValueError`.** The `month` column holds exactly what `_utc_month()`
  writes, and every read is `WHERE month=?`. So a month string off by one
  character — `"2026-8"`, a trailing space, `"2026/08"` out of somebody
  else's date formatting — matched zero rows and returned the COMPLETE
  roster with `used: 0` on every line. A clean invoice for nothing, at the
  moment an operator believes they are billing a month, with no error and no
  warning (the orphan check cannot fire either: a month with no counts has
  nothing to be orphaned from). `export()`, `usage()` and `legacy_usage()`
  now refuse a `month` that is not `YYYY-MM`. Only a mistake could have
  produced such a value, since nothing but this package writes that column
  — but it IS a new refusal on a public entry point, so: flagged. The
  validator uses `re.fullmatch`, not a `$`-anchored `match`, because in
  Python `$` also matches before a trailing newline and a month string with a
  trailing newline (read out of a file without `.strip()`) would have sailed
  through the
  check and then matched nothing anyway. Test:
  `test_a_malformed_month_is_refused_not_billed_as_a_zero_invoice`, watched
  failing before the fix.
- **`keys add` no longer prints a U+2014 em dash.** It is the one command
  whose output cannot be recovered (the secret is shown once and never
  stored), and on a legacy Windows console codepage without that character an
  encode error would take the "store it now" instruction down with it.
- **FIXED (docs promising a warning that was never emitted):**
  `examples/stripe_invoice_export.py` fell back from a missing `key_hash` to
  the 12-hex `key_id` under a comment reading "say so rather than silently
  mis-keying" — and said nothing, for four releases. It matters: the Stripe
  `idempotency_key` is derived from that value, so two keys sharing a 48-bit
  prefix collapse onto ONE idempotency key and Stripe answers the second
  customer's invoice item with the first one's — a silent under-bill, not an
  error. It warns now.
- **`RECIPE_STRIPE_BILLING.md` drift corrected** (the doc debt disclosed as
  audit F7 in 0.1.4): its inline `build_invoice_items` snippet had diverged
  from the shipped example (description text, `skipped` row shape,
  metadata); its example ledger rows predated the `key_hash` field 0.1.4
  added; its reconciliation snippet told you to filter per key on `key_id`,
  the exact 48-bit identity 0.1.2 removed from the counting path; its
  `VerifyResult` repr was four fields short; and it declared the package
  version to be `0.1.0`. The verify section now states arcaeon-ledger's
  three-valued contract explicitly — `ok=True` **plus**
  `verified_scope="full"` is the only green, `ok=None` is a bounded scan and
  not a bill-it, and `breaks` (not just `first_break`) is the fault count.
- Hygiene: dropped unused imports (`os` in `arcaeon_meter/__init__.py`,
  `key_id_of` in `test_property_meter.py`). The two stale `## Unreleased`
  headers below are retitled — that work shipped in 0.1.4, and 0.1.4's own
  entry says so.

## 0.1.5 — 2026-08-28 (the 0.1.4 fix's residual: Meter's own stat()-level OSError swallow)

The 0.1.4 F1/F5 fix moved `keys.load()` off swallow-every-OSError — but
`Meter._load_keys()` had its own `except OSError: return {}` around the
`stat()` call UPSTREAM of `load()`, so the same class of fault (a
PermissionError or scanner/backup sharing violation, landing on `stat()`
instead of the read) still read as an EMPTY ROSTER inside Meter itself.
Same masquerade as F5: every real key denied `unknown_key` ("key not in
the keys file") while the fault was server-side — a permissions failure
presenting as no-usage.

- **Fix:** only `FileNotFoundError` means "empty roster" at the stat level
  (matching the 0.1.4 rule at the load level); every other OSError
  propagates, and `Meter.check()`'s existing handler maps it to the typed
  `keys_unreadable` denial. Nothing is cached on the failure (the F2
  memoization shape), so a transient clears on the very next call instead
  of wedging until restart. `usage()`/`export()`/`add_key`/`revoke_key`
  inherit the same propagation and fail loud, exactly as 0.1.4 documented
  for the load path.
- **`Denied.keys_unreadable` docs widened** (dataclass docstring + README):
  the reason now explicitly covers OS-level read-path failures, `stat()`
  included, and states the invariant — a permissions fault must never
  masquerade as an empty roster.
- **Test (`test_stat_failure_is_keys_unreadable_not_an_empty_roster`), with
  the planted red demonstrated:** a stand-in path object whose `stat()`
  raises `PermissionError` (Windows `chmod` can't make `stat()` fail, so
  the transient is simulated at the exact syscall) must yield
  `keys_unreadable` from `check()` and from the `@metered` decorator, and
  the next call against the healthy file must grant (no memoized failure).
  Mutation-verified: reverting the one line to `except OSError` fails the
  test with `surfaced as 'unknown_key' -- a permissions fault is
  masquerading as an empty roster`.

## 0.1.4 — 2026-08-24 (F1/F2/F5 one root cause: transient unreadability read as an empty roster; plus F4, the receipt's billing identity)

Adversarial audit, CRITICAL. `keys.load()` swallowed EVERY OSError as
"empty roster" — intended for file-not-yet-created, it also fired on
PermissionError / sharing violations (scanner or backup tooling holding
the file), so:

- **F1 (CRITICAL):** `add_key()` racing a 2-second transient read-hold
  "succeeded" by REPLACING the entire keys file with one key, and
  `export()` then silently dropped every orphaned customer's accrued
  usage from the invoice — 37 real billed calls gone from the CSV with
  no warning on any surface. Silent revenue loss.
- **F2 (HIGH):** the in-process cache memoized the empty-on-OSError
  result under a stat stamp that never changed, denying every customer
  until restart from a sub-second transient.
- **F5:** an existing-but-unreadable keys file reported `unknown_key`
  ("key not in the keys file") for keys that ARE in the file — a support
  flow branching on the reason would tell a paying customer their key is
  invalid when the fault is server-side.

One-line root fix: `load()` treats only `FileNotFoundError` as empty;
every other OSError propagates, which the existing paths already handle
honestly (typed `keys_unreadable` denial; `add_key`/`revoke_key` fail
loud instead of destroying state). Second, independent defense: `export()`
now WARNS when usage rows exist for hashes absent from the roster, naming
the orphaned hashes and the total, so a roster/counts disagreement
surfaces at invoice time, not from a customer. Both mutation-verified.

**F4 (MEDIUM):** the tamper-evident ledger — the invoice-dispute receipt —
identified customers only by the 48-bit display `key_id`, the exact
identity 0.1.2 removed from SQLite because two customers can collide on
it (the repo's own colliding probe secrets prove it). Grant, void, and
deny rows now also carry the full `key_hash` (backward-compatible
additive field); denials without a valid key have no hash and honestly
omit it.

Known, disclosed, next release (audit F3/F6/F7): the repo's two
Windows-lock fixes described under "Unreleased" below still need this
release cut to actually reach PyPI (they are included here); the ASGI
middleware answers 401 for the server-side `keys_unreadable` fault where
503 would be honest; recipe doc drift.

## Shipped in 0.1.4 — Windows file-lock flake: durable fix (2026-08-17)

The pre-existing concurrency flake (`test_concurrent_revoke_is_not_erased_by_a_concurrent_add`, nondeterministic `PermissionError`, fired only under machine load — logged 2026-08-16) traced to two real defects in `keys.py`, not to the test:

- **`save()`'s `os.replace` retry was a fixed 50 × 20 ms = 1.0 s budget.** On Windows, external scanners (Defender real-time scan, the search indexer) open freshly written `.json` files without `FILE_SHARE_DELETE`; under load that hold can outlive a flat 1 s, so the retry exhausted and `PermissionError` escaped into callers — exactly the flake's shape (load-dependent, nondeterministic). Now a bounded time-budget retry: exponential backoff (10 ms doubling, capped 250 ms) under a 10 s ceiling. Still bounded, still raises at the deadline — no retry spiral, just a budget sized for a scanner hold instead of a wish.
- **`_locked()`'s retry loop had an unbounded busy-spin path with no timeout.** When `lock.stat()` raised `OSError` — the COMMON case under contention, because the holder unlinks the lock between the loser's failed open and its stat — the loop `continue`d past both the deadline check and the sleep. The deadline is now enforced first on every iteration, and the stat-failure path falls through to the sleep instead of spinning.
- **Flake bar met: full suite (50 tests, all 4 files) run 5 times consecutively after the fix — `50 passed` × 5 (114.2 s / 120.6 s / 113.9 s / 112.7 s / 113.5 s), zero flakes.**
- **SPDX:** `# SPDX-License-Identifier: MIT` added as the first line of every `.py` file in the repo (10 files), per the license-header pass at repo touch.

Test-only; no product-logic change. A second, independent property pass — this one built on the `hypothesis` library (`@given` + strategies + shrinking), distinct in mechanism from the existing seeded `random`-module fuzzer in `test_property_meter.py` — found **no billing or fail-closed bug**. Every invariant held; the value is a second opinion generated a different way, and failures now shrink to minimal repros.

- **New `test_hypothesis_meter.py`** (16 Hypothesis properties, checked in at 80 examples/property — bumped to 400 during development, which is what surfaced the test-construction traps noted below, then settled to the sibling-repo CI convention). Coverage: (1) **aggregation determinism** — replaying an identical generated op sequence against two independent fresh databases lands on identical per-key counts, and `export()` per-row totals equal `usage()` per-key sums with no drop/duplicate; (2) **key-hash collision resistance** — the 0.1.2 48-bit `key_id` fix generalized to a `@given` property over many generated full-hash pairs sharing a 12-hex display prefix (counts never merge, ambiguous prefix lookup refuses), plus sha256 sanity fuzzing (determinism, 64-hex format, distinct inputs → distinct outputs); (3) **the U+0085/U+2028/U+2029 line-separator class** — pinned through both meter's own keys.json round-trip and the optional `ledger=` path; (4) **fails-closed** — a wide generated space of malformed keys, caps, entry shapes, unreadable files, and bad costs, every one denying (never an `Allowance`), never crashing.
- **Unicode-JSONL-line-separator bug: absent in meter's own I/O, fixed transitively on the ledger path.** meter's keys.json is read/written as one whole JSON document (`json.loads`/`json.dump`), never split into lines, so there is no `.splitlines()` row-boundary to corrupt — `grep -n "splitlines\|readlines" arcaeon_meter/*.py` is empty. The one write-JSONL-then-read-back path is `Meter(ledger=...)` → `arcaeon_ledger`, whose `.splitlines()` bug was fixed in arcaeon-ledger 0.5.6 (splits on `"\n"` only); a test pins that the installed ledger is ≥0.5.6 and that grant rows carrying those characters survive `verify()` + `Ledger.__iter__` intact.

## Shipped in 0.1.4 — property-fuzzing regression suite (2026-08-15)

Test-only; no product-logic change (the property pass found no billing bug — the counting invariants held under fuzzing, which is the result being recorded).

- **New `test_property_meter.py`.** A seeded 5000-operation property loop over a random roster (6–14 keys with mixed cap configs — finite caps, explicit-unlimited, plan-deferred, and misconfigured fail-closed) driving random `check`/peek/deny with random costs, checked against an independent in-memory oracle on every op. Asserts the four money invariants: counts **exact + monotonic**, **no cross-key contamination** (each key's stored/exported count equals its own oracle and only its own), **cap never exceeded** (an over-cap call is a typed `over_cap` denial that does not increment), and **a denied call never increments** (unknown/malformed/revoked/over-cap/no-cap). Result on the committed seed: `grant_cost_sum == billed`, zero drift. Plus (1) a **ledger receipt invariant** run — with `ledger=` set, `sum(grant costs) − sum(void costs) == total billed count` and the chained usage log verifies GREEN; (2) a **prefix-collision** test proving two keys.json entries sharing a 12-hex display prefix keep separate counts and that an ambiguous prefix lookup refuses rather than guess; (3) a **concurrency property** — random `(cap, workers, load)` across real OS processes, asserting `grants == min(load, cap)` exactly, cap never exceeded. Scales via `METER_PROP_OPS`.

## 0.1.2 — 2026-08-15

Billing-integrity release, from a hostile audit of the *counting* (0.1.1 audited
the fail-closed *denying*). The headline is a keyspace change, so it lands now,
while the install base is small enough that "migrate everyone" is a sentence
rather than a project.

- **Counts key on the full sha256, not the 12-hex `key_id`.** That prefix is 48
  bits. Two customers whose key hashes shared those 12 hex shared one `usage`
  row: the busy one's calls appeared on BOTH invoices, and the quiet one's cap
  was spent by traffic it never sent — silently, no error, wrong denials in both
  directions. Birthday odds put a collision at ~50% around **16.7M keys**, which
  is inside this product's own "millions of agents" pitch, not a footnote.
  Reproduced with two REAL keys found by brute-force search (`am_probe3197488`
  and `am_probe27007650`, both hashing to `fc98907cfe56…`), not a mock:

  ```
  0.1.1:  label=acme-BIG   key_id=fc98907cfe56  used=900  cap=1000
          label=tiny-free  key_id=fc98907cfe56  used=900  cap=100     <- never called
          tiny-free's very first call: DENIED reason=over_cap used=900
  0.1.2:  label=acme-BIG   key_id=fc98907cfe56  used=900  cap=1000
          label=tiny-free  key_id=fc98907cfe56  used=0    cap=100
          tiny-free's very first call: GRANTED
  ```

  `key_id` remains the display prefix everywhere it was (CLI, `Allowance`,
  `Usage`, export) — it is a label now, not an identity.

- **Migration, and exactly what it can and cannot recover.** Opening a pre-0.1.2
  database migrates it in one transaction. A legacy row whose prefix matches
  **exactly one key in your keys file** carries over intact: the roster is the
  whole universe of keys that could have incremented that row, so a single match
  is provably its owner. A row whose prefix matches **two or more keys cannot be
  split by anyone** — that merged row IS the defect, and truncation is not
  reversible; there is no honest way to say which calls were whose. Same for a
  prefix matching **no** key (a hand-deleted entry — `revoke` keeps entries, so
  this is rare). Both unrecoverable cases are preserved as
  `legacy_truncated_keyspace:<prefix>`, **excluded from `export()`** (nobody can
  be honestly invoiced for a count with an unknown owner), and readable via
  `meter.legacy_usage()`; the CLI `export` prints a warning to stderr when any
  exist. Your original table is kept as `usage_pre_0_1_2` — nothing is dropped.
  One caveat stated rather than papered over: if entries were DELETED from
  keys.json after spending, a surviving key sharing their prefix inherits their
  counts. Deletion already destroyed that evidence; the migration cannot invent
  it back. If the keys file can't be read, the migration **refuses to run**
  (loud `RuntimeError`) rather than zeroing every recoverable count.

- **`export()` and `list_keys()` gained a `key_hash` column (full sha256) — a
  format change.** Map customers on it, not on `key_id`: colliding prefixes
  would otherwise point two customers' invoice rows at one mapping. It is the
  same one-way hash already in `keys.json` — not a secret, not reversible to
  one; plaintext secrets still appear nowhere. CSV header is now
  `key_id,key_hash,label,plan,used,monthly_cap,revoked,month`. The Stripe recipe
  and `examples/stripe_invoice_export.py` now key the customer map and the
  idempotency key on `key_hash` (the example still accepts an old key_id-keyed
  map so an existing mapping file keeps working).

- **A `COMMIT` that fails after the ledger append now chains its inverse.** The
  0.1.1 fix covered one direction of the two-store seam (ledger raises → count
  rolls back). The other direction: the grant is chained, then `COMMIT` fails on
  a full disk — SQLite has no such grant, but an append-only chain cannot have a
  row removed, so the ledger stayed permanently ahead of the billed count while
  `verify()` still reported `ok` (the chain was intact; the row was just
  phantom). The recipe sells exactly that equality as "the receipt." Now a
  `meter.void` row with `reason: "commit_failed"` is chained, and the stated
  invariant is **grants − voids == the billed count** — documented in the README
  and with a reconcile snippet in the recipe. If the void append fails too (same
  dying disk), the ledger stays `+cost` ahead and that same reconcile is what
  surfaces it; the caller sees the raised error either way.

- **The ASGI middleware no longer bills CORS preflights.** `OPTIONS` was metered
  like a call — and since browsers don't send `Authorization` on a preflight, it
  was billed *and* answered 401, breaking the handshake it was inspecting.
  `OPTIONS` is now passed through unmetered (`scope["arcaeon_meter"] = None`),
  configurable via `meter.asgi_middleware(skip_methods=...)`. The rest of the
  policy is now stated instead of implied: `HEAD` is billed by default (add it
  to `skip_methods` if you disagree), and a request your handler answers 5xx is
  still billed — the cap has to be spent before the work runs, which is what
  makes it a cap and what makes it atomic across processes, and refunding would
  need the negative cost that 0.1.1 deliberately removed.

Not changed, still true: happy-path counting is exact and concurrency-safe
(`2 processes × 200 → used=400, zero lost`; `cap=300 vs 400 attempts → exactly
300 grants`), and this meter counts CALLS, not tokens.

## 0.1.1 — 2026-08-14

Hostile audit of the fail-closed claim. It did not hold on five paths; it does
now. Every fix is in the deny direction, so nothing that was legitimately
granted before is denied today.

- **A cap that isn't a cap is no longer unlimited.** `used + cost > cap` is
  `False` for both `NaN` and `+Infinity`, so either one in a keys file was a
  silent unlimited grant — and `json.loads` accepts the bare `NaN`/`Infinity`
  literals, so it round-tripped through this package's own writer. Caps are
  now validated as `None` (explicit unlimited) or a non-negative `int`;
  anything else resolves to `no_cap_configured`. `keys.load()` also rejects
  the non-JSON literals at parse time, and `keys.save()` refuses to write
  them.
- **`cost=` must be a positive int.** It is a public kwarg and the SQL is
  `used = used + ?`, so a negative cost was an unbounded refund that persisted
  in SQLite across processes, and `cost=0` was unlimited free calls at the cap.
  Both now raise `ValueError` before anything is read or written.
- **Malformed keys and unreadable keys files are typed denials.** A lone
  surrogate (`"am_\ud800"`) is legal JSON, so it arrives from the wire; it used
  to escape `except MeterDenied` as a `UnicodeEncodeError` and 500 instead of
  401. New reasons: `malformed_key`, `keys_unreadable`. A corrupt or truncated
  keys file now denies rather than raising out of `json`.
- **The ASGI middleware no longer waves through non-HTTP scopes.** WebSocket
  connections bypassed metering entirely — unkeyed, uncapped, on the exact
  protocol where unbounded work hides. `lifespan` still passes through; a
  websocket scope is closed with 1008.
- **Revocation survives a concurrent write.** `add_key`/`revoke_key` were
  load-mutate-save with no lock, so a concurrent add rewrote the document from
  a stale read and silently un-revoked a key the CLI had just reported as
  revoked. The whole cycle now runs under a cross-process lock; `save()` fsyncs
  and retries `os.replace` (on Windows it fails with `PermissionError` while a
  reader holds the file, which made "revocation takes effect without a restart"
  false in practice).
- **A failed ledger write rolls the count back.** The grant was chained *after*
  the commit, so a ledger failure billed for a call that raised before it ran,
  and `verify()` reported `ok` across the gap (a missing row is not an altered
  one). The chain write now happens inside the transaction.
- **Key-id prefixes shorter than 6 chars are refused.** `revoke_key(kp, "")`
  resolved to whichever key sorted first — an unset `$KEY_ID` in an ops script
  could revoke a key at random. Same guard on `usage()`.
- Keys-file cache invalidation now keys on size + inode + ctime as well as
  mtime, so a coarse-granularity filesystem or a timestamp-preserving copy
  can't leave a revoked key spending until restart.

Known, not fixed in this release (documented rather than papered over): if the
usage SQLite file is deleted or not persisted, every budget resets to zero on
the next start. See the README honesty section.

## 0.1.0 — 2026-08-14

Initial release. Keyed usage metering for agent tools, stdlib-only.

- `Meter("keys.json")` + `@meter.metered` decorator (the 3-line promise) and
  `meter.check(key)` returning truth-testable `Allowance | Denied`; denials are
  typed (`over_cap`, `revoked`, `unknown_key`, `missing_key`,
  `no_cap_configured`) — never a silent pass, and an unresolvable cap fails
  CLOSED rather than defaulting to unlimited.
- SQLite (WAL) usage counts per key per UTC month; check-then-increment inside
  a `BEGIN IMMEDIATE` transaction — proven by a two-process contention test
  (400 competing attempts vs cap=300 grants exactly 300).
- Key management CLI (`python -m arcaeon_meter keys add|revoke|list`, plus
  `usage` and `export`): random `am_` secrets shown once, stored sha256-hashed
  only; revocation is live (keys file re-read on mtime change).
- Billing handoff: `usage(key_or_id)` and `export(fmt="json"|"csv")` — full
  roster, invoice-ready, no secrets; Stripe recipe documented as a how-to
  (no payment code by design).
- Optional pure-ASGI middleware (`meter.asgi_middleware()`) — bearer-key
  checks for FastAPI/Starlette/any ASGI with 401/429 JSON denials; zero
  framework imports.
- Optional tamper-evident record: `Meter(..., ledger="usage.log.jsonl")`
  hash-chains every grant/denial via arcaeon-ledger (soft dep,
  `pip install arcaeon-meter[ledger]`; missing dep is a loud ImportError).
- Why keyed (not x402) for v0.1: per Arcaeon research #26 (2026-08-14),
  keyed API + Stripe is the revenue rail for the next 12 months; x402 demand
  is still mostly self-dealing. An x402 adapter remains a later shop-window
  add-on, out of scope here.
