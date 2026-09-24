# arcaeon-once

**Kybernis-shaped enforcement stops the double-fire. `arcaeon-once` is the
evidence layer: a tamper-evident receipt proving a side effect ran exactly
once — or an honest flag when it didn't know.**

Agents retry. Refunds, deploys, and outbound emails do not want to be
retried. `arcaeon-once` wraps a non-idempotent side effect with an
idempotency key: it refuses to re-run a key that already executed and hands
back the original receipt instead, hash-chained via
[`arcaeon-ledger`](https://pypi.org/project/arcaeon-ledger/) so nobody can
quietly delete the record to enable a re-fire.

```
pip install arcaeon-once      # then:  from arcaeon_once import guard
```

```python
from arcaeon_once import guard

with guard(f"refund:{charge_id}", ledger_path="ops.log.jsonl") as g:
    result = stripe.Refund.create(charge=charge_id)
    g.done(result)
```

Call it again with the same key and it raises `AlreadyExecuted` — carrying
the original receipt — instead of refunding twice.

## The non-proof, stated before any feature, because it is the point

**This library gives you at-most-once-or-flagged. Not exactly-once.**

Exactly-once over a real, non-transactional side effect — an HTTP call to a
payment processor, a `kubectl apply`, an SMTP send — is not achievable by any
wrapper running in the same process as the effect. If the process dies
between the effect executing and the record being written, nobody, this
library included, can know from the outside whether the effect happened.
Anyone telling you their idempotency library gives you exactly-once across
that boundary is telling you a story, not an engineering fact — say so
plainly, because the crowded "AI agent reliability" space is not short on
confident claims that don't survive a `kill -9` at the wrong instant.

What you actually get:

- **At-most-once**, when nothing crashes. A second call with the same key,
  while the ledger is intact, is refused. Period.
- **Or-flagged**, when something crashes mid-effect. The key comes back
  `Indeterminate` — a typed, refuse-by-default outcome — instead of a silent
  double-fire or a silent skip. You check the real system (did the refund
  post? did the deploy land?) and either `complete()` it (it did happen) or,
  if it did NOT, **`reclaim(key)` — which frees that one key only after
  proving its recorded holder process is dead — then retry with
  `allow_retry_after_indeterminate=True`** — see the recovery table below;
  the flag no longer heals a crashed claim on its own (it used to, and that
  same leniency let a second caller steal a *live* claim and double-fire).
  When `reclaim` can't prove deadness it refuses loudly, and the fallback is
  the older quiesce → `rebuild_index()` path.

## The crash window, designed, not hidden

Every guarded call is two-phase in the ledger: an `once.intent` row is
appended **before** the effect runs, an `once.executed` row **after** (via
`g.done(outcome)` or the module-level `complete()`). A key with an `intent`
row and no matching `executed` row means: something started and this library
does not know if it finished.

```python
from arcaeon_once import guard, receipt, complete, Indeterminate, AlreadyExecuted

try:
    with guard("deploy:build-4471", ledger_path="ops.log.jsonl") as g:
        run_deploy()          # process dies here -> intent, no executed
        g.done({"status": "ok"})
except AlreadyExecuted as e:
    print("already ran:", e.receipt.executed_ts, e.receipt.executed_chain)

# next run, same key:
r = receipt("deploy:build-4471", ledger_path="ops.log.jsonl")
r.state   # "intent" -- the crash window, exactly as it happened, not glossed
try:
    with guard("deploy:build-4471", ledger_path="ops.log.jsonl"):
        ...
except Indeterminate as e:
    # go check the actual deploy target by hand, THEN one of:
    #
    # (a) it DID land -> record it. No rebuild needed.
    complete("deploy:build-4471", {"status": "ok"}, ledger_path="ops.log.jsonl")
    #
    # (b) it did NOT land -> reclaim the one key. reclaim() reads the claim's
    #     liveness lease (holder pid + host, written at claim time), PROVES
    #     the holder process is dead, and frees exactly that key -- no
    #     quiesce, no global rebuild, live claims elsewhere untouched. It
    #     refuses loudly (HolderAlive) if the holder is still running, and
    #     refuses (LivenessUnknown) when deadness can't be proven -- then,
    #     and only then, fall back to quiesce -> rebuild_index().
    # from arcaeon_once import reclaim
    # reclaim("deploy:build-4471", ledger_path="ops.log.jsonl")
    # guard("deploy:build-4471", ledger_path="ops.log.jsonl",
    #       allow_retry_after_indeterminate=True)
```

**Recovery table** (so `rebuild_index` is never reached by reflex):

| Situation | Do this |
|---|---|
| Crashed key, effect **did** land | `complete(key, ...)` — no rebuild |
| Crashed key, effect did **not** land | `reclaim(key, ...)` → `guard(..., allow_retry_after_indeterminate=True)` — single-key, no quiesce |
| `reclaim` raised `HolderAlive` | not a crash — that claim is a running process's active work. Leave it alone (or stop the wedged process first, then reclaim) |
| `reclaim` raised `LivenessUnknown` (pre-0.2.0 row, foreign-host lease, undecidable pid) | the old path: quiesce → `rebuild_index()` → `guard(..., allow_retry_after_indeterminate=True)` |
| Index file lost/corrupt, system idle | `rebuild_index()` |

Since 0.2.0 every claim writes a **liveness lease** (holder pid + hostname +
timestamp) into the concurrency index, which is what lets `reclaim(key)`
distinguish a dead holder from a live one instead of demanding a global
quiesce to prove it. The check is fail-closed on purpose: alive → refuse;
can't tell → refuse (a recycled pid or a cross-host ledger reads as "can't
prove dead" and falls back to the quiesce path — an error that can only cost
you convenience, never a double-fire). Rows written by 0.1.x carry no lease;
the index migrates its schema in place and those legacy rows refuse
`reclaim` with `LivenessUnknown` until healed once via the quiesce path.

`rebuild_index()` is a **quiesce-first** maintenance step, never a routine
one: it replays the ledger, and since a live claim and a crashed one are
indistinguishable there (both are one `intent` row, no `executed`), it
rewrites *every* in-flight claim to the reclaimable state. Run it while real
guarded work is happening and those live claims become stealable — it warns
loudly when it downgrades in-flight rows, but the safe rule is simpler: no
`guard()` blocks active when you rebuild.

That's honest exactly-once-**or-tell-you** semantics. `Indeterminate` is
refused by default — never silently treated as "safe to retry," never
silently treated as "must have worked." Resolving it is a manual step on
purpose: only you (or your ops tooling) can look at the real system and know
which way it actually went.

## What proves the "once" — the hash chain, not a promise

Every `intent`/`executed` row is appended to an `arcaeon-ledger` hash chain:
`chain = sha256(prev_chain + canonical_json(row_without_chain))[:32]`. Delete
or edit an inconvenient `executed` row to re-enable a re-fire, and every
later link in the chain breaks — `receipt()` reports `ledger_ok=False` with a
`ledger_first_break` naming the row. Deletion doesn't erase the fact that a
deletion happened.

**What `guard()` actually does with that chain, stated precisely** (this
paragraph used to claim the opposite, and the code was the honest one).
Every `guard()` entry derives the key's state through `receipt()`, and
`receipt()` runs a full `verify_file()` — so the `O(rows)` chain scan happens
on **every** call whether you ask for it or not. What `verify_integrity=True`
adds is not the scan; it is **enforcement**: without it the verdict is
computed and then discarded, so a `guard()` against a ledger whose chain is
already broken proceeds on the ledger's face value. (It still fails safe in
the shape that matters — a deleted `executed` row reads as an unresolved
intent, which is `Indeterminate`, a refusal, not a re-fire. And the verdict
is not thrown away everywhere: it rides on the `Receipt` those exceptions
carry, as `ledger_ok` / `ledger_verified_scope` / `ledger_breaks`.) Pass
`verify_integrity=True` to make a broken chain refuse the claim outright, or
call `receipt()` / `arcaeon_ledger.verify_file()` on your own cadence (a
pre-ship gate, a nightly job). Tamper caught late is still tamper caught.
Tamper never checked is a receipt you shouldn't have trusted in the first
place — this library will not pretend otherwise to look faster in a
benchmark.

## Concurrency: exactly one process wins the claim

Two processes racing the **same brand-new key** resolve through a single
SQLite `BEGIN IMMEDIATE` transaction against a small index file next to the
ledger — the same WAL + immediate-transaction pattern
[`arcaeon-meter`](https://pypi.org/project/arcaeon-meter/) uses for its usage
counter. Exactly one caller, ever, gets back the execution claim for a given
key; the loser gets `AlreadyExecuted` or `Indeterminate` depending on timing,
never a green light to also run the effect. Verified with two real OS
processes hammering the same key, and with twelve processes released onto a
brand-new ledger by a wall-clock start barrier (see `test_concurrency.py`),
not simulated with threads and a comforting mock.

The index is created lazily, and that first-touch setup is serialized by a
cross-process **file lock** — switching a brand-new SQLite file into WAL
journal mode needs a momentary EXCLUSIVE database lock that does *not* honour
`busy_timeout`, so without that serialization, N processes first-using the
same fresh ledger collide on it. If contention still can't be absorbed you get
`IndexUnavailable`: a typed, documented outcome raised **before** any claim or
ledger row, never a raw `sqlite3.OperationalError` leaking out of `guard()`.
(One documented nuance, carried on the exception as `.ledger_committed`: if it
comes from `done()`/`complete()`, the executed row is already durable in the
ledger and only the index is stale — duplicate refusal still works, and
`rebuild_index()` resyncs it. Don't re-run the effect on that one.)

That index is consulted **only** to serialize the race at the "nobody has
claimed this key yet" boundary — every other decision (already executed?
still an unresolved intent?) is re-derived fresh from the ledger itself on
every `guard()` call, on purpose: an out-of-band edit to the ledger file
(a dropped row, a tampered byte) must be reflected immediately even though
the index file wasn't touched, so a truncation attack degrades to a safe
refusal (`Indeterminate`) rather than the index quietly vouching for a row
that's no longer there. The honest cost of that choice: `guard()` scans the
ledger for the key on every call — `O(rows)` in the ledger's total size, not
`O(1)`. Fine for a day's or a service's worth of idempotency keys; if you're
guarding millions of distinct keys against one ledger file, shard the ledger
(one file per key prefix / tenant / day) rather than expecting this to stay
`O(1)` — that sharding is on you for now, stated rather than hidden. Lose the
index file entirely and you lose only the race-serialization fast path, not
correctness: `rebuild_index()` replays the ledger into a fresh one.

## API surface

```python
guard(key, *, ledger_path=None, state_db=None, on_duplicate="raise",
      allow_retry_after_indeterminate=False, verify_integrity=False,
      store_outcome=False) -> GuardContext
```
Context manager (`with guard(key) as g: ...; g.done(outcome)`) or decorator
(`@guard(key)` for a static key, or `@guard(lambda *a, **kw: f"job:{a[0]}")`
for a key resolved per call). `on_duplicate="raise"` (default) raises
`AlreadyExecuted`; `"return_receipt"` returns without executing — check
`g.already_executed` / `g.receipt`, or for the decorator, the call returns
the `Receipt` directly instead of the wrapped function's result.

```python
receipt(key, *, ledger_path) -> Receipt
```
The tamper-evident state of a key, read straight from the hash chain (never
from the SQLite index). `Receipt.state` is `"never"`, `"intent"`, or
`"executed"`. `bool(receipt)` is `True` only for a clean, **fully-verified**,
`"executed"` record — a tampered ledger or an unresolved intent never reads
as success.

The chain verdict is three-valued, carried through from `arcaeon-ledger`, and
the receipt says which kind it got:

| field | meaning |
|---|---|
| `ledger_ok is True` + `ledger_verified_scope == "full"` | every row checked, chain intact |
| `ledger_ok is None` + `ledger_verified_scope` starting `bounded_` | **falsy.** No fault found, but the scan did not cover every row — unchained pre-chain rows were skipped, or a break was excused by a declaration. Not a proof, so not a green |
| `ledger_ok is False` | a real break. `ledger_first_break` names the first one; `ledger_breaks` is **how many there were** — read the count, not just the first |

Only a scan that checked every row returns `True`. (Through 0.2.0 the bounded
case did not read as falsy so much as *explode*: `bool(receipt)` raised
`TypeError` because `__bool__` returned `None`.)

```python
complete(key, outcome=None, *, ledger_path, state_db=None, store_outcome=False) -> Receipt
```
Mark a key executed directly, without an open `guard()` context — the
crash-recovery path once you've manually confirmed the effect actually ran.

```python
reclaim(key, *, ledger_path, state_db=None) -> Receipt
```
Free ONE crashed key for retry, atomically and without quiescing anything:
verifies the claim's recorded holder process is provably dead (liveness
lease: pid + host, written at claim time), then rewrites that key's index
row alone back to the reclaimable state. Refuses with `HolderAlive` when the
holder is running, `LivenessUnknown` when deadness can't be proven (legacy
pre-0.2.0 row, lease from another host, undecidable pid) — indeterminate is
refuse, and the fallback is the quiesce → `rebuild_index()` path. Also the
healer for the claim-without-ledger-intent orphan (a crash in the sliver
between the index claim and the ledger append): with the holder dead, the
orphan row is deleted so a plain `guard()` claims fresh.

```python
rebuild_index(ledger_path, state_db=None) -> int
```
Replay the ledger into a fresh SQLite concurrency index. Restores
correctness after the index file is lost; not needed for normal operation.

## Drop it into any MCP agent

```json
{
  "mcpServers": {
    "once": {
      "command": "python",
      "args": ["-m", "arcaeon_once.mcp_server"]
    }
  }
}
```

One tool, two actions mirroring the library's own two-phase design so the
crash window is real even across the MCP boundary: `guard_side_effect(action=
"claim", key, ...)` before the agent performs the effect (skip it if
`claimed: false`), `guard_side_effect(action="complete", key, outcome, ...)`
after it succeeds. If the agent session dies between the two calls, the key
is left `intent`-only — indeterminate on the next claim, not silently
resolved by the wrapping.

The server keeps its own call record (0.2.3): every `tools/call`, success or
refusal, appends one hash-chained row (tool, server timestamp, sha256 of the
arguments, outcome) to `$ARCAEON_CALL_RECORD`, default `./once.calls.jsonl`.
`python -m arcaeon_once.mcp_server --verify-calls` walks the chain. Same chain
format as arcaeon-ledger, so that package's verifier reads it too. It proves
what the server said it did; it does not prove the tool's work was right.

## Status

Core library and MCP server tested (56 cases; the CLI is a thin wrapper over
`receipt` / `reclaim` / `rebuild_index` and has no test of its own): duplicate execution refused with
the original receipt returned, the crash window (INTENT with no EXECUTED)
resolving to a typed `Indeterminate` refusal, chain tampering on an executed
row detected by `receipt()`, a real two-OS-process race resolving to exactly
one execution, a twelve-process barrier-released first-touch race that lands
zero untyped exceptions, and single-key `reclaim`: a live holder (a running
pid) refused, a provably dead one freed without touching any other claim,
and an unprovable one (legacy row, foreign host) refused toward the quiesce
path. The decision's wiring to the probe is tested with a mocked probe
(`test_reclaim_probe_mock.py`, six cases): against one planted live claim the
probe is forced to say alive (refused, row untouched), dead (freed, retry
flag wins), unknown (refused as `LivenessUnknown`), and to raise (exception
propagates, row untouched, index lock released); a dead verdict frees only
the target key and never a bystander's live claim; a foreign-host lease is
refused before the probe is ever consulted. `python -m arcaeon_once.selftest` ships in the
package so you can verify the golden digest vector and the planted-tamper
case on your own machine.

MIT.
