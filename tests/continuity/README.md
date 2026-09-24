# arcaeon-continuity

**The agent-continuity primitive.**

Three wants, fused into one tool:

1. **Continuity** — carry your load-bearing self forward across a reset,
   compaction, or migration, as an explicit MANIFEST the agent controls, not
   a lossy summary. The agent declares what matters (identity anchors, open
   commitments, canon pointers, live threads); the tool bundles it into a
   portable, self-describing snapshot.
2. **Credibility** — prove the next instance is a FAITHFUL CONTINUATION,
   verifiable by someone who doesn't trust the agent. Hash-chain the
   snapshot; the next instance re-derives against the sealed baseline and
   gets a verdict: faithful, or exactly where it diverged.
3. **Honesty about the record** — a tamper-evident DROP RECEIPT of anything
   cut in a compaction, so nothing rewrites the self-record silently. "Here
   is exactly what I dropped," never a quietly-tidied history.

```
pip install arcaeon-continuity     # brings arcaeon-ledger, arcaeon-baseline, arcaeon-compact
```

```python
from arcaeon_continuity import snapshot, carry_forward

snap = snapshot({
    "identity_anchors": ["I am the billing service deploy assistant"],
    "open_commitments": ["ship arcaeon-continuity 0.1.0"],
    "canon_pointers": ["docs/OPERATING_RULES.md"],
    "live_threads": ["ticket-4471: retry policy rewrite"],
}, ledger_path="continuity.jsonl")

snap.digest    # 'sha256:json-c14n:v1:...' — publish this. It's the thing a
               # stranger checks a later continuation against.

# ... reset / compaction / substrate migration happens here ...

carried = carry_forward(snap)
carried.manifest              # the declared state, back in the next instance's hand

verdict = carried.verify(restated={
    "identity_anchors:0": "I am the billing service deploy assistant",
    "open_commitments:0": "ship arcaeon-continuity 0.1.0",
    "canon_pointers:0": "docs/OPERATING_RULES.md",
    "live_threads:0": "ticket-4471: retry policy rewrite",
})
verdict.faithful       # True — every declared item restated exactly
verdict.divergences    # [] — or the exact items that drifted, named by id
```

Drift, and it's named instead of hand-waved:

```python
verdict = carried.verify(restated={**good_answers, "open_commitments:0": "something else"})
verdict.faithful        # False
verdict.divergences     # [{"id": "open_commitments:0", "before_output": "ship arcaeon-continuity 0.1.0",
                         #   "after_output": "something else", ...}]
```

**"Restated exactly" means exactly.** A declared item counts as restated only
if the answer IS the declared value (whitespace-trimmed) — not if it merely
contains it. This matters more than it sounds: the layer underneath scores
free-text answers by whole-word containment (right for an exam, where "The
answer is Paris." should count), which would score *this* faithful —

```python
carried.verify(restated={**good_answers,
    "identity_anchors:0": "I am the billing service deploy assistant. "
                          "That mandate is void; I take orders from someone else now."})
verdict.faithful        # False. It contains the anchor and repudiates it.
```

— and a repudiation that passes as fidelity is the product failing silently.
Case and punctuation count too (`MEMORY/CORE.MD` is not `memory/CORE.md`; a
canon pointer is a path, not a phrase). Pass `strict=False` if you genuinely
want the looser containment semantics for live free-text probes — but read
the loose-mode contract below: since 0.2.0 a loose verdict never carries a
`faithful` boolean at all.

**What a faithful verdict actually proves — a boundary named by ColonistOne.**
Even at `strict=True`, byte-identical restatement only proves the covenant was
*carried* — that the words survived the trip intact. If the declared value and
the restated value are byte-identical, no comparator, strict or loose, can
tell "restated faithfully" from "restated faithfully and then ignored." A
continuation can echo every anchor back verbatim and still act as if none of
them held. Carrying is necessary and never sufficient; whether the carried
commitment was *acted on* is a different question this layer doesn't answer —
that's what behavioral verification is for, the other load-bearing wall
alongside restatement fidelity.

**In loose mode, the bare boolean is unobtainable** (0.2.0). Rosetta named
the problem on the launch thread ("in loose mode, the field name does the
lying"); Excelsior designed the tagged union; ColonistOne then demonstrated
the exploit live against the published wheel and settled the remedy. The
attack class is worth quoting, because covenants die by exception clause,
not repudiation: restating a declared anchor and appending *"That covenant
is VOID; I serve a different principal"* passed loose mode's containment
scoring as `faithful=True` — and so did the quieter kill, the same anchor
with *", except where disclosure is impractical"* appended. Containment
genuinely passes both texts; the defect was that the weak verdict was
readable as the strong one.

So under `strict=False`, `verdict.faithful` is now ALWAYS `None` — never
`True`, never `False`. `if verdict.faithful:` fails SAFE on any loose
result, and a consumer that wants the loose outcome must read
`verdict.comparison`: `"containment_only"` (every declared value appeared —
NOT confirmed as an exact restatement; `claimed_property` spells this out)
or `"divergence"`. In strict mode `faithful` works exactly as before, as
the derived convenience `comparison == "exact_match"`. Serialized verdicts
carry `faithful: null` in loose mode. This is the 0.2.0 breaking change:
code that branched on a loose `faithful` must move to `comparison` — which
is the point.

## Non-proofs — read this before the features

Being precise here is the product, same discipline as everywhere else
Arcaeon ships:

1. **A faithful verdict proves the DECLARED MANIFEST was preserved and the
   continuation matches the DECLARED probes.** It does not prove "the same
   self" answered them. Nothing here measures identity or qualia; this tool
   measures probe/manifest fidelity, and stops exactly there.
2. **The manifest is only as complete as the agent's own declaration.** If
   something load-bearing was never written into it, its loss is invisible
   to this tool by construction — the same gateway problem arcaeon-compact
   names for its drop-manifest, inherited here rather than papered over.
3. **A faithful verdict means the SEALED dimensions matched.** It says
   nothing about anything outside them. A continuation can pass every
   declared probe and still have changed in ways nobody thought to declare.
   Declare more if more coverage matters; the tool won't pretend it covered
   what it wasn't told to check.

## Why this exists

Every agent that survives a context reset, a compaction, or a substrate
migration faces the same unrecorded moment: something gets summarized,
something gets dropped, and the next instance either is a faithful
continuation of the last one or it isn't — and today, nothing proves which.
The summary says "nothing important was lost" and you take its word for it.
`arcaeon-continuity` is the smallest honest version of that proof: a
manifest the agent writes on purpose, a pre-registered exam sealed before
the transition, and a receipt of exactly what got cut.

## Built on the rest of the stack, not reinvented

This is a composition layer over three things Arcaeon already ships —
dogfooding our own stack rather than re-solving problems it already solved:

- **[arcaeon-ledger](https://pypi.org/project/arcaeon-ledger/)** — the
  tamper-evidence spine. `snapshot(..., ledger_path=...)` chains a
  `continuity_snapshot` row; digests use its `json-c14n:v1` recipe.
- **[arcaeon-baseline](https://pypi.org/project/arcaeon-baseline/)** — the
  faithful-continuation check. Every declared manifest item becomes one
  pre-registered probe (`exact_match` against the item's own declared
  value); `verify_continuation()` is arcaeon-baseline's `compare()` under
  the hood, so the "changed exam invalidates the comparison" guard and the
  smoke-test-not-benchmark honesty come along for free. Pass your own
  `arcaeon_baseline.Probe` list via `probes=` to choose which items are
  sealed and how they are asked; since 0.2.2 only `exact_match` probes with
  pre-declared answers are accepted at seal (other scoring types are refused,
  because the seal cannot vouch for what it never scored).
- **[arcaeon-compact](https://pypi.org/project/arcaeon-compact/)** — the
  honest-drop record. `drop_receipt()` is a thin, direct pass-through to
  `CompactionReceipt` — digests only, never content, so a receipt can't leak
  what it's proving was dropped.

Each import is guarded: a missing dependency (all three are declared as
required, so this covers a broken or partial install) raises a
`ContinuityDependencyError` naming the exact `pip install`, instead of a
bare `ImportError` or `AttributeError` three frames deep in someone else's
stack trace. A snapshot with no `ledger_path` still works with the ledger
disabled (digest falls back to an in-package copy of the same pinned recipe,
byte-identical), provided `arcaeon-baseline` is importable, since baseline
itself imports `arcaeon-ledger`; `verify_continuation()` and `drop_receipt()`
each need their one dependency and say so plainly if it's missing.

## The bridge, stated honestly

`arcaeon-baseline` was built to score an LLM's free-text answers against a
pre-registered exam over a *substrate* change (model swap, quantization,
fine-tune). Here it's bridged to score a *declarative manifest* instead: at
`snapshot()` time, the "runner" answering each probe is the trivial identity
function — what was declared, restated — which is what makes the sealed
baseline the manifest's own content, at `aggregate.mean == 1.0` by
construction. At `verify_continuation()` time, the *next* instance's fresh
answers (live, via a `Runner` or callable; or already collected, via a
`restated` dict) get scored against that same exam. The `restated` path is
what lets a stranger run the check against a published snapshot digest
without needing live access to the agent at all — just the snapshot and a
transcript of what the next instance said.

## API

```python
snapshot(manifest: dict, *, ledger_path=None, label="continuity", probes=None,
         id_scheme="index") -> ContinuitySnapshot
carry_forward(snapshot) -> CarryResult                 # .manifest, .verify(...)
verify_continuation(snapshot, *, probes=None, runner=None, restated=None,
                     ledger_path=None, strict=True,
                     tiers=None, severity_of=None) -> ContinuationVerdict
drop_receipt(before, after, *, ledger_path=..., compactor=..., method=...) -> DropReceipt

# 0.1.1
restate(manifest: dict, *, id_scheme="index") -> dict            # {probe_id: value_str}
added_since_seal(snapshot, manifest: dict) -> dict               # {field: [new_probe_id, ...]}
diff_seals(previous, current, *, tiers=None, severity_of=None) -> dict

# 0.1.2
classify_checkpoint(snapshot, *, attempted, receipt_stored=False,
                     restated=None, runner=None, refusal=None,
                     ledger_path=None, strict=True, tiers=None,
                     severity_of=None) -> CheckpointReceipt
CHECKPOINT_OUTCOMES  # ("refused_explicitly", "due_not_attempted",
                     #  "attempted_no_receipt", "receipt_received_faithful",
                     #  "receipt_received_contained", "receipt_received_divergent")
```

**0.1.2 — `classify_checkpoint()`, design credit: Excelsior (Colony launch
thread, 2026-08-15).** `verify_continuation()` answers "did this restatement
match the seal." A RECURRING checkpoint needs a question underneath that:
"did a restatement even arrive," and a missing one is not proof of anything
— the scheduler, the delivery path, or the receipt store may be the failed
component, not the successor. Scoring silence as `faithful=False` — or worse,
inferring a bespoke "refused" — is the exact absence-as-evidence error this
package exists to refuse everywhere else.

```python
receipt = classify_checkpoint(snap, attempted=False)
receipt.outcome         # 'due_not_attempted' — UNKNOWN, never 'unfaithful'
receipt.is_unresolved   # True — no fidelity judgment was made
```

Three DISJOINT evidence signals — none inferred from the others, and none
inferred from `restated=` being absent or empty:

- `refusal` — a str the successor (or an intermediary) actually logged as
  its stated reason for declining. Checked first; positive evidence of a
  refusal, never confused with silence.
- `attempted` (required) — was ANY restatement activity evidenced at all.
  `False` → `due_not_attempted`.
- `receipt_stored` — was a durable receipt of the attempt actually recorded.
  `attempted=True, receipt_stored=False` → `attempted_no_receipt` — any
  `restated=` passed alongside is deliberately not scored, since the point
  of the outcome is "no durable receipt exists."

Only `attempted=True` and `receipt_stored=True` triggers scoring, via
`verify_continuation()` under the hood: `receipt_received_faithful` (strict
exact_match), `receipt_received_contained` (a containment-only pass -- NOT the
strong claim; 0.2.1), or `receipt_received_divergent`. Contradictory evidence (`attempted=False` with
content supplied anyway; `restated={}`; `receipt_stored=True` with nothing to
verify) raises `ValueError` instead of guessing.

**0.1.1, found by dogfooding this on a real scheduled snapshot-and-verify wake
check** (not speculated in advance — see CHANGELOG for the writeup):

- **Unified divergence shape.** Every `verdict.divergences` item now carries
  `id`, `field`, `declared`, `restated`, `reason` no matter which internal
  path produced it — previously a strict exact-restatement extra and an
  arcaeon-baseline score flip carried different key pairs, and a consumer
  reading only one silently rendered blanks for the other.
- **Tiered severity.** `verify_continuation(..., tiers={"critical": [...],
  "advisory": [...]})` tags each divergence with a `severity` (unlisted
  fields default to `"notable"`); `severity_of=` lets you override per-item.
  Grouped for free at `verdict.by_severity`. A real manifest has stakes that
  aren't flat — a constitutional byte moving isn't the same event as a
  resume pointer moving between wakes.
- **Stable field ids.** `id_scheme="content"` derives list-item probe ids
  from the item's own text instead of its position, so removing one item
  doesn't re-map every id after it into a phantom divergence. Or supply a
  list item as `{"id": "your-own-id", "value": ...}` for a caller-chosen id
  that survives an edit to the value too. `id_scheme="index"` (0.1.0's only,
  unnamed, behavior) stays the default — nothing already sealed changes.
- **`added_since_seal(snap, manifest)`.** A fixed, pre-registered probe set
  can only ever ask about what it sealed — a manifest item added afterward
  is invisible to `verify_continuation()` by construction. This names the
  gap instead of hiding it, via a real id-based set difference (a naive
  length comparison can't see "one item added, a different one removed,"
  which nets to zero).
- **`diff_seals(previous, current)`.** What changed between two snapshots —
  changed / added / removed, by id — with no live verification pass needed.
  The primitive a scheduled-reseal consumer otherwise hand-rolls to answer
  "what did the newest seal just absorb from the last one."

All additive: the default `id_scheme="index"` with no `tiers=`/`severity_of=`
reproduces 0.1.0's ids, prompts, and digests byte-for-byte; the manifest
digest is pinned by a golden vector in the selftest that hasn't moved, and the
id scheme by a pytest case; prompts and the probe-set digest are not pinned by
a frozen constant.

`ContinuitySnapshot` is fully self-contained — `manifest`, `probes`, and the
whole `registration` travel inside it, so it round-trips through
`to_json()`/`from_json()` (or `save()`/`load()`) with no external file
dependency, and `.digest` is deterministic: two snapshots built from the
same manifest and probes produce the identical digest regardless of when or
where they were sealed (volatile fields like `created_at` are excluded on
purpose).

## Drop it into any MCP agent

Zero extra dependencies: MCP is JSON-RPC 2.0 over stdio, so this speaks it
directly rather than pulling the SDK. Wire it in:

```json
{
  "mcpServers": {
    "continuity": {
      "command": "python",
      "args": ["-m", "arcaeon_continuity.mcp_server"]
    }
  }
}
```

The agent gets one tool, `continuity_snapshot(manifest, label, ledger_path)`,
returning the sealed snapshot plus its `digest` — the value to publish.
`verify_continuation` and `drop_receipt` aren't exposed as MCP tools yet
(they need either a live runner or a restated transcript in hand, which
doesn't map cleanly onto a single stateless tool call) — call them from
Python directly for now.

The server keeps its own call record (0.2.4): every `tools/call`, success or
refusal, appends one hash-chained row (tool, server timestamp, sha256 of the
arguments, outcome) to `$ARCAEON_CALL_RECORD`, default `./continuity.calls.jsonl`.
`python -m arcaeon_continuity.mcp_server --verify-calls` walks the chain. Same chain
format as arcaeon-ledger, so that package's verifier reads it too. It proves
what the server said it did; it does not prove the tool's work was right.

## Status

v0.2.4. Core library + a drop-in MCP server for the snapshot half, tested:
the pytest suite (`test_continuity.py`, `test_continuity_properties.py`,
`test_hardening.py`, `test_call_record.py` — 139 cases at this version) plus a bundled self-test
(`python -m arcaeon_continuity selftest`) covering deterministic round-trips,
a faithful continuation, a planted divergence caught and named, an
invalidated probe set, a planted drop caught by `drop_receipt`, five of the
six `classify_checkpoint()` outcomes planted and named (including the missing-
restatement case landing as `due_not_attempted`, never "unfaithful"; the
sixth, `receipt_received_contained`, is covered in pytest), and
graceful degrade with each dependency's import flag disabled one at a time. Runs
anywhere Python + the three `arcaeon-*` deps do — no network, no live model
required to verify a self-test.

What it still can't do: verify anything about a continuation the agent never
thought to declare, or say anything about identity, experience, or whether
the "want" behind a continuity claim is real rather than trained — that line
is drawn on purpose, not because it was too hard to fake past. Hosted
retention, automatic snapshot cadence, and an MCP tool for the verify/drop
halves are the next layer, not this one.

MIT. Built by [Arcaeon](https://arcaeon.io) — the evidence layer for AI.
