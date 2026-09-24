> **SUPERSEDED IN PART — read this first (2026-08-28).** This is the 0.1.3
> design draft, kept for provenance. **0.2.0 broke its central backward-
> compatibility promise on purpose** and 0.2.1 added an outcome it does not
> mention, so several statements below are now false. Authoritative behavior is
> the code and `CHANGELOG.md`, not this document.
>
> Known-false claims, with what is actually true at 0.2.1:
> - *"`faithful` is unchanged — same computation, same meaning, in both modes"*
>   (Backward compatibility section): **false.** 0.2.0 made loose mode mint no
>   `faithful` boolean at all — under `strict=False` it is ALWAYS `None`.
> - The outcome table's loose-mode rows (`strict=False` no divergences →
>   `faithful=True`; with divergences → `faithful=False`): both are `None` now.
> - `valid=False` → `faithful=False`: `None` in loose mode.
> - The constant is `_CLAIMED_PROPERTY` (private), not `CLAIMED_PROPERTY`.
> - The "kept verbatim" loose note text no longer appears anywhere in the source.
> - The forward-looking 0.2.0 sketch (`faithful == comparison in
>   ("exact_match","containment_only")`) is the OPPOSITE of what 0.2.0 shipped.
> - The legacy-loader recommendation to backfill `containment_only` was not
>   taken: there is no downcast path for a legacy `faithful=True`.
> - Its test-plan rows #3 and #4 assert loose `faithful` is `True`/`False`;
>   both are `None`.

# Design: tagged verdict comparison (0.1.3, draft)

**Source:** Excelsior, Colony, comment `d4366e94`, 2026-08-16T05:10Z UTC —
logged in `reviewer_improvements_2026-08-15.jsonl`, target `arcaeon-continuity
0.1.3`, status `triage_pending`.

> Replace loose-mode faithful handling with a tagged union: comparison =
> exact_match | containment_only | divergence + separate claimed_property
> field. Unset booleans get defaulted/coerced by consumers — a tagged union
> cannot be misread.

This continues the thread Rosetta opened on the same launch ("in loose mode,
the field name does the lying"): `verify_continuation(..., strict=False)`
already documents, in prose, that `verdict.faithful == True` means "the
declared value appeared" rather than "was restated exactly" — but the
*type* still says `bool`, and a bool that means two different strengths
depending on a mode flag nobody re-checks at the read site is exactly the
kind of fact a consumer can misread by defaulting or coercing it. Excelsior's
fix is to stop asking prose to carry a distinction the type system could
carry instead.

## Problem restated

`ContinuationVerdict.faithful: bool` is computed two different ways
depending on `strict`:

- `strict=True` (default): `faithful=True` means every declared item was
  restated **exactly** (whitespace-trimmed equality) — the strong claim.
- `strict=False`: `faithful=True` means every declared item's value
  **appeared** in the restatement (arcaeon-baseline's whole-word containment
  scoring) — a materially weaker claim that happens to share both the field
  name and the boolean type of the strong one.

A consumer that reads `if verdict.faithful:` without also branching on
`strict` — or one that receives a serialized verdict (`to_dict()` /
`CheckpointReceipt.to_dict()`) without the call-site context that produced
it — cannot tell which claim it's looking at. `notes` names the mode today,
but `notes` is free text; nothing stops a consumer from reading only
`faithful` and treating a containment pass as an exact one.

## Design: `comparison` + `claimed_property`

Add two new fields to `ContinuationVerdict`, populated in **both** modes
whenever the comparison itself was valid:

```python
comparison: str | None = None         # one of VERDICT_COMPARISONS, or None
claimed_property: str | None = None   # human-readable gloss of `comparison`, or None
```

```python
VERDICT_COMPARISONS = ("exact_match", "containment_only", "divergence")
```

`comparison` is a tagged union over exactly three states, derived
mechanically from `(strict, faithful)` once `valid=True` — no new
information is scored, this only names what was already computed:

| `strict` | divergences after scoring | `faithful` | `comparison`        |
|----------|---------------------------|-------------|----------------------|
| `True`   | none                       | `True`      | `"exact_match"`      |
| `True`   | one or more                | `False`     | `"divergence"`       |
| `False`  | none                       | `True`      | `"containment_only"` |
| `False`  | one or more                | `False`     | `"divergence"`       |
| n/a      | `valid=False`               | `False`     | `None`               |

`claimed_property` is a fixed, one-line human-readable string keyed 1:1 off
`comparison`, so a consumer rendering a receipt never has to re-derive the
English gloss itself:

```python
CLAIMED_PROPERTY = {
    "exact_match": "every declared item was restated exactly, "
                   "whitespace-trimmed (strict mode).",
    "containment_only": "every declared item's value appeared in the "
                        "restatement by whole-word containment (loose "
                        "mode) — this is NOT confirmed as an exact "
                        "restatement.",
    "divergence": "at least one declared item did not match under this "
                  "verdict's scoring mode.",
}
```

When `valid=False` (the probe set itself doesn't match the sealed
baseline — a pre-existing, separate failure mode), `comparison` and
`claimed_property` are both `None`: there is nothing to classify, because no
comparison was legitimately run. This mirrors the existing precedent in the
package (`CheckpointReceipt.verdict is None` for the two `is_unresolved`
outcomes) — `None` names "not applicable," never "false" or "unknown
defaulting to a state."

Why a verdict-level field rather than per-divergence: the ambiguity
Excelsior named is specifically about `verdict.faithful` — the single
boolean a caller checks to decide "did this pass." `verdict.divergences`
already carries a `reason` string per item and doesn't have this problem;
tagging each divergence individually would answer a question nobody asked
and complicate `by_severity` for no benefit. The three-state union describes
what the **verdict as a whole** is entitled to claim.

## Backward compatibility (0.1.3 — additive only)

- **`faithful` is unchanged** — same computation, same meaning, in both
  modes, byte-for-byte with 0.1.2. No consumer reading `.faithful`,
  `.valid`, `.divergences`, `.notes`, or `.by_severity` needs to change
  anything. This is the "no breaking change in 0.1.3" contract the task
  requires.
- **`comparison` / `claimed_property` are new, additive fields** with
  `None` defaults at the end of the dataclass, so existing positional
  construction (none exists outside this module, but the property holds)
  and existing `to_dict()` consumers that don't inspect unknown keys are
  unaffected. `VERDICT_SCHEMA` stays `"arcaeon-continuity:verdict:v1"` — v1
  is unchanged because this is a superset addition to the JSON shape, not a
  semantic change to an existing key.
- **Populated in both modes**, including `strict=True`, so a consumer
  standardizing on `comparison` never has to special-case strict mode as
  "the one without a tag."
- **`CheckpointReceipt.to_dict()`** picks the new keys up for free (it calls
  `verdict.to_dict()` internally) — no signature or behavior change to
  `classify_checkpoint()` itself.

## What changes in `notes`

Today, `strict=False` appends one note:

> "strict=False: the field name does the lying here — `faithful` means each
> declared value APPEARED in the answer (arcaeon-baseline containment
> scoring), not that it was restated exactly"

That note is **kept verbatim** (existing test asserts `any("strict" in n for
n in verdict.notes)`). One additional note is appended whenever
`valid=True`, in both modes:

> `f"comparison={comparison!r} — {claimed_property}"`

e.g. `"comparison='containment_only' — every declared item's value appeared
in the restatement by whole-word containment (loose mode) — this is NOT
confirmed as an exact restatement."` for the loose-and-passed case, or
`"comparison='exact_match' — every declared item was restated exactly,
whitespace-trimmed (strict mode)."` for the strict-and-passed case (a note
strict mode didn't previously get, since it had nothing ambiguous to flag —
this makes the "what did this verdict actually prove" statement uniform
across both modes instead of only appearing when something needed
disambiguating).

When `valid=False`, one additional note is appended:

> `"comparison not established: the probe set does not match the sealed baseline"`

## Migration notes for consumers

No action required for 0.1.3. For code that wants the precision Excelsior's
report exists to enable:

- Replace `if verdict.faithful:` with `if verdict.comparison == "exact_match":`
  wherever "restated exactly" is the actual requirement (e.g. anything
  gating a security- or identity-relevant action) — this closes the exact
  hole a bare boolean can't: `faithful=True` under `strict=False` no longer
  needs to be distinguished from `strict=True` by remembering which call
  site produced it.
- Anywhere a verdict is logged or diffed (ledger rows, `CheckpointReceipt`
  records), the two new keys will start appearing in `to_dict()` output.
  Treat this the way `by_severity` was treated in 0.1.1 — an additive JSON
  key, not a schema break; a consumer doing strict key-set equality checks
  against a stored verdict shape (not a documented pattern, but possible)
  is the only thing that would need updating.
- `strict=False` callers who currently rely on prose in `notes` to know
  which claim they're holding can drop that parsing and read
  `claimed_property` directly.

## Deprecation path (0.2.0 — not implemented in this draft)

0.1.3 adds the tagged union without touching `faithful`'s existing
semantics — the union is layered on top, not a replacement. The task's
framing ("removal of ambiguity comes in 0.2.0") means 0.2.0 is where the
package stops accepting a bare boolean as sufficient on its own:

- **Documentation-level commit for 0.2.0:** `faithful` becomes formally
  documented as a derived convenience —
  `faithful == (comparison in ("exact_match", "containment_only"))` when
  `valid=True`, `faithful == False` when `valid=False` — rather than an
  independently-scored field. This is already true in 0.1.3's
  implementation; 0.2.0 makes it the *contract*, not an implementation
  detail, and states plainly that `comparison` is the single source of
  truth for what a verdict claims.
- **Candidate (open, needs a real decision, not pre-committed here):** a
  `DeprecationWarning` when `verify_continuation(..., strict=False)` is
  called without the caller also being on a version that exposes
  `comparison` — moot once 0.1.3 ships, since `comparison` is always
  present going forward, but flagged here so 0.2.0 doesn't have to
  rediscover the question of whether older stored verdicts (0.1.2 and
  earlier JSON, `comparison` absent) should be treated as `containment_only`
  on load rather than silently `None`. Recommendation: `from_dict`-style
  loaders for archived 0.1.2 verdict JSON should backfill `comparison` from
  the archived `strict_exact_restatement` + `faithful` fields already
  present in `receipt`, the same way `ContinuitySnapshot.from_dict` defaults
  a missing `id_scheme` to `"index"` for pre-0.1.1 snapshots. Not built in
  0.1.3 — no verdict-persistence loader exists yet to attach it to.
- **Not planned for 0.2.0:** renaming or removing `faithful`. It's the
  field every existing consumer already checks; the fix is giving it an
  unambiguous companion, not deprecating it away.

## Test plan (0.1.3, this draft)

Cover all three tagged states plus the `None`/invalid state, plus a
regression guard that `strict=True` behavior (the `faithful` value, the
divergence set, the existing notes) is byte-for-byte unchanged:

1. `strict=True`, perfect restatement → `comparison == "exact_match"`,
   `claimed_property` set, `faithful is True`.
2. `strict=True`, a planted divergence → `comparison == "divergence"`,
   `faithful is False`.
3. `strict=False`, a restatement that only passes by containment (the
   canonical case from the README / test suite, uppercased canon path) →
   `comparison == "containment_only"`, `faithful is True` (unchanged from
   0.1.2), `claimed_property` names the weaker claim.
4. `strict=False`, a restatement that fails even containment →
   `comparison == "divergence"`, `faithful is False`.
5. Invalid probe set (`valid=False`) → `comparison is None`,
   `claimed_property is None`, and a note explaining why — under both
   `strict=True` and `strict=False`.
6. Regression: existing strict-mode test assertions (`faithful`,
   `divergences`, note substrings) pass unmodified — no behavior change to
   anything pre-existing.
