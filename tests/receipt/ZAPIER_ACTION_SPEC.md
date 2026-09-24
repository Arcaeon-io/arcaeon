# Zapier Action: "Mint a Receipt" (SPEC, NOT BUILT)

Spec for L-021 (BATCH_500 lane L, `memory/BATCH_500_2026-09-12.md` line 391),
the #2-ranked idea in `memory/RESEARCH_overlooked_bindings_2026-09-12.md`:
"Zapier as a distribution action (`emit a receipt as a Zap step`)." Reader:
Daniel/Fable, **before** committing any developer-platform effort. This
document describes an action that does not exist. Nothing in it is wired,
deployed, or reachable from any Zap today.

## Status, stated up front

- **Not implemented.** No code in this repo or any other backs this action.
- **Not reachable.** The claude.ai Zapier connector attached to this session
  is session-only with zero code usage (`RESEARCH_overlooked_bindings`'s own
  audit, table row 1) — it lets a chat session call Zapier, not the reverse.
  A real Zapier *Action* (the thing a Zap author picks from a dropdown of
  "Arcaeon" steps) requires Zapier's own developer platform (the Zapier CLI,
  a hosted integration, Zapier's own review), which is separate infrastructure
  from these connector tools and does not exist yet either.
- **Blocked on a component this repo's own spec already says is unbuilt.**
  `docs/VENDOR_PACKAGE_SPEC.md` §2.4 states plainly: "DOES NOT EXIST YET: any
  ballot issuing endpoint, in any language," and its §6 limit 5 names the
  issuing API as the one of five components that is unbuilt, with "the four
  that exist are command-line tools." The only HTTP surface anywhere in this
  repo today is the outbound hosted-witness pin call in `core.py`'s
  `_witness_pin()` (`POST {ARCAEON_WITNESS_URL}/api/pin` with a bearer key) —
  a working pattern to copy, not an issuing endpoint a Zap could call. This
  spec describes a Zapier Action that would sit in front of an issuing API;
  it does not design that API, and it cannot ship before that API exists.

## What the action would do

A single Zap step, "Mint a receipt," addable to any of Zapier's connected
apps as a workflow action (per the research file: forms, CRMs, e-sign tools
buyers already run Zaps against). It would take a `kind` and a `subject` and
return the same receipt object `arcaeon_receipt.core.build_receipt()`
already returns today when called from Python — body, digest, ledger row,
witness pin, OpenTimestamps anchor — reusing the existing library, not a
sixth receipt-minting implementation.

## Inputs (proposed Zap action fields)

| field | type | required | notes |
|---|---|---|---|
| `kind` | enum | yes | one of the five existing adapters — `cite`, `call`, `approval`, `authorship`, `ballot`. No new kind; the action is a front door onto adapters that already exist, not a sixth one. |
| `subject` | object | yes | shaped per the chosen `kind`'s own adapter (e.g. a ballot's `{trainee, scenario, score, ...}`, a citation batch's `{brief_text}`). Shape is `kind`-dependent and validated by that adapter, not invented at the Zap layer. |
| `checks` | array | adapter-dependent | some adapters derive `checks` internally from `subject` (e.g. `cite_batch`); others require them supplied. Field-by-field mapping is undecided and is design work for whoever builds this, not this spec. |
| `namespace` | string | yes | the ledger namespace the receipt's row is appended to — ties the mint to one vendor's chain, mirroring how `ballot --namespace` already works from the CLI. |
| `witness` | boolean | no, default `true` | passed straight to `build_receipt(..., witness=)`. |
| `anchor` | boolean | no, default `true` | passed straight to `build_receipt(..., anchor=)`. |

## Output

On success: the full receipt object, unchanged from what `build_receipt()`
returns today (`receipt_version`, `kind`, `issued_at`, `subject`, `checks`,
`scope`, `body_digest`, `ledger`, `witness`, `anchor`) — the Zap step hands
this downstream to whatever app the buyer chained after it (store it, email
it, attach it to a CRM record). No new receipt shape, no summarized or
Zapier-specific subset of the fields.

On failure: a typed error naming which of the checks below refused the
request. Never a partial receipt and never a receipt-shaped object standing
in for a failure.

## The receipt type it mints

Not a new receipt type. `kind` selects one of the four adapters (or ballot,
the fifth) already shipped in `arcaeon_receipt/`, and that adapter's own
`SCOPE` dict — its `proves`/`does_not_prove` wording — rides into the receipt
verbatim, exactly as it does when the same adapter is called from the CLI or
from another Python caller. This action never authors its own scope wording;
scope is locked per adapter, not per integration surface. A Zap step that
invented looser scope wording than the adapter's own CLI path would be the
exact loophole `core.build_receipt()`'s mandatory scope check exists to
close, and this design routes through that same function rather than around
it.

## Auth model (proposed, undecided in code)

- Zapier's developer platform requires each Action to authenticate against
  the vendor's own API (API key or OAuth) before Zapier will let a user add
  it to a Zap. Proposed: an API key issued per vendor/namespace, sent as a
  bearer token — the same shape `_witness_pin()` already uses for the hosted
  witness call (`ARCAEON_WITNESS_URL` + a bearer key), so this would be a
  second consumer of an auth pattern that already exists rather than a new
  one.
- No receipt mints anonymously. The key identifies which namespace the
  ledger row is allowed to append to; a key scoped to one vendor's namespace
  must not be able to mint into another vendor's chain. This is a fencing
  requirement on the (not-yet-built) issuing API, not something this Zap
  layer can enforce on its own.
- Key issuance, rotation, and revocation are out of scope for this document
  entirely — they are the issuing API's problem once it exists.

## Error handling

- **Malformed `subject`/`checks` for the given `kind` refuses the WHOLE
  request**, never a partial mint — the same cap-or-refuse discipline
  `cite_batch.py` and `verify --batch` already use elsewhere in this repo:
  refuse loudly and name what's wrong, never silently drop or truncate.
- **Missing `kind`, `subject`, or `namespace`** is a 400-equivalent naming
  the missing field, before any ledger or network call is attempted.
- **`build_receipt()`'s own `ValueError`** (a scope missing `proves` or
  `does_not_prove` — should not be reachable through this action since scope
  is adapter-owned, not caller-supplied, but the underlying function still
  guards it) surfaces to the Zap as a typed failure, never swallowed into an
  apparent success.
- **A witness-pin failure is not a mint failure.** `core.py`'s existing rule
  is that an unreachable witness degrades the receipt to `witness: {status:
  "pin_failed", reason: ...}` rather than blocking the mint — the receipt
  still exists, unwitnessed. Whether this Zap action should report that case
  as a Zap-step success (with a warning field) or a failure is an open
  design question this spec does not decide.
- **A ledger-append failure DOES block the mint.** `build_receipt()` has no
  receipt without a ledger row; a ledger write failure must fail the whole
  Zap step, not return a body-only object with no chain behind it.

## The honest limit: a Zap failure reads as our failure

Stated verbatim from the research this spec is built on
(`memory/RESEARCH_overlooked_bindings_2026-09-12.md`, idea #2): "Zapier
take-rate and their own reliability sit between us and the receipt; a Zap
failure looks like our failure to the buyer." Concretely: if Zapier's
platform is degraded, rate-limits the vendor's Zap, silently drops a step
mid-workflow, or a buyer misconfigures their own Zap, the visible symptom to
that buyer is "the receipt didn't mint" — and they have no way to tell
Zapier's infrastructure apart from Arcaeon's. This repo's own scope block
(`proves`/`does_not_prove` on every receipt) disclaims what a receipt does
not prove about its subject; it cannot disclaim a delivery failure in
somebody else's platform sitting between the buyer's click and our own API.
Any customer-facing description of this action should say so plainly rather
than let a Zap failure read as a receipt-integrity failure.

## What this spec does not do

- Does not build the issuing API. Every field and behavior above is written
  contingent on that component existing first (`VENDOR_PACKAGE_SPEC.md`
  §2.4, still DOES NOT EXIST YET as of this writing).
- Does not commit to Zapier developer-platform effort. Per L-021's own
  instruction, this document exists so Daniel/Fable can decide whether that
  effort is worth committing to, not to start it.
- Does not propose a price. Pricing authority sits with Fable's Monday
  pricing call per standing canon; nothing here assumes free, metered, or
  paid.
- Does not design the MCP-vs-HTTP question, the per-vendor API key issuance
  mechanism, or how `checks` gets populated per adapter when the caller is a
  Zap step rather than Python code. All three are named as open rather than
  answered.

## Reader

Daniel/Fable, before any Zapier developer-platform effort is committed.
