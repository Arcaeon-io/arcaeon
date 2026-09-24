# Changelog — arcaeon-compact

## 0.1.5 — 2026-09-01 — a hostile row gets a verdict, not a traceback

Sell-code audit. Three findings; none changes the verdict on an honest row,
and the golden vectors are untouched (selftest still `ALL CHECKS PASSED`).

1. **`verify_receipt` crashed on a malformed row.** A string or null count,
   a non-list `dropped.items`, an object or int inside the manifest, or a row
   that is not a JSON object at all raised `TypeError` / `AttributeError`
   from inside the arithmetic — reproduced seven ways. Why it matters: the
   function is meant to be swept over a ledger, and one planted row was
   enough to abort the sweep with no verdict for that row or any after it.
   A verifier that can be switched off by the thing it verifies is not a
   verifier. It now returns `ok=False, self_consistent=False` with a
   `malformed receipt row: ...` note, the same shape the unknown-schema path
   has always used. Also refuses JSON `true` as a count (Python subtracts it
   as 1; a byte total of `true` is not a number).
2. **`_well_formed` accepted `int()`-isms** (`0x1f`, `+1f`, ` 1f`, `1_f`) as
   a digest tail — disclosed in 0.1.3's changelog, fixed now with an explicit
   lowercase-hex allowlist. No digest recipe ever emits those shapes, so a
   "well-formed" verdict on them was a false one.
3. **README and docstring overclaimed out-of-ledger detection.** "An edited
   row is caught even when copied out of its ledger" — the `receipt_digest`
   covers only the deterministic core, so a backdated `ts` / `opened_at`
   passes `verify_receipt` outside the ledger (also disclosed in 0.1.3,
   unfixed). Reworded to say exactly what the core covers and that
   timestamps are ledger-attested only. The README's Status line also said
   v0.1.2 while the package shipped 0.1.4; it now tracks `__version__` and a
   test holds it there.

Not changed, on purpose: `open()` raises `UnicodeEncodeError` on a str with
a lone surrogate and `RecursionError` on pathologically nested dict content.
Both are loud failures before any receipt exists — nothing false is minted —
so they are reported here rather than papered over.

New tests: `test_hardening.py` (28). Full suite 56 (was 28).

## 0.1.4 — 2026-08-28 — a bounded verification now says it was bounded

`verify_receipt()` answered one question and was read as answering two. `ok`
means "nothing I looked at contradicted this row." It never meant "I looked at
all of it," and with no content supplied it looked at almost none of it — the
row's numbers were checked against each other and against nothing else.

Two ways that read as a clean bill of health when it was not:

1. **`ok=True` with `content="skipped"` and an EMPTY `notes` list.** Nothing was
   recomputed. Self-consistency proves the four numbers are mutually coherent;
   it cannot prove any one of them true. The empty notes list is what made this
   dangerous — it looks identical to a full verification that found nothing.
2. **A v1 row claiming an introduction.** v1 never recorded `introduced.bytes`,
   so `post.bytes` is only LOWER-bounded and `dropped.bytes` can be understated
   behind the claimed introduction by an arbitrary margin. A receipt that
   destroyed 30 bytes can claim it destroyed 1, re-seal its own
   `receipt_digest`, and return `ok=True`, `self_consistent=True`, `notes=[]`.
   That was already known (the HIGH-1 gap, noted in 0.1.3's source comments) —
   what was missing is that the verdict never mentioned it out loud.

**New field: `verified_scope`.** Additive; nothing existing changed shape.
Values borrow arcaeon-ledger's vocabulary so the two packages answer the
coverage question in the same words:

  - `"full"` — both contents supplied and reconciled; every claimed number was
    recomputed from content you hold.
  - `"bounded_pre_only"` / `"bounded_post_only"` — one side only, so the drop
    SET was never recomputed (that needs both sides).
  - `"bounded_no_content"` — self-consistency only.
  - any bounded value may carry a `"+v1_lower_bound"` suffix when the v1 gap is
    live for that row.

**A bounded scope also now emits a note**, so the silence is gone: the pass
still passes, and it says what it did not check.

**`ok` is unchanged and still a plain bool.** arcaeon-ledger returns `ok=None`
for a scan that did not cover everything, and by that standard every
no-content pass here should be falsy. Making that change would break every
existing `if result["ok"]:` in the wild, so it is deliberately NOT made here
and is left as an open question for a 0.2.0 that can announce it properly.
Until then, `verified_scope` carries the honest answer and the docstring tells
callers to read it.

## 0.1.3 — 2026-08-24 (H1: the published floor admitted a silently-broken tamper-evidence combination)

Adversarial audit of the PUBLISHED artifacts (HIGH). PyPI 0.1.2's metadata
declares `arcaeon-ledger>=0.5.1` — and under 0.5.1, a compactor label
carrying a U+2028-class character makes a sealed receipt silently
unreadable: sealed ok, verify_receipt ok=True, then ZERO rows read back
and the ledger chain reports the file bad. Attacker-influenceable data
(an external compactor identity string) could evict a receipt from the
audit trail on the floor version the package itself declared compatible.
The repo has known this since the 8/16 hypothesis pass and bumped the
floor to >=0.5.6 locally — the edit sat UNCOMMITTED and unpublished for
eight days. Default installs were always fine (pip resolves the latest
ledger); the exposure is pinned/constrained/air-gapped environments
trusting the declared floor — exactly where audit-trail products deploy.

This release commits and ships that floor. Also from the same audit,
disclosed for the next pass: version 0.1.2 existed as two different
artifacts (the published wheel and a locally rebuilt one with different
metadata — the stale dist/ has been deleted and any future metadata
change bumps the version); the README's "an edited row is caught even
out-of-ledger" overclaims (timestamps are ledger-attested only —
witnessed backdating passes out-of-ledger verify); `_well_formed`'s hex
check accepts int()-isms; one tautological sub-assert in the suite.


## 0.1.2 — 2026-08-15

Fix from the 2026-08-15 adversarial scrutiny pass
(`projects/online_business/SCRUTINY_COMPACT_2026-08-15.md` in the private monorepo).

- **Fixed (HIGH-1) — the content-free byte-understatement catch was void
  whenever an introduction was claimed.** v1 never recorded
  `introduced.bytes`, so a receipt claiming an introduction (every real
  `method="llm-summary"` summarizer, the primary advertised use case) left
  `post.bytes` only lower-bounded by `verify_receipt`'s self-consistency
  check — a receipt could claim it dropped 1 byte out of 500 (really 500)
  and still self-verify with zero content held. Reproduced from the report
  and now caught:
  ```
  liar (dropped.bytes=1, post.bytes inflated to 599):
  {'ok': False, 'self_consistent': False, ...,
   'notes': ['bytes do not reconcile: pre.bytes - dropped.bytes + '
             'introduced.bytes = 502, got post.bytes 599']}
  ```
  **Mechanics — schema v2:** `CompactionReceipt.seal()` now computes and
  records `introduced.bytes` (built from a size-by-digest lookup over the
  real post-content given to `record_kept()` — not a number a caller can
  hand-wave) and writes `schema: "arcaeon-compact:receipt:v2"`.
  `verify_receipt` asserts `post.bytes == pre.bytes - dropped.bytes +
  introduced.bytes` **exactly, unconditionally** for v2 rows (previously
  exact only when `introduced.count == 0`).

- **v1 compatibility, by design, not by accident.** `verify_receipt` reads
  both schemas. A receipt sealed before 0.1.2 (no `introduced.bytes`) still
  verifies — same digests, same counts, nothing stranded — but the result
  now says which rule applied: `out["schema"]` is `"v1"` or `"v2"`, and
  `out["understatement_check"]` is `"truncation-only"` (v1 — pinned only
  when nothing was introduced, the honest residual) or `"full"` (v2 —
  pinned always). A hand-built legacy v1 row still recomputes to the exact
  frozen 0.1.0 golden `receipt_digest` vector — proven in
  `arcaeon_compact/selftest.py`, not just asserted.

- **README updated** ("Verification, honestly scoped" + the anatomized
  receipt example) to state the v2 guarantee and the v1 residual plainly,
  including that self-consistency — v1 or v2 — still can't *prove* a claim
  without content; v2 narrows the forgeable range, it doesn't eliminate it.

- **New regression tests** (`test_compact.py`): `seal()` mints v2 with real
  `introduced.bytes`; the report's exact liar reproduction is caught under
  v2 with no content; a hand-built legacy v1 row still verifies labeled
  `truncation-only`; the v1 residual (understated `dropped.bytes` +
  inflated `post.bytes` behind an introduction) is documented as still
  passing v1 self-consistency, honestly, on purpose. `arcaeon_compact
  /selftest.py` gained a matching golden-vector split (v1 legacy digest,
  frozen forever + a new v2 digest) and a live HIGH-1 demonstration section.
  Full suite: 17/17 (`test_compact.py`, was 13), selftest `ALL CHECKS PASSED`.

- No change to LOW-1 (dict-shape crashes on `open()`) or LOW-2 (str/bytes
  digest collision) — both were explicitly deferred in the source audit to
  keep that pass minimal, and this pass's brief scoped to HIGH-1 only.

## 0.1.1 and earlier

Pre-CHANGELOG history. See git log and the 2026-08-15 audit for the
byte-arithmetic self-consistency additions and the README digest-privacy
wording pass that preceded this release.
