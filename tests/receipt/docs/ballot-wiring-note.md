<!--
Cross-repo wiring note for the ballot receipt (K-015, BATCH_500 lane K).
DESIGN ONLY -- no JS mint is implemented by this note. Per section 8 rule 1
of memory/BATCH_500_2026-09-12.md this is a DECIDED question, not an open
one: this file records the decision and its consequences so the next K
worker who implements the mint doesn't re-derive it.
-->

# Ballot receipt: the language boundary

## The decision (not re-derived here)

Every deployed function we own runs on Vercel as Node. There is no Python
runtime in that deploy target, and there will not be one: no Python
microservice on Vercel, and no function shells out to `py`/`python` to
borrow the reference implementation at request time. So:

- The ballot receipt is **minted in JavaScript**, at the grading path
  (`projects/ascenvo_site/api/grade_board.js`), the moment a sim finishes
  and a graded ballot object exists.
- `arcaeon_receipt/ballot.py` (`ballot_receipt()`, `arcaeon_receipt/core.py`'s
  `build_receipt()`) stays the **reference implementation** -- the thing a
  JS body/digest is checked against, not the thing that runs in production
  for this path.
- A shared **canonicalization vector** is the parity test both legs must
  pass before the JS mint ships. This note names it; it does not add a new
  one.

Local tools stay Python: the CLI, the MCP wrappers, the pre-commit hook.
Only the deployed grading-path mint moves to JS.

## Which fields the JS mint must produce

`core.build_receipt()`'s body shape, field for field, is what the JS mint
has to reproduce exactly -- not a reshaped equivalent:

```
body = {
  receipt_version: RECEIPT_VERSION,
  kind: "ballot",
  issued_at: <ISO8601 string>,
  subject: { trainee, scenario, grader: grader || "(unspecified)" },
  checks: [{
    ballot: <the graded object verbatim, never reshaped>,
    ballot_digest: <sha256 hex of the canonical `ballot` object alone>,
    trainee, scenario, grader, timestamp,
  }],
  scope: SCOPE,   // K-005's wording, copied verbatim -- see below
  extra: {},
}
```

`SCOPE` is not re-derived in JS. It is copied byte-for-byte from
`arcaeon_receipt/ballot.py`'s `SCOPE` constant (K-005, ratified):

```
proves:         ["the score and the ballot are unaltered since the timestamp"]
does_not_prove: ["the score is correct", "the sim was not attempted before"]
method:         "sha256 digest of the canonical JSON ballot object (score, verdict, and
                 whatever fields the grading engine produced), bound to a stated
                 timestamp inside the receipt body; hash-chained in arcaeon-ledger,
                 one row per ballot."
```

A JS mint that paraphrases this sentence instead of copying it has silently
forked the receipt's defensibility from the wording Fable signed off on
(A2). If the wording ever needs to change, it changes in `ballot.py` first
and the JS copy is updated to match in the same commit -- never the other
way.

On top of the body, `build_receipt()` adds (after the digest is taken):

```
receipt.body_digest = <the digest below>
receipt.ledger = { path, namespace, rows, chain, algorithm: "truncated_sha256_128 hash chain (arcaeon-ledger)" }
receipt.witness = <pin status, or {status:"skipped"}>
receipt.anchor  = <OTS stamp status, or {status:"skipped"}>
```

## Which digest

`body_digest` is `sha256(canonical_json(body)).hexdigest()`, where
`canonical_json` is the **json-c14n v1** recipe already documented in
`tools/c14n_vectors.py` and implemented in Python by
`arcaeon_ledger.digest_json`:

```
json.dumps(value, sort_keys=True, separators=(",", ":"),
           ensure_ascii=False, allow_nan=False)
```

`JSON.stringify` in JS does **not** sort keys and is not a substitute. The
verify page (`web/verify-receipt.html`) already carries a hand-rolled JS
canonicalizer between its `C14N-START`/`C14N-END` markers (lines 352-611)
built for exactly this recipe, and `tools/c14n_vectors.py`'s vectors already
check that canonicalizer against the Python implementation via
`tests/test_verify_page_parity.py`. The grading-path mint reuses that same
canonicalizer function -- extracted to one shared module both
`verify-receipt.html` and `grade_board.js` import -- rather than a second
hand-rolled copy. Two independent JS implementations of the same digest,
with only one covered by the vector, is exactly the class of drift Rule 6
(section 8) forbids ("never introduces a second implementation of a digest
without a parity vector").

`ballot_digest` (the inner per-check digest of the `ballot` object alone,
before it's wrapped in `body`) uses the identical recipe on the `ballot`
value alone.

## How parity is tested

- `tools/c14n_vectors.py` already generates the vector set; a ballot-shaped
  vector was added at K-012.
- `tests/test_verify_page_parity.py` already checks both legs against every
  vector: the Python leg (`arcaeon_ledger.digest_json`) and the JS leg (the
  verify page's extracted canonicalizer, run under Node).
- `arcaeon-ledger/test_canonicalization_divergence.py` is the existing
  cross-repo convention for catching exactly this kind of drift between
  repos that must agree on one digest.
- When the grading-path mint is implemented, its canonicalizer is either
  (a) the literal same shared module the verify page imports (preferred --
  one implementation, zero drift surface), or (b) a distinct copy that is
  added as a **third leg** to `test_verify_page_parity.py`'s vector loop, so
  a drift between the grading-path copy and the verify-page copy fails a
  test instead of shipping silently. A JS mint with no vector coverage at
  all does not ship (Rule 6).
- Before the JS mint ships, run the existing vector suite plus whichever
  leg it adds; a red result there is a stop, not a thing to route around.

## What this note does NOT decide

Digest parity is the easy half. `build_receipt()` also does a
hash-chain ledger append (`Ledger.append`), a witness pin
(`_witness_pin`), and an optional OpenTimestamps anchor (`_ots_stamp`) --
none of which are pure functions of the body; they touch file-based chain
state and (for the witness pin) the hosted witness API. Replicating those
three steps from a Vercel Node function is a **separate design question**
from the digest, is not decided by this note, and is not implemented by
this cycle (K-015 is design-only). The likely shape -- the JS mint calls
out to the existing witness HTTP API (`arcaeon-witness`) for the pin/chain
step rather than reimplementing a hash chain inside `grade_board.js` -- is
named here only as the obvious next question, not as a ratified decision.
A worker picking this up next reports the open question rather than
choosing an answer alone.

## The stop lines (unchanged from section 8)

- No Python microservice on Vercel, ever, for this or any deployed function.
- No function shells out to `py`/`python` to borrow the reference
  implementation at request time.
- No second digest implementation ships without a parity vector covering it.
- `SCOPE`'s wording is copied verbatim, never re-derived, in either language.
