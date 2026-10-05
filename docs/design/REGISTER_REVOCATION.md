# Register of named operators: revocation rows (design + stub)

Status: a design and a reference stub (`arcaeon.prove.register`), not a
service. No server route, no published register, no network, no real keys.
One read-only CLI verb, `arcaeon register page` (L3-04), renders a register
as a static page with its verdict on top: [REGISTER.md](../REGISTER.md).
Tests: `tests/test_register_revocation.py`, `tests/test_register_page.py`.

The register of named operators (TE-41) holds, per member, the things a
reader checks a member's work against: its public key(s), its chain name and
its witness endpoints (pin cadence sits beside these in the full entry and is
not revoked; it is replaced). This document fixes the one part that has to be
right before the register is public: how a thing in it stops being good, and
how a verifier reads that.

It sits beside, and does not replace, the account binding rows in
[ACCOUNT_ID_API.md](../ACCOUNT_ID_API.md). Those bind an AGENT key to an
agent account under a human owner, signed by the arcaeon.io binding key. The
register names OPERATORS (the members a receiver or a marketplace checks
against), signed by the register operator key. Both use the same row scheme.

## The register

One append-only list of rows, oldest first, signed by the register operator
key. Each row names the previous row's digest in `prev`, so the whole
register is one hash-linked chain (not one chain per member: dropping a
member's revocation would otherwise leave every other member's chain intact).
Two events:

- `add`: a member now holds a thing (a key, a chain name, a witness endpoint).
- `revoke`: a member's thing stops being good, from a stated time, for a
  stated reason.

A row is never deleted and never edited. A change is a new row. A thing once
added is never added again, under that member or any other: a revoked key,
chain name or endpoint is not reissued, so its record cannot be reset by
re-adding it.

## The row

Kind `register.row`, v `1`. Every field but `sig` is signed; a field an
event does not use is null.

| field | add | revoke |
|---|---|---|
| `kind`, `v` | `register.row`, `1` | `register.row`, `1` |
| `event` | `add` | `revoke` |
| `member` | the member's account, `acct:NAME@arcaeon.io` | the same member the add named |
| `what` | `key` \| `chain` \| `witness_endpoint` | the same `what` the add named |
| `value` | the thing: an Ed25519 `did:key`, a chain name (one line, at most 128 chars), an `https://` endpoint | null: a revoke names the thing by digest |
| `digest` | `thing_digest(what, value)` = `sha256:json-c14n:v1:` digest of `{"what", "value"}` | the digest of the thing revoked |
| `at` | UTC `YYYY-MM-DDTHH:MM:SSZ`, when the row was written | when the revocation was written |
| `reason` | null | one of `key_compromise`, `retired`, `superseded`, `operator_request` |
| `compromised_since` | null | `key_compromise` only: UTC time at or before `at`; null for every other reason |
| `prev` | null on the register's first row, else the previous row's digest | the previous row's digest |
| `signer` | the register operator key (a `did:key`) | the same |
| `sig` | base64 Ed25519 over `PAE("application/vnd.arcaeon.register.row.v1+json", C)`, `C` the json-c14n v1 bytes of the signed fields | the same |

A revoke row in full:

```json
{"kind": "register.row", "v": 1, "event": "revoke",
 "member": "acct:operator-a@arcaeon.io", "what": "key", "value": null,
 "digest": "sha256:json-c14n:v1:<64 hex>",
 "at": "2026-10-15T12:00:00Z", "reason": "key_compromise",
 "compromised_since": "2026-10-08T12:00:00Z",
 "prev": "sha256:json-c14n:v1:<64 hex>",
 "signer": "did:key:z6Mk...register-operator", "sig": "base64..."}
```

**One scheme, reused.** Signing and chaining are account_id's helpers
(`fields_digest`, `sign_fields`, `verify_fields`): the same PAE + json-c14n
signing, the same "sig outside, every other field signed" rule, the same
digest for `prev`. The register has its own payload type, so an
`account.binding` signature can never pass as a register row, or the other
way round.

**The reason words are a fixed set.** Any other word is refused by the
writer and reads the register BROKEN in a reader (even when the operator's
key signed it). `key_compromise` is for a key only; a chain or an endpoint is
`retired`, `superseded` or `operator_request`.

## How a seal is read against a revocation

`reading_at(rows, member, digest, sealed_at, operator_keys=[...],
fetched_at=...)`: was this key (or chain, or endpoint) good for this member at
`sealed_at`, by this copy of the register?

| reason | sealed before the cut | sealed at or after the cut | the cut |
|---|---|---|---|
| `retired`, `superseded`, `operator_request` | VERIFIED, with the revocation shown beside it | BROKEN | `at` |
| `key_compromise` | VERIFIED, with the revocation shown beside it | BROKEN | `compromised_since`, which may be before `at` |

**Compromise is read from `compromised_since`, not from `at`.** A compromise
is found late: the key may have been in a thief's hands days before anyone
wrote the revoke row. So the revoke row states when the compromise is taken to
have started, and every seal from then on reads BROKEN, including seals dated
before the row was written. A retirement is a plan, not an accident: work
sealed before it stays VERIFIED, and the reader is shown the revocation
beside it.

**The boundary is inclusive.** A seal in the same second as the cut reads
BROKEN; one second before reads VERIFIED. A sub-second seal time inside the
cut's second is at or after the cut and reads BROKEN.

**Other answers.**

| case | word |
|---|---|
| the register itself does not check: a signature fails, a `prev` does not name the row before it, a row is dated before the one it follows, a row is out of the schema, a revoke names a thing never added, a thing is added twice or re-added after a revoke, a row is signed by a key you did not name | BROKEN, for the register itself (no member reading is given from a broken register) |
| the register names this thing under another member | BROKEN |
| no rows, no operator key named, no Ed25519 backend | COULD NOT LOOK |
| an unknown member | COULD NOT LOOK |
| an unknown key, chain or endpoint under a known member | COULD NOT LOOK |
| `sealed_at` before the thing was added | COULD NOT LOOK (the member did not hold it then) |
| `sealed_at` that is not a UTC time | COULD NOT LOOK |

The trusted operator key comes from the reader (`operator_keys`), never from
the rows themselves.

## A stale copy

A verifier reads whatever copy of the register it fetched. **A copy is as
fresh as its fetch; a revocation written after the fetch is not seen.**

- The reading carries `as_of` (the `fetched_at` the reader passed, or null)
  and every VERIFIED says "as of T" or "as of an unknown time".
- A copy that is a true prefix of the register (the newest rows missing)
  still checks: it is an older register, not a forged one. That is exactly
  the case a fetch time must be shown for.
- A copy with a row missing from the middle, or rows moved, does not check:
  `prev` breaks.
- Because a `key_compromise` revoke reaches back to `compromised_since`, a
  seal that read VERIFIED against an old copy can read BROKEN against a newer
  one. A receiver that keeps a VERIFIED should keep the `as_of` with it, and
  fetch again before relying on a seal near a member's possible compromise.
- The register head (`check_register(...)["head"]`, the last row's digest)
  is what to pin outside the operator's control. Two readers holding the
  same head hold the same register.

## Writer refusals (nothing is appended)

`add` and `revoke` raise `RegisterError` and leave the register as it was
when: the member is not an `acct:NAME@arcaeon.io` account; `what` is not one
of the three; a value is the wrong shape (a non-Ed25519 or over-long
`did:key`, a non-https endpoint, a chain name that is empty or not one line);
the reason is not one of the four; `compromised_since` is missing on
`key_compromise`, present on another reason, or after `at`; `key_compromise`
names a chain or endpoint; the revoke names a thing not added under that
member and `what`, or one already revoked; the thing was ever added before
(a revoked thing is never re-added); or the row is dated before the last row.
The writer runs the reader's own row rules, so a register the writer built
is one the reader accepts.

## What it cannot prove

- **A seal time is the signer's own word.** A thief holding a revoked key
  can write a `sealed_at` before the cut and get VERIFIED. Only an outside
  clock on the envelope (a witness pin, OpenTimestamps, Rekor) dated before
  the cut separates that from an honest seal. A `key_compromise` revocation
  with a seal that has no outside time should be read as doubtful even when
  the reading says VERIFIED.
- **`compromised_since` is a judgment, not a measurement.** It is the
  operator's (or member's) best estimate of when the compromise began. Set
  too late, it leaves stolen seals VERIFIED; nothing in the row can show it
  was set too late.
- **Freshness.** A copy cannot prove it is the newest. A missing tail (the
  newest revocations) is indistinguishable from an older honest copy until
  the head is compared with a pinned one.
- **The operator.** The rows are signed by the register operator key. Until
  the head is pinned outside the operator's control, the register is the
  operator's word, and an operator that refuses to write a revocation is not
  caught by the rows.
- **Who the member is.** The register says this member name held this key;
  not that the name is who it suggests, and not that the member behaves.

## Open questions for the lead

- A witness endpoint can be hijacked (a lapsed domain). Should
  `key_compromise` (or a separate `endpoint_compromise` with its own
  `compromised_since`) apply to endpoints, instead of keys only?
- Register operator key rotation is not designed: today every row's signer
  must be among the keys the reader names.
- Pin cadence and the rest of the TE-41 entry (SCITT statement form, the
  bound external identity) are not in this row; they belong to the full entry.
