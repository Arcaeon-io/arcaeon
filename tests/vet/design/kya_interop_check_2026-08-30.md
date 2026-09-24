# KYA-OS interop check — `mcp_vet/receipts.py` against the real spec + conformance vectors

_Design note, 2026-08-30. Board item D8. Verifies the conformance claims already
stated in the `receipts.py` module docstring (written same day) against the
actual published spec and its own machine-checkable test vectors — not just
read the spec and assert agreement, but round-trip real vectors through our code._

## What was fetchable

Search budget was dead going in, so this used `WebFetch` only, against the repo
named in `receipts.py`'s own docstring: `github.com/decentralized-identity/kya-os-mcp`
(the "KYA-OS" project; Checkpoint's blog names the draft "KYA-OS · draft-04").
Everything below was fetched **2026-08-30** from that repository at ref `main`:

| What | URL |
|---|---|
| Repo structure / README | `https://github.com/decentralized-identity/kya-os-mcp` |
| Full spec | `https://raw.githubusercontent.com/decentralized-identity/kya-os-mcp/main/SPEC.md` |
| Conformance dir listing | `https://github.com/decentralized-identity/kya-os-mcp/tree/main/conformance` |
| Vectors dir listing | `https://github.com/decentralized-identity/kya-os-mcp/tree/main/conformance/vectors` |
| Signed-proof test vectors | `https://raw.githubusercontent.com/decentralized-identity/kya-os-mcp/main/conformance/vectors/signed-proof.json` |

Not fetched: `conformance/verify.py` (the fetch tool's own summarizing model
declined to reproduce it in full, citing licensing — got a functional
description only, not usable for byte-level comparison, so nothing from it is
claimed here). The other vector files (`did-key-resolution.json`,
`did-web-resolution.json`, `card-proof.json`, `delegation-chain.json`,
`entity-card.json`, `negotiation.json`, `status-list.json`,
`audit-integrity.json`) were listed but not opened — out of scope for what
`receipts.py` implements (we sign one-shot grades, not sessions, cards,
delegation chains, or status lists), and budget went to the vectors that
actually exercise our code (canonicalization, hashing, did:key, EdDSA).

**Caveat on `WebFetch` fidelity:** the tool runs fetched HTML/markdown through a
small summarizing model before returning it, which is a real risk for anything
hex- or base64-shaped — a single transposed character in a summarized hash
would look identical to a correct one on the page. Two independent fetches of
`SPEC.md` asking for the Appendix C content (once loosely, once demanding
verbatim reproduction) returned byte-identical hex strings and did:key values,
which is *some* evidence against transcription drift, but the real check below
is stronger: every fetched value that matters was **independently recomputed or
verified in Python**, not trusted as transcribed. `signed-proof.json` in
particular was verified by actually running its bytes through our EdDSA
verifier, which would fail loudly on a single flipped base64 character — it
didn't.

## What the spec defines (SPEC.md, §4.3, §7.2–§7.6, Appendix C)

- **Claims** (§7.2/§7.4): `iss`, `sub`, `aud`, `nonce`, `ts`, `sessionId`,
  `requestHash`, `responseHash`, `scopeId`, `delegationRef`, `clientDid`,
  `outcome`, `reason`, `prf`, plus header-only `kid`/`alg`.
- **Envelope** (§7.5): a detached compact JWS
  (`BASE64URL(header).BASE64URL(payload).BASE64URL(signature)`) at
  `response._meta["org.kya-os/response-proof"]` (with `org.kya-os/proof` and
  bare `proof` accepted for back-compat).
- **Canonicalization** (§7.3, Appendix C.1): RFC 8785 (JCS) — sorted keys, no
  whitespace — before hashing.
- **Hash format**: `sha256:<64-char-lowercase-hex>`.
- **`did:key`** (§4.3, Appendix C.2): Ed25519 multicodec prefix `0xed01` +
  32-byte raw pubkey, base58btc-encoded, `z`-prefixed multibase.

This matches, claim-name-for-claim-name, what the `receipts.py` docstring
already asserted before this check ran. The check below is not "does the spec
say what we thought" (it does) — it's "does our code actually produce the
spec's bytes," which a docstring can't self-verify.

## Vectors round-tripped through our code — all PASS

### 1. Appendix C.1 — JCS canonicalization + SHA-256

Spec's worked example:

```
input:     {"method":"tools/call","params":{"name":"echo","arguments":{}}}
canonical: {"method":"tools/call","params":{"arguments":{},"name":"echo"}}
hash:      sha256:5057521f310b536837b619f0ac040ef8064f8c597da8ec22a56801b435744033
```

Ran through `mcp_vet.receipts._canonical()` and `.canonical_sha256()` on the
same input dict:

- canonical bytes: **exact match**, byte for byte
- hash: **exact match**

### 2. Appendix C.2 — `did:key` derivation

Spec's worked example: pubkey `8076ee2cfc1acdd3f8f4e38c665a0a3e6ad6e06dc05b4f6ec9c5b1ae7c81c9a2`
(hex) → `did:key:z6Mko6jQvza2BSKRcrbJwgwbL9KYDn1isCUV5Lnq7gSTTKJq`.

Ran through `mcp_vet.receipts.did_key()` on the raw 32-byte key: **exact match**.

### 3. `conformance/vectors/signed-proof.json`, vector `signed-proof/valid-basic`

This is a real, published, machine-checkable conformance vector — a full
detached compact JWS (`header.payload.signature`), an Ed25519 public key as a
JWK (`kty: OKP, crv: Ed25519, x: <base64url>`), and an expected verdict
(`pass`). This is the strongest check available without fetching key material
from the reference implementation's own test harness (which the spec's §C.3
JWS-structure example explicitly says has no worked signature — "implementers
should verify the structure and use the test key material from the reference
implementation's test suite for bit-exact validation." The `signed-proof.json`
vector *is* that test key material, one directory further in.)

Decoded the JWK `x` to raw bytes (32 bytes, correct for Ed25519), formed the
JWS signing input (`b64url(header) + "." + b64url(payload)`), and called our
own `receipts._verify_bytes(pubkey, signing_input, signature)` — the same
Ed25519-verify primitive `verify_receipt_detail()` uses internally, just fed a
JWS-shaped message instead of our own canonical-payload message (our envelope
doesn't produce compact JWS, so there's no higher-level function to call
as-is; this exercises the actual EdDSA math, which is the part that has to
agree for the two envelopes to ever be bridged).

Results:

- **Real JWS verifies**: `True`, using our `cryptography`-backed Ed25519
  verifier.
- **`signed-proof/tampered-signature` vector** (same payload, one flipped
  leading byte in the signature) correctly **fails** verification under the
  same code path — confirms the check isn't vacuously true.
- **`did_key()` on the JWK's raw pubkey bytes** reproduces the vector's own
  `did:key:z6Mkpd1rBMiyhdo3WrUSssDWa1f1VssuxDGcu6SpTamXJsex` exactly, and
  matches both `iss` and `sub` inside the decoded payload.
- Decoded payload claim names (`aud, iss, nonce, requestHash, responseHash,
  sessionId, sub, ts`) match the spec's §7.2 list and our own conformance
  claim exactly, `iss`/`sub` are `did:key` values (self-certifying, no
  resolution step) — same choice `receipts.py` makes.

## What this confirms and what it doesn't

**Confirmed, not just asserted:** the three primitives `receipts.py` claims
conformance on — JCS canonicalization, the `sha256:` hash format, and `did:key`
construction — produce byte-identical output to the spec's own worked examples
and its own conformance-vector public key. The Ed25519 verify path
(`cryptography` backend) correctly verifies a real signature minted by
(presumably) the reference implementation and correctly rejects a tampered
one. Nothing here was invented; every value quoted above came from the fetched
files and was independently recomputed, not just visually compared.

**Still true, unchanged by this check** — the five `DIVERGENCES` already listed
in `receipts.py` all stand: our envelope is a plain JSON object, not the
detached-compact-JWS-in-`_meta` shape (§7.5); we sign the canonical payload
alone, not the JWS signing input (`header + "." + payload`) — this check had
to *construct* that JWS-shaped input by hand to test against the vector,
because `sign_grade()`/`verify_receipt()` don't produce or consume it; we omit
`sessionId`/`scopeId`/`delegationRef`/`clientDid`; we don't publish a DID
document (trust-on-first-use only); and our extension claims
(`source_sha256`, `verdict`, `checks_run`, `tool_version`, `target`) aren't
KYA claim names. A receipt `sign_grade()` emits today will **not** verify
against a real KYA-OS verifier as-is — the envelope shape alone rules that
out. What this check adds is confidence that *if* the envelope were
reshaped to match §7.5, the cryptographic core underneath (JCS, SHA-256,
did:key, EdDSA) is already bit-for-bit compatible — that part was the
harder thing to get wrong silently, and it isn't wrong.

**UNVERIFIABLE, explicitly:** the `_meta.proof` MCP binding end-to-end (would
need a live KYA-OS server or the `examples/verify-proof` runnable, neither
fetched); `conformance/verify.py`'s exact reference-verifier logic (fetch
declined full reproduction); the other 8 vector files (out of scope for what
`receipts.py` signs); and whether `demo-mcp.kya-os.ai`'s live deployment
matches `main`'s `SPEC.md` (not queried — this was a spec/vector check, not a
live interop test).
