# SCITT-shaped receipts for the hosted witness (L3-05)

We do not claim RFC 9943 / RFC 9942 conformance until the scitt-cose vectors
pass. Until then this is "SCITT-shaped": the message shapes follow the RFCs as
we read them, but nothing outside this repo has checked our bytes yet.

Code: `arcaeon.remote.scitt` (COSE), `arcaeon.remote.merkle` (RFC 9162 tree),
`arcaeon.remote._cbor` (the CBOR subset). CLI: `arcaeon tally scitt-export`,
`arcaeon tally scitt-verify` (docs/VERBS.md, `tally`). Offline only: nothing
here opens a socket.

## What maps to what

| Ours | SCITT / COSE | Where |
|---|---|---|
| v2 pin statement (`tally_chain.pin_statement`), canonical JSON bytes | the Statement (the preimage) | not carried; its sha256 is the payload |
| sha256 of `statement_canonical(st)` | payload of the Signed Statement (RFC 9995 hash envelope) | COSE_Sign1 payload |
| SHA-256 | payload_hash_alg 258 = -16 | protected |
| `application/json` | preimage_content_type 259 | protected; content_type (3) is absent |
| the issuer key (Ed25519 seed, the `--key` file shape the envelope uses) | alg 1 = -8 (EdDSA) | protected |
| sha256 of the issuer's raw public key | kid 4 | protected |
| did:key of the issuer (or `--iss`) | CWT_Claims 15 → iss 1 | protected |
| the statement's `chain` | CWT_Claims 15 → sub 2 | protected |
| the witness's log as an RFC 9162 tree | vds 395 = 1 (RFC9162_SHA256) | receipt protected |
| tree size, leaf index, audit path | vdp 396 → -1: `[[tree-size, leaf-index, [path...]]]` | receipt unprotected |
| the tree root | the receipt's payload, detached (nil); the verifier recomputes it | Sig_structure only |
| the witness's key (`--ts-key`) | the Transparency Service's Ed25519 key, kid 4, CWT iss/sub | receipt protected |
| tree size and leaf index again | private-use label -65537 = `[tree-size, leaf-index]` | receipt protected (ours) |
| receipt attached | receipts 394 = `[receipt bytes]` | statement unprotected, so the issuer signature stands |

Both messages are tagged COSE_Sign1 (#6.18), signed over
`["Signature1", protected, h'', payload]`. Encoding is RFC 8949 core
deterministic (shortest heads, sorted map keys).

## Verdicts

`verify_receipt(statement, receipt, ts_pubkey, issuer_pubkey=, pin_statement=)`:

- BROKEN: the statement or receipt is not a tagged COSE_Sign1; the statement
  lacks CWT iss/sub or mixes 258 with content_type; the receipt has no vds or
  no inclusion proof; the proof computes no root for this statement; the
  receipt signature does not verify over the computed root (changed statement,
  path, size, index, or another TS key); the signed tree position disagrees
  with vdp; the issuer signature fails (when an issuer key is given); the
  payload is not the given pin statement's sha256.
- COULD NOT LOOK: no TS public key; a vds other than 1; an alg other than
  EdDSA; no Ed25519 backend.
- VERIFIED names what it did not check: the leaf preimage rule (below),
  consistency with any other root, that the TS key is really the witness's,
  and the issuer signature when no issuer key was given.

## Why the receipt signs its tree size (-65537)

RFC 9162's verification walk (section 2.1.3.2) uses the tree size only to
steer the walk, so one audit path can prove a leaf under several sizes: leaf
2's path gives the same root for every size from 5 to 8. The receipt signs
only the root, so the size in vdp is not authenticated.
`tests/test_merkle_rfc9162.py::test_tree_size_only_shapes_the_walk` pins
this. Our receipts also sign `[tree-size, leaf-index]` in a private-use
protected header. The verifier holds a receipt to it when it is present. When
it is absent (a foreign receipt), the verdict lists "the tree size" as not
checked.

## Open items

1. **Leaf preimage (UNVERIFIED, R01).** We take the Merkle leaf to be the
   Signed Statement's bytes as the issuer emitted them, i.e. the statement
   with receipts (394) removed from the unprotected header
   (`scitt.LEAF_PREIMAGE_RULE`). The alternatives are the bytes with the
   whole unprotected header emptied, or a hash of either. RFC 9943 section 7
   and RFC 9942 section 5 have not been read verbatim for this, and the
   scitt-cose vectors are the tiebreak.
2. **Inclusion-proof wrapping.** We write vdp -1 as a list of bare
   `[tree-size, leaf-index, path]` arrays, as R01 records it. We also read a
   proof wrapped as `bstr .cbor`, which is the other reading of the CDDL. The
   vectors settle which one is right.
3. **alg.** We use -8 (EdDSA). The newer fully-specified -19 (Ed25519) is not
   written or read yet.
4. **Empty path.** A one-leaf tree has an empty audit path. The CDDL says
   `[+ bstr]`, so the path must have at least one entry. We write and read
   the empty path anyway.
5. **No consistency proofs (-2)** and no SCRAPI endpoints. The hosted witness
   does not yet keep an RFC 9162 tree, so `--proof` is supplied by hand
   (`{"tree_size", "leaf_index", "path": [hex...], "root"?}`).

## Dependencies

None added. CBOR comes from a ~150-line module (`arcaeon.remote._cbor`) that
is checked against RFC 8949 Appendix A vectors and hostile-input refusals.
Signing uses the existing `[sign]` extra (cryptography, or PyNaCl), through
`arcaeon.prove.vet.receipts`. cbor2 and pycose are outside oracles in the
tests only. Each of those tests skips with a stated reason when its library
is not installed. Next step: the scitt-cose vectors in CI. Only after they
pass does the conformance sentence above change.
