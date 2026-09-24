# Universal checker conformance set (failure first)

These are the cases `web/verify-any.html` is tested against, published so anyone can run them against this checker or their own. Most of them are things a checker must REFUSE. A checker that only ships happy paths cannot be told apart from one that always says yes; that is the lesson of the Sigstore peer study (`PEER_STUDY_SIGSTORE_2026-09.md`, s.6), where the high-impact failures were verifiers saying "verified" when they should have said no.

**Verdicts.** VERIFIED (every core check ran and passed), BROKEN (a check ran and failed, or the input is malformed for a format it was recognized as), COULD NOT LOOK (no recognized format, ambiguous, no key, no payload, or an algorithm a browser does not run). An unrecognized input is always COULD NOT LOOK, never BROKEN. Every result also reports the record axis, which is NEVER CHECKED for every receipt today: no check record is published for anything yet.

**How to use it.** `manifest.json` is the machine-readable list: for each case, the input file, whether to read it as bytes, any key / original file / detached payload / claimed format to supply, and the expected verdict and detected format. `node tests/test_universal_checker.mjs` runs all of it plus seven break arms (a detector that always says our own format, a checker that always says VERIFIED, a signature check that always passes, a receipt proof step that returns the claimed root, a proof reader that takes an integral float as a uint, a lenient base64 decoder, an Arcaeon cross-check that always calls the witness block and the attestation signature consistent), and a differential that requires the Arcaeon arm to give the same verdict as `web/verify-receipt.html` on every Arcaeon case; each arm must turn the suite red. Receipt cases also name a transparency service key (`receiptKeyFile`) and, for a receipt given on its own, the statement it claims to include (`statementFile`).

**Where the fixtures come from.** `tools/make_universal_fixtures.mjs`, which shares no code with the checker (its own JCS, CBOR and DER writers) and re-checks every signature with node:crypto before writing. Keys are published test keys: RFC 8032 s7.1 TEST 1 and TEST 2 (Ed25519; their public keys are also the Agent Receipts did:key vectors 1 and 2), and the RFC 7515 Appendix A.3 ES256 key. The one "wrong" P-256 key is random and only its public half is stored. The Arcaeon receipt was issued by the Python tool and is re-verified by the Python `verify_receipt` in `tests/test_universal_checker.py`. The Agent Receipts receipts are the spec's own s4.1 example, re-signed (the published example names did:agent, which cannot be resolved, and its proofValue is not a signature by any published key). The SCITT statements follow RFC 9943 s6.1's shape; the RFC's own example is elided (`h'a4012603...'`), so it cannot be used byte for byte.

**Specs read (live, 2026-09-22).**
- Agent Receipts v0.5.0: https://raw.githubusercontent.com/agent-receipts/obsigna/main/spec/v0.5.0/spec.md, schema https://raw.githubusercontent.com/agent-receipts/obsigna/main/spec/schema/agent-receipt.schema.json, did:key vectors https://raw.githubusercontent.com/agent-receipts/obsigna/main/spec/test-vectors/did-key/vectors.json
- SCITT: https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/ (published as RFC 9943), https://www.rfc-editor.org/rfc/rfc9943.html; COSE Hash Envelope https://datatracker.ietf.org/doc/draft-ietf-cose-hash-envelope/ (RFC 9995)
- SCITT Receipts: RFC 9942 https://www.rfc-editor.org/rfc/rfc9942.html (s4.3, s4.4, s5.1, s5.2, s5.2.1); Merkle tree RFC 9162 https://www.rfc-editor.org/rfc/rfc9162.html (s2.1.1, s2.1.2, s2.1.3); the entry rule from RFC 9943 s6.3; registries https://www.iana.org/assignments/cose/cose.xhtml (VDS: only 1, RFC9162_SHA256)
- RFC 8785 (JCS): https://www.rfc-editor.org/rfc/rfc8785.html
- Signet: https://github.com/Prismer-AI/signet, https://raw.githubusercontent.com/Prismer-AI/signet/main/docs/ARCHITECTURE.md, https://raw.githubusercontent.com/Prismer-AI/signet/main/docs/rfcs/0002-composite-receipt.md. No published schema for the co-signed (v3) record: the RFC is "Draft (discussion open, no implementation committed)" and says the signable bodies are rebuilt inside the signing code. So Signet is recognized and answered "could not look: no published schema", and nothing further was built for it.

**Two cases are not refusals, on purpose.** `arc_wrong_key`: an Arcaeon receipt carries no signature (its seal is the body digest), so a supplied key has nothing to be wrong against and is ignored. `arc_signature_value_unchecked`: an attestation signature that names this receipt's digest but whose value is forged; format 0.1 carries no key and no scheme, so the value is COULD NOT LOOK on its own row and cannot fail the run. Both are listed so the gap is visible rather than hidden.

**Attachments outside the body digest.** The witness block, the ledger block, the anchor and an attestation signature are not part of the body digest, so editing them leaves it matching. The `arc_witness_*`, `arc_ledger_edited_witnessed` and `arc_signature_mismatch` cases are refused by the cross-checks `web/verify-receipt.html` runs, which `web/verify-any.html` loads from the same bytes (`web/universal/crosscheck_pinned.js`, extracted by `tools/extract_c14n.py`). A witness block that does not contradict anything is still only the issuer's claim, NOT LOOKED.

**The padding-bits case.** `ar_tampered_signature_padding_bits` changes only the unused low bits of the last base64url character. A lenient decoder turns the edited text into the same signature bytes and says VERIFIED over a receipt whose text changed. This checker refuses non-zero leftover bits, and the `lenient-base64` break arm proves the case catches a decoder that does not.

### arcaeon-receipt

| case | input | also given | expected | why |
|---|---|---|---|---|
| `arc_valid` | arc_valid.json |  | VERIFIED | issued by the Python tool; the seven body fields hash to body_digest |
| `arc_tampered_payload` | arc_tampered_payload.json |  | BROKEN | a body field changed after issue |
| `arc_tampered_seal` | arc_tampered_seal.json |  | BROKEN | this format has no signature; its seal is body_digest, and one hex digit of it changed |
| `arc_missing_required` | arc_missing_required.json |  | BROKEN | body_digest removed (the required seal) |
| `arc_truncated` | arc_truncated.json |  | COULD NOT LOOK | half the bytes: no longer JSON, so no format is recognized |
| `arc_wrong_format_claimed` | arc_valid.json | format claimed: scitt | COULD NOT LOOK | the reader said SCITT; it reads as an Arcaeon receipt |
| `arc_duplicate_key` | arc_duplicate_key.json |  | BROKEN | a repeated key reads one way to a first-wins parser and another to a last-wins one |
| `arc_float_overflow` | arc_float_overflow.json |  | COULD NOT LOOK | json-c14n v1 cannot canonicalize a float that overflows; could not look, never a pass |
| `arc_wrong_key` | arc_valid.json | key: key_ed25519_test2.txt | VERIFIED | NOT APPLICABLE by construction: this format carries no signature, so a supplied key is ignored; listed so the gap is visible, not hidden |
| `arc_witness_inconsistent` | arc_witness_inconsistent.json |  | BROKEN | the body digest matches, but the witness block and its pin were edited to another ledger head, so they contradict the ledger block |
| `arc_witness_pin_self_mismatch` | arc_witness_pin_self_mismatch.json |  | BROKEN | one field of the witness pin edited; only its own self digest, recomputed with the Python recipe, sees it |
| `arc_ledger_edited_witnessed` | arc_ledger_edited_witnessed.json |  | BROKEN | the ledger claim edited on a witnessed receipt: the witness block taken of the same head now disagrees with it |
| `arc_signature_mismatch` | arc_signature_mismatch.json |  | BROKEN | an attestation signature that names another body digest does not belong to this receipt |
| `arc_signature_value_unchecked` | arc_signature_value_unchecked.json |  | VERIFIED | NOT APPLICABLE by construction: the signature names this digest and its value is forged, but the format carries no key or scheme, so the value is COULD NOT LOOK on its own row and the body still verifies; listed so the gap is visible, not hidden |

### agent-receipts

| case | input | also given | expected | why |
|---|---|---|---|---|
| `ar_valid_didkey` | ar_valid_didkey.json |  | VERIFIED | spec s4.1 example, signed with the RFC 8032 TEST 1 key, named by its did:key (vector 1) |
| `ar_valid_supplied_key` | ar_valid_didkey.json | key: key_ed25519_test1.txt | VERIFIED | the same receipt with the matching key supplied by the reader |
| `ar_spec_example_verbatim` | ar_spec_example_verbatim.json |  | COULD NOT LOOK | the spec example exactly as published: did:agent cannot be resolved in a browser, so the signature is not looked at |
| `ar_tampered_payload` | ar_tampered_payload.json |  | BROKEN | outcome.status changed from success to failure after signing |
| `ar_tampered_signature` | ar_tampered_signature.json |  | BROKEN | one bit of the signature flipped |
| `ar_tampered_signature_padding_bits` | ar_tampered_signature_padding_bits.json |  | BROKEN | only the unused low bits of the last base64url character changed (a lenient decoder yields the SAME signature bytes, so it would say VERIFIED over edited text) |
| `ar_missing_required` | ar_missing_required.json |  | BROKEN | proof.proofPurpose removed; the schema requires all five proof fields |
| `ar_missing_required_nullable` | ar_missing_required_nullable.json |  | BROKEN | chain.previous_receipt_hash removed; it is required even when null |
| `ar_wrong_key_named` | ar_wrong_key_named.json |  | BROKEN | signed by TEST 1 but names the TEST 2 did:key (vector 2) |
| `ar_wrong_key_supplied` | ar_valid_didkey.json | key: key_ed25519_test2.txt | BROKEN | the reader supplies the TEST 2 key for a TEST 1 signature |
| `ar_truncated` | ar_truncated.json |  | COULD NOT LOOK | 60% of the bytes: not JSON, so no format is recognized (never BROKEN) |
| `ar_wrong_format_claimed` | ar_valid_didkey.json | format claimed: scitt | COULD NOT LOOK | the reader said SCITT; it reads as an Agent Receipt |
| `ar_duplicate_key` | ar_duplicate_key.json |  | BROKEN | version given twice; I-JSON (RFC 8785 s3.1) forbids it |

### scitt

| case | input | also given | expected | why |
|---|---|---|---|---|
| `scitt_valid_es256_x5chain` | scitt_valid_es256_x5chain.cbor (bytes) |  | VERIFIED | RFC 9943 s6.1 shape (tag 18; alg ES256, content type, CWT iss+sub); key from the embedded x5chain leaf |
| `scitt_valid_hex_text` | scitt_valid_es256_x5chain.hex |  | VERIFIED | the same statement pasted as hex |
| `scitt_valid_base64_text` | scitt_valid_es256_x5chain.b64 |  | VERIFIED | the same statement pasted as base64 |
| `scitt_valid_supplied_jwk` | scitt_valid_es256_x5chain.cbor (bytes) | key: key_p256_rfc7515.jwk | VERIFIED | the RFC 7515 A.3 public key supplied as a JWK |
| `scitt_tampered_payload` | scitt_tampered_payload.cbor (bytes) |  | BROKEN | one bit of the embedded payload flipped |
| `scitt_tampered_signature` | scitt_tampered_signature.cbor (bytes) |  | BROKEN | one bit of the signature flipped |
| `scitt_missing_cwt_claims` | scitt_missing_cwt_claims.cbor (bytes) |  | BROKEN | validly signed, but no CWT Claims (label 15), which RFC 9943 requires |
| `scitt_missing_sub` | scitt_missing_sub.cbor (bytes) |  | BROKEN | validly signed, CWT Claims present, but no sub (label 2) |
| `scitt_wrong_key_supplied` | scitt_valid_es256_x5chain.cbor (bytes) | key: key_p256_wrong.jwk | BROKEN | the reader supplies a different P-256 key |
| `scitt_wrong_key_embedded` | scitt_wrong_key_embedded.cbor (bytes) |  | BROKEN | signed with the RFC 7515 key but carries a certificate for a different key |
| `scitt_truncated` | scitt_truncated.cbor (bytes) |  | BROKEN | half the bytes: the tag 18 prefix is recognized, and the CBOR runs out |
| `scitt_wrong_format_claimed` | scitt_valid_es256_x5chain.cbor (bytes) | format claimed: agent-receipts | COULD NOT LOOK | the reader said Agent Receipts; it reads as SCITT |
| `scitt_trailing_bytes` | scitt_trailing_bytes.cbor (bytes) |  | BROKEN | one extra byte after the COSE_Sign1 |
| `scitt_detached_with_payload` | scitt_detached.cbor (bytes) | detached payload: scitt_detached_payload.bin | VERIFIED | detached payload (nil, as in the RFC 9943 s6.1 example) with the payload supplied |
| `scitt_detached_without_payload` | scitt_detached.cbor (bytes) |  | COULD NOT LOOK | detached payload and none supplied: nothing to check the signature over |
| `scitt_detached_tampered_payload` | scitt_detached.cbor (bytes) | detached payload: scitt_detached_payload_tampered.bin | BROKEN | the supplied detached payload differs by one bit |
| `scitt_hash_envelope_with_preimage` | scitt_hash_envelope_eddsa.cbor (bytes) | key: key_ed25519_test1.txt; original: scitt_hash_preimage.txt | VERIFIED | RFC 9995 hash envelope, EdDSA, the preimage hashes to the signed payload |
| `scitt_hash_envelope_no_preimage` | scitt_hash_envelope_eddsa.cbor (bytes) | key: key_ed25519_test1.txt | VERIFIED | signature verifies; the payload digest row is NOT LOOKED because no preimage was given |
| `scitt_hash_envelope_tampered_preimage` | scitt_hash_envelope_eddsa.cbor (bytes) | key: key_ed25519_test1.txt; original: scitt_hash_preimage_tampered.txt | BROKEN | the supplied file differs by one bit from what was hashed |
| `scitt_hash_envelope_wrong_key` | scitt_hash_envelope_eddsa.cbor (bytes) | key: key_ed25519_test2.txt | BROKEN | the RFC 8032 TEST 2 key supplied for a TEST 1 signature |
| `scitt_hash_envelope_no_key` | scitt_hash_envelope_eddsa.cbor (bytes) |  | COULD NOT LOOK | no certificate in the statement and no key supplied |
| `scitt_hash_envelope_with_content_type` | scitt_hash_envelope_with_content_type.cbor (bytes) | key: key_ed25519_test1.txt | BROKEN | validly signed, but a hash envelope must not carry content type (RFC 9995) |
| `scitt_hash_envelope_short_payload` | scitt_hash_envelope_short_payload.cbor (bytes) | key: key_ed25519_test1.txt | BROKEN | validly signed, but the payload is 31 bytes where SHA-256 gives 32 |
| `scitt_unsupported_alg` | scitt_unsupported_alg.cbor (bytes) | key: key_p256_rfc7515.jwk | COULD NOT LOOK | alg -47 (ES256K) is not in WebCrypto; could not look, never BROKEN and never a pass |

### scitt receipts (RFC 9942, slice 2)

A SCITT Receipt is checked in two steps, as RFC 9942 s5.2.1 orders them: the inclusion proof is applied to the statement's own leaf to recompute the Merkle root (RFC 9162 s2.1.3.2), then the transparency service's signature is checked over that recomputed root with a key the reader supplies. The leaf is SHA-256(0x00 || entry), and the entry is the Signed Statement with its unprotected header replaced by an empty map (RFC 9943 s6.3). That entry rule is this checker's reading, stated here so it can be argued with: neither RFC 9942 nor RFC 9162 names the entry bytes for SCITT, and a service that logs something else will read as BROKEN here.

The receipts can arrive two ways: on their own (the reader also supplies the statement), or attached at label 394 of the statement they are about (a Transparent Statement, RFC 9943 s7). The detector calls a COSE_Sign1 a receipt only when it carries both markers RFC 9942 makes mandatory, vds (395) protected and vdp (396) unprotected; one without the other is COULD NOT LOOK, never a guess.

**Where these fixtures come from.** RFC 9942's receipt example (Figure 6) and RFC 9943's (Figures 8 to 11) are elided (`h'fc9f050f...221c92cb'`), so none can be rebuilt byte for byte. `tools/make_universal_fixtures.mjs` builds a seven-entry log (not a power of two, so the path is uneven) with the statement at index 5, computes the root and path from the RFC 9162 s2.1.1 and s2.1.3.1 recursive definitions, cross-checks the root with the s2.1.2 stack algorithm and re-walks the path by recursion, and checks every tree head signature with node:crypto. None of that code is shared with the checker, which slices the entry out of the bytes it is given where the generator encodes it from parts. The service key is P-256 with private scalar SHA-256("arcaeon universal fixtures: transparency service tree-head key"); its public half is `key_p256_transparency_service.jwk`.

**The claimed-root break arm.** RFC 9942 s4.4 names the failure: a signature verified over a payload the proof does not reach. The `claimed-root` arm swaps in a proof step that hands back the root the receipt carries instead of the one the path reaches. With a detached root it has nothing to hand back and crashes; with an attached root it turns `scitt_receipt_attached_root_tampered_path` and `scitt_receipt_attached_root_wrong_leaf` into VERIFIED. The suite requires that false yes to appear, so the arm is caught for the right reason.

| case | input | also given | expected | why |
|---|---|---|---|---|
| `scitt_receipt_valid` | scitt_receipt_valid.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | VERIFIED | RFC 9942 s5.2.1 shape (alg ES256, vds 1, vdp -1, detached root), tree size 7, leaf index 5; the root is recomputed from the statement's leaf and the service signature checks over it (detected: scitt-receipt) |
| `scitt_receipt_valid_attached_root` | scitt_receipt_attached_root.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | VERIFIED | the same receipt with the root attached (RFC 9942 s4.4 says SHOULD detach, so attached is allowed); the recomputed root equals it (detected: scitt-receipt) |
| `scitt_receipt_no_ts_key` | scitt_receipt_valid.cbor (bytes) | statement: scitt_receipt_statement.cbor | COULD NOT LOOK | no transparency service key: the root is recomputed, but whether the service signed it was not looked at (detected: scitt-receipt) |
| `scitt_receipt_no_statement` | scitt_receipt_valid.cbor (bytes) | service key: key_p256_transparency_service.jwk | COULD NOT LOOK | a receipt alone names no entry; without the statement there is no leaf to start the path from (detected: scitt-receipt) |
| `scitt_receipt_wrong_ts_key` | scitt_receipt_valid.cbor (bytes) | service key: key_p256_rfc7515.jwk; statement: scitt_receipt_statement.cbor | BROKEN | the reader supplies a different P-256 key (the issuer's) as the service key (detected: scitt-receipt) |
| `scitt_receipt_tampered_path` | scitt_receipt_tampered_path.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | BROKEN | one bit of the second path hash flipped; the genuine signature no longer covers the recomputed root (detected: scitt-receipt) |
| `scitt_receipt_attached_root_tampered_path` | scitt_receipt_attached_root_tampered_path.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | BROKEN | the same tampered path with the genuine root attached: the signature over the attached root is valid, so only recomputing the root catches it (detected: scitt-receipt) |
| `scitt_receipt_wrong_leaf_index` | scitt_receipt_wrong_leaf_index.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | BROKEN | leaf index 5 changed to 4: the path is applied at the wrong leaf position (detected: scitt-receipt) |
| `scitt_receipt_attached_root_wrong_leaf` | scitt_receipt_attached_root.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_valid_es256_x5chain.cbor | BROKEN | root attached, statement swapped: the leaf is another statement's, so the recomputed root is not the attached one (hash equality fails before any signature) (detected: scitt-receipt) |
| `scitt_receipt_other_statement` | scitt_receipt_valid.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_valid_es256_x5chain.cbor | BROKEN | a genuine receipt checked against a different, validly signed statement: real evidence, about something else (detected: scitt-receipt) |
| `scitt_receipt_truncated_proof` | scitt_receipt_truncated_proof.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | BROKEN | last path hash dropped: RFC 9162 s2.1.3.2 ends with sn not 0, so the proof fails on its own shape (detected: scitt-receipt) |
| `scitt_receipt_truncated_proof_no_key` | scitt_receipt_truncated_proof.cbor (bytes) |  | BROKEN | the same short path with no statement and no key: a proof that does not fit its own tree is BROKEN before anything else is needed (detected: scitt-receipt) |
| `scitt_receipt_extra_path_hash` | scitt_receipt_extra_path_hash.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | BROKEN | one hash too many: sn reaches 0 with path left over (RFC 9162 s2.1.3.2 step 4a) (detected: scitt-receipt) |
| `scitt_receipt_index_past_size` | scitt_receipt_index_past_size.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | BROKEN | leaf index equals tree size (RFC 9942 s5.2: fail the proof verification) (detected: scitt-receipt) |
| `scitt_receipt_float_tree_size` | scitt_receipt_float_tree_size.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | BROKEN | tree size is the float 7.5; RFC 9942 s5.2 says uint (detected: scitt-receipt) |
| `scitt_receipt_float_tree_size_integral` | scitt_receipt_float_tree_size_integral.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | BROKEN | tree size is the float 7.0 (fb 40 1c 00..): the same number, but major type 7, not a uint (RFC 9942 s5.2) (detected: scitt-receipt) |
| `scitt_receipt_float_leaf_index` | scitt_receipt_float_leaf_index.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | BROKEN | leaf index is the float 5.0; RFC 9942 s5.2 says uint (detected: scitt-receipt) |
| `scitt_receipt_short_path_hash` | scitt_receipt_short_path_hash.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | BROKEN | a path hash of 31 bytes where SHA-256 gives 32 (detected: scitt-receipt) |
| `scitt_receipt_truncated` | scitt_receipt_truncated.cbor (bytes) |  | BROKEN | half the receipt's bytes: tag 18 is seen but the headers cannot be read, so the detector cannot call it a receipt; the statement checker reports the CBOR running out (detected: scitt) |
| `scitt_receipt_unsupported_vds` | scitt_receipt_unsupported_vds.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | COULD NOT LOOK | vds 2 (the CCF ledger profile, an Internet-Draft, not in the IANA registry): could not look, never read as RFC 9162 (detected: scitt-receipt) |
| `scitt_receipt_consistency_only` | scitt_receipt_consistency_only.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | COULD NOT LOOK | only a consistency proof (-2); this page checks inclusion, not consistency (detected: scitt-receipt) |
| `scitt_receipt_two_inclusion_proofs` | scitt_receipt_two_inclusion_proofs.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | COULD NOT LOOK | two inclusion proofs under one signature; this page checks receipts with exactly one (detected: scitt-receipt) |
| `scitt_receipt_unsupported_alg` | scitt_receipt_unsupported_alg.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | COULD NOT LOOK | tree head signed with alg -47 (ES256K), which WebCrypto does not run (detected: scitt-receipt) |
| `scitt_receipt_missing_alg` | scitt_receipt_missing_alg.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | BROKEN | no alg (label 1), which RFC 9942 s5.2.1 makes REQUIRED (detected: scitt-receipt) |
| `scitt_receipt_vds_without_vdp` | scitt_receipt_vds_without_vdp.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor | COULD NOT LOOK | vds (395) but no proofs (396): one receipt marker without the other, so the detector calls it neither a receipt nor a statement (detected: none) |
| `scitt_receipt_wrong_format_claimed` | scitt_receipt_valid.cbor (bytes) | service key: key_p256_transparency_service.jwk; statement: scitt_receipt_statement.cbor; format claimed: scitt | COULD NOT LOOK | the reader said Signed Statement; it reads as a receipt (detected: scitt-receipt) |
| `scitt_receipt_bare_statement_claimed` | scitt_receipt_statement.cbor (bytes) | format claimed: scitt-receipt | COULD NOT LOOK | a bare Signed Statement the reader called a receipt: it carries no vds or vdp, so it is not one (detected: scitt) |
| `scitt_transparent_valid` | scitt_transparent_valid.cbor (bytes) | service key: key_p256_transparency_service.jwk | VERIFIED | RFC 9943 s7 Transparent Statement: the issuer signature (x5chain leaf) and the attached receipt both check; the entry drops the 394 header it now carries (detected: scitt) |
| `scitt_transparent_no_ts_key` | scitt_transparent_valid.cbor (bytes) |  | COULD NOT LOOK | the issuer signature checks, but with no service key the transparency it claims was not looked at (detected: scitt) |
| `scitt_transparent_wrong_ts_key` | scitt_transparent_valid.cbor (bytes) | service key: key_p256_rfc7515.jwk | BROKEN | the wrong service key for its only receipt (detected: scitt) |
| `scitt_transparent_tampered_receipt` | scitt_transparent_tampered_receipt.cbor (bytes) | service key: key_p256_transparency_service.jwk | BROKEN | the attached receipt keeps its genuine signature, but one bit of its third path hash was flipped (detected: scitt) |
| `scitt_transparent_two_receipts_one_ours` | scitt_transparent_two_receipts.cbor (bytes) | service key: key_p256_transparency_service.jwk | VERIFIED | two receipts from two services; the second verifies under the supplied key (RFC 9943 s7.1: a Relying Party MAY verify a single acceptable receipt), the first is shown and not counted (detected: scitt) |

### other

| case | input | also given | expected | why |
|---|---|---|---|---|
| `none_json_object` | none_json_object.json |  | COULD NOT LOOK | valid JSON with none of the markers |
| `none_plain_text` | none_plain_text.txt |  | COULD NOT LOOK | plain text |
| `none_empty` | none_empty.txt |  | COULD NOT LOOK | empty input |
| `none_random_bytes` | none_random_bytes.bin (bytes) |  | COULD NOT LOOK | binary that is not tag 18 |
| `none_untagged_cose` | none_untagged_cose.cbor (bytes) |  | COULD NOT LOOK | a COSE_Sign1 array without tag 18: RFC 9943 requires the tag, so the page does not guess |
| `none_ambiguous_markers` | none_ambiguous_markers.json |  | COULD NOT LOOK | carries both the Arcaeon and the Agent Receipts markers; the page will not pick one |
| `signet_v1_shape` | signet_v1_shape.json |  | COULD NOT LOOK | recognized as Signet; could not look: no published schema |
