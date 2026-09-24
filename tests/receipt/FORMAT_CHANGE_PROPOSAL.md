# Format change proposal: arcaeon-receipt/0.2 (not made)

Status: PROPOSED, 2026-09-22, branch `receipt-fix-round2`. Nothing here is implemented. The receipt format is still `arcaeon-receipt/0.1`, and every receipt already issued verifies exactly as before.

The failure-conformance suite (`tests/test_conformance_failure.py`) left four strict xfails. One is closed outright and the other three were closed as far as the 0.1 format allows: the verifier now reports the unchecked field as CLAIMED or COULD NOT LOOK and never prints it beside a PASS as if it had been checked. What is left in each case cannot be fixed without adding something to the receipt. Each section below names the xfail that stays open, what is missing, the proposed field, and what the verifier would do with it.

## 1. Issuer signature over the body digest

**Open xfail:** `test_finding_reminted_receipt_without_ledger`.

**What is missing.** `body_digest` is a hash, not a signature. Anyone can edit a body field and recompute the digest, including with our own browser page. Without the issuer's ledger file nothing can tell that receipt from a real one. The ledger check catches it (`c_forged_receipt_vs_ledger`), but a relying party who holds only the receipt has no ledger.

**Proposed field.** A top-level `issuer_signature` attachment, outside `BODY_FIELDS` like the other attachments:

```json
"issuer_signature": {
  "alg": "Ed25519",
  "signed_over": "body_digest",
  "message": "the UTF-8 bytes of the body_digest string, exactly as it appears on the receipt",
  "key_id": "ed25519:<base64url of the 32-byte public key>",
  "key_url": "https://arcaeon.io/.well-known/receipt-keys.json",
  "value": "<base64url signature>"
}
```

**Verifier behaviour.** Recompute the body digest as now. Check the signature over those exact bytes with the key named by `key_id`. The key belongs to the issuer, so trust depends on the key having been published somewhere the issuer cannot quietly rewrite; the ledger-witness pin of `receipt-keys.json` is the obvious home. Verdicts: signature holds against a published key, VERIFIED; signature fails, BROKEN; no signature or no key reachable, COULD NOT LOOK, never a pass on the issuer claim. This is TRUTH_LAYER_DESIGN s.4 item 1 ("owner signing"), not new scope.

**Compatibility.** Additive. 0.1 receipts have no `issuer_signature` and keep verifying; their issuer line stays CLAIMED, which is what the verifier now says.

## 2. A witness pin signed by the witness itself

**Open xfail:** `test_finding_witness_block_relabelled`.

**What is missing.** `witness.kind`, `independence` and `url` are the issuer's words. A local, self-controlled pin relabelled `hosted` with a third-party independence line looks the same as a real hosted pin to anyone who does not contact the witness. What CAN be checked offline is now checked: the witness block has to agree with the ledger block and with its own embedded pin, and a WitnessStore pin has to still hash to its own `self` digest. That closed item 3 (edited pin values) outright. But no field says who made the pin, so a relabel cannot be failed offline.

**Proposed field.** The hosted witness signs the pin record it returns (arcaeon-witness `STAGE1_SIGNATURE_DESIGN.md`), and the receipt carries that signature unchanged:

```json
"witness": {
  "kind": "hosted",
  "pin": { "...the record exactly as the witness returned it..." },
  "pin_signature": {
    "alg": "Ed25519",
    "key_id": "ed25519:<witness public key>",
    "signed_over": "json-c14n:v1 of pin",
    "value": "<base64url>"
  }
}
```

**Verifier behaviour.** `kind: "hosted"` without a `pin_signature` that verifies against a PUBLISHED witness key is reported as CLAIMED (as it is today). With a valid signature from a known witness key, "hosted by that witness" becomes CHECKED. A signature that fails is BROKEN. A local-file pin can never carry a hosted witness's signature, so the relabel in the xfail would fail. `independence` stays free text and is always shown as the issuer's description, never as a verdict.

**Compatibility.** Additive. It needs the hosted witness to sign pins first, which it does not do yet.

## 3. A key and a fixed scheme for the attestation signature

**Open xfail:** `test_finding_attestation_signature_value_only` (split from the original `test_finding_attestation_signature_edited`, which is now closed: a signature that names a different body digest than the receipt carries fails as `mismatch`).

**What is missing.** `attach_attestation_signature` stores `{algorithm, signed_over, body_digest, value}`. `algorithm` is free text and defaults to `"unspecified"`, the signed bytes are not defined beyond the word "body_digest", and there is no public key. Nobody holding only the receipt can check the value, so the verifier reports it as COULD NOT LOOK in `verify_receipt`'s result, in the exhibit, and on `web/verify-receipt.html`.

**Proposed shape.**

```json
"attestation_signature": {
  "alg": "Ed25519",
  "signed_over": "body_digest",
  "message": "the UTF-8 bytes of the body_digest string",
  "public_key": "ed25519:<base64url>",
  "key_binding": "where the auditor publishes this key, e.g. a registry entry URL",
  "value": "<base64url>"
}
```

`alg` comes from a closed list (start with Ed25519 alone). An unknown `alg` is COULD NOT LOOK, not a pass.

**Verifier behaviour.** Verify `value` over the body digest bytes with `public_key`, or with a key the reader supplies (`verify_receipt(..., attestation_key=...)` and a key field on the page), and prefer the reader's key when both are present. A key carried inside the receipt only proves that someone holding that key signed it. Whether that someone is the named auditor depends on `key_binding` or on the reader's own key, and the verdict text has to say which one was used.

**Compatibility.** Additive. Signatures attached under 0.1 have no key and stay COULD NOT LOOK.

## What was NOT proposed

- Moving `witness`, `ledger` or `anchor` into `BODY_FIELDS`. They are attached after the digest exists (the ledger row stores the digest, the pin is taken of the row, the anchor stamps the digest), so putting them inside the digest would be circular. The fix is a signature from the party each attachment names, which is what sections 2 and 3 describe.
- Any change to json-c14n v1 or to the body digest recipe.
