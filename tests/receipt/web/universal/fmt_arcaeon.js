/* universal/fmt_arcaeon.js: our own format, arcaeon-receipt/0.1.
 *
 * Nothing here decides anything verify-receipt.html also decides. Two blocks
 * of that page are loaded before this file, each copied out by
 * tools/extract_c14n.py and held byte-identical by
 * tests/test_universal_checker.py:
 *   universal/c14n_pinned.js       the json-c14n v1 canonicalizer
 *   universal/crosscheck_pinned.js checkWitness and checkAttestationSignature:
 *                                  the witness block against the ledger block,
 *                                  its own pin and the pin's self digest; the
 *                                  attestation signature against this body digest
 * Nobody edits either pinned file by hand; regenerate them.
 *
 * The verdict map mirrors verify-receipt.html's verifyOneText, and
 * tests/test_universal_checker.mjs runs both on every Arcaeon fixture (and on
 * a set of attachment edits made in memory) and requires agreement:
 * PASS -> VERIFIED, FAIL -> BROKEN, UNDETERMINED -> COULD NOT LOOK.
 * Attachments outside the body digest: an inconsistent witness block or a
 * signature over another digest is BROKEN; otherwise witness, ledger and anchor
 * are NOT LOOKED (claimed), and a signature value is COULD NOT LOOK, the same
 * words verify-receipt.html renders.
 */
"use strict";

// The cross-check block asks its page for this; verify-receipt.html has its
// own. Same digest, through core.js's WebCrypto helper.
async function sha256Hex(bytes) {
  return UC.hex(await UC.sha("SHA-256", bytes));
}

UC.ARCAEON_BODY_FIELDS = ["receipt_version", "kind", "issued_at", "subject", "checks", "scope", "extra"];

UC.verifyArcaeon = async function (text) {
  var F = "arcaeon-receipt";
  var root;
  try { root = parseC14NValue(text); }
  catch (e) { return UC.couldNotLook(F, "not readable JSON: " + e.message); }
  if (root.t !== "obj") { return UC.couldNotLook(F, "a receipt is a JSON object at the top level"); }
  var dup = UC.findDuplicateKey(text);
  if (dup !== null) {
    return UC.finish(F, [UC.claim("body digest", UC.BROKEN,
      "duplicate key " + JSON.stringify(dup) + ": the file reads differently to a first-wins and a last-wins parser", true)]);
  }

  var claimedNode = root.v.has("body_digest") ? root.v.get("body_digest") : null;
  var claimed = claimedNode && claimedNode.t === "str" ? claimedNode.v : null;

  var body = new Map();
  UC.ARCAEON_BODY_FIELDS.forEach(function (k) {
    body.set(k, root.v.has(k) ? root.v.get(k) : { t: "null", v: null });
  });
  var canonical;
  try { canonical = canonicalizeC14N({ t: "obj", v: body }); }
  catch (e2) {
    return UC.finish(F, [UC.claim("body digest", UC.COULD_NOT_LOOK,
      "could not canonicalize this receipt: " + e2.message, true)].concat(await UC.arcaeonAttachments(root, claimed, false)));
  }
  var computed = "sha256:json-c14n:v1:" + UC.hex(await UC.sha("SHA-256", UC.utf8(canonical)));
  var c;
  if (!claimed) { c = UC.claim("body digest", UC.BROKEN, "this receipt has no body_digest field", true); }
  else if (claimed === computed) { c = UC.claim("body digest", UC.VERIFIED, "the seven body fields hash to the digest on the receipt (json-c14n v1, SHA-256)", true); }
  else { c = UC.claim("body digest", UC.BROKEN, "body digest mismatch: a body field was altered after issue", true); }
  return UC.finish(F, [c].concat(await UC.arcaeonAttachments(root, claimed, true)), { computed: computed, claimed: claimed });
};

// Rows for what sits outside the body digest. `reached` is false when the body
// could not be read, so nothing after it was looked at (verify-receipt.html
// stops there too, as UNDETERMINED).
UC.arcaeonAttachments = async function (root, claimed, reached) {
  var rows = [];
  var ledger = getField(root, "ledger");
  rows.push(UC.claim("ledger sequence", UC.NOT_LOOKED, ledger === null ? "no ledger block on this receipt" :
    "CLAIMED: the ledger block is the issuer's statement, outside the body digest; this page was not given the ledger file"));

  if (!reached) {
    rows.push(UC.claim("witness block", UC.NOT_LOOKED, "not reached: the body could not be read"));
  } else {
    var w = await checkWitness(root);
    if (w.verdict === "inconsistent") {
      rows.push(UC.claim("witness block", UC.BROKEN, "BROKEN: this witness block contradicts the receipt it is attached to (" +
        w.problems.join("; ") + "). It was edited after issue, or it belongs to another receipt"));
    } else if (w.verdict === "claimed") {
      rows.push(UC.claim("witness block", UC.NOT_LOOKED, "CLAIMED, not checked: kind, independence, status and url are the issuer's " +
        "statement, and this page did not contact any witness; open verify-receipt.html for the link" +
        (w.pinSelf === "checked" ? ". What was checked: it agrees with the ledger block, and its pin still hashes to its own self digest" :
          w.pinSelf === "not_recomputed" ? ". Its pin's self digest was not recomputed here (a lone surrogate the browser cannot encode as Python does)" : "")));
    } else {
      rows.push(UC.claim("witness block", UC.NOT_LOOKED, "no witness block on this receipt"));
    }
  }

  var anchor = getField(root, "anchor");
  var status = anchor === null ? null : asString(getField(anchor, "status"));
  rows.push(UC.claim("Bitcoin anchor", UC.NOT_LOOKED, anchor === null ? "no anchor block on this receipt" :
    "CLAIMED" + (status ? " (status " + status + ")" : "") + ": needs the ots tool, which does not run in a browser"));

  if (getField(root, "attestation_signature") !== null) {
    if (!reached) {
      rows.push(UC.claim("attestation signature", UC.NOT_LOOKED, "not reached: the body could not be read"));
    } else {
      var s = checkAttestationSignature(root, claimed);
      if (s.verdict === "mismatch") {
        rows.push(UC.claim("attestation signature", UC.BROKEN, "this signature does not belong to this receipt: " + s.problems.join("; ")));
      } else {
        rows.push(UC.claim("attestation signature", UC.COULD_NOT_LOOK, "the value was not checked: the receipt carries no public key and " +
          "names no signature scheme this page can run. It sits outside the body digest; check it against the auditor's published key yourself"));
      }
    }
  }
  return rows;
};
