/* universal/fmt_scitt.js: SCITT Signed Statements (COSE_Sign1).
 *
 * Read from the live specs, 2026-09-22:
 *   https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
 *     (published as RFC 9943, June 2026; draft -22 was the last revision)
 *   https://www.rfc-editor.org/rfc/rfc9943.html s6.1, the CDDL:
 *     Signed_Statement = #6.18(COSE_Sign1)
 *     Protected_Header = { &(CWT_Claims: 15) => CWT_Claims, ? alg 1 => int,
 *       ? content_type 3 => tstr / uint, ? kid 4 => bstr, ? x5t 34, ? x5chain 33 }
 *     CWT_Claims = { &(iss: 1) => tstr, &(sub: 2) => tstr }
 *     Unprotected_Header = { ? x5chain 33, ? receipts 394 => [+ bstr .cbor Receipt] }
 *     payload : bstr / nil   (nil = detached)
 *   https://datatracker.ietf.org/doc/draft-ietf-cose-hash-envelope/ (RFC 9995):
 *     258 payload_hash_alg MUST be in the protected header and not the
 *     unprotected one; 259 and 260 likewise never unprotected; label 3
 *     content_type MUST NOT be present; the payload is the hash.
 *   Sig_structure: RFC 9052 s4.4, ["Signature1", protected, h'', payload].
 *
 * What a browser does here: CBOR parse, the header rules above, the payload
 * digest, and the signature through WebCrypto with a supplied key or the leaf
 * of an embedded x5chain. Receipts attached at 394 (a Transparent Statement)
 * are checked by fmt_scitt_receipt.js against this statement and a supplied
 * transparency service key. What it does not: certificate chains against a
 * trust root. That is NOT LOOKED, and the page says so on every run.
 */
"use strict";

UC.HASH_ALGS = { "-16": { name: "SHA-256", len: 32 }, "-43": { name: "SHA-384", len: 48 },
                 "-44": { name: "SHA-512", len: 64 } };

UC.verifyScitt = async function (bytes, opts) {
  var F = "scitt";
  opts = opts || {};
  function broken(what) { return UC.finish(F, [UC.claim("structure", UC.BROKEN, what, true)]); }

  var top;
  try { top = UC.cborDecode(bytes); }
  catch (e) {
    if (e.unsupported) { return UC.couldNotLook(F, "CBOR this checker does not read: " + e.message); }
    return broken("the CBOR does not parse: " + e.message);
  }
  if (!top || top.tag !== 18) { return broken("not tag 18 (COSE_Sign1)"); }
  var arr = top.value;
  if (!Array.isArray(arr) || arr.length !== 4) { return broken("COSE_Sign1 is not a four-element array"); }
  var protBytes = arr[0], unprot = arr[1], payload = arr[2], signature = arr[3];
  if (!(UC.isBytes(protBytes))) { return broken("the protected header is not a byte string"); }
  if (!(unprot instanceof Map)) { return broken("the unprotected header is not a map"); }
  if (!(UC.isBytes(payload)) && payload !== null) { return broken("the payload is neither bytes nor nil"); }
  if (!(UC.isBytes(signature))) { return broken("the signature is not a byte string"); }

  var prot;
  if (protBytes.length === 0) { prot = new Map(); }
  else {
    try { prot = UC.cborDecode(protBytes); }
    catch (e2) {
      if (e2.unsupported) { return UC.couldNotLook(F, "protected header uses CBOR this checker does not read: " + e2.message); }
      return broken("the protected header does not parse: " + e2.message);
    }
  }
  if (!(prot instanceof Map)) { return broken("the protected header is not a map"); }

  // ---- RFC 9943 header rules ----
  var cwt = prot.get(15);
  if (!(cwt instanceof Map)) { return broken("protected header has no CWT Claims (label 15), which RFC 9943 requires"); }
  if (typeof cwt.get(1) !== "string") { return broken("CWT Claims has no issuer (iss, label 1)"); }
  if (typeof cwt.get(2) !== "string") { return broken("CWT Claims has no subject (sub, label 2)"); }
  if (prot.has(1) && typeof prot.get(1) !== "number" && typeof prot.get(1) !== "bigint") { return broken("alg (label 1) is not an integer"); }
  if (prot.has(3) && typeof prot.get(3) !== "string" && !(typeof prot.get(3) === "number" && prot.get(3) >= 0)) {
    return broken("content type (label 3) is not text or an unsigned integer");
  }
  if (prot.has(4) && !(UC.isBytes(prot.get(4)))) { return broken("kid (label 4) is not a byte string"); }
  for (var h = 258; h <= 260; h++) {
    if (unprot.has(h)) { return broken("hash envelope label " + h + " sits in the unprotected header, which RFC 9995 forbids"); }
  }
  var envelope = prot.has(258);
  var hashAlg = null;
  if (envelope) {
    if (prot.has(3) || unprot.has(3)) { return broken("a hash envelope carries content type (label 3), which RFC 9995 forbids"); }
    hashAlg = UC.HASH_ALGS[String(prot.get(258))] || null;
    if (hashAlg && payload !== null && payload.length !== hashAlg.len) {
      return broken("the payload is " + payload.length + " bytes, but " + hashAlg.name + " digests are " + hashAlg.len);
    }
  }

  var claims = [UC.claim("structure", UC.VERIFIED,
    "tag 18 COSE_Sign1; CWT Claims iss " + JSON.stringify(cwt.get(1)) + ", sub " + JSON.stringify(cwt.get(2)), true)];

  // ---- which bytes were signed ----
  var signedPayload = payload;
  if (payload === null) {
    if (UC.isBytes(opts.detachedPayload)) {
      signedPayload = opts.detachedPayload;
      if (envelope && hashAlg && signedPayload.length !== hashAlg.len) {
        claims.push(UC.claim("payload", UC.BROKEN, "the detached payload you supplied is not a " + hashAlg.name + " digest", true));
        return UC.finish(F, claims.concat(await UC.scittNotLooked(bytes, unprot, prot, opts)));
      }
    } else {
      claims.push(UC.claim("signature", UC.COULD_NOT_LOOK,
        "the payload is detached (nil) and none was supplied, so there is nothing to check the signature over", true));
      return UC.finish(F, claims.concat(await UC.scittNotLooked(bytes, unprot, prot, opts)));
    }
  }

  // ---- payload digest ----
  if (envelope) {
    if (!hashAlg) {
      claims.push(UC.claim("payload digest", UC.COULD_NOT_LOOK, "payload_hash_alg " + prot.get(258) + " is not a hash this page runs"));
    } else if (UC.isBytes(opts.preimage)) {
      var d = await UC.sha(hashAlg.name, opts.preimage);
      claims.push(UC.bytesEqual(d, signedPayload)
        ? UC.claim("payload digest", UC.VERIFIED, "the file you supplied hashes (" + hashAlg.name + ") to the signed payload", true)
        : UC.claim("payload digest", UC.BROKEN, "the file you supplied does not hash to the signed payload", true));
    } else {
      claims.push(UC.claim("payload digest", UC.NOT_LOOKED, "the statement signs a " + hashAlg.name +
        " digest; supply the original file to check it matches"));
    }
  } else {
    var pd = await UC.sha("SHA-256", signedPayload);
    claims.push(UC.claim("payload digest", UC.NOT_LOOKED, "the signature covers " + signedPayload.length +
      " payload bytes, SHA-256 " + UC.hex(pd) + " (shown, not compared: this statement carries no digest to compare to)"));
  }

  // ---- signature ----
  var alg = prot.get(1);
  var algSpec = alg === undefined ? null : UC.COSE_ALGS[String(alg)];
  if (alg === undefined) {
    claims.push(UC.claim("signature", UC.COULD_NOT_LOOK, "the protected header names no algorithm (label 1)", true));
    return UC.finish(F, claims.concat(await UC.scittNotLooked(bytes, unprot, prot, opts)));
  }
  if (!algSpec) {
    claims.push(UC.claim("signature", UC.COULD_NOT_LOOK, "algorithm " + String(alg) + " is not one a browser's WebCrypto runs", true));
    return UC.finish(F, claims.concat(await UC.scittNotLooked(bytes, unprot, prot, opts)));
  }
  var keySpec = null, keyFrom = "";
  var supplied = UC.parseSuppliedKey(opts.publicKey);
  if (supplied && supplied.error) {
    claims.push(UC.claim("signature", UC.COULD_NOT_LOOK, supplied.error, true));
    return UC.finish(F, claims.concat(await UC.scittNotLooked(bytes, unprot, prot, opts)));
  }
  if (supplied) { keySpec = supplied; keyFrom = supplied.label; }
  else {
    var x5 = prot.has(33) ? prot.get(33) : null;
    var where = "protected";
    if (x5 === null && unprot.has(33)) { x5 = unprot.get(33); where = "unprotected"; }
    if (x5 !== null) {
      var leaf = Array.isArray(x5) ? x5[0] : x5;
      if (!(UC.isBytes(leaf))) { return broken("x5chain (label 33) is not a certificate byte string"); }
      try { keySpec = { kind: "spki", der: UC.spkiFromCertificate(leaf) }; }
      catch (e4) { return broken("the x5chain leaf certificate does not parse: " + e4.message); }
      keyFrom = "the leaf certificate the statement carries (" + where + " header)";
    }
  }
  if (!keySpec) {
    var kid = prot.get(4);
    claims.push(UC.claim("signature", UC.COULD_NOT_LOOK, "no key: the statement carries no certificate" +
      (kid ? " and names kid " + UC.hex(kid) : "") + ". Supply the issuer's public key to check it.", true));
    return UC.finish(F, claims.concat(await UC.scittNotLooked(bytes, unprot, prot, opts)));
  }
  var res = await UC.verifySignature(algSpec, keySpec, signature, UC.coseSign1ToBeSigned(protBytes, signedPayload));
  if (res.cannot) { claims.push(UC.claim("signature", UC.COULD_NOT_LOOK, res.cannot, true)); }
  else if (res.ok) { claims.push(UC.claim("signature", UC.VERIFIED, algSpec.name + " over the COSE Sig_structure, checked against " + keyFrom, true)); }
  else { claims.push(UC.claim("signature", UC.BROKEN, "the " + algSpec.name + " signature does not verify under " + keyFrom, true)); }
  return UC.finish(F, claims.concat(await UC.scittNotLooked(bytes, unprot, prot, opts)), { keyFrom: keyFrom });
};

// The rows every statement run ends with: issuer identity (never reached),
// and the transparency receipts it carries at 394, which ARE checked
// (fmt_scitt_receipt.js). A Transparent Statement's receipts are core: its
// claim to be transparent is the reason it carries them.
UC.scittNotLooked = async function (bytes, unprot, prot, opts) {
  var out = [UC.claim("issuer identity", UC.NOT_LOOKED,
    "no certificate chain or trust root was checked; a key that verifies is only the key that signed")];
  return out.concat(await UC.scittReceiptClaims(bytes, prot, unprot, opts || {}));
};
