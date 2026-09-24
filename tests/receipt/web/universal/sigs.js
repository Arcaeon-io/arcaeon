/* universal/sigs.js: signature checks through the browser's own WebCrypto.
 *
 * Algorithms by COSE identifier (IANA COSE Algorithms registry, the numbers
 * RFC 9052/9053 use). Anything not in this table is COULD NOT LOOK with the
 * reason, never a pass and never a BROKEN: the page did not look.
 */
"use strict";

UC.COSE_ALGS = {
  "-7":   { name: "ES256", imp: { name: "ECDSA", namedCurve: "P-256" }, ver: { name: "ECDSA", hash: "SHA-256" } },
  "-35":  { name: "ES384", imp: { name: "ECDSA", namedCurve: "P-384" }, ver: { name: "ECDSA", hash: "SHA-384" } },
  "-36":  { name: "ES512", imp: { name: "ECDSA", namedCurve: "P-521" }, ver: { name: "ECDSA", hash: "SHA-512" } },
  "-8":   { name: "EdDSA (Ed25519)", imp: { name: "Ed25519" }, ver: { name: "Ed25519" } },
  "-19":  { name: "Ed25519", imp: { name: "Ed25519" }, ver: { name: "Ed25519" } },
  "-37":  { name: "PS256", imp: { name: "RSA-PSS", hash: "SHA-256" }, ver: { name: "RSA-PSS", saltLength: 32 } },
  "-38":  { name: "PS384", imp: { name: "RSA-PSS", hash: "SHA-384" }, ver: { name: "RSA-PSS", saltLength: 48 } },
  "-39":  { name: "PS512", imp: { name: "RSA-PSS", hash: "SHA-512" }, ver: { name: "RSA-PSS", saltLength: 64 } },
  "-257": { name: "RS256", imp: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ver: { name: "RSASSA-PKCS1-v1_5" } },
  "-258": { name: "RS384", imp: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, ver: { name: "RSASSA-PKCS1-v1_5" } },
  "-259": { name: "RS512", imp: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, ver: { name: "RSASSA-PKCS1-v1_5" } }
};

// keySpec: {kind:"jwk", jwk} | {kind:"spki", der} | {kind:"raw-ed25519", raw}
// Returns {ok: true|false} when a look happened, {cannot: reason} when not.
UC.verifySignature = async function (algSpec, keySpec, signature, data) {
  var subtle = UC.subtle();
  if (!subtle) { return { cannot: "this browser has no WebCrypto (crypto.subtle)" }; }
  var key;
  try {
    if (keySpec.kind === "jwk") {
      var j = keySpec.jwk || {};
      var clean = {};
      ["kty", "crv", "x", "y", "n", "e"].forEach(function (k) { if (j[k] !== undefined) { clean[k] = j[k]; } });
      key = await subtle.importKey("jwk", clean, algSpec.imp, false, ["verify"]);
    } else if (keySpec.kind === "spki") {
      key = await subtle.importKey("spki", keySpec.der, algSpec.imp, false, ["verify"]);
    } else if (keySpec.kind === "raw-ed25519") {
      if (algSpec.imp.name !== "Ed25519") {
        return { cannot: "a raw Ed25519 key cannot check a " + algSpec.name + " signature" };
      }
      key = await subtle.importKey("raw", keySpec.raw, algSpec.imp, false, ["verify"]);
    } else {
      return { cannot: "no usable key" };
    }
  } catch (e) {
    return { cannot: "the key could not be loaded for " + algSpec.name + " in this browser (" +
      (e && e.message ? e.message : String(e)) + ")" };
  }
  try {
    var ok = await subtle.verify(algSpec.ver, key, signature, data);
    return { ok: !!ok };
  } catch (e2) {
    return { cannot: "this browser could not run " + algSpec.name + " (" + (e2 && e2.message ? e2.message : String(e2)) + ")" };
  }
};

UC.ED25519 = { name: "Ed25519", imp: { name: "Ed25519" }, ver: { name: "Ed25519" } };
