/* universal/fmt_agent_receipts.js: Agent Receipts (Obsigna), a W3C
 * Verifiable Credential with an Ed25519 proof.
 *
 * Read from the live spec, 2026-09-22:
 *   https://raw.githubusercontent.com/agent-receipts/obsigna/main/spec/v0.5.0/spec.md
 *     s4.3.3 proofValue: multibase "u" (base64url, no padding) Ed25519 signature
 *     s7.2   the signature is over the RFC 8785 canonical JSON of the receipt
 *            with the "proof" field removed
 *     s7.8   verify order: schema, key resolution, signature, timestamp, chain
 *   https://raw.githubusercontent.com/agent-receipts/obsigna/main/spec/schema/agent-receipt.schema.json
 *     required fields, enums and patterns checked below
 *   https://raw.githubusercontent.com/agent-receipts/obsigna/main/spec/test-vectors/did-key/vectors.json
 *     did:key encoding (multicodec 0xed01, base58btc "z"), used as our key test
 *
 * What this page can resolve: a did:key verificationMethod (pure arithmetic),
 * or a key the reader supplies. Any other DID method (the spec's own example
 * uses did:agent, whose resolution the spec leaves open, s9.6) is COULD NOT
 * LOOK, not BROKEN.
 */
"use strict";

UC.AR_CONTEXT0 = "https://www.w3.org/ns/credentials/v2";
UC.AR_CONTEXT1 = ["https://agentreceipts.ai/context/v1", "https://agentreceipts.ai/context/v2",
                  "https://agentreceipts.ai/context/v3"];
UC.AR_VERSIONS = ["0.1.0", "0.2.0", "0.2.1", "0.3.0", "0.4.0", "0.5.0", "0.6.0"];

UC.agentReceiptSchemaProblem = function (r) {
  function isObj(x) { return x !== null && typeof x === "object" && !Array.isArray(x); }
  function str(x) { return typeof x === "string"; }
  var UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
  var top = ["@context", "id", "type", "version", "issuer", "issuanceDate", "credentialSubject", "proof"];
  for (var i = 0; i < top.length; i++) { if (!(top[i] in r)) { return "missing required field " + top[i]; } }
  var ctx = r["@context"];
  if (!Array.isArray(ctx) || ctx[0] !== UC.AR_CONTEXT0 || UC.AR_CONTEXT1.indexOf(ctx[1]) < 0) {
    return "@context is not [W3C VC v2, an Agent Receipts context]";
  }
  if (!str(r.id) || !new RegExp("^urn:receipt:" + UUID + "$").test(r.id)) { return "id is not urn:receipt:<uuid>"; }
  if (!Array.isArray(r.type) || r.type.length !== 2 || r.type[0] !== "VerifiableCredential" || r.type[1] !== "AgentReceipt") {
    return "type is not [\"VerifiableCredential\", \"AgentReceipt\"]";
  }
  if (UC.AR_VERSIONS.indexOf(r.version) < 0) { return "version " + JSON.stringify(r.version) + " is not a published version"; }
  if (!isObj(r.issuer) || !str(r.issuer.id)) { return "issuer.id is missing"; }
  if (!str(r.issuanceDate)) { return "issuanceDate is missing"; }
  var cs = r.credentialSubject;
  if (!isObj(cs)) { return "credentialSubject is not an object"; }
  var need = ["principal", "action", "outcome", "chain"];
  for (var j = 0; j < need.length; j++) { if (!isObj(cs[need[j]])) { return "credentialSubject." + need[j] + " is missing"; } }
  if (!str(cs.principal.id)) { return "credentialSubject.principal.id is missing"; }
  var a = cs.action;
  if (!str(a.id) || !new RegExp("^act_" + UUID + "$").test(a.id)) { return "action.id is not act_<uuid>"; }
  if (!str(a.type)) { return "action.type is missing"; }
  if (["low", "medium", "high", "critical"].indexOf(a.risk_level) < 0) { return "action.risk_level is not low, medium, high or critical"; }
  if (!str(a.timestamp)) { return "action.timestamp is missing"; }
  if (["success", "failure", "pending"].indexOf(cs.outcome.status) < 0) { return "outcome.status is not success, failure or pending"; }
  var ch = cs.chain;
  if (!Number.isInteger(ch.sequence) || ch.sequence < 1) { return "chain.sequence is not an integer of at least 1"; }
  if (!("previous_receipt_hash" in ch) || !(ch.previous_receipt_hash === null || str(ch.previous_receipt_hash))) {
    return "chain.previous_receipt_hash is missing (it is required, and null for the first receipt)";
  }
  if (!str(ch.chain_id)) { return "chain.chain_id is missing"; }
  var p = r.proof;
  if (!isObj(p)) { return "proof is not an object"; }
  var pf = ["type", "created", "verificationMethod", "proofPurpose", "proofValue"];
  for (var k = 0; k < pf.length; k++) { if (!(pf[k] in p)) { return "proof." + pf[k] + " is missing"; } }
  if (p.type !== "Ed25519Signature2020") { return "proof.type is not Ed25519Signature2020"; }
  if (p.proofPurpose !== "assertionMethod") { return "proof.proofPurpose is not assertionMethod"; }
  if (!str(p.verificationMethod)) { return "proof.verificationMethod is not text"; }
  if (!str(p.proofValue) || !/^u[A-Za-z0-9_-]{86}$/.test(p.proofValue)) { return "proof.proofValue is not u + 86 base64url characters"; }
  return null;
};

UC.verifyAgentReceipt = async function (text, opts) {
  var F = "agent-receipts";
  var r;
  try { r = JSON.parse(text); } catch (e) { return UC.couldNotLook(F, "not readable JSON"); }
  var dup = UC.findDuplicateKey(text);
  if (dup !== null) {
    return UC.finish(F, [UC.claim("schema", UC.BROKEN, "duplicate key " + JSON.stringify(dup) +
      ": I-JSON forbids it, and the file reads two ways", true)]);
  }
  var claims = [];
  var problem = UC.agentReceiptSchemaProblem(r);
  if (problem) {
    return UC.finish(F, [UC.claim("schema", UC.BROKEN, "MALFORMED_RECEIPT: " + problem, true)]);
  }
  claims.push(UC.claim("schema", UC.VERIFIED, "required fields, enums and patterns of agent-receipt.schema.json", true));

  // key: a supplied key wins; otherwise a did:key in verificationMethod.
  var vm = r.proof.verificationMethod;
  var named = /^did:key:/.test(vm) ? UC.didKeyEd25519(vm) : null;
  var keySpec = null, keyFrom = "";
  var supplied = UC.parseSuppliedKey(opts && opts.publicKey);
  if (supplied && supplied.error) {
    claims.push(UC.claim("signature", UC.COULD_NOT_LOOK, supplied.error, true));
    return UC.finish(F, claims.concat(UC.arNotLooked(r)));
  }
  if (supplied) {
    keySpec = supplied; keyFrom = supplied.label;
    if (named && named.key && supplied.kind === "raw-ed25519" && !UC.bytesEqual(named.key, supplied.raw)) {
      claims.push(UC.claim("named key", UC.BROKEN,
        "the receipt names " + vm.split("#")[0] + ", which is not the key you supplied"));
    }
  } else if (named && named.key) {
    keySpec = { kind: "raw-ed25519", raw: named.key }; keyFrom = "the did:key the receipt names";
  } else if (named && named.error) {
    claims.push(UC.claim("signature", UC.COULD_NOT_LOOK, "UNRESOLVABLE_DID: " + named.error, true));
    return UC.finish(F, claims.concat(UC.arNotLooked(r)));
  } else {
    var method = (/^did:([a-z0-9]+):/.exec(vm) || [null, "(not a DID)"])[1];
    claims.push(UC.claim("signature", UC.COULD_NOT_LOOK, "UNRESOLVABLE_DID: the key is named by did:" + method +
      ", which a browser cannot resolve on its own (the spec leaves resolution open, s9.6). " +
      "Supply the issuer's public key to check it.", true));
    return UC.finish(F, claims.concat(UC.arNotLooked(r)));
  }

  var sig = UC.fromBase64(r.proof.proofValue.slice(1));
  if (!sig || sig.length !== 64) {
    claims.push(UC.claim("signature", UC.BROKEN, "proofValue does not decode to a 64-byte Ed25519 signature", true));
    return UC.finish(F, claims.concat(UC.arNotLooked(r)));
  }
  var unsigned = Object.create(null); // a "__proto__" key stays a key, never a prototype
  Object.keys(r).forEach(function (k) { if (k !== "proof") { unsigned[k] = r[k]; } });
  var canonical;
  try { canonical = UC.jcs(unsigned); }
  catch (e3) {
    claims.push(UC.claim("signature", UC.COULD_NOT_LOOK, "RFC 8785 canonicalization refused: " + e3.message, true));
    return UC.finish(F, claims.concat(UC.arNotLooked(r)));
  }
  var res = await UC.verifySignature(UC.ED25519, keySpec, sig, UC.utf8(canonical));
  if (res.cannot) { claims.push(UC.claim("signature", UC.COULD_NOT_LOOK, res.cannot, true)); }
  else if (res.ok) { claims.push(UC.claim("signature", UC.VERIFIED, "Ed25519 over RFC 8785 canonical JSON without proof, checked against " + keyFrom, true)); }
  else { claims.push(UC.claim("signature", UC.BROKEN, "INVALID_SIGNATURE: the receipt does not verify under " + keyFrom, true)); }
  return UC.finish(F, claims.concat(UC.arNotLooked(r)), { canonical: canonical });
};

UC.arNotLooked = function (r) {
  var out = [
    UC.claim("issuer identity", UC.NOT_LOOKED, "a key proves who holds the key, not who the issuer is"),
    UC.claim("chain link", UC.NOT_LOOKED, "needs the previous receipt in the chain; one receipt was given")
  ];
  var a = r && r.credentialSubject && r.credentialSubject.action;
  if (a && a.trusted_timestamp) {
    out.push(UC.claim("trusted timestamp", UC.NOT_LOOKED, "RFC 3161 tokens are not checked in this browser"));
  }
  return out;
};
