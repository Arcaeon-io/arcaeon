/* universal/detect.js: the format detector and the one entry point.
 *
 * The detector never guesses. A format is recognized only by markers its own
 * spec makes mandatory; zero matches is COULD NOT LOOK ("no recognized
 * format"), more than one is COULD NOT LOOK ("ambiguous"), and neither is ever
 * BROKEN: BROKEN is a finding about a record, and an input nobody recognized
 * has not been looked at.
 *
 *   arcaeon-receipt  JSON object; receipt_version starts "arcaeon-receipt/"
 *                    or body_digest starts "sha256:json-c14n:v1:"
 *   agent-receipts   JSON object; type is an array holding "AgentReceipt"
 *   signet           JSON object; integer "v", "sig" starting "ed25519:",
 *                    "action" and "signer" objects (recognized only to say
 *                    plainly that there is no published schema to check)
 *   scitt            CBOR tag 18 around a 4-element array (bytes d2 84),
 *                    given as a binary file, hex, or base64, whose headers
 *                    carry neither receipt marker below (a Signed Statement,
 *                    or a Transparent Statement with receipts at 394)
 *   scitt-receipt    the same COSE_Sign1 shape with BOTH markers RFC 9942
 *                    s5.2.1 makes mandatory for a receipt: vds (395) in the
 *                    protected header and vdp (396) in the unprotected one.
 *                    One marker without the other is ambiguous, and so is a
 *                    receipt that also carries receipts (394): COULD NOT LOOK.
 *                    Bytes that do not parse far enough to see the headers
 *                    stay "scitt", whose checker reports the parse failure.
 */
"use strict";

UC.FORMATS = {
  "arcaeon-receipt": "Arcaeon receipt (arcaeon-receipt/0.1)",
  "agent-receipts": "Agent Receipts (W3C VC, Ed25519)",
  "scitt": "SCITT Signed Statement (COSE_Sign1, RFC 9943)",
  "scitt-receipt": "SCITT Receipt (RFC 9942, RFC9162_SHA256 inclusion proof)",
  "signet": "Signet receipt"
};

UC.SIGNET_SOURCES = [
  "https://github.com/Prismer-AI/signet (README: v1 example only)",
  "https://raw.githubusercontent.com/Prismer-AI/signet/main/docs/ARCHITECTURE.md (no v3 schema)",
  "https://raw.githubusercontent.com/Prismer-AI/signet/main/docs/rfcs/0002-composite-receipt.md (Draft; signable bodies not published)"
];

function isCoseSign1Prefix(b) { return b && b.length >= 2 && b[0] === 0xd2 && b[1] === 0x84; }

// Receipt or statement, read off the headers; never guessed.
function classifyCose(bytes) {
  var top, prot;
  try { top = UC.cborDecode(bytes); } catch (e) { return { format: "scitt", bytes: bytes }; }
  var arr = top && top.value;
  if (!Array.isArray(arr) || arr.length !== 4 || !UC.isBytes(arr[0]) || !(arr[1] instanceof Map)) { return { format: "scitt", bytes: bytes }; }
  try { prot = arr[0].length ? UC.cborDecode(arr[0]) : new Map(); } catch (e2) { return { format: "scitt", bytes: bytes }; }
  if (!(prot instanceof Map)) { return { format: "scitt", bytes: bytes }; }
  var vds = prot.has(395), vdp = arr[1].has(396), rcpts = prot.has(394) || arr[1].has(394);
  if (vds && vdp && !rcpts) { return { format: "scitt-receipt", bytes: bytes }; }
  if (vds || vdp) {
    return { none: "ambiguous: this COSE_Sign1 carries " + (vds && vdp ? "both receipt markers (vds 395, vdp 396) and receipts of its own (394)"
      : (vds ? "vds (395) but no proofs (vdp 396)" : "proofs (vdp 396) but no vds (395)")) +
      ", so it is neither a clean receipt nor a clean statement, and this page will not pick one" };
  }
  return { format: "scitt", bytes: bytes };
}

// input: {text} or {bytes}. Returns {format, text?, bytes?} or {none: reason}.
UC.detectFormat = function (input) {
  var text = null, bytes = null;
  if (input && UC.isBytes(input.bytes)) {
    if (isCoseSign1Prefix(input.bytes)) { return classifyCose(input.bytes); }
    text = UC.utf8DecodeStrict(input.bytes);
    if (text === null) { return { none: "no recognized format: binary input that is not a COSE_Sign1 (tag 18)" }; }
  } else if (input && typeof input.text === "string") {
    text = input.text;
  }
  if (text === null) { return { none: "no recognized format: nothing was given" }; }
  var t = text.replace(/^﻿/, "").trim();
  if (!t) { return { none: "no recognized format: the input is empty" }; }

  if (t[0] === "{") {
    var v;
    try { v = JSON.parse(t); }
    catch (e) { return { none: "no recognized format: it starts like JSON but does not parse (" + e.message + ")" }; }
    if (v === null || typeof v !== "object" || Array.isArray(v)) { return { none: "no recognized format" }; }
    var hits = [];
    if ((typeof v.receipt_version === "string" && v.receipt_version.indexOf("arcaeon-receipt/") === 0) ||
        (typeof v.body_digest === "string" && v.body_digest.indexOf("sha256:json-c14n:v1:") === 0)) {
      hits.push("arcaeon-receipt");
    }
    if (Array.isArray(v.type) && v.type.indexOf("AgentReceipt") >= 0) { hits.push("agent-receipts"); }
    if (Number.isInteger(v.v) && typeof v.sig === "string" && v.sig.indexOf("ed25519:") === 0 &&
        v.action && typeof v.action === "object" && v.signer && typeof v.signer === "object") {
      hits.push("signet");
    }
    if (hits.length === 0) { return { none: "no recognized format: a JSON object with none of the markers this page knows" }; }
    if (hits.length > 1) { return { none: "ambiguous: the object carries the markers of " + hits.join(" and ") + ", and this page will not pick one" }; }
    return { format: hits[0], text: t };
  }

  // Encoded CBOR: hex, then base64. If both decodings give a COSE_Sign1 it is
  // ambiguous; if neither does, it is unrecognized.
  var compact = t.replace(/\s+/g, "");
  var cands = [];
  var hx = /^[0-9a-fA-F]+$/.test(compact) ? UC.fromHex(compact) : null;
  if (isCoseSign1Prefix(hx)) { cands.push(hx); }
  var b64 = UC.fromBase64(compact);
  if (isCoseSign1Prefix(b64)) { cands.push(b64); }
  if (cands.length === 1) { return classifyCose(cands[0]); }
  if (cands.length > 1) { return { none: "ambiguous: this text decodes to a COSE_Sign1 both as hex and as base64" }; }
  return { none: "no recognized format" };
};

// The entry point. opts: {claimedFormat, publicKey, detachedPayload, preimage,
//                        receiptKey (the transparency service's public key),
//                        statement (a Signed Statement's bytes, for a standalone receipt)}
UC.verifyAny = async function (input, opts) {
  opts = opts || {};
  var d = UC.detectFormat(input);
  if (d.none) {
    if (opts.claimedFormat && opts.claimedFormat !== "auto") {
      return UC.couldNotLook(null, "you said this is " + (UC.FORMATS[opts.claimedFormat] || opts.claimedFormat) +
        ", but it does not read as that format (" + d.none + ")");
    }
    return UC.couldNotLook(null, d.none);
  }
  if (opts.claimedFormat && opts.claimedFormat !== "auto" && opts.claimedFormat !== d.format) {
    return UC.couldNotLook(d.format, "you said this is " + (UC.FORMATS[opts.claimedFormat] || opts.claimedFormat) +
      ", but it reads as " + UC.FORMATS[d.format] + ". Nothing was checked; pick the right format or leave it on auto.");
  }
  try {
    if (d.format === "arcaeon-receipt") { return await UC.verifyArcaeon(d.text); }
    if (d.format === "agent-receipts") { return await UC.verifyAgentReceipt(d.text, opts); }
    if (d.format === "scitt") { return await UC.verifyScitt(d.bytes, opts); }
    if (d.format === "scitt-receipt") { return await UC.verifyScittReceipt(d.bytes, opts); }
    if (d.format === "signet") {
      return UC.couldNotLook("signet", "could not look: no published schema. Signet documents a v1 example and says " +
        "its signable bodies are rebuilt inside its own code, not published as a versioned spec. Sources read: " +
        UC.SIGNET_SOURCES.join("; "));
    }
  } catch (e) {
    return UC.couldNotLook(d.format, "the checker stopped on an unexpected error, so nothing is claimed: " +
      (e && e.message ? e.message : String(e)));
  }
  return UC.couldNotLook(null, "no recognized format");
};
