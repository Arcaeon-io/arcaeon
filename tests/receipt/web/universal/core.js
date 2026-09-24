/* universal/core.js: shared vocabulary and byte helpers for verify-any.html.
 *
 * Pure: no DOM, no network. Loaded by the page with <script src> and by
 * tests/test_universal_checker.mjs under node:vm, in the order the page lists.
 *
 * Verdict vocabulary (DESIGN_CONSISTENCY_AND_NEVER_LOOKED_2026-09-22.md, B2):
 *   run axis, one result per run:      VERIFIED / BROKEN / COULD NOT LOOK
 *   per-claim, the viewer's coverage:  the three above, plus NOT LOOKED
 *   record axis (never merged):        BLIND, because no check record
 *                                      is published for any receipt yet, and
 *                                      this page does not publish yours.
 *
 * Vocabulary pass (2026-09-23): the words a person reads are one set across
 * every Arcaeon surface. NOT LOOKED stays a distinct value here (a non-core
 * row, which never decides the run) but the page prints it as COULD NOT LOOK
 * in the neutral colour: one word for "did not look". The record axis uses
 * the audit-state word BLIND (no check by anyone), the same word the witness
 * status page uses; UC.NEVER_CHECKED keeps its name so callers do not break.
 */
"use strict";

var UC = (typeof UC !== "undefined") ? UC : {};

UC.VERIFIED = "VERIFIED";
UC.BROKEN = "BROKEN";
UC.COULD_NOT_LOOK = "COULD NOT LOOK";
UC.NOT_LOOKED = "NOT LOOKED";
UC.NEVER_CHECKED = "BLIND";

// A claim row. core claims decide the run verdict; the rest are coverage.
UC.claim = function (name, result, detail, core) {
  return { name: name, result: result, detail: detail || "", core: !!core };
};

// Run verdict from claims: any BROKEN wins; else every core claim VERIFIED
// gives VERIFIED; else COULD NOT LOOK with the first core claim that did not
// verify. A result with no core claims can never be VERIFIED.
UC.finish = function (format, claims, extra) {
  var out = { format: format, claims: claims, record: UC.NEVER_CHECKED };
  var broken = claims.filter(function (c) { return c.result === UC.BROKEN; });
  var core = claims.filter(function (c) { return c.core; });
  if (broken.length) {
    out.verdict = UC.BROKEN;
    out.reason = broken[0].name + ": " + broken[0].detail;
  } else if (core.length && core.every(function (c) { return c.result === UC.VERIFIED; })) {
    out.verdict = UC.VERIFIED;
    out.reason = core.map(function (c) { return c.name; }).join(", ") + " checked in this browser";
  } else {
    var first = core.filter(function (c) { return c.result !== UC.VERIFIED; })[0];
    out.verdict = UC.COULD_NOT_LOOK;
    out.reason = first ? (first.name + ": " + first.detail) : "nothing this page can check";
  }
  if (extra) { Object.keys(extra).forEach(function (k) { out[k] = extra[k]; }); }
  return out;
};

UC.couldNotLook = function (format, reason, extra) {
  var out = { format: format, verdict: UC.COULD_NOT_LOOK, reason: reason, claims: [],
              record: UC.NEVER_CHECKED };
  if (extra) { Object.keys(extra).forEach(function (k) { out[k] = extra[k]; }); }
  return out;
};

// ---- bytes ----

UC.utf8 = function (s) { return new TextEncoder().encode(s); };

UC.utf8DecodeStrict = function (bytes) {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch (e) { return null; }
};

UC.hex = function (bytes) {
  var s = "";
  for (var i = 0; i < bytes.length; i++) { s += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16); }
  return s;
};

UC.fromHex = function (s) {
  if (!/^([0-9a-fA-F]{2})*$/.test(s)) { return null; }
  var out = new Uint8Array(s.length / 2);
  for (var i = 0; i < out.length; i++) { out[i] = parseInt(s.substr(i * 2, 2), 16); }
  return out;
};

var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Accepts standard or url-safe alphabet, padded or not. Returns null on any
// character outside the alphabet, an impossible length, or NON-ZERO leftover
// bits in the last character. That last rule matters: without it, two
// different strings decode to the same signature bytes, and a receipt whose
// signature text was edited would still verify.
UC.fromBase64 = function (s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (!/^[A-Za-z0-9+/]*$/.test(s) || s.length % 4 === 1) { return null; }
  var out = [];
  var buf = 0, bits = 0;
  for (var i = 0; i < s.length; i++) {
    buf = ((buf << 6) | B64.indexOf(s[i])) & 0xffff;
    bits += 6;
    if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); }
  }
  if (bits > 0 && (buf & ((1 << bits) - 1)) !== 0) { return null; }
  return new Uint8Array(out);
};

var B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

UC.fromBase58btc = function (s) {
  var n = BigInt(0);
  for (var i = 0; i < s.length; i++) {
    var v = B58.indexOf(s[i]);
    if (v < 0) { return null; }
    n = n * BigInt(58) + BigInt(v);
  }
  var body = [];
  while (n > BigInt(0)) { body.unshift(Number(n % BigInt(256))); n = n / BigInt(256); }
  var lead = s.match(/^1*/)[0].length;
  return new Uint8Array(new Array(lead).fill(0).concat(body));
};

UC.bytesEqual = function (a, b) {
  if (a.length !== b.length) { return false; }
  for (var i = 0; i < a.length; i++) { if (a[i] !== b[i]) { return false; } }
  return true;
};

UC.subtle = function () {
  var c = (typeof crypto !== "undefined") ? crypto : (typeof window !== "undefined" ? window.crypto : null);
  return c && c.subtle ? c.subtle : null;
};

UC.sha = async function (name, bytes) {
  var s = UC.subtle();
  if (!s) { throw new Error("this browser has no WebCrypto (crypto.subtle)"); }
  return new Uint8Array(await s.digest(name, bytes));
};

// ---- JSON: strict duplicate-key scan (not a canonicalizer) ----
// Runs over text JSON.parse has ALREADY accepted, so it only tracks strings
// and nesting. Keys compare after unescaping. Returns the first repeated key.
UC.findDuplicateKey = function (text) {
  var stack = [];
  var n = text.length, i = 0;
  while (i < n) {
    var c = text[i];
    if (c === '"') {
      var j = i + 1;
      while (j < n && text[j] !== '"') { j += (text[j] === "\\") ? 2 : 1; }
      var raw = text.slice(i, j + 1);
      i = j + 1;
      var top = stack.length ? stack[stack.length - 1] : null;
      if (top) {
        var k = i;
        while (k < n && /\s/.test(text[k])) { k++; }
        if (text[k] === ":") {
          var key = JSON.parse(raw);
          if (top.has(key)) { return key; }
          top.add(key);
        }
      }
      continue;
    }
    if (c === "{") { stack.push(new Set()); }
    else if (c === "[") { stack.push(null); }
    else if (c === "}" || c === "]") { stack.pop(); }
    i++;
  }
  return null;
};

// ---- supplied public keys ----
// Accepts: a JWK (JSON), a PEM "PUBLIC KEY" (SPKI), a did:key (Ed25519), or
// 64 hex characters (a raw Ed25519 key). Returns {kind, ...} or {error}.
UC.parseSuppliedKey = function (text) {
  if (text === null || text === undefined) { return null; }
  var t = String(text).trim();
  if (!t) { return null; }
  if (t[0] === "{") {
    try { return { kind: "jwk", jwk: JSON.parse(t), label: "the key you supplied (JWK)" }; }
    catch (e) { return { error: "the supplied key is not valid JSON" }; }
  }
  var pem = /^-----BEGIN PUBLIC KEY-----([\s\S]*)-----END PUBLIC KEY-----$/.exec(t);
  if (pem) {
    var der = UC.fromBase64(pem[1].replace(/\s+/g, ""));
    if (!der) { return { error: "the supplied PEM does not decode" }; }
    return { kind: "spki", der: der, label: "the key you supplied (PEM)" };
  }
  if (/^did:key:/.test(t)) {
    var raw = UC.didKeyEd25519(t);
    if (raw.error) { return { error: raw.error }; }
    return { kind: "raw-ed25519", raw: raw.key, label: "the key you supplied (did:key)" };
  }
  if (/^[0-9a-fA-F]{64}$/.test(t)) {
    return { kind: "raw-ed25519", raw: UC.fromHex(t), label: "the key you supplied (raw Ed25519)" };
  }
  return { error: "the supplied key is not a JWK, a PEM public key, a did:key, or 64 hex characters" };
};

// did:key for Ed25519 only: multibase "z" (base58btc) over 0xed 0x01 + 32 bytes.
UC.didKeyEd25519 = function (did) {
  var id = did.split("#")[0];
  var m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(id);
  if (!m) { return { error: "not a base58btc did:key" }; }
  var b = UC.fromBase58btc(m[1]);
  if (!b || b.length !== 34 || b[0] !== 0xed || b[1] !== 0x01) {
    return { error: "did:key is not an Ed25519 key (multicodec 0xed01)" };
  }
  return { key: b.slice(2) };
};

// Byte strings from any realm (a file read in the page, a Buffer in a test).
UC.isBytes = function (x) {
  return !!x && Object.prototype.toString.call(x) === "[object Uint8Array]";
};
