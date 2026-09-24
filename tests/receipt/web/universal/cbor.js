/* universal/cbor.js: a strict CBOR reader (RFC 8949), the one CBOR writer
 * COSE needs (Sig_structure, RFC 9052 s4.4), and a DER walk that finds the
 * SubjectPublicKeyInfo inside an X.509 certificate.
 *
 * Strict means: definite lengths only (an indefinite length is reported as
 * unsupported, never guessed at), no duplicate map keys, no trailing bytes,
 * and a clean error at the exact offset where the bytes run out.
 *
 * Decoded shapes: unsigned/negative int -> Number (BigInt past 2^53),
 * bstr -> Uint8Array, tstr -> string, array -> Array, map -> Map (keys are
 * Numbers or strings), tag -> {tag, value}, simple -> true/false/null/undefined,
 * float -> Number.
 */
"use strict";

function CBORError(message, unsupported) {
  this.name = "CBORError";
  this.message = message;
  this.unsupported = !!unsupported;
}
CBORError.prototype = Object.create(Error.prototype);

UC.cborDecode = function (bytes) {
  var i = 0;
  var n = bytes.length;

  function need(k) {
    if (i + k > n) { throw new CBORError("the bytes end early: needed " + k + " more at offset " + i); }
  }
  function u8() { need(1); return bytes[i++]; }
  function readUint(ai) {
    if (ai < 24) { return ai; }
    if (ai === 24) { return u8(); }
    if (ai === 25) { need(2); var v2 = (bytes[i] << 8) | bytes[i + 1]; i += 2; return v2; }
    if (ai === 26) { need(4); var v4 = ((bytes[i] << 24) >>> 0) + (bytes[i + 1] << 16) + (bytes[i + 2] << 8) + bytes[i + 3]; i += 4; return v4; }
    if (ai === 27) {
      need(8);
      var big = BigInt(0);
      for (var k = 0; k < 8; k++) { big = big * BigInt(256) + BigInt(bytes[i + k]); }
      i += 8;
      return big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big;
    }
    if (ai === 31) { throw new CBORError("indefinite-length items are not supported by this checker", true); }
    throw new CBORError("reserved additional-information value " + ai + " at offset " + (i - 1));
  }
  function lengthOf(ai) {
    var len = readUint(ai);
    if (typeof len !== "number") { throw new CBORError("a length too large to be real"); }
    return len;
  }
  function half(h) {
    var s = (h & 0x8000) ? -1 : 1, e = (h >> 10) & 0x1f, f = h & 0x3ff;
    if (e === 0) { return s * Math.pow(2, -14) * (f / 1024); }
    if (e === 31) { return f ? NaN : s * Infinity; }
    return s * Math.pow(2, e - 15) * (1 + f / 1024);
  }

  function item(depth) {
    if (depth > 64) { throw new CBORError("nesting deeper than 64 levels"); }
    var ib = u8();
    var mt = ib >> 5, ai = ib & 0x1f;
    switch (mt) {
      case 0: return readUint(ai);
      case 1: {
        var v = readUint(ai);
        return typeof v === "bigint" ? (BigInt(-1) - v) : (-1 - v);
      }
      case 2: {
        var bl = lengthOf(ai); need(bl);
        var b = bytes.slice(i, i + bl); i += bl; return b;
      }
      case 3: {
        var tl = lengthOf(ai); need(tl);
        var t = UC.utf8DecodeStrict(bytes.slice(i, i + tl));
        if (t === null) { throw new CBORError("a text string is not valid UTF-8 at offset " + i); }
        i += tl; return t;
      }
      case 4: {
        var al = lengthOf(ai);
        var arr = [];
        for (var a = 0; a < al; a++) { arr.push(item(depth + 1)); }
        return arr;
      }
      case 5: {
        var ml = lengthOf(ai);
        var map = new Map();
        for (var m = 0; m < ml; m++) {
          var key = item(depth + 1);
          if (typeof key !== "number" && typeof key !== "string") {
            throw new CBORError("a map key that is neither an integer nor text", true);
          }
          if (map.has(key)) { throw new CBORError("duplicate map key " + JSON.stringify(key)); }
          map.set(key, item(depth + 1));
        }
        return map;
      }
      case 6: {
        var tag = readUint(ai);
        return { tag: tag, value: item(depth + 1) };
      }
      case 7: {
        if (ai === 20) { return false; }
        if (ai === 21) { return true; }
        if (ai === 22) { return null; }
        if (ai === 23) { return undefined; }
        if (ai === 25) { need(2); var h = (bytes[i] << 8) | bytes[i + 1]; i += 2; return half(h); }
        if (ai === 26) { need(4); var f32 = new DataView(bytes.buffer, bytes.byteOffset + i, 4).getFloat32(0); i += 4; return f32; }
        if (ai === 27) { need(8); var f64 = new DataView(bytes.buffer, bytes.byteOffset + i, 8).getFloat64(0); i += 8; return f64; }
        if (ai === 31) { throw new CBORError("a stray break byte at offset " + (i - 1)); }
        throw new CBORError("unsupported simple value " + ai, true);
      }
    }
    throw new CBORError("unreachable major type");
  }

  var value = item(0);
  if (i !== n) { throw new CBORError((n - i) + " trailing byte(s) after the CBOR item"); }
  return value;
};

// Offset just past the CBOR item that starts at `i`. Only called on bytes
// UC.cborDecode has already accepted, so it trusts definite lengths and does
// not re-check what the strict reader checked. Used to slice the exact bytes
// of a COSE_Sign1's elements, so nothing is re-encoded (and so nothing can
// change shape) when a statement is turned into its log entry.
UC.cborItemEnd = function (bytes, i) {
  var ib = bytes[i], mt = ib >> 5, ai = ib & 0x1f;
  var p = i + 1, n = 0;
  if (ai < 24) { n = ai; }
  else if (ai === 24) { n = bytes[p]; p += 1; }
  else if (ai === 25) { n = (bytes[p] << 8) | bytes[p + 1]; p += 2; }
  else if (ai === 26) { n = (((bytes[p] << 24) >>> 0) + (bytes[p + 1] << 16) + (bytes[p + 2] << 8) + bytes[p + 3]); p += 4; }
  else if (ai === 27) {
    if (mt === 2 || mt === 3 || mt === 4 || mt === 5) { throw new CBORError("a length too large to be real"); }
    p += 8;
  } else { throw new CBORError("unexpected additional information " + ai + " at offset " + i); }
  if (mt === 0 || mt === 1 || mt === 7) { return p; }
  if (mt === 2 || mt === 3) { return p + n; }
  if (mt === 6) { return UC.cborItemEnd(bytes, p); }
  var count = mt === 4 ? n : 2 * n;
  for (var k = 0; k < count; k++) { p = UC.cborItemEnd(bytes, p); }
  return p;
};

// ---- writer: only what Sig_structure needs (text, bytes, array) ----
function cborHead(mt, len) {
  if (len < 24) { return [(mt << 5) | len]; }
  if (len < 0x100) { return [(mt << 5) | 24, len]; }
  if (len < 0x10000) { return [(mt << 5) | 25, len >> 8, len & 0xff]; }
  return [(mt << 5) | 26, (len >>> 24) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff];
}

UC.cborEncode = function (v) {
  var out = [];
  function put(x) {
    if (x === null) {
      throw new CBORError("the Sig_structure writer was handed no payload");
    } else if (typeof x === "string") {
      var b = UC.utf8(x);
      out.push.apply(out, cborHead(3, b.length));
      for (var k = 0; k < b.length; k++) { out.push(b[k]); }
    } else if (UC.isBytes(x)) {
      out.push.apply(out, cborHead(2, x.length));
      for (var j = 0; j < x.length; j++) { out.push(x[j]); }
    } else if (Array.isArray(x)) {
      out.push.apply(out, cborHead(4, x.length));
      x.forEach(put);
    } else {
      throw new CBORError("the Sig_structure writer only handles text, bytes and arrays");
    }
  }
  put(v);
  return new Uint8Array(out);
};

// RFC 9052 s4.4: Sig_structure for COSE_Sign1.
UC.coseSign1ToBeSigned = function (protectedBytes, payloadBytes) {
  return UC.cborEncode(["Signature1", protectedBytes, new Uint8Array(0), payloadBytes]);
};

// ---- DER: the SubjectPublicKeyInfo of an X.509 certificate ----
// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
// tbsCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature,
//                               issuer, validity, subject, subjectPublicKeyInfo, ... }
UC.spkiFromCertificate = function (der) {
  function tlv(buf, off) {
    if (off + 2 > buf.length) { throw new CBORError("certificate DER ends early"); }
    var tag = buf[off];
    var len = buf[off + 1];
    var hl = 2;
    if (len & 0x80) {
      var nb = len & 0x7f;
      if (nb < 1 || nb > 4 || off + 2 + nb > buf.length) { throw new CBORError("certificate DER has a bad length"); }
      len = 0;
      for (var k = 0; k < nb; k++) { len = len * 256 + buf[off + 2 + k]; }
      hl = 2 + nb;
    }
    if (off + hl + len > buf.length) { throw new CBORError("certificate DER ends early"); }
    return { tag: tag, start: off, bodyStart: off + hl, end: off + hl + len };
  }
  var cert = tlv(der, 0);
  if (cert.tag !== 0x30 || cert.end !== der.length) { throw new CBORError("not a DER certificate"); }
  var tbs = tlv(der, cert.bodyStart);
  if (tbs.tag !== 0x30) { throw new CBORError("certificate has no tbsCertificate"); }
  var p = tbs.bodyStart;
  var el = tlv(der, p);
  if (el.tag === 0xa0) { p = el.end; }
  for (var s = 0; s < 5; s++) { p = tlv(der, p).end; } // serial, sigalg, issuer, validity, subject
  var spki = tlv(der, p);
  if (spki.tag !== 0x30) { throw new CBORError("certificate subjectPublicKeyInfo not found"); }
  return der.slice(spki.start, spki.end);
};
