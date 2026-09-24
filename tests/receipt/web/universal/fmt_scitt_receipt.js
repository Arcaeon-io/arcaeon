/* universal/fmt_scitt_receipt.js: SCITT Receipts (RFC 9942 COSE Receipts),
 * with the inclusion proof recomputed and the tree head signature checked.
 *
 * Read from the live specs, 2026-09-22:
 *   https://www.rfc-editor.org/rfc/rfc9942.html (COSE Receipts)
 *     s4.3  receipts (394) carry [+ bstr .cbor Receipt]; Receipts MUST be
 *           tagged COSE_Sign1; the verifier MUST confirm the VDS and VDPs are
 *           in the registries
 *     s4.4  the payload SHOULD be detached: "Detached payloads force verifiers
 *           to recompute the root from the proof and protect against
 *           implementation errors where the signature is verified but the
 *           payload is incompatible with the proof"
 *     s5.1  RFC9162_SHA256 is VDS 1
 *     s5.2  inclusion proof = [tree-size: uint, leaf-index: uint,
 *           inclusion-path: [+ bstr]]; leaf_index >= tree_size fails
 *     s5.2.1 protected header REQUIRES alg (1) and vds (395); unprotected
 *           REQUIRES vdp (396) holding inclusion proofs at -1 (array of bstr);
 *           the payload is the Merkle Tree Hash; verification is (1) apply
 *           the proof to the bytes of a candidate entry, the resulting root
 *           becomes the COSE_Sign1 payload, then (2) check the signature
 *   https://www.rfc-editor.org/rfc/rfc9162.html (Merkle tree)
 *     s2.1.1 leaf hash HASH(0x00 || d), node hash HASH(0x01 || left || right)
 *     s2.1.3.2 the inclusion proof verification algorithm, step for step
 *   https://www.rfc-editor.org/rfc/rfc9943.html (SCITT architecture)
 *     s6.3 "the unprotected header of a Signed Statement MUST be set to an
 *           empty map before the Signed Statement can be included in a
 *           Statement Sequence"
 *   https://www.iana.org/assignments/cose/cose.xhtml: the VDS registry holds
 *     only 0 (reserved) and 1 (RFC9162_SHA256); the proofs registry holds -1
 *     (inclusion) and -2 (consistency) for VDS 1.
 *
 * THE ENTRY RULE (the one reading this page makes, stated so it can be
 * argued with): neither RFC 9942 nor RFC 9162 says which bytes of a SCITT
 * Signed Statement are the log entry. This page takes RFC 9943 s6.3 at its
 * word: the entry is the Signed Statement, byte for byte, with its
 * unprotected header replaced by an empty map (a0). The leaf is then
 * SHA-256(0x00 || entry). A transparency service that defines its entry some
 * other way will not verify here, and the page says which rule it used every
 * time a receipt fails, because from the bytes alone a wrong proof, a
 * different statement, a wrong key and a different entry rule all look the
 * same: the signature does not verify over the recomputed root.
 *
 * Not checked here, by construction: consistency proofs (-2; beside an
 * inclusion proof they get a NOT LOOKED row, alone the receipt is COULD NOT
 * LOOK), any VDS other
 * than 1 (CCF's draft profile uses 2, unregistered), receipts with more than
 * one inclusion proof, who the transparency service is (the key is the
 * reader's), and validity periods.
 */
"use strict";

UC.VDS_NAMES = { "1": "RFC9162_SHA256" };

// RFC 9162 s2.1.3.2, steps 1, 2, 4 and 5 without the hashing: does this path
// have exactly the length a tree of this size needs for this index? Returns
// null when it does, else the reason. Runs before any key or statement is
// needed, so a truncated proof is BROKEN even when nothing else was given.
UC.rfc9162PathShape = function (leafIndex, treeSize, pathLen) {
  if (leafIndex >= treeSize) { return "leaf index " + leafIndex + " is not below tree size " + treeSize + " (RFC 9162 s2.1.3.2 step 1)"; }
  var fn = leafIndex, sn = treeSize - 1;
  for (var k = 0; k < pathLen; k++) {
    if (sn === 0) { return "the path has " + pathLen + " hashes, more than a tree of size " + treeSize + " needs at index " + leafIndex; }
    if (fn % 2 === 1 || fn === sn) {
      if (fn % 2 === 0) { while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); } }
    }
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  if (sn !== 0) { return "the path has " + pathLen + " hashes, fewer than a tree of size " + treeSize + " needs at index " + leafIndex; }
  return null;
};

function concatBytes(parts) {
  var n = 0; parts.forEach(function (p) { n += p.length; });
  var out = new Uint8Array(n), o = 0;
  parts.forEach(function (p) { out.set(p, o); o += p.length; });
  return out;
}

UC.merkleLeafHash = async function (entry) {
  return UC.sha("SHA-256", concatBytes([new Uint8Array([0]), entry]));
};

// RFC 9162 s2.1.3.2, step 3 onward: the root this path reaches from this leaf.
// Returns {root} or {fail}. The shape was already checked; it is checked
// again here so this function is safe on its own.
UC.rfc9162RootFromPath = async function (leafHash, leafIndex, treeSize, path) {
  var shape = UC.rfc9162PathShape(leafIndex, treeSize, path.length);
  if (shape) { return { fail: shape }; }
  var one = new Uint8Array([1]);
  var fn = leafIndex, sn = treeSize - 1, r = leafHash;
  for (var k = 0; k < path.length; k++) {
    var p = path[k];
    if (fn % 2 === 1 || fn === sn) {
      r = await UC.sha("SHA-256", concatBytes([one, p, r]));
      if (fn % 2 === 0) { while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); } }
    } else {
      r = await UC.sha("SHA-256", concatBytes([one, r, p]));
    }
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return { root: r };
};

// The step the break arm replaces: from the receipt's payload (the attached
// root, or null when detached) and the recomputed path, the root the
// signature must be checked over. RFC 9942 s5.2.1 step 1.
UC.receiptRoot = async function (attachedRoot, leafHash, proof) {
  var got = await UC.rfc9162RootFromPath(leafHash, proof.leafIndex, proof.treeSize, proof.path);
  if (got.fail) { return got; }
  if (attachedRoot !== null && !UC.bytesEqual(attachedRoot, got.root)) {
    return { mismatch: "the receipt carries root " + UC.hex(attachedRoot) + ", but the path from this statement's leaf reaches " +
      UC.hex(got.root) + ". The receipt is about some other entry, or its proof was changed. Entry rule used: the statement with an " +
      "empty unprotected header (RFC 9943 s6.3)." };
  }
  return { root: got.root };
};

// The log entry for a Signed Statement: its own bytes with the unprotected
// header replaced by an empty map (RFC 9943 s6.3). Sliced, never re-encoded.
// statementBytes must already have passed UC.cborDecode as tag 18 around a
// four-element array, with the one-byte d2 84 head the detector requires.
UC.scittEntryBytes = function (statementBytes) {
  if (statementBytes[0] !== 0xd2 || statementBytes[1] !== 0x84) { throw new Error("the statement does not start d2 84"); }
  var s0 = 2, e0 = UC.cborItemEnd(statementBytes, s0);
  var e1 = UC.cborItemEnd(statementBytes, e0);
  var e2 = UC.cborItemEnd(statementBytes, e1);
  var e3 = UC.cborItemEnd(statementBytes, e2);
  if (e3 !== statementBytes.length) { throw new Error("the statement has bytes after its fourth element"); }
  return concatBytes([new Uint8Array([0xd2, 0x84]), statementBytes.slice(s0, e0), new Uint8Array([0xa0]),
    statementBytes.slice(e1, e2), statementBytes.slice(e2, e3)]);
};

// CBOR head length for an initial byte (1, 2, 3, 5 or 9 bytes).
function cborHeadLen(ib) { var ai = ib & 0x1f; return ai < 24 ? 1 : ai === 24 ? 2 : ai === 25 ? 3 : ai === 26 ? 5 : 9; }

// RFC 9942 s5.2 types tree-size and leaf-index as uint: CBOR major type 0.
// The decoder turns a float into a Number, and 7.0 into 7, so the check is
// made on the proof's own bytes: the first two items of its array must be
// major type 0. Returns null when they are, else the reason. proofBytes must
// already have decoded as a three-element array.
UC.proofUintCheck = function (proofBytes) {
  var o = cborHeadLen(proofBytes[0]);
  var names = ["tree size", "leaf index"];
  for (var k = 0; k < 2; k++) {
    var mt = proofBytes[o] >> 5;
    if (mt !== 0) {
      return names[k] + " is CBOR major type " + mt + (mt === 7 ? " (a float or simple value)" : "") +
        ", not an unsigned integer (major type 0), which RFC 9942 s5.2 requires (uint)";
    }
    o = UC.cborItemEnd(proofBytes, o);
  }
  return null;
};

// Parse one receipt as far as it can be read without an entry or a key.
// Returns {receipt} or {broken} or {cannot}.
UC.parseReceipt = function (bytes) {
  var top;
  try { top = UC.cborDecode(bytes); }
  catch (e) { return e.unsupported ? { cannot: "the receipt uses CBOR this checker does not read: " + e.message }
                                   : { broken: "the receipt's CBOR does not parse: " + e.message }; }
  if (!top || top.tag !== 18) { return { broken: "the receipt is not tagged 18 (COSE_Sign1), which RFC 9942 s4.3 requires" }; }
  var arr = top.value;
  if (!Array.isArray(arr) || arr.length !== 4) { return { broken: "the receipt is not a four-element COSE_Sign1" }; }
  var protBytes = arr[0], unprot = arr[1], payload = arr[2], sig = arr[3];
  if (!UC.isBytes(protBytes) || !(unprot instanceof Map) || !UC.isBytes(sig) || !(payload === null || UC.isBytes(payload))) {
    return { broken: "the receipt's COSE_Sign1 elements have the wrong types" };
  }
  var prot;
  try { prot = protBytes.length ? UC.cborDecode(protBytes) : new Map(); }
  catch (e2) { return e2.unsupported ? { cannot: "the receipt's protected header uses CBOR this checker does not read" }
                                     : { broken: "the receipt's protected header does not parse: " + e2.message }; }
  if (!(prot instanceof Map)) { return { broken: "the receipt's protected header is not a map" }; }
  if (!prot.has(1) || typeof prot.get(1) !== "number") { return { broken: "the receipt's protected header has no integer alg (label 1), which RFC 9942 s5.2.1 requires" }; }
  if (!prot.has(395) || typeof prot.get(395) !== "number") { return { broken: "the receipt's protected header has no integer vds (label 395), which RFC 9942 s5.2.1 requires" }; }
  if (unprot.has(395)) { return { broken: "vds (395) sits in the unprotected header, where anyone could change it" }; }
  var vds = prot.get(395);
  if (!UC.VDS_NAMES[String(vds)]) {
    return { cannot: "the receipt uses verifiable data structure " + vds + ". This page runs only RFC9162_SHA256 (1), the one the IANA " +
      "registry holds; 2 is the CCF ledger profile, still an Internet-Draft. It was not read as a format it is not." };
  }
  var vdp = unprot.get(396);
  if (!(vdp instanceof Map)) { return { broken: "the receipt has no proofs map (vdp, label 396), which RFC 9942 s5.2.1 requires" }; }
  if (!vdp.has(-1)) {
    if (vdp.has(-2)) { return { cannot: "the receipt carries only consistency proofs (-2); this page checks inclusion proofs, not consistency" }; }
    return { broken: "the proofs map has no inclusion proofs (-1), which RFC 9942 s5.2.1 requires" };
  }
  var list = vdp.get(-1);
  if (!Array.isArray(list) || list.length === 0 || !list.every(UC.isBytes)) {
    return { broken: "inclusion proofs (-1) is not a non-empty array of byte strings" };
  }
  if (list.length > 1) {
    return { cannot: "the receipt carries " + list.length + " inclusion proofs under one signature; this page checks receipts with exactly one" };
  }
  var content;
  try { content = UC.cborDecode(list[0]); }
  catch (e3) { return { broken: "the inclusion proof does not parse: " + e3.message }; }
  if (!Array.isArray(content) || content.length !== 3 || !Array.isArray(content[2])) {
    return { broken: "the inclusion proof is not [tree-size, leaf-index, [path]] (RFC 9942 s5.2)" };
  }
  var notUint = UC.proofUintCheck(list[0]);
  if (notUint) { return { broken: "the inclusion proof's " + notUint }; }
  if (!Number.isInteger(content[0]) || !Number.isInteger(content[1]) || content[0] < 0 || content[1] < 0) {
    return { broken: "the inclusion proof's tree size and leaf index are not unsigned integers this page can count to (RFC 9942 s5.2)" };
  }
  var path = content[2];
  if (path.length === 0 && content[0] !== 1) {
    return { broken: "the inclusion path is empty, which only a one-leaf tree allows; this tree has size " + content[0] };
  }
  for (var k = 0; k < path.length; k++) {
    if (!UC.isBytes(path[k]) || path[k].length !== 32) { return { broken: "inclusion path hash " + (k + 1) + " is not 32 bytes (SHA-256)" }; }
  }
  if (payload !== null && payload.length !== 32) { return { broken: "the receipt's attached root is " + payload.length + " bytes, not a 32-byte SHA-256 tree hash" }; }
  var shape = UC.rfc9162PathShape(content[1], content[0], path.length);
  if (shape) { return { broken: "the inclusion proof does not fit its own tree: " + shape }; }
  var cwt = prot.get(15);
  var otherProofs = [];
  vdp.forEach(function (v, k) { if (k !== -1) { otherProofs.push(k); } });
  return { receipt: { otherProofs: otherProofs, protBytes: protBytes, prot: prot, alg: prot.get(1), vds: vds, payload: payload, sig: sig,
    proof: { treeSize: content[0], leafIndex: content[1], path: path },
    iss: (cwt instanceof Map && typeof cwt.get(1) === "string") ? cwt.get(1) : null } };
};

// Check one receipt against one entry and one supplied key. `label` prefixes
// every claim name. Returns claims (all core) for this receipt.
UC.checkReceipt = async function (receiptBytes, entryBytes, keyText, label, noEntryWhy) {
  var L = label ? label + ": " : "";
  var p = UC.parseReceipt(receiptBytes);
  if (p.broken) { return [UC.claim(L + "receipt structure", UC.BROKEN, p.broken, true)]; }
  if (p.cannot) { return [UC.claim(L + "receipt structure", UC.COULD_NOT_LOOK, p.cannot, true)]; }
  var r = p.receipt;
  var claims = [UC.claim(L + "receipt structure", UC.VERIFIED, "tag 18 COSE_Sign1; vds " + r.vds + " (" + UC.VDS_NAMES[String(r.vds)] +
    "); one inclusion proof claiming tree size " + r.proof.treeSize + " and leaf index " + r.proof.leafIndex +
    " (unsigned claims from the receipt's unprotected header; the root is what is signed), " + r.proof.path.length +
    " path hashes; root " + (r.payload ? "attached" : "detached") + (r.iss ? "; service says it is " + JSON.stringify(r.iss) : ""), true)];
  r.otherProofs.forEach(function (k) {
    var what = k === -2 ? "a consistency proof (-2)" : "proofs under label " + k + " (not a proof type the IANA registry names for vds 1)";
    claims.push(UC.claim(L + "other proofs", UC.NOT_LOOKED, "the proofs map also carries " + what + " beside the inclusion proof; " +
      "this page checks the inclusion proof only, so that one was not looked at"));
  });

  if (!entryBytes) {
    claims.push(UC.claim(L + "inclusion", UC.COULD_NOT_LOOK, noEntryWhy || ("a receipt proves some entry is in a log; supply the " +
      "Signed Statement it claims to include, so there is an entry to recompute the root from"), true));
    return claims;
  }
  var leaf = await UC.merkleLeafHash(entryBytes);
  var got = await UC.receiptRoot(r.payload, leaf, r.proof);
  if (got.fail) { claims.push(UC.claim(L + "inclusion", UC.BROKEN, got.fail, true)); return claims; }
  if (got.mismatch) { claims.push(UC.claim(L + "inclusion", UC.BROKEN, got.mismatch, true)); return claims; }
  var rootNote = "leaf SHA-256(0x00 || statement with an empty unprotected header) = " + UC.hex(leaf) +
    "; the path reaches root " + UC.hex(got.root) + (r.payload ? ", equal to the root the receipt carries" : "");

  var algSpec = UC.COSE_ALGS[String(r.alg)];
  if (!algSpec) {
    claims.push(UC.claim(L + "inclusion", UC.COULD_NOT_LOOK, rootNote + ". The tree head is signed with algorithm " + r.alg +
      ", which a browser's WebCrypto does not run, so whether the service signed that root was not looked at", true));
    return claims;
  }
  var key = UC.parseSuppliedKey(keyText);
  if (!key) {
    claims.push(UC.claim(L + "inclusion", UC.COULD_NOT_LOOK, rootNote + ". No transparency service key was supplied, so whether the " +
      "service signed that root was not looked at. A receipt carries no key of its own worth trusting; supply the service's public key.", true));
    return claims;
  }
  if (key.error) { claims.push(UC.claim(L + "inclusion", UC.COULD_NOT_LOOK, "transparency service key: " + key.error, true)); return claims; }
  var res = await UC.verifySignature(algSpec, key, r.sig, UC.coseSign1ToBeSigned(r.protBytes, got.root));
  if (res.cannot) { claims.push(UC.claim(L + "inclusion", UC.COULD_NOT_LOOK, res.cannot, true)); return claims; }
  if (res.ok) {
    claims.push(UC.claim(L + "inclusion", UC.VERIFIED, rootNote + ". " + algSpec.name + " over that root verifies under the transparency " +
      "service key you supplied: the service signed a tree that contains this statement. Tree size and leaf index are the receipt's " +
      "unsigned claims; the root is what is signed.", true));
  } else {
    claims.push(UC.claim(L + "inclusion", UC.BROKEN, "the " + algSpec.name + " signature does not verify over the root recomputed " +
      "from this statement (" + UC.hex(got.root) + ") under the key you supplied. The proof, the statement, or the key is not what the " +
      "service signed; the bytes cannot say which. Entry rule used: the statement with an empty unprotected header (RFC 9943 s6.3).", true));
  }
  return claims;
};

// A standalone receipt. opts.statement = the Signed Statement's bytes,
// opts.receiptKey = the transparency service's public key.
UC.verifyScittReceipt = async function (bytes, opts) {
  var F = "scitt-receipt";
  opts = opts || {};
  var entry = null, noEntryWhy = null;
  var extra = [];
  if (UC.isBytes(opts.statement)) {
    var st = UC.readStatementForEntry(opts.statement);
    if (st.cannot) { noEntryWhy = "the file you supplied as the statement could not be read as one: " + st.cannot; }
    else { entry = st.entry; }
  }
  var claims = await UC.checkReceipt(bytes, entry, opts.receiptKey, "", noEntryWhy);
  extra.push(UC.claim("statement signature", UC.NOT_LOOKED, "a receipt shows the service logged the statement, not that its issuer " +
    "signed it; check the statement itself (with its receipt attached, or on its own) for the issuer's signature"));
  extra.push(UC.claim("service identity", UC.NOT_LOOKED, UC.parseSuppliedKey(opts.receiptKey) !== null
    ? "the key is the one you supplied; this page cannot say it belongs to the service it names"
    : "no transparency service key was supplied, so no key was tied to the service it names"));
  return UC.finish(F, claims.concat(extra));
};

// A supplied statement, checked only far enough to cut its entry out.
UC.readStatementForEntry = function (bytes) {
  if (!(bytes.length >= 2 && bytes[0] === 0xd2 && bytes[1] === 0x84)) {
    return { cannot: "it is not a tagged COSE_Sign1 (it does not start d2 84)" };
  }
  var top;
  try { top = UC.cborDecode(bytes); }
  catch (e) { return { cannot: "its CBOR does not parse (" + e.message + ")" }; }
  if (!top || top.tag !== 18 || !Array.isArray(top.value) || top.value.length !== 4) { return { cannot: "it is not a four-element COSE_Sign1" }; }
  try { return { entry: UC.scittEntryBytes(bytes) }; }
  catch (e2) { return { cannot: e2.message }; }
};

// The receipts a Signed Statement carries at 394, checked against the
// statement they are attached to. Returns claims: one core claim for the
// set, plus rows per receipt.
UC.scittReceiptClaims = async function (statementBytes, prot, unprot, opts) {
  if (prot && prot.has(394)) {
    return [UC.claim("transparency receipt", UC.COULD_NOT_LOOK, "receipts (394) sit in the protected header; this page reads them " +
      "only where RFC 9943 puts them, the unprotected header", true)];
  }
  if (!unprot || !unprot.has(394)) {
    return [UC.claim("transparency receipt", UC.NOT_LOOKED, "no Receipt attached: nothing shows this statement was ever registered")];
  }
  var list = unprot.get(394);
  if (!Array.isArray(list) || list.length === 0 || !list.every(UC.isBytes)) {
    return [UC.claim("transparency receipt", UC.BROKEN, "receipts (394) is not a non-empty array of byte strings (RFC 9942 s4.3)", true)];
  }
  var entry;
  try { entry = UC.scittEntryBytes(statementBytes); }
  catch (e) { return [UC.claim("transparency receipt", UC.COULD_NOT_LOOK, "the log entry could not be cut from this statement: " + e.message, true)]; }
  var per = [];
  for (var i = 0; i < list.length; i++) {
    per.push(await UC.checkReceipt(list[i], entry, opts.receiptKey, list.length > 1 ? "receipt " + (i + 1) : "receipt"));
  }
  function outcome(cs) {
    if (cs.some(function (c) { return c.result === UC.BROKEN; })) { return UC.BROKEN; }
    var core = cs.filter(function (c) { return c.core; });
    return core.length && core.every(function (c) { return c.result === UC.VERIFIED; }) ? UC.VERIFIED : UC.COULD_NOT_LOOK;
  }
  var outs = per.map(outcome);
  var good = outs.indexOf(UC.VERIFIED);
  var rows;
  if (good >= 0) {
    // RFC 9943 s7.1: a Relying Party MAY verify only a single Receipt that is
    // acceptable to them. One that verifies under the reader's key is enough;
    // the others become coverage rows, not a verdict.
    rows = [UC.claim("transparency receipt", UC.VERIFIED, (list.length > 1 ? "receipt " + (good + 1) + " of " + list.length : "the receipt") +
      " proves inclusion under the transparency service key you supplied", true)];
    per.forEach(function (cs, i) {
      cs.forEach(function (c) {
        rows.push(i === good ? UC.claim(c.name, c.result, c.detail, false)
          : UC.claim(c.name, UC.NOT_LOOKED, "not counted: another receipt verified, and this one may be another service's (" + c.result + ": " + c.detail + ")", false));
      });
    });
    return rows;
  }
  // None verified: every row counts. A BROKEN one breaks the run.
  rows = [];
  per.forEach(function (cs) { cs.forEach(function (c) { rows.push(c); }); });
  return rows;
};
