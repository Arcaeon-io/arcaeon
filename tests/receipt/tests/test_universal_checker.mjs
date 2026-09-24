/**
 * test_universal_checker.mjs: FAILURE conformance for web/verify-any.html,
 * the universal checker. Does it refuse when handed a bad receipt, in every
 * format it claims to read?
 *
 * Mirrors private monorepo projects/arcaeon_site/tests/test_verify_receipt_conformance.mjs:
 * the code under test is the shipped code (every <script src> that
 * verify-any.html lists, in the page's own order, run under node:vm), the
 * fixtures were built by an independent generator (tools/make_universal_fixtures.mjs,
 * its own JCS, CBOR and DER writers, every signature re-checked by node:crypto),
 * and break arms run on every invocation: each arm swaps in a lying piece and
 * the suite MUST go red against it. A suite that stays green against a liar
 * cannot tell a checker from one that always says yes.
 *
 * Parts:
 *   1. spec vectors: RFC 8785 examples, the Agent Receipts did:key vectors,
 *      strict base64
 *   2. the conformance set: tests/fixtures/universal/manifest.json, every case
 *      at its expected verdict and detected format
 *   3. differential: verify-receipt.html's own verifyOneText, the universal
 *      Arcaeon arm and UC.verifyAny give the same verdict on every arc_*
 *      fixture and on a set of attachment edits made in memory
 *      (since the 2026-09-23 vocabulary pass both pages print VERIFIED/BROKEN/
 *      COULD NOT LOOK, so the words are compared as they are)
 *   4. README: every case id is listed with its expected verdict
 *   5. break arms: always-arcaeon detector, always-VERIFIED, signature check
 *      that always passes, a receipt proof verifier that returns the claimed
 *      root, a proof reader that takes an integral float as a uint (RFC 9942
 *      s5.2 says uint), lenient base64, an Arcaeon cross-check that always
 *      calls the witness block and signature consistent (caught by the set
 *      AND by the differential)
 *
 * Run:  node tests/test_universal_checker.mjs
 *       node tests/test_universal_checker.mjs --red always-arcaeon   (watch it go red)
 * Exit 0 = every case at its verdict and every break arm caught.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';
import { webcrypto, createHash } from 'node:crypto';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const WEB = join(ROOT, 'web');
const FIX = join(ROOT, 'tests', 'fixtures', 'universal');
const MANIFEST = JSON.parse(readFileSync(join(FIX, 'manifest.json'), 'utf8'));

const argv = process.argv.slice(2);
const redIdx = argv.indexOf('--red');
const RED = redIdx !== -1 ? argv[redIdx + 1] : null;

const LIARS = {
  // the detector the brief names: it always says our own format
  'always-arcaeon': 'UC.detectFormat = function (input) {' +
    ' var t = typeof input.text === "string" ? input.text : (UC.utf8DecodeStrict(input.bytes) || "");' +
    ' return { format: "arcaeon-receipt", text: t }; };',
  'always-verified': 'UC.verifyAny = async function () { return { format: null, verdict: "VERIFIED", reason: "", claims: [] }; };',
  'skip-signature': 'UC.verifySignature = async function () { return { ok: true }; };',
  // RFC 9942 s4.4's named failure: a proof verifier that hands back the root
  // the receipt claims instead of the one the path reaches. The signature then
  // checks over a root nobody recomputed.
  'claimed-root': 'UC.receiptRoot = async function (attachedRoot, leafHash, proof) { return { root: attachedRoot }; };',
  // RFC 9942 s5.2 says uint; the decoder turns 7.0 into 7, so a checker
  // that only asks Number.isInteger takes an integral float as a tree size.
  'float-as-uint': 'UC.proofUintCheck = function () { return null; };',
  // The disagreement slice 3 closed: an Arcaeon arm that checks only the body
  // digest and calls every witness block and attestation signature consistent.
  // Replaces the shared cross-check functions (crosscheck_pinned.js) by name.
  'always-consistent': 'checkWitness = async function () { return { verdict: "claimed", problems: [], pinSelf: "checked" }; };' +
    ' checkAttestationSignature = function () { return { verdict: "could_not_look", problems: [] }; };',
  'lenient-base64': 'UC.fromBase64 = function (s) { s = s.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");' +
    ' var B = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", out = [], buf = 0, bits = 0;' +
    ' for (var i = 0; i < s.length; i++) { buf = ((buf << 6) | B.indexOf(s[i])) & 0xffff; bits += 6;' +
    ' if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 255); } } return new Uint8Array(out); };',
};
if (RED && !LIARS[RED]) { console.error('unknown --red mode: ' + RED); process.exit(2); }

function pageScripts() {
  const html = readFileSync(join(WEB, 'verify-any.html'), 'utf8');
  const srcs = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
  if (srcs.length < 5) { throw new Error('verify-any.html lists too few scripts; stopping rather than testing nothing'); }
  return srcs;
}

function loadUC(liar) {
  // Only I/O-ish globals are passed in; builtins stay the vm's own, so every
  // byte string a test hands over crosses a realm, as a page's file read may.
  const ctx = { console, TextEncoder, TextDecoder };
  ctx.crypto = webcrypto;
  vm.createContext(ctx);
  for (const src of pageScripts()) {
    vm.runInContext(readFileSync(join(WEB, src), 'utf8'), ctx, { filename: src });
  }
  if (liar) { vm.runInContext(LIARS[liar], ctx); }
  return vm.runInContext('UC', ctx);
}

function readCaseInput(c) {
  const buf = readFileSync(join(FIX, c.file));
  return c.bytes ? { bytes: new Uint8Array(buf) } : { text: buf.toString('utf8') };
}
function optsFor(c) {
  const o = {};
  if (c.claimedFormat) o.claimedFormat = c.claimedFormat;
  if (c.publicKeyFile) o.publicKey = readFileSync(join(FIX, c.publicKeyFile), 'utf8');
  if (c.preimageFile) o.preimage = new Uint8Array(readFileSync(join(FIX, c.preimageFile)));
  if (c.detachedPayloadFile) o.detachedPayload = new Uint8Array(readFileSync(join(FIX, c.detachedPayloadFile)));
  if (c.receiptKeyFile) o.receiptKey = readFileSync(join(FIX, c.receiptKeyFile), 'utf8');
  if (c.statementFile) o.statement = new Uint8Array(readFileSync(join(FIX, c.statementFile)));
  return o;
}

// Runs the conformance set; returns a list of failure strings.
async function runCases(UC) {
  const fails = [];
  for (const c of MANIFEST.cases) {
    let res;
    try { res = await UC.verifyAny(readCaseInput(c), optsFor(c)); }
    catch (e) { fails.push(c.id + ': threw ' + e.message); continue; }
    if (res.verdict !== c.expect) { fails.push(c.id + ': expected ' + c.expect + ', got ' + res.verdict + ' (' + res.reason + ')'); continue; }
    if ((res.format || null) !== (c.format || null)) { fails.push(c.id + ': expected format ' + c.format + ', got ' + res.format); continue; }
    if (res.verdict !== 'VERIFIED' && !res.reason) { fails.push(c.id + ': a refusal with no reason'); }
    if (res.record !== 'BLIND') { fails.push(c.id + ': record axis is ' + res.record + ', not BLIND'); }
  }
  return fails;
}

let failures = 0;
function ok(cond, label) {
  if (cond) { console.log('  ok    ' + label); } else { failures++; console.log('  FAIL  ' + label); }
}

// ---------------------------------------------------------------- 1. spec vectors
async function specVectors(UC) {
  console.log('1. spec vectors');
  // RFC 8785 s3.2.2 / s3.2.3 (https://www.rfc-editor.org/rfc/rfc8785.html)
  const inText = '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],' +
    '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}';
  const want = '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],' +
    '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}';
  ok(UC.jcs(JSON.parse(inText)) === want, 'RFC 8785 s3.2.3 canonical output');
  const sortIn = JSON.parse('{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh",' +
    '"1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}');
  // read the order off the canonical TEXT: a JS object would move "1" first
  const order = [...UC.jcs(sortIn).matchAll(/:"([^"]*)"/g)].map((m) => m[1]);
  ok(JSON.stringify(order) === JSON.stringify(['Carriage Return', 'One', 'Control', 'Latin Small Letter O With Diaeresis',
    'Euro Sign', 'Emoji: Grinning Face', 'Hebrew Letter Dalet With Dagesh']), 'RFC 8785 s3.2.3 UTF-16 key order');
  // Agent Receipts did:key vectors (spec/test-vectors/did-key/vectors.json)
  const vec = [['d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw'],
    ['3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', 'did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT'],
    ['3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29', 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp']];
  vec.forEach(([hex, did], i) => {
    const r = UC.didKeyEd25519(did);
    ok(r.key && UC.hex(r.key) === hex, 'did:key vector ' + (i + 1));
  });
  ok(UC.didKeyEd25519('did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme').error !== undefined, 'a secp256k1 did:key is refused, not misread');
  ok(UC.fromBase64('QQ') !== null && UC.fromBase64('QR') === null, 'base64: non-zero leftover bits refused');

  // RFC 9162: the checker's s2.1.3.2 loop against this file's own s2.1.1 /
  // s2.1.3.1 recursion, every index of every tree size 1..33. A path one hash
  // short or long must be refused at every one of those positions too.
  const H = (...p) => createHash('sha256').update(Buffer.concat(p)).digest();
  const k2 = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
  const mth = (D) => D.length === 1 ? H(Buffer.from([0]), D[0]) : H(Buffer.from([1]), mth(D.slice(0, k2(D.length))), mth(D.slice(k2(D.length))));
  const path = (m, D) => D.length === 1 ? [] : (m < k2(D.length) ? [...path(m, D.slice(0, k2(D.length))), mth(D.slice(k2(D.length)))]
    : [...path(m - k2(D.length), D.slice(k2(D.length))), mth(D.slice(0, k2(D.length)))]);
  let agree = 0, total = 0, shapeOk = 0;
  for (let n = 1; n <= 33; n++) {
    const D = Array.from({ length: n }, (_, i) => Buffer.from('entry ' + i));
    const root = mth(D);
    for (let m = 0; m < n; m++) {
      total++;
      const p = path(m, D);
      const got = await UC.rfc9162RootFromPath(new Uint8Array(H(Buffer.from([0]), D[m])), m, n, p.map((x) => new Uint8Array(x)));
      if (got.root && Buffer.from(got.root).equals(root)) agree++;
      if (UC.rfc9162PathShape(m, n, p.length + 1) && (p.length === 0 || UC.rfc9162PathShape(m, n, p.length - 1))) shapeOk++;
    }
  }
  ok(agree === total, 'RFC 9162 inclusion: checker root equals the recursive MTH at every index of sizes 1..33 (' + agree + '/' + total + ')');
  ok(shapeOk === total, 'RFC 9162 inclusion: a path one hash long or short is refused at every position (' + shapeOk + '/' + total + ')');
}

// ---------------------------------------------------------------- 3. differential
function fakeDomContext() {
  class FakeEl {
    constructor() { this.children = []; this._text = ''; this.hidden = false; this.style = {}; this.className = ''; this.value = ''; this.classList = { add() {}, remove() {} }; }
    get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
    set textContent(v) { this._text = String(v); this.children = []; }
    get firstChild() { return this.children[0] || null; }
    appendChild(c) { this.children.push(c); return c; }
    removeChild(c) { this.children = this.children.filter((x) => x !== c); return c; }
    addEventListener() {}
    click() {}
  }
  const byId = new Map();
  const document = {
    getElementById(id) { if (!byId.has(id)) byId.set(id, new FakeEl()); return byId.get(id); },
    createElement() { return new FakeEl(); },
    createTextNode(t) { const e = new FakeEl(); e.textContent = t; return e; },
    addEventListener() {},
  };
  const ctx = { document, console, TextEncoder, Uint8Array, Map, Array, JSON, Promise,
    atob: (s) => Buffer.from(s, 'base64').toString('binary'), Blob: class {}, URL: { createObjectURL: () => 'blob:' },
    FileReader: class { readAsText() {} } };
  ctx.window = { crypto: webcrypto };
  vm.createContext(ctx);
  return { ctx, byId };
}

// Attachment edits made in memory on the Python-issued receipt, beyond the
// published fixtures: every shape the cross-checks distinguish, so the
// differential compares the two pages on more than the cases someone thought
// to write down.
function attachmentVariants() {
  const base = readFileSync(join(FIX, 'arc_valid.json'), 'utf8');
  const mut = (fn) => { const o = JSON.parse(base); fn(o); return JSON.stringify(o); };
  const D = JSON.parse(base).body_digest;
  return {
    'witness removed': mut((o) => { delete o.witness; }),
    'witness skipped': mut((o) => { o.witness = { status: 'skipped' }; }),
    'witness not an object': mut((o) => { o.witness = 'pinned'; }),
    'witness pin not an object': mut((o) => { o.witness.pin = 7; }),
    'witness pin removed': mut((o) => { delete o.witness.pin; }),
    'witness namespace edited': mut((o) => { o.witness.namespace = 'other'; }),
    'witness pin chain edited': mut((o) => { o.witness.pin.chain = '0'.repeat(32); }),
    'witness pin self edited': mut((o) => { o.witness.pin.self = '0'.repeat(32); }),
    'witness rows as float': mut((o) => { o.witness.rows = 1.0; }).replace('"rows":1,"chain":"72b53c7c5126a24614c09170fe48a928","pin"', '"rows":1.0,"chain":"72b53c7c5126a24614c09170fe48a928","pin"'),
    'witness relabelled hosted': mut((o) => { o.witness.kind = 'hosted'; o.witness.url = 'https://witness.example'; }),
    'ledger edited, witness skipped': mut((o) => { o.ledger.rows = 9999; o.witness = { status: 'skipped' }; }),
    'ledger removed': mut((o) => { delete o.ledger; }),
    'anchor forged': mut((o) => { o.anchor = { kind: 'opentimestamps', status: 'bitcoin-attested', ots_b64: 'AAAA' }; }),
    'signature not an object': mut((o) => { o.attestation_signature = 'sig'; }),
    'signature over another field': mut((o) => { o.attestation_signature = { signed_over: 'ledger', body_digest: D, value: 'x' }; }),
    'signature with no digest': mut((o) => { o.attestation_signature = { signed_over: 'body_digest', value: 'x' }; }),
    'signature ok, witness inconsistent': mut((o) => { o.attestation_signature = { signed_over: 'body_digest', body_digest: D, value: 'x' }; o.witness.rows = 2; }),
    'body tampered and witness inconsistent': mut((o) => { o.checks[0].score = 1; o.witness.rows = 2; }),
    'body overflow and witness inconsistent': mut((o) => { o.checks[0].weight = 1; o.witness.rows = 2; }).replace('"weight":1,', '"weight":1e999,'),
  };
}

async function verifyReceiptPage() {
  const html = readFileSync(join(WEB, 'verify-receipt.html'), 'utf8');
  const script = /<script>([\s\S]*?)<\/script>/.exec(html)[1];
  const { ctx } = fakeDomContext();
  vm.runInContext(script, ctx);
  return vm.runInContext('verifyOneText', ctx);
}

// The single-receipt view (runVerify), read off the verdict tag it renders on
// the body. Fresh page per call so no tag from an earlier run can linger.
async function singleViewVerdict(text) {
  const html = readFileSync(join(WEB, 'verify-receipt.html'), 'utf8');
  const script = /<script>([\s\S]*?)<\/script>/.exec(html)[1];
  const { ctx, byId } = fakeDomContext();
  vm.runInContext(script, ctx);
  await vm.runInContext('runVerify', ctx)(text);
  const tag = byId.get('verdict-body');
  return { verdict: tag ? tag.textContent : '', reason: (byId.get('verdict-body-reason') || { textContent: '' }).textContent };
}

// Every Arcaeon input through both pages: returns [label, old, new] where the
// two disagree. verifyAny is compared too, since that is what the page calls.
async function disagreements(UC, verifyOneText) {
  const words = new Set(['VERIFIED', 'BROKEN', 'COULD NOT LOOK']);
  const inputs = [];
  for (const c of MANIFEST.cases.filter((x) => x.id.startsWith('arc_'))) {
    inputs.push([c.id, readFileSync(join(FIX, c.file), 'utf8'), !c.claimedFormat && !c.publicKeyFile]);
  }
  for (const [k, text] of Object.entries(attachmentVariants())) { inputs.push(['variant: ' + k, text, true]); }
  const rows = [];
  for (const [label, text, viaAny] of inputs) {
    const said = (await verifyOneText('r.json', text)).verdict;
    const old = words.has(said) ? said : 'unknown word ' + said;
    const arm = (await UC.verifyArcaeon(text)).verdict;
    const any = viaAny ? (await UC.verifyAny({ text }, {})).verdict : arm;
    rows.push([label, old, arm, any]);
  }
  return rows;
}

async function differential(UC) {
  console.log('3. differential: every Arcaeon case, same verdict from verify-receipt.html verifyOneText and verify-any.html');
  const verifyOneText = await verifyReceiptPage();
  const rows = await disagreements(UC, verifyOneText);
  ok(rows.length >= 30, 'at least thirty Arcaeon inputs to compare (' + rows.length + ')');
  for (const [label, old, arm, any] of rows) {
    ok(old === arm && old === any, label + ': verify-receipt says ' + old + ', universal Arcaeon arm says ' + arm + ', verifyAny says ' + any);
  }
  // Not vacuous: some of those BROKENs come only from an attachment, with the
  // body digest matching.
  const attachFails = rows.filter(([l, old]) => old === 'BROKEN' && (/^arc_(witness|ledger|signature)/.test(l) || /^variant: (witness|signature|ledger)/.test(l)));
  ok(attachFails.length >= 6, 'at least six of them are refused only by an attachment cross-check (' + attachFails.length + ')');

  // An input the canonicalizer refuses: the single view, the batch view and
  // verify-any must say the same word. Before 2026-09-23 the single view said
  // BROKEN here while the other two said COULD NOT LOOK. The duplicate-key
  // input is the control: determined, so BROKEN in all three.
  const overflow = readFileSync(join(FIX, 'arc_float_overflow.json'), 'utf8');
  const c14nInputs = [
    ['arc_float_overflow (canonicalization refused)', overflow, 'COULD NOT LOOK'],
    ['score overflows to Infinity (canonicalization refused)', overflow.replace('"score": 88', '"score": 1e400'), 'COULD NOT LOOK'],
    ['duplicate key, first occurrence tampered (control)', readFileSync(join(FIX, 'arc_valid.json'), 'utf8').replace(/^{/, '{"kind": "tampered", '), 'BROKEN'],
  ];
  for (const [label, text, want] of c14nInputs) {
    const single = await singleViewVerdict(text);
    const batch = (await verifyOneText('r.json', text)).verdict;
    const any = (await UC.verifyAny({ text }, {})).verdict;
    ok(single.verdict === want && batch === want && any === want,
      label + ': single view says ' + single.verdict + ', batch says ' + batch + ', verifyAny says ' + any + ' (want ' + want + ')');
    if (want === 'COULD NOT LOOK') {
      ok(/canonicalize/.test(single.reason), label + ': single view states the reason (' + single.reason + ')');
    }
  }
  return verifyOneText;
}

// ---------------------------------------------------------------- main
async function main() {
  const UC = loadUC(RED);
  if (RED) {
    const f = await runCases(UC);
    console.log('--red ' + RED + ': ' + f.length + ' case(s) failed');
    f.forEach((x) => console.log('  FAIL  ' + x));
    process.exit(f.length ? 1 : 0);
  }

  await specVectors(UC);

  console.log('2. conformance set (' + MANIFEST.cases.length + ' cases)');
  const f = await runCases(UC);
  const failed = new Set(f.map((x) => x.split(':')[0]));
  for (const c of MANIFEST.cases) {
    ok(!failed.has(c.id), c.id + ' -> ' + c.expect + (c.notARefusal ? ' (not applicable, see README)' : ''));
  }
  f.forEach((x) => console.log('        ' + x));
  const refusals = MANIFEST.cases.filter((c) => c.expect !== 'VERIFIED').length;
  const formats = ['arcaeon-receipt', 'agent-receipts', 'scitt'];
  for (const fmt of formats) {
    const ids = MANIFEST.cases.filter((c) => c.format === fmt || (c.format === null && c.id.startsWith(fmt === 'agent-receipts' ? 'ar_' : fmt === 'scitt' ? 'scitt_' : 'arc_'))).map((c) => c.id);
    for (const kind of ['valid', 'tampered_payload', 'tampered_signature|tampered_seal', 'missing', 'wrong_key', 'truncated', 'wrong_format_claimed']) {
      ok(ids.some((id) => new RegExp('_(' + kind + ')').test(id)), fmt + ' has a ' + kind.split('|')[0] + ' case');
    }
  }

  // SCITT receipts: every failure the slice-2 brief names has a case
  const rids = MANIFEST.cases.map((c) => c.id).filter((id) => id.startsWith('scitt_receipt_') || id.startsWith('scitt_transparent_'));
  for (const kind of ['receipt_valid', 'tampered_path', 'wrong_leaf', 'truncated_proof', 'wrong_ts_key', 'other_statement', 'unsupported_vds',
    'transparent_valid', 'no_ts_key', 'no_statement']) {
    ok(rids.some((id) => id.includes(kind)), 'scitt receipts have a ' + kind + ' case');
  }

  const verifyOneText = await differential(UC);

  console.log('4. README lists every case');
  const readme = readFileSync(join(FIX, 'README.md'), 'utf8');
  for (const c of MANIFEST.cases) {
    const line = readme.split('\n').find((l) => l.startsWith('| `' + c.id + '` |'));
    ok(!!line && line.includes(c.expect), 'README: ' + c.id + ' with ' + c.expect);
  }

  console.log('5. break arms (each must turn the suite red)');
  for (const liar of Object.keys(LIARS)) {
    const bad = await runCases(loadUC(liar));
    ok(bad.length > 0, 'break arm ' + liar + ' caught: ' + bad.length + ' case(s) went red' +
      (bad.length ? ' (first: ' + bad[0] + ')' : ''));
  }
  // The claimed-root arm must be caught by a FALSE YES (a bad receipt called
  // VERIFIED), not only by crashing on detached roots: otherwise the attached-
  // root cases would be proving nothing.
  const cr = await runCases(loadUC('claimed-root'));
  ok(cr.some((x) => /expected BROKEN, got VERIFIED/.test(x)), 'break arm claimed-root is caught by a false VERIFIED on a BROKEN receipt (' +
    cr.filter((x) => /got VERIFIED/.test(x)).map((x) => x.split(':')[0]).join(', ') + ')');
  // The always-consistent arm is the bug slice 3 closed. It must be caught by
  // a false VERIFIED in the conformance set AND by the differential, which is
  // the test that was missing when verify-any said VERIFIED and
  // verify-receipt said FAIL.
  const ac = await runCases(loadUC('always-consistent'));
  ok(ac.some((x) => /expected BROKEN, got VERIFIED/.test(x)), 'break arm always-consistent is caught by a false VERIFIED on a BROKEN receipt (' +
    ac.filter((x) => /got VERIFIED/.test(x)).map((x) => x.split(':')[0]).join(', ') + ')');
  const acDiff = (await disagreements(loadUC('always-consistent'), verifyOneText)).filter(([, old, arm, any]) => old !== arm || old !== any);
  ok(acDiff.length > 0, 'break arm always-consistent is caught by the differential too: ' + acDiff.length + ' input(s) disagree (' +
    acDiff.map((r) => r[0]).slice(0, 4).join(', ') + (acDiff.length > 4 ? ', ...' : '') + ')');

  console.log('\n' + (failures ? failures + ' FAILED' : 'all ok') + '; ' + MANIFEST.cases.length + ' cases, ' + refusals + ' refusals');
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
