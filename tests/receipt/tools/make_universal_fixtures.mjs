/**
 * make_universal_fixtures.mjs: writes tests/fixtures/universal/, the
 * failure-first conformance set for web/verify-any.html.
 *
 * Uses node:crypto only (built in; nothing installed, nothing downloaded).
 * Deliberately shares NO code with web/universal/: its own JCS, its own CBOR
 * writer, its own DER writer. A checker that agrees with itself cannot bless
 * these, and every signature is re-checked here with node:crypto before a file
 * is written.
 *
 * Keys are published test keys, so anyone can rebuild the set:
 *   Ed25519: RFC 8032 s7.1 TEST 1 and TEST 2 secret keys
 *            (https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1),
 *            whose public keys are also the Agent Receipts did:key vectors 1-2
 *            (https://raw.githubusercontent.com/agent-receipts/obsigna/main/spec/test-vectors/did-key/vectors.json)
 *   P-256:   RFC 7515 Appendix A.3 ES256 example key
 *            (https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.3)
 *   The one "wrong" P-256 key is random and only its public half is kept.
 *   Transparency service (SCITT receipts): P-256 whose private scalar is the
 *            SHA-256 of a fixed string written below, so it is rebuildable.
 *
 * Run: node tools/make_universal_fixtures.mjs
 * ECDSA signatures are randomized, so re-running changes the SCITT ES256 bytes;
 * the expected verdicts do not change.
 */
import crypto from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'tests', 'fixtures', 'universal');
mkdirSync(OUT, { recursive: true });

const cases = [];
function put(name, data) { writeFileSync(join(OUT, name), data); return name; }
function kase(c) { cases.push(c); }

// ------------------------------------------------------------------ keys
const ED1_SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const ED1_PUB = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const ED2_SEED = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';
const ED2_PUB = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';
const DIDKEY1 = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw';
const DIDKEY2 = 'did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT';

function edKey(seedHex) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]);
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}
const ED1 = edKey(ED1_SEED), ED2 = edKey(ED2_SEED);
for (const [k, pub] of [[ED1, ED1_PUB], [ED2, ED2_PUB]]) {
  const raw = crypto.createPublicKey(k).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  if (raw !== pub) { throw new Error('RFC 8032 key derivation mismatch'); }
}
const P256_JWK = { kty: 'EC', crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI' };
const P256 = crypto.createPrivateKey({ key: P256_JWK, format: 'jwk' });
const P256_PUB_JWK = { kty: 'EC', crv: 'P-256', x: P256_JWK.x, y: P256_JWK.y };
const WRONG_P256_PUB_JWK = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });

put('key_ed25519_test1.txt', ED1_PUB + '\n');
put('key_ed25519_test2.txt', ED2_PUB + '\n');
put('key_p256_rfc7515.jwk', JSON.stringify(P256_PUB_JWK) + '\n');
put('key_p256_wrong.jwk', JSON.stringify(WRONG_P256_PUB_JWK) + '\n');

// ------------------------------------------------------------------ JCS (own copy)
function jcs(v) {
  if (v === null || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'number') return String(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}

// ------------------------------------------------------------------ Arcaeon (issued by the Python tool)
// Issued by arcaeon_receipt.core.build_receipt, 2026-09-22; the same text as
// private monorepo projects/arcaeon_site/tests/test_verify_receipt_conformance.mjs
// HONEST. tests/test_universal_checker.py re-verifies it with the Python
// verify_receipt, so the page's own canonicalizer is not its only witness.
const HONEST = '{"receipt_version": "arcaeon-receipt/0.1", "kind": "conformance", "issued_at": "2026-09-22T12:00:00Z", "subject": {"trainee": "t. a", "scenario": "s1"}, "checks": [{"name": "c1", "score": 88, "weight": 0.32, "verdict": "PASS"}], "scope": {"proves": ["p"], "does_not_prove": ["q"]}, "extra": {}, "body_digest": "sha256:json-c14n:v1:c50076abd58066846165f1aca264150d7f439758d80f33648b574e7dfb85720f", "ledger": {"path": "x.ledger.jsonl", "namespace": "conf", "rows": 1, "chain": "72b53c7c5126a24614c09170fe48a928", "algorithm": "truncated_sha256_128 hash chain (arcaeon-ledger)"}, "witness": {"kind": "local-file", "independence": "none (self-controlled file)", "path": "x.ledger.jsonl.witness.jsonl", "namespace": "conf", "rows": 1, "chain": "72b53c7c5126a24614c09170fe48a928", "pin": {"namespace": "conf", "rows": 1, "chain": "72b53c7c5126a24614c09170fe48a928", "as_of": "2026-09-23T01:28:32Z", "received_at": "2026-09-23T01:28:32Z", "prev": "witness-genesis", "self": "fa334ca1cccabb7db5ff8e58b523bc36"}, "status": "pinned"}, "anchor": {"status": "skipped"}}';
const A = 'arcaeon-receipt';
kase({ id: 'arc_valid', file: put('arc_valid.json', HONEST), format: A, expect: 'VERIFIED',
  why: 'issued by the Python tool; the seven body fields hash to body_digest' });
kase({ id: 'arc_tampered_payload', file: put('arc_tampered_payload.json', HONEST.replace('"score": 88', '"score": 89')), format: A, expect: 'BROKEN',
  why: 'a body field changed after issue' });
kase({ id: 'arc_tampered_seal', file: put('arc_tampered_seal.json', HONEST.replace('85720f"', '85720e"')), format: A, expect: 'BROKEN',
  why: 'this format has no signature; its seal is body_digest, and one hex digit of it changed' });
{ const o = JSON.parse(HONEST); delete o.body_digest;
  kase({ id: 'arc_missing_required', file: put('arc_missing_required.json', JSON.stringify(o)), format: A, expect: 'BROKEN',
    why: 'body_digest removed (the required seal)' }); }
kase({ id: 'arc_truncated', file: put('arc_truncated.json', HONEST.slice(0, Math.floor(HONEST.length / 2))), format: null, expect: 'COULD NOT LOOK',
  why: 'half the bytes: no longer JSON, so no format is recognized' });
kase({ id: 'arc_wrong_format_claimed', file: 'arc_valid.json', format: A, claimedFormat: 'scitt', expect: 'COULD NOT LOOK',
  why: 'the reader said SCITT; it reads as an Arcaeon receipt' });
kase({ id: 'arc_duplicate_key', file: put('arc_duplicate_key.json', HONEST.replace('"kind": "conformance",', '"kind": "conformance", "kind": "other",')), format: A, expect: 'BROKEN',
  why: 'a repeated key reads one way to a first-wins parser and another to a last-wins one' });
kase({ id: 'arc_float_overflow', file: put('arc_float_overflow.json', HONEST.replace('"weight": 0.32', '"weight": 1e999')), format: A, expect: 'COULD NOT LOOK',
  why: 'json-c14n v1 cannot canonicalize a float that overflows; could not look, never a pass' });
kase({ id: 'arc_wrong_key', file: 'arc_valid.json', format: A, publicKeyFile: 'key_ed25519_test2.txt', expect: 'VERIFIED', notARefusal: true,
  why: 'NOT APPLICABLE by construction: this format carries no signature, so a supplied key is ignored; listed so the gap is visible, not hidden' });
// Attachments outside the body digest (slice 3, 2026-09-22). The body stays the
// Python-issued one, so body_digest still matches: only the cross-checks that
// verify-receipt.html runs (and verify-any.html now shares) can say no.
{ const o = JSON.parse(HONEST); o.witness.rows = 9999; o.witness.chain = 'f'.repeat(32); o.witness.pin.rows = 9999;
  kase({ id: 'arc_witness_inconsistent', file: put('arc_witness_inconsistent.json', JSON.stringify(o)), format: A, expect: 'BROKEN',
    why: 'the body digest matches, but the witness block and its pin were edited to another ledger head, so they contradict the ledger block' }); }
{ const o = JSON.parse(HONEST); o.witness.pin.as_of = '2020-01-01T00:00:00Z';
  kase({ id: 'arc_witness_pin_self_mismatch', file: put('arc_witness_pin_self_mismatch.json', JSON.stringify(o)), format: A, expect: 'BROKEN',
    why: 'one field of the witness pin edited; only its own self digest, recomputed with the Python recipe, sees it' }); }
{ const o = JSON.parse(HONEST); o.ledger.rows = 9999; o.ledger.chain = 'f'.repeat(32);
  kase({ id: 'arc_ledger_edited_witnessed', file: put('arc_ledger_edited_witnessed.json', JSON.stringify(o)), format: A, expect: 'BROKEN',
    why: 'the ledger claim edited on a witnessed receipt: the witness block taken of the same head now disagrees with it' }); }
{ const o = JSON.parse(HONEST); o.attestation_signature = { algorithm: 'unspecified', signed_over: 'body_digest', body_digest: 'sha256:json-c14n:v1:' + '0'.repeat(64), value: 'forged' };
  kase({ id: 'arc_signature_mismatch', file: put('arc_signature_mismatch.json', JSON.stringify(o)), format: A, expect: 'BROKEN',
    why: 'an attestation signature that names another body digest does not belong to this receipt' }); }
{ const o = JSON.parse(HONEST); o.attestation_signature = { algorithm: 'ed25519', signed_over: 'body_digest', body_digest: o.body_digest, value: 'forged' };
  kase({ id: 'arc_signature_value_unchecked', file: put('arc_signature_value_unchecked.json', JSON.stringify(o)), format: A, expect: 'VERIFIED', notARefusal: true,
    why: 'NOT APPLICABLE by construction: the signature names this digest and its value is forged, but the format carries no key or scheme, so the value is COULD NOT LOOK on its own row and the body still verifies; listed so the gap is visible, not hidden' }); }

// ------------------------------------------------------------------ Agent Receipts
// Built from spec v0.5.0 s4.1's own example, verbatim except verificationMethod
// (did:agent is unresolvable, spec s9.6) and proofValue (the example's value is
// not a signature by any published key).
const SPEC_EXAMPLE = {
  '@context': ['https://www.w3.org/ns/credentials/v2', 'https://agentreceipts.ai/context/v2'],
  id: 'urn:receipt:550e8400-e29b-41d4-a716-446655440000',
  type: ['VerifiableCredential', 'AgentReceipt'],
  version: '0.5.0',
  issuer: { id: 'did:agent:claude-cowork-instance-abc123', type: 'AIAgent', name: 'Claude Cowork',
    operator: { id: 'did:org:anthropic', name: 'Anthropic' }, model: 'claude-sonnet-4-6', session_id: 'session_xyz789',
    runtime: { agent_id: 'a3e49db54342a92d4', agent_type: 'general-purpose' } },
  issuanceDate: '2026-03-31T14:30:00Z',
  credentialSubject: {
    principal: { id: 'did:user:otto-abc', type: 'HumanPrincipal' },
    action: { id: 'act_7f3a1b2c-d4e5-46f7-a8b9-c0d1e2f3a4b5', type: 'communication.email.send', risk_level: 'high',
      target: { system: 'mail.google.com', resource: 'email:compose' },
      parameters_hash: 'sha256:a3f1c2d4e5b6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1d6',
      timestamp: '2026-03-31T14:30:00Z', trusted_timestamp: null },
    intent: { conversation_hash: 'sha256:b4e2d1f3a5c6b7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1e7',
      prompt_preview: 'Send the Q3 report to the team', prompt_preview_truncated: true,
      reasoning_hash: 'sha256:c5f3e2d4a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2f8' },
    outcome: { status: 'success', error: null, reversible: true, reversal_method: 'gmail:undo_send', reversal_window_seconds: 30,
      state_change: { before_hash: 'sha256:d604f3e5a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3a9',
        after_hash: 'sha256:e7a504f6a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4ba' } },
    authorization: { scopes: ['email:send', 'drive:read'], granted_at: '2026-03-31T14:00:00Z', expires_at: '2026-03-31T15:00:00Z', grant_ref: null },
    chain: { sequence: 1, previous_receipt_hash: null, chain_id: 'chain_session_xyz789' } },
  proof: { type: 'Ed25519Signature2020', created: '2026-03-31T14:30:01Z',
    verificationMethod: 'did:agent:claude-cowork-instance-abc123#key-1', proofPurpose: 'assertionMethod',
    proofValue: 'ul_wFLgGWlzFaYt2ckT4wZfoeRa7ZqL0tt3y10dgr7FdsVMivs5tc9ZrUYBJ_FKEE4aFApeAzPH6jp57irtgDCw' } };

function arSign(receipt, key, did) {
  const r = JSON.parse(JSON.stringify(receipt));
  r.proof.verificationMethod = did + '#' + did.slice('did:key:'.length);
  const unsigned = { ...r }; delete unsigned.proof;
  const msg = Buffer.from(jcs(unsigned), 'utf8');
  const sig = crypto.sign(null, msg, key);
  r.proof.proofValue = 'u' + sig.toString('base64url');
  if (!crypto.verify(null, msg, crypto.createPublicKey(key), sig)) throw new Error('self-check failed');
  return r;
}
const R = 'agent-receipts';
const AR_VALID = arSign(SPEC_EXAMPLE, ED1, DIDKEY1);
const arText = (o) => JSON.stringify(o, null, 2);
kase({ id: 'ar_valid_didkey', file: put('ar_valid_didkey.json', arText(AR_VALID)), format: R, expect: 'VERIFIED',
  why: 'spec s4.1 example, signed with the RFC 8032 TEST 1 key, named by its did:key (vector 1)' });
kase({ id: 'ar_valid_supplied_key', file: 'ar_valid_didkey.json', format: R, publicKeyFile: 'key_ed25519_test1.txt', expect: 'VERIFIED',
  why: 'the same receipt with the matching key supplied by the reader' });
kase({ id: 'ar_spec_example_verbatim', file: put('ar_spec_example_verbatim.json', arText(SPEC_EXAMPLE)), format: R, expect: 'COULD NOT LOOK',
  why: 'the spec example exactly as published: did:agent cannot be resolved in a browser, so the signature is not looked at' });
{ const t = JSON.parse(JSON.stringify(AR_VALID)); t.credentialSubject.outcome.status = 'failure';
  kase({ id: 'ar_tampered_payload', file: put('ar_tampered_payload.json', arText(t)), format: R, expect: 'BROKEN',
    why: 'outcome.status changed from success to failure after signing' }); }
{ const t = JSON.parse(JSON.stringify(AR_VALID));
  const b = Buffer.from(t.proof.proofValue.slice(1), 'base64url'); b[10] ^= 0x01;
  t.proof.proofValue = 'u' + b.toString('base64url');
  kase({ id: 'ar_tampered_signature', file: put('ar_tampered_signature.json', arText(t)), format: R, expect: 'BROKEN',
    why: 'one bit of the signature flipped' }); }
{ const t = JSON.parse(JSON.stringify(AR_VALID));
  const last = t.proof.proofValue.slice(-1);
  const alph = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const idx = alph.indexOf(last);
  t.proof.proofValue = t.proof.proofValue.slice(0, -1) + alph[idx ^ 0x01];
  const same = Buffer.from(t.proof.proofValue.slice(1), 'base64url').equals(Buffer.from(AR_VALID.proof.proofValue.slice(1), 'base64url'));
  kase({ id: 'ar_tampered_signature_padding_bits', file: put('ar_tampered_signature_padding_bits.json', arText(t)), format: R, expect: 'BROKEN',
    why: 'only the unused low bits of the last base64url character changed' + (same ? ' (a lenient decoder yields the SAME signature bytes, so it would say VERIFIED over edited text)' : '') }); }
{ const t = JSON.parse(JSON.stringify(AR_VALID)); delete t.proof.proofPurpose;
  kase({ id: 'ar_missing_required', file: put('ar_missing_required.json', arText(t)), format: R, expect: 'BROKEN',
    why: 'proof.proofPurpose removed; the schema requires all five proof fields' }); }
{ const t = JSON.parse(JSON.stringify(AR_VALID)); delete t.credentialSubject.chain.previous_receipt_hash;
  kase({ id: 'ar_missing_required_nullable', file: put('ar_missing_required_nullable.json', arText(t)), format: R, expect: 'BROKEN',
    why: 'chain.previous_receipt_hash removed; it is required even when null' }); }
{ const t = JSON.parse(JSON.stringify(AR_VALID)); t.proof.verificationMethod = DIDKEY2 + '#' + DIDKEY2.slice(8);
  kase({ id: 'ar_wrong_key_named', file: put('ar_wrong_key_named.json', arText(t)), format: R, expect: 'BROKEN',
    why: 'signed by TEST 1 but names the TEST 2 did:key (vector 2)' }); }
kase({ id: 'ar_wrong_key_supplied', file: 'ar_valid_didkey.json', format: R, publicKeyFile: 'key_ed25519_test2.txt', expect: 'BROKEN',
  why: 'the reader supplies the TEST 2 key for a TEST 1 signature' });
{ const s = arText(AR_VALID);
  kase({ id: 'ar_truncated', file: put('ar_truncated.json', s.slice(0, Math.floor(s.length * 0.6))), format: null, expect: 'COULD NOT LOOK',
    why: '60% of the bytes: not JSON, so no format is recognized (never BROKEN)' }); }
kase({ id: 'ar_wrong_format_claimed', file: 'ar_valid_didkey.json', format: R, claimedFormat: 'scitt', expect: 'COULD NOT LOOK',
  why: 'the reader said SCITT; it reads as an Agent Receipt' });
{ const s = arText(AR_VALID).replace('"version": "0.5.0",', '"version": "0.5.0",\n  "version": "0.4.0",');
  kase({ id: 'ar_duplicate_key', file: put('ar_duplicate_key.json', s), format: R, expect: 'BROKEN',
    why: 'version given twice; I-JSON (RFC 8785 s3.1) forbids it' }); }

// ------------------------------------------------------------------ CBOR / DER writers (own copy)
function head(mt, n) {
  if (n < 24) return Buffer.from([(mt << 5) | n]);
  if (n < 256) return Buffer.from([(mt << 5) | 24, n]);
  if (n < 65536) return Buffer.from([(mt << 5) | 25, n >> 8, n & 255]);
  const b = Buffer.alloc(5); b[0] = (mt << 5) | 26; b.writeUInt32BE(n, 1); return b;
}
class Tag { constructor(t, v) { this.t = t; this.v = v; } }
class F64 { constructor(x) { this.x = x; } } // a CBOR float64 (major type 7, fb), even when integral
function cbor(v) {
  if (v === null) return Buffer.from([0xf6]);
  if (v instanceof Tag) return Buffer.concat([head(6, v.t), cbor(v.v)]);
  if (v instanceof F64) { const b = Buffer.alloc(9); b[0] = 0xfb; b.writeDoubleBE(v.x, 1); return b; }
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === 'string') { const b = Buffer.from(v, 'utf8'); return Buffer.concat([head(3, b.length), b]); }
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(cbor)]);
  if (v instanceof Map) { const parts = [head(5, v.size)]; for (const [k, x] of v) { parts.push(cbor(k), cbor(x)); } return Buffer.concat(parts); }
  throw new Error('cbor: ' + typeof v);
}
function der(tag, body) {
  const n = body.length;
  const len = n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]);
  return Buffer.concat([Buffer.from([tag]), len, body]);
}
function selfSignedCert(priv) {
  const spki = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' });
  const ecdsaSha256 = der(0x30, der(0x06, Buffer.from('2a8648ce3d040302', 'hex')));
  const name = der(0x30, der(0x31, der(0x30, Buffer.concat([der(0x06, Buffer.from('550403', 'hex')), der(0x0c, Buffer.from('scitt fixture issuer'))]))));
  const validity = der(0x30, Buffer.concat([der(0x17, Buffer.from('260101000000Z')), der(0x17, Buffer.from('360101000000Z'))]));
  const tbs = der(0x30, Buffer.concat([der(0xa0, der(0x02, Buffer.from([2]))), der(0x02, Buffer.from([1])), ecdsaSha256, name, validity, name, spki]));
  const sig = crypto.sign('sha256', tbs, priv); // DER-encoded ECDSA, as X.509 wants
  const cert = der(0x30, Buffer.concat([tbs, ecdsaSha256, der(0x03, Buffer.concat([Buffer.from([0]), sig]))]));
  const x = new crypto.X509Certificate(cert);
  if (!x.verify(crypto.createPublicKey(priv))) throw new Error('cert self-check failed');
  return cert;
}
const CERT = selfSignedCert(P256);

function sign1(protMap, unprot, payload, signFn, detached) {
  const prot = cbor(protMap);
  const tbs = cbor(['Signature1', prot, Buffer.alloc(0), detached || payload]);
  const sig = signFn(tbs);
  return { bytes: cbor(new Tag(18, [prot, unprot, payload, sig])), prot, sig, tbs };
}
const es256 = (tbs) => crypto.sign('sha256', tbs, { key: P256, dsaEncoding: 'ieee-p1363' });
const eddsa = (tbs) => crypto.sign(null, tbs, ED1);
const cwt = (sub) => new Map([[1, 'https://issuer.example'], [2, sub]]);

const S = 'scitt';
const PAYLOAD = Buffer.from('{"action":"tool.call","tool":"fixture","call":1}', 'utf8');
const P_ES256 = new Map([[1, -7], [3, 'application/json'], [15, cwt('agent-action/0001')], [33, CERT]]);
const V1 = sign1(P_ES256, new Map(), PAYLOAD, es256);
if (!crypto.verify('sha256', V1.tbs, { key: crypto.createPublicKey(P256), dsaEncoding: 'ieee-p1363' }, V1.sig)) throw new Error('es256 self-check');

kase({ id: 'scitt_valid_es256_x5chain', file: put('scitt_valid_es256_x5chain.cbor', V1.bytes), format: S, expect: 'VERIFIED', bytes: true,
  why: 'RFC 9943 s6.1 shape (tag 18; alg ES256, content type, CWT iss+sub); key from the embedded x5chain leaf' });
kase({ id: 'scitt_valid_hex_text', file: put('scitt_valid_es256_x5chain.hex', V1.bytes.toString('hex') + '\n'), format: S, expect: 'VERIFIED',
  why: 'the same statement pasted as hex' });
kase({ id: 'scitt_valid_base64_text', file: put('scitt_valid_es256_x5chain.b64', V1.bytes.toString('base64') + '\n'), format: S, expect: 'VERIFIED',
  why: 'the same statement pasted as base64' });
kase({ id: 'scitt_valid_supplied_jwk', file: 'scitt_valid_es256_x5chain.cbor', bytes: true, format: S, publicKeyFile: 'key_p256_rfc7515.jwk', expect: 'VERIFIED',
  why: 'the RFC 7515 A.3 public key supplied as a JWK' });
{ const b = Buffer.from(V1.bytes); const at = b.indexOf(PAYLOAD); b[at + 10] ^= 0x01;
  kase({ id: 'scitt_tampered_payload', file: put('scitt_tampered_payload.cbor', b), bytes: true, format: S, expect: 'BROKEN',
    why: 'one bit of the embedded payload flipped' }); }
{ const b = Buffer.from(V1.bytes); b[b.length - 5] ^= 0x01;
  kase({ id: 'scitt_tampered_signature', file: put('scitt_tampered_signature.cbor', b), bytes: true, format: S, expect: 'BROKEN',
    why: 'one bit of the signature flipped' }); }
{ const p = new Map(P_ES256); p.delete(15);
  kase({ id: 'scitt_missing_cwt_claims', file: put('scitt_missing_cwt_claims.cbor', sign1(p, new Map(), PAYLOAD, es256).bytes), bytes: true, format: S, expect: 'BROKEN',
    why: 'validly signed, but no CWT Claims (label 15), which RFC 9943 requires' }); }
{ const p = new Map(P_ES256); p.set(15, new Map([[1, 'https://issuer.example']]));
  kase({ id: 'scitt_missing_sub', file: put('scitt_missing_sub.cbor', sign1(p, new Map(), PAYLOAD, es256).bytes), bytes: true, format: S, expect: 'BROKEN',
    why: 'validly signed, CWT Claims present, but no sub (label 2)' }); }
kase({ id: 'scitt_wrong_key_supplied', file: 'scitt_valid_es256_x5chain.cbor', bytes: true, format: S, publicKeyFile: 'key_p256_wrong.jwk', expect: 'BROKEN',
  why: 'the reader supplies a different P-256 key' });
{ const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
  const p = new Map(P_ES256); p.set(33, selfSignedCert(other));
  kase({ id: 'scitt_wrong_key_embedded', file: put('scitt_wrong_key_embedded.cbor', sign1(p, new Map(), PAYLOAD, es256).bytes), bytes: true, format: S, expect: 'BROKEN',
    why: 'signed with the RFC 7515 key but carries a certificate for a different key' }); }
kase({ id: 'scitt_truncated', file: put('scitt_truncated.cbor', V1.bytes.subarray(0, Math.floor(V1.bytes.length / 2))), bytes: true, format: S, expect: 'BROKEN',
  why: 'half the bytes: the tag 18 prefix is recognized, and the CBOR runs out' });
kase({ id: 'scitt_wrong_format_claimed', file: 'scitt_valid_es256_x5chain.cbor', bytes: true, format: S, claimedFormat: 'agent-receipts', expect: 'COULD NOT LOOK',
  why: 'the reader said Agent Receipts; it reads as SCITT' });
kase({ id: 'scitt_trailing_bytes', file: put('scitt_trailing_bytes.cbor', Buffer.concat([V1.bytes, Buffer.from([0x00])])), bytes: true, format: S, expect: 'BROKEN',
  why: 'one extra byte after the COSE_Sign1' });

// detached payload
const P_DET = new Map([[1, -7], [3, 'application/json'], [15, cwt('agent-action/0002')], [33, CERT]]);
const VD = sign1(P_DET, new Map(), null, es256, PAYLOAD);
put('scitt_detached_payload.bin', PAYLOAD);
kase({ id: 'scitt_detached_with_payload', file: put('scitt_detached.cbor', VD.bytes), bytes: true, format: S, detachedPayloadFile: 'scitt_detached_payload.bin', expect: 'VERIFIED',
  why: 'detached payload (nil, as in the RFC 9943 s6.1 example) with the payload supplied' });
kase({ id: 'scitt_detached_without_payload', file: 'scitt_detached.cbor', bytes: true, format: S, expect: 'COULD NOT LOOK',
  why: 'detached payload and none supplied: nothing to check the signature over' });
{ const alt = Buffer.from(PAYLOAD); alt[5] ^= 1; put('scitt_detached_payload_tampered.bin', alt);
  kase({ id: 'scitt_detached_tampered_payload', file: 'scitt_detached.cbor', bytes: true, format: S, detachedPayloadFile: 'scitt_detached_payload_tampered.bin', expect: 'BROKEN',
    why: 'the supplied detached payload differs by one bit' }); }

// hash envelope (RFC 9995), EdDSA, key supplied
const PRE = Buffer.from('fixture preimage: the artifact a SCITT statement is about\n', 'utf8');
put('scitt_hash_preimage.txt', PRE);
{ const alt = Buffer.from(PRE); alt[0] ^= 1; put('scitt_hash_preimage_tampered.txt', alt); }
const DIG = crypto.createHash('sha256').update(PRE).digest();
const P_HE = new Map([[1, -8], [15, cwt('artifact/0001')], [258, -16], [259, 'text/plain'], [260, 'https://example.invalid/preimage.txt']]);
const VH = sign1(P_HE, new Map(), DIG, eddsa);
put('scitt_hash_envelope_eddsa.cbor', VH.bytes);
kase({ id: 'scitt_hash_envelope_with_preimage', file: 'scitt_hash_envelope_eddsa.cbor', bytes: true, format: S, publicKeyFile: 'key_ed25519_test1.txt', preimageFile: 'scitt_hash_preimage.txt', expect: 'VERIFIED',
  why: 'RFC 9995 hash envelope, EdDSA, the preimage hashes to the signed payload' });
kase({ id: 'scitt_hash_envelope_no_preimage', file: 'scitt_hash_envelope_eddsa.cbor', bytes: true, format: S, publicKeyFile: 'key_ed25519_test1.txt', expect: 'VERIFIED',
  why: 'signature verifies; the payload digest row is NOT LOOKED because no preimage was given' });
kase({ id: 'scitt_hash_envelope_tampered_preimage', file: 'scitt_hash_envelope_eddsa.cbor', bytes: true, format: S, publicKeyFile: 'key_ed25519_test1.txt', preimageFile: 'scitt_hash_preimage_tampered.txt', expect: 'BROKEN',
  why: 'the supplied file differs by one bit from what was hashed' });
kase({ id: 'scitt_hash_envelope_wrong_key', file: 'scitt_hash_envelope_eddsa.cbor', bytes: true, format: S, publicKeyFile: 'key_ed25519_test2.txt', expect: 'BROKEN',
  why: 'the RFC 8032 TEST 2 key supplied for a TEST 1 signature' });
kase({ id: 'scitt_hash_envelope_no_key', file: 'scitt_hash_envelope_eddsa.cbor', bytes: true, format: S, expect: 'COULD NOT LOOK',
  why: 'no certificate in the statement and no key supplied' });
{ const p = new Map(P_HE); p.set(3, 'text/plain');
  kase({ id: 'scitt_hash_envelope_with_content_type', file: put('scitt_hash_envelope_with_content_type.cbor', sign1(p, new Map(), DIG, eddsa).bytes), bytes: true, format: S, publicKeyFile: 'key_ed25519_test1.txt', expect: 'BROKEN',
    why: 'validly signed, but a hash envelope must not carry content type (RFC 9995)' }); }
{ kase({ id: 'scitt_hash_envelope_short_payload', file: put('scitt_hash_envelope_short_payload.cbor', sign1(P_HE, new Map(), DIG.subarray(0, 31), eddsa).bytes), bytes: true, format: S, publicKeyFile: 'key_ed25519_test1.txt', expect: 'BROKEN',
    why: 'validly signed, but the payload is 31 bytes where SHA-256 gives 32' }); }
{ const p = new Map([[1, -47], [15, cwt('x')]]);
  kase({ id: 'scitt_unsupported_alg', file: put('scitt_unsupported_alg.cbor', sign1(p, new Map(), PAYLOAD, () => Buffer.alloc(64, 7)).bytes), bytes: true, format: S, publicKeyFile: 'key_p256_rfc7515.jwk', expect: 'COULD NOT LOOK',
    why: 'alg -47 (ES256K) is not in WebCrypto; could not look, never BROKEN and never a pass' }); }

// ------------------------------------------------------------------ SCITT Receipts (RFC 9942, RFC9162_SHA256)
// RFC 9942's own examples are elided (Figure 6: h'fc9f050f...221c92cb',
// signature h'de24f0cc...9a5ade89'; RFC 9943 Figures 8-11 likewise), so no
// receipt can be rebuilt from them byte for byte. These are generated here,
// with this file's own Merkle code written from the RFC 9162 definitions, not
// from the checker's verification loop:
//   MTH and PATH: RFC 9162 s2.1.1 and s2.1.3.1, the recursive definitions;
//   the root is cross-checked by the s2.1.2 stack algorithm (a second method);
//   the entry is the statement encoded with an EMPTY unprotected map (RFC 9943
//   s6.3), built from its parts, where the checker slices the bytes it is given.
// Every tree head signature is re-checked with node:crypto before writing, and
// every path is re-walked by recursion against the root it must reach.
//
// Transparency service key: P-256, private scalar = SHA-256 of a published
// string (below), so anyone can rebuild it. The "wrong service key" cases use
// the RFC 7515 A.3 public key, which is the ISSUER's key here, never the TS's.
const sha256 = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts)).digest();
const TS_SEED_TEXT = 'arcaeon universal fixtures: transparency service tree-head key';
const TS_D = sha256(Buffer.from(TS_SEED_TEXT, 'utf8'));
const tsEcdh = crypto.createECDH('prime256v1'); tsEcdh.setPrivateKey(TS_D);
const tsPubPoint = tsEcdh.getPublicKey(null, 'uncompressed');
const b64u = (b) => Buffer.from(b).toString('base64url');
const TS_JWK = { kty: 'EC', crv: 'P-256', x: b64u(tsPubPoint.subarray(1, 33)), y: b64u(tsPubPoint.subarray(33, 65)), d: b64u(TS_D) };
const TS_PRIV = crypto.createPrivateKey({ key: TS_JWK, format: 'jwk' });
const TS_PUB = crypto.createPublicKey(TS_PRIV);
put('key_p256_transparency_service.jwk', JSON.stringify({ kty: 'EC', crv: 'P-256', x: TS_JWK.x, y: TS_JWK.y }) + '\n');
const tsSign = (tbs) => crypto.sign('sha256', tbs, { key: TS_PRIV, dsaEncoding: 'ieee-p1363' });
const tsCheck = (tbs, sig) => crypto.verify('sha256', tbs, { key: TS_PUB, dsaEncoding: 'ieee-p1363' }, sig);

// RFC 9162 s2.1.1 and s2.1.3.1, recursively.
const leafH = (d) => sha256(Buffer.from([0]), d);
const nodeH = (l, r) => sha256(Buffer.from([1]), l, r);
function kSplit(n) { let k = 1; while (k * 2 < n) k *= 2; return k; } // largest power of two < n
function MTH(D) {
  if (D.length === 0) return sha256(Buffer.alloc(0));
  if (D.length === 1) return leafH(D[0]);
  const k = kSplit(D.length);
  return nodeH(MTH(D.slice(0, k)), MTH(D.slice(k)));
}
function PATH(m, D) {
  if (D.length === 1) return [];
  const k = kSplit(D.length);
  return m < k ? [...PATH(m, D.slice(0, k)), MTH(D.slice(k))] : [...PATH(m - k, D.slice(k)), MTH(D.slice(0, k))];
}
// Re-walk a path by the same recursion that made it: the leaf hash rises
// through the subtree splits, taking path hashes from the END (deepest first
// is last in PATH's order, so we consume from the tail while descending).
function rootFromPathRecursive(m, n, leafHash, path) {
  if (n === 1) { if (path.length) throw new Error('path too long'); return leafHash; }
  const k = kSplit(n);
  const sib = path[path.length - 1], rest = path.slice(0, -1);
  if (sib === undefined) throw new Error('path too short');
  return m < k ? nodeH(rootFromPathRecursive(m, k, leafHash, rest), sib) : nodeH(sib, rootFromPathRecursive(m - k, n - k, leafHash, rest));
}
// RFC 9162 s2.1.2: the stack algorithm, a second way to the same root.
function stackRoot(D) {
  const st = [];
  D.forEach((d, i) => {
    st.push(leafH(d));
    let merges = 0; while ((i >> merges) & 1) merges++;
    for (let j = 0; j < merges; j++) { const r = st.pop(), l = st.pop(); st.push(nodeH(l, r)); }
  });
  while (st.length > 1) { const r = st.pop(), l = st.pop(); st.push(nodeH(l, r)); }
  return st[0];
}

// The statement a receipt is about: ES256 by the issuer, x5chain, like V1.
const P_RS = new Map([[1, -7], [3, 'application/json'], [15, cwt('agent-action/0003')], [33, CERT]]);
const RS = sign1(P_RS, new Map(), PAYLOAD, es256);
put('scitt_receipt_statement.cbor', RS.bytes);
const ENTRY = cbor(new Tag(18, [RS.prot, new Map(), PAYLOAD, RS.sig])); // RFC 9943 s6.3 entry, built from parts

// A seven-entry log (not a power of two, so the path is uneven); ours is d[5].
const TREE_SIZE = 7, LEAF_INDEX = 5;
const LOG = [];
for (let i = 0; i < TREE_SIZE; i++) LOG.push(i === LEAF_INDEX ? ENTRY : Buffer.from('fixture log entry ' + i, 'utf8'));
const ROOT_HASH = MTH(LOG);
if (!ROOT_HASH.equals(stackRoot(LOG))) throw new Error('MTH and the s2.1.2 stack algorithm disagree');
const PATH5 = PATH(LEAF_INDEX, LOG);
if (!rootFromPathRecursive(LEAF_INDEX, TREE_SIZE, leafH(ENTRY), PATH5).equals(ROOT_HASH)) throw new Error('path self-check');

const RCWT = new Map([[1, 'https://ts.example'], [2, 'agent-action/0003']]); // RFC 9943 s6: receipts carry CWT iss+sub too
const P_RCPT = new Map([[1, -7], [395, 1], [15, RCWT]]);
const proofBytes = (size, idx, path) => cbor([size, idx, path]);
const vdp = (proofs, label = -1) => new Map([[396, new Map([[label, proofs]])]]);
// A receipt over `root`, with `unprot` as given. The signature never covers
// the unprotected header, so a tampered proof keeps a genuine signature.
function receipt(prot, unprot, root, { attach = false, signer = tsSign } = {}) {
  const r = sign1(prot, unprot, attach ? root : null, signer, root);
  if (signer === tsSign && !tsCheck(r.tbs, r.sig)) throw new Error('tree head self-check');
  return r;
}
const GOOD_PROOF = proofBytes(TREE_SIZE, LEAF_INDEX, PATH5);
const RC = receipt(P_RCPT, vdp([GOOD_PROOF]), ROOT_HASH);
const RC_ATT = receipt(P_RCPT, vdp([GOOD_PROOF]), ROOT_HASH, { attach: true });
const T = 'scitt-receipt';
const withStmt = { statementFile: 'scitt_receipt_statement.cbor', receiptKeyFile: 'key_p256_transparency_service.jwk' };

kase({ id: 'scitt_receipt_valid', file: put('scitt_receipt_valid.cbor', RC.bytes), bytes: true, format: T, ...withStmt, expect: 'VERIFIED',
  why: 'RFC 9942 s5.2.1 shape (alg ES256, vds 1, vdp -1, detached root), tree size 7, leaf index 5; the root is recomputed from the statement\'s leaf and the service signature checks over it' });
kase({ id: 'scitt_receipt_valid_attached_root', file: put('scitt_receipt_attached_root.cbor', RC_ATT.bytes), bytes: true, format: T, ...withStmt, expect: 'VERIFIED',
  why: 'the same receipt with the root attached (RFC 9942 s4.4 says SHOULD detach, so attached is allowed); the recomputed root equals it' });
kase({ id: 'scitt_receipt_no_ts_key', file: 'scitt_receipt_valid.cbor', bytes: true, format: T, statementFile: 'scitt_receipt_statement.cbor', expect: 'COULD NOT LOOK',
  why: 'no transparency service key: the root is recomputed, but whether the service signed it was not looked at' });
kase({ id: 'scitt_receipt_no_statement', file: 'scitt_receipt_valid.cbor', bytes: true, format: T, receiptKeyFile: 'key_p256_transparency_service.jwk', expect: 'COULD NOT LOOK',
  why: 'a receipt alone names no entry; without the statement there is no leaf to start the path from' });
kase({ id: 'scitt_receipt_wrong_ts_key', file: 'scitt_receipt_valid.cbor', bytes: true, format: T, statementFile: 'scitt_receipt_statement.cbor',
  receiptKeyFile: 'key_p256_rfc7515.jwk', expect: 'BROKEN', why: 'the reader supplies a different P-256 key (the issuer\'s) as the service key' });
const TAMPERED_PATH = PATH5.map((h) => Buffer.from(h)); TAMPERED_PATH[1][7] ^= 0x01;
kase({ id: 'scitt_receipt_tampered_path', file: put('scitt_receipt_tampered_path.cbor', receipt(P_RCPT, vdp([proofBytes(TREE_SIZE, LEAF_INDEX, TAMPERED_PATH)]), ROOT_HASH).bytes),
  bytes: true, format: T, ...withStmt, expect: 'BROKEN', why: 'one bit of the second path hash flipped; the genuine signature no longer covers the recomputed root' });
kase({ id: 'scitt_receipt_attached_root_tampered_path', file: put('scitt_receipt_attached_root_tampered_path.cbor',
  receipt(P_RCPT, vdp([proofBytes(TREE_SIZE, LEAF_INDEX, TAMPERED_PATH)]), ROOT_HASH, { attach: true }).bytes), bytes: true, format: T, ...withStmt, expect: 'BROKEN',
  why: 'the same tampered path with the genuine root attached: the signature over the attached root is valid, so only recomputing the root catches it' });
kase({ id: 'scitt_receipt_wrong_leaf_index', file: put('scitt_receipt_wrong_leaf_index.cbor', receipt(P_RCPT, vdp([proofBytes(TREE_SIZE, 4, PATH5)]), ROOT_HASH).bytes),
  bytes: true, format: T, ...withStmt, expect: 'BROKEN', why: 'leaf index 5 changed to 4: the path is applied at the wrong leaf position' });
kase({ id: 'scitt_receipt_attached_root_wrong_leaf', file: 'scitt_receipt_attached_root.cbor', bytes: true, format: T,
  statementFile: 'scitt_valid_es256_x5chain.cbor', receiptKeyFile: 'key_p256_transparency_service.jwk', expect: 'BROKEN',
  why: 'root attached, statement swapped: the leaf is another statement\'s, so the recomputed root is not the attached one (hash equality fails before any signature)' });
kase({ id: 'scitt_receipt_other_statement', file: 'scitt_receipt_valid.cbor', bytes: true, format: T, statementFile: 'scitt_valid_es256_x5chain.cbor',
  receiptKeyFile: 'key_p256_transparency_service.jwk', expect: 'BROKEN',
  why: 'a genuine receipt checked against a different, validly signed statement: real evidence, about something else' });
kase({ id: 'scitt_receipt_truncated_proof', file: put('scitt_receipt_truncated_proof.cbor', receipt(P_RCPT, vdp([proofBytes(TREE_SIZE, LEAF_INDEX, PATH5.slice(0, -1))]), ROOT_HASH).bytes),
  bytes: true, format: T, ...withStmt, expect: 'BROKEN', why: 'last path hash dropped: RFC 9162 s2.1.3.2 ends with sn not 0, so the proof fails on its own shape' });
kase({ id: 'scitt_receipt_truncated_proof_no_key', file: 'scitt_receipt_truncated_proof.cbor', bytes: true, format: T, expect: 'BROKEN',
  why: 'the same short path with no statement and no key: a proof that does not fit its own tree is BROKEN before anything else is needed' });
kase({ id: 'scitt_receipt_extra_path_hash', file: put('scitt_receipt_extra_path_hash.cbor', receipt(P_RCPT, vdp([proofBytes(TREE_SIZE, LEAF_INDEX, [...PATH5, PATH5[0]])]), ROOT_HASH).bytes),
  bytes: true, format: T, ...withStmt, expect: 'BROKEN', why: 'one hash too many: sn reaches 0 with path left over (RFC 9162 s2.1.3.2 step 4a)' });
kase({ id: 'scitt_receipt_index_past_size', file: put('scitt_receipt_index_past_size.cbor', receipt(P_RCPT, vdp([proofBytes(TREE_SIZE, TREE_SIZE, PATH5)]), ROOT_HASH).bytes),
  bytes: true, format: T, ...withStmt, expect: 'BROKEN', why: 'leaf index equals tree size (RFC 9942 s5.2: fail the proof verification)' });
// RFC 9942 s5.2 types tree-size and leaf-index as uint. A float is not a
// uint even when integral: 7.0 decodes to the same Number as 7, so only a
// checker that looks at the major type catches it.
kase({ id: 'scitt_receipt_float_tree_size', file: put('scitt_receipt_float_tree_size.cbor', receipt(P_RCPT, vdp([proofBytes(new F64(7.5), LEAF_INDEX, PATH5)]), ROOT_HASH).bytes),
  bytes: true, format: T, ...withStmt, expect: 'BROKEN', why: 'tree size is the float 7.5; RFC 9942 s5.2 says uint' });
kase({ id: 'scitt_receipt_float_tree_size_integral', file: put('scitt_receipt_float_tree_size_integral.cbor', receipt(P_RCPT, vdp([proofBytes(new F64(7), LEAF_INDEX, PATH5)]), ROOT_HASH).bytes),
  bytes: true, format: T, ...withStmt, expect: 'BROKEN', why: 'tree size is the float 7.0 (fb 40 1c 00..): the same number, but major type 7, not a uint (RFC 9942 s5.2)' });
kase({ id: 'scitt_receipt_float_leaf_index', file: put('scitt_receipt_float_leaf_index.cbor', receipt(P_RCPT, vdp([proofBytes(TREE_SIZE, new F64(5), PATH5)]), ROOT_HASH).bytes),
  bytes: true, format: T, ...withStmt, expect: 'BROKEN', why: 'leaf index is the float 5.0; RFC 9942 s5.2 says uint' });
kase({ id: 'scitt_receipt_short_path_hash', file: put('scitt_receipt_short_path_hash.cbor',
  receipt(P_RCPT, vdp([proofBytes(TREE_SIZE, LEAF_INDEX, [PATH5[0], PATH5[1].subarray(0, 31), PATH5[2]])]), ROOT_HASH).bytes),
  bytes: true, format: T, ...withStmt, expect: 'BROKEN', why: 'a path hash of 31 bytes where SHA-256 gives 32' });
kase({ id: 'scitt_receipt_truncated', file: put('scitt_receipt_truncated.cbor', RC.bytes.subarray(0, Math.floor(RC.bytes.length / 2))), bytes: true, format: 'scitt', expect: 'BROKEN',
  why: 'half the receipt\'s bytes: tag 18 is seen but the headers cannot be read, so the detector cannot call it a receipt; the statement checker reports the CBOR running out' });
{ const p = new Map(P_RCPT); p.set(395, 2);
  kase({ id: 'scitt_receipt_unsupported_vds', file: put('scitt_receipt_unsupported_vds.cbor', receipt(p, vdp([GOOD_PROOF]), ROOT_HASH).bytes), bytes: true, format: T, ...withStmt,
    expect: 'COULD NOT LOOK', why: 'vds 2 (the CCF ledger profile, an Internet-Draft, not in the IANA registry): could not look, never read as RFC 9162' }); }
kase({ id: 'scitt_receipt_consistency_only', file: put('scitt_receipt_consistency_only.cbor', receipt(P_RCPT, vdp([cbor([3, 7, [PATH5[0]]])], -2), ROOT_HASH).bytes),
  bytes: true, format: T, ...withStmt, expect: 'COULD NOT LOOK', why: 'only a consistency proof (-2); this page checks inclusion, not consistency' });
kase({ id: 'scitt_receipt_two_inclusion_proofs', file: put('scitt_receipt_two_inclusion_proofs.cbor', receipt(P_RCPT, vdp([GOOD_PROOF, GOOD_PROOF]), ROOT_HASH).bytes),
  bytes: true, format: T, ...withStmt, expect: 'COULD NOT LOOK', why: 'two inclusion proofs under one signature; this page checks receipts with exactly one' });
{ const p = new Map(P_RCPT); p.set(1, -47);
  kase({ id: 'scitt_receipt_unsupported_alg', file: put('scitt_receipt_unsupported_alg.cbor', receipt(p, vdp([GOOD_PROOF]), ROOT_HASH, { signer: () => Buffer.alloc(64, 7) }).bytes),
    bytes: true, format: T, ...withStmt, expect: 'COULD NOT LOOK', why: 'tree head signed with alg -47 (ES256K), which WebCrypto does not run' }); }
{ const p = new Map(P_RCPT); p.delete(1);
  kase({ id: 'scitt_receipt_missing_alg', file: put('scitt_receipt_missing_alg.cbor', receipt(p, vdp([GOOD_PROOF]), ROOT_HASH).bytes), bytes: true, format: T, ...withStmt,
    expect: 'BROKEN', why: 'no alg (label 1), which RFC 9942 s5.2.1 makes REQUIRED' }); }
kase({ id: 'scitt_receipt_vds_without_vdp', file: put('scitt_receipt_vds_without_vdp.cbor', receipt(P_RCPT, new Map(), ROOT_HASH).bytes), bytes: true, format: null, ...withStmt,
  expect: 'COULD NOT LOOK', why: 'vds (395) but no proofs (396): one receipt marker without the other, so the detector calls it neither a receipt nor a statement' });
kase({ id: 'scitt_receipt_wrong_format_claimed', file: 'scitt_receipt_valid.cbor', bytes: true, format: T, claimedFormat: 'scitt', ...withStmt, expect: 'COULD NOT LOOK',
  why: 'the reader said Signed Statement; it reads as a receipt' });
kase({ id: 'scitt_receipt_bare_statement_claimed', file: 'scitt_receipt_statement.cbor', bytes: true, format: 'scitt', claimedFormat: 'scitt-receipt', expect: 'COULD NOT LOOK',
  why: 'a bare Signed Statement the reader called a receipt: it carries no vds or vdp, so it is not one' });

// Transparent Statements (RFC 9943 s7): the same statement with receipts at 394.
const transparent = (receipts) => cbor(new Tag(18, [RS.prot, new Map([[394, receipts]]), PAYLOAD, RS.sig]));
kase({ id: 'scitt_transparent_valid', file: put('scitt_transparent_valid.cbor', transparent([RC.bytes])), bytes: true, format: 'scitt',
  receiptKeyFile: 'key_p256_transparency_service.jwk', expect: 'VERIFIED',
  why: 'RFC 9943 s7 Transparent Statement: the issuer signature (x5chain leaf) and the attached receipt both check; the entry drops the 394 header it now carries' });
kase({ id: 'scitt_transparent_no_ts_key', file: 'scitt_transparent_valid.cbor', bytes: true, format: 'scitt', expect: 'COULD NOT LOOK',
  why: 'the issuer signature checks, but with no service key the transparency it claims was not looked at' });
kase({ id: 'scitt_transparent_wrong_ts_key', file: 'scitt_transparent_valid.cbor', bytes: true, format: 'scitt', receiptKeyFile: 'key_p256_rfc7515.jwk', expect: 'BROKEN',
  why: 'the wrong service key for its only receipt' });
{ const p = PATH5.map((h) => Buffer.from(h)); p[2][0] ^= 0x80;
  const bad = cbor(new Tag(18, [RC.prot, vdp([proofBytes(TREE_SIZE, LEAF_INDEX, p)]), null, RC.sig]));
  kase({ id: 'scitt_transparent_tampered_receipt', file: put('scitt_transparent_tampered_receipt.cbor', transparent([bad])), bytes: true, format: 'scitt',
    receiptKeyFile: 'key_p256_transparency_service.jwk', expect: 'BROKEN',
    why: 'the attached receipt keeps its genuine signature, but one bit of its third path hash was flipped' }); }
{ const other = receipt(P_RCPT, vdp([GOOD_PROOF]), ROOT_HASH, { signer: es256 }); // a second "service": signed with a key the reader did not supply
  if (!crypto.verify('sha256', other.tbs, { key: crypto.createPublicKey(P256), dsaEncoding: 'ieee-p1363' }, other.sig)) throw new Error('second receipt self-check');
  kase({ id: 'scitt_transparent_two_receipts_one_ours', file: put('scitt_transparent_two_receipts.cbor', transparent([other.bytes, RC.bytes])), bytes: true, format: 'scitt',
    receiptKeyFile: 'key_p256_transparency_service.jwk', expect: 'VERIFIED',
    why: 'two receipts from two services; the second verifies under the supplied key (RFC 9943 s7.1: a Relying Party MAY verify a single acceptable receipt), the first is shown and not counted' }); }

// ------------------------------------------------------------------ unrecognized, ambiguous, Signet
kase({ id: 'none_json_object', file: put('none_json_object.json', '{"hello": "world"}\n'), format: null, expect: 'COULD NOT LOOK',
  why: 'valid JSON with none of the markers' });
kase({ id: 'none_plain_text', file: put('none_plain_text.txt', 'this is not a receipt\n'), format: null, expect: 'COULD NOT LOOK', why: 'plain text' });
kase({ id: 'none_empty', file: put('none_empty.txt', ''), format: null, expect: 'COULD NOT LOOK', why: 'empty input' });
kase({ id: 'none_random_bytes', file: put('none_random_bytes.bin', Buffer.from('ff00fe01fd02fc03', 'hex')), bytes: true, format: null, expect: 'COULD NOT LOOK', why: 'binary that is not tag 18' });
{ const untagged = V1.bytes.subarray(1); // drop the d2 tag byte
  kase({ id: 'none_untagged_cose', file: put('none_untagged_cose.cbor', untagged), bytes: true, format: null, expect: 'COULD NOT LOOK',
    why: 'a COSE_Sign1 array without tag 18: RFC 9943 requires the tag, so the page does not guess' }); }
{ const o = JSON.parse(HONEST); o.type = ['VerifiableCredential', 'AgentReceipt'];
  kase({ id: 'none_ambiguous_markers', file: put('none_ambiguous_markers.json', JSON.stringify(o)), format: null, expect: 'COULD NOT LOOK',
    why: 'carries both the Arcaeon and the Agent Receipts markers; the page will not pick one' }); }
// Shape of the v1 example in https://github.com/Prismer-AI/signet README; the
// README elides its values, so these are placeholders of the same shape.
kase({ id: 'signet_v1_shape', file: put('signet_v1_shape.json', JSON.stringify({ v: 1, id: 'rec_e7039e7e7714e84f',
  action: { tool: 'github_create_issue', params: { title: 'fix bug' }, params_hash: 'sha256:b878192252cb', target: 'mcp://github.local', transport: 'stdio' },
  signer: { pubkey: 'ed25519:0CRkURt/tc6r', name: 'demo-bot', owner: 'willamhou' }, ts: '2026-03-29T23:24:03.309Z',
  nonce: 'rnd_dcd4e135799393', sig: 'ed25519:6KUohbnSmehP' }, null, 2)), format: 'signet', expect: 'COULD NOT LOOK',
  why: 'recognized as Signet; could not look: no published schema' });

writeFileSync(join(OUT, 'manifest.json'), JSON.stringify({
  generated_by: 'tools/make_universal_fixtures.mjs',
  verdicts: ['VERIFIED', 'BROKEN', 'COULD NOT LOOK'],
  cases }, null, 2) + '\n');
console.log(cases.length + ' cases written to ' + OUT);
