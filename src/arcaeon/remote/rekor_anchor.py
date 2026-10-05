# SPDX-License-Identifier: MIT
"""arcaeon.remote.rekor_anchor: the public-log anchor for a sealed envelope.
ARMED = False. Offline skeleton; the plan is docs/design/REKOR_REWRITE_PLAN.md.

WHAT IS ANCHORED. One digest: sha256(PAE(payloadType, payload)) of the DSSE
envelope, the exact bytes the envelope's signature covers. Signatures are not
in it, so every witness of one envelope anchors the same digest.

THREE ANCHORS, EACH A SIDECAR BESIDE THE BUNDLE, NEVER INSIDE IT:

  BUNDLE.rekor.json   a Rekor v1 `hashedrekord` v0.0.1 entry: data.hash =
                      the digest, a witness signature over the PAE bytes
                      (ECDSA P-256, SHA-256), the witness public key (PEM)
  BUNDLE.tsq/.tsr     an RFC 3161 request (messageImprint = the digest, a
                      nonce, certReq) and the TSA's reply: the clock
  BUNDLE.ots          an OpenTimestamps proof of the digest

Why not the Rekor `dsse` type and why not Rekor v2: v2 dropped `dsse` and
returns no integrated time; the public default stays v1. The plan says more.

MULTI-WITNESS = N BUNDLES. A Sigstore bundle carries exactly one signature,
so an envelope with N signatures splits into N one-signature bundles, each
with its own sidecars (split_witnesses, witness_bundle_path).

THE READING. Each anchor answers on its own, VERIFIED / BROKEN / COULD NOT
LOOK, or NOT CLAIMED when its sidecar is absent. There is no rolled-up anchor
verdict, and the envelope's own verdict never waits on any of this.

THE GATE. ARMED is False. submit() is the one function that can reach the
network, and it refuses unless ARMED is True AND the caller passes
i_have_his_go=True. A public log entry is permanent; arming is the owner's
call, not a code change made in passing.

Stdlib only at import. The signature checks import `cryptography` (the [sign]
extra) when they run; without it they answer COULD NOT LOOK.
"""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.prove import envelope as E

__all__ = ["ARMED", "REKOR_V1_URL", "NOT_CLAIMED", "AnchorError", "NotArmed",
           "envelope_digest", "compose_hashedrekord", "check_hashedrekord", "new_nonce",
           "tsa_request", "parse_tsa_request", "check_tsa_token", "ots_sidecar_path",
           "tsa_sidecar_path", "tsa_request_sidecar_path", "rekor_sidecar_path",
           "write_bundle", "split_witnesses", "witness_bundle_path", "read_anchors", "submit"]

# THE GATE. The only line that may ever arm this module. Branch on ARMED
# itself (never a copy) so a search for the name finds every gate.
ARMED = False

#: The public-good Rekor v1 log (the Sigstore default as of 2026-06-28).
REKOR_V1_URL = "https://rekor.sigstore.dev"
NOT_CLAIMED = "NOT CLAIMED"
HASHEDREKORD_KIND = "hashedrekord"
HASHEDREKORD_VERSION = "0.0.1"
#: Sidecar suffixes, appended to the bundle's full file name.
OTS_SUFFIX = ".ots"
TSR_SUFFIX = ".tsr"
TSQ_SUFFIX = ".tsq"
REKOR_SUFFIX = ".rekor.json"
_SIDECAR_SUFFIXES = (OTS_SUFFIX, TSR_SUFFIX, TSQ_SUFFIX, REKOR_SUFFIX)
#: A sidecar or bundle bigger than this is not read.
MAX_SIDECAR_BYTES = 1 << 20
#: A bundle holds exactly these fields; a proof under any other key is refused.
_BUNDLE_KEYS = {"mediaType", "dsseEnvelope"}
_DSSE_KEYS = {"payloadType", "payload", "signatures"}
_SIG_KEYS = {"keyid", "sig"}
_HEX64 = re.compile(r"[0-9a-f]{64}")
_PEM_PUBLIC = re.compile(rb"-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+"
                         rb"-----END PUBLIC KEY-----\r?\n?")


class AnchorError(ValueError):
    """Refused: the input is not something this module will compose or write.
    Nothing was written or sent."""


class NotArmed(RuntimeError):
    """submit() refused: the module is not armed, or the caller did not say
    they have the owner's go. Nothing was sent."""


# --- the digest -------------------------------------------------------------------------

def _dsse_of(envelope: Any) -> dict:
    if isinstance(envelope, (str, Path)):
        p = Path(envelope)
        try:
            if p.stat().st_size > MAX_SIDECAR_BYTES:
                raise AnchorError(f"{p.name} is over {MAX_SIDECAR_BYTES} bytes; not read")
            envelope = json.loads(p.read_bytes().decode("utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as e:
            raise AnchorError(f"{p.name} cannot be read as a JSON envelope "
                              f"({type(e).__name__})") from None
    if not isinstance(envelope, dict):
        raise AnchorError("not an envelope (a JSON object was expected)")
    dsse = envelope.get("dsseEnvelope", envelope)
    if not isinstance(dsse, dict) or "payload" not in dsse or "payloadType" not in dsse:
        raise AnchorError("no DSSE envelope (payloadType and payload) found")
    return dsse


def envelope_digest(envelope: Any) -> str:
    """sha256(PAE(payloadType, payload)) as 64 lower-case hex: the digest every
    anchor names. `envelope` is a bundle dict, a bare DSSE dict, or a path."""
    dsse = _dsse_of(envelope)
    ptype, payload = dsse.get("payloadType"), dsse.get("payload")
    if not isinstance(ptype, str) or not isinstance(payload, str):
        raise AnchorError("payloadType and payload must be strings")
    try:
        body = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        raise AnchorError("the payload is not base64") from None
    return hashlib.sha256(E.pae(ptype, body)).hexdigest()


def _pae_of(envelope: Any) -> bytes:
    dsse = _dsse_of(envelope)
    envelope_digest(dsse)   # same checks, same refusals
    return E.pae(dsse["payloadType"], base64.b64decode(dsse["payload"]))


# --- the hashedrekord entry ---------------------------------------------------------------

def compose_hashedrekord(digest: str, sig: bytes, pubkey_pem: bytes) -> dict:
    """The Rekor v1 hashedrekord v0.0.1 body for `digest`. `sig` is the
    witness signature over the PAE bytes (ECDSA P-256 with SHA-256, which
    Rekor checks against the digest), `pubkey_pem` the witness public key.
    Shape-checked only: no key is loaded and nothing is sent."""
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise AnchorError("digest must be 64 lower-case hex characters (sha256)")
    if not isinstance(sig, (bytes, bytearray)) or not sig:
        raise AnchorError("the signature is empty")
    if not isinstance(pubkey_pem, (bytes, bytearray)) or not _PEM_PUBLIC.fullmatch(
            bytes(pubkey_pem)):
        raise AnchorError("the public key must be one PEM 'PUBLIC KEY' block "
                          "(never a private key)")
    return {
        "apiVersion": HASHEDREKORD_VERSION,
        "kind": HASHEDREKORD_KIND,
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": digest}},
            "signature": {"content": base64.b64encode(bytes(sig)).decode("ascii"),
                          "publicKey": {"content": base64.b64encode(bytes(pubkey_pem))
                                        .decode("ascii")}},
        },
    }


def _entry_parts(entry: Any) -> tuple[str, bytes, bytes]:
    """(digest, sig, pem) from a hashedrekord body, or AnchorError."""
    try:
        if entry.get("kind") != HASHEDREKORD_KIND or entry.get("apiVersion") != \
                HASHEDREKORD_VERSION:
            raise AnchorError("not a hashedrekord v0.0.1 entry")
        spec = entry["spec"]
        h = spec["data"]["hash"]
        if h.get("algorithm") != "sha256" or not _HEX64.fullmatch(str(h.get("value"))):
            raise AnchorError("data.hash is not a sha256 digest")
        sig = base64.b64decode(spec["signature"]["content"], validate=True)
        pem = base64.b64decode(spec["signature"]["publicKey"]["content"], validate=True)
    except AnchorError:
        raise
    except (AttributeError, KeyError, TypeError, binascii.Error, ValueError) as e:
        raise AnchorError(f"the entry cannot be read ({type(e).__name__})") from None
    return h["value"], sig, pem


def check_hashedrekord(entry: Any, envelope: Any) -> dict:
    """Read a hashedrekord body against an envelope, offline.

    steps.digest: data.hash equals the envelope's PAE digest. steps.signature:
    the entry's signature verifies under the entry's own key. `verdict` covers
    those two only. `inclusion` (is the entry in the log, at what index, under
    which signed checkpoint) is a separate question this skeleton does not
    answer: always COULD NOT LOOK here."""
    r = {"verdict": None, "steps": {"digest": None, "signature": None},
         "inclusion": V.COULD_NOT_LOOK, "findings": [],
         "not_checked": ["log inclusion: no inclusion proof or signed entry timestamp is "
                         "read by this skeleton"]}
    try:
        digest, sig, pem = _entry_parts(entry)
    except AnchorError as e:
        r["findings"].append(str(e))
        r["steps"]["digest"] = r["steps"]["signature"] = V.COULD_NOT_LOOK
        r["verdict"] = V.COULD_NOT_LOOK
        return r
    try:
        want = envelope_digest(envelope)
        r["steps"]["digest"] = V.VERIFIED if want == digest else V.BROKEN
        if want != digest:
            r["findings"].append("the entry names another digest than this envelope's PAE")
    except AnchorError as e:
        r["findings"].append(f"envelope: {e}")
        r["steps"]["digest"] = V.COULD_NOT_LOOK
    r["steps"]["signature"] = _check_entry_signature(r, digest, sig, pem)
    r["verdict"] = _roll(r["steps"].values())
    return r


def _check_entry_signature(r: dict, digest: str, sig: bytes, pem: bytes) -> str:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils
    except ImportError:
        r["findings"].append("no signature backend: pip install 'arcaeon[sign]'")
        return V.COULD_NOT_LOOK
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError):
        r["findings"].append("the entry's public key cannot be loaded")
        return V.COULD_NOT_LOOK
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve,
                                                                        ec.SECP256R1):
        r["findings"].append("the entry's key is not ECDSA P-256, the one type this reads")
        return V.COULD_NOT_LOOK
    try:
        key.verify(sig, bytes.fromhex(digest), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except InvalidSignature:
        r["findings"].append("the entry's signature does not verify under its key")
        return V.BROKEN
    return V.VERIFIED


def _roll(words) -> str:
    words = list(words)
    if V.BROKEN in words:
        return V.BROKEN
    if any(w != V.VERIFIED for w in words):
        return V.COULD_NOT_LOOK
    return V.VERIFIED


# --- minimal DER ------------------------------------------------------------------------

class _Unreadable(ValueError):
    pass


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(n: int) -> bytes:
    return _der(0x02, n.to_bytes(n.bit_length() // 8 + 1, "big"))


def _oid_bytes(dotted: str) -> bytes:
    a = [int(x) for x in dotted.split(".")]
    out = bytearray([a[0] * 40 + a[1]])
    for v in a[2:]:
        chunk = [v & 0x7F]
        v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(chunk))
    return _der(0x06, bytes(out))


def _read(buf: bytes, i: int, end: int | None = None) -> tuple[int, int, int, int]:
    """(tag, header_start, value_start, value_end) of the TLV at i. Definite
    lengths only (DER); anything else is unreadable."""
    end = len(buf) if end is None else end
    if i + 2 > end:
        raise _Unreadable("truncated")
    tag, ln, j = buf[i], buf[i + 1], i + 2
    if tag & 0x1F == 0x1F:
        raise _Unreadable("multi-byte tags are not read")
    if ln == 0x80:
        raise _Unreadable("indefinite length (BER, not DER)")
    if ln > 0x80:
        k = ln & 0x7F
        if k > 4 or j + k > end:
            raise _Unreadable("bad length")
        ln, j = int.from_bytes(buf[j:j + k], "big"), j + k
    if j + ln > end:
        raise _Unreadable("truncated")
    return tag, i, j, j + ln


def _kids(buf: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    out, i = [], start
    while i < end:
        t = _read(buf, i, end)
        out.append(t)
        i = t[3]
    return out


def _expect(t: tuple, tag: int, what: str) -> tuple:
    if t[0] != tag:
        raise _Unreadable(f"{what}: tag {t[0]:#04x}, expected {tag:#04x}")
    return t


def _int_of(buf: bytes, t: tuple) -> int:
    _expect(t, 0x02, "INTEGER")
    return int.from_bytes(buf[t[2]:t[3]], "big", signed=True)


def _oid_of(buf: bytes, t: tuple) -> bytes:
    return bytes(buf[_expect(t, 0x06, "OID")[1]:t[3]])


OID_SHA256 = _oid_bytes("2.16.840.1.101.3.4.2.1")
_HASH_BY_OID = {OID_SHA256: "sha256", _oid_bytes("2.16.840.1.101.3.4.2.2"): "sha384",
                _oid_bytes("2.16.840.1.101.3.4.2.3"): "sha512"}
OID_SIGNED_DATA = _oid_bytes("1.2.840.113549.1.7.2")
OID_TSTINFO = _oid_bytes("1.2.840.113549.1.9.16.1.4")
OID_CONTENT_TYPE = _oid_bytes("1.2.840.113549.1.9.3")
OID_MESSAGE_DIGEST = _oid_bytes("1.2.840.113549.1.9.4")
OID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"


# --- the RFC 3161 request -------------------------------------------------------------

def new_nonce() -> int:
    """A fresh positive 64-bit nonce for one request. Keep it (the .tsq does)."""
    return secrets.randbelow((1 << 64) - 1) + 1


def tsa_request(digest: str, nonce: int, cert_req: bool = True) -> bytes:
    """A DER TimeStampReq (RFC 3161 section 2.4.1): version 1, messageImprint =
    sha256 `digest`, `nonce`, certReq. Byte-for-byte what `openssl ts -query
    -sha256 -digest D -cert` writes for the same nonce."""
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise AnchorError("digest must be 64 lower-case hex characters (sha256)")
    if isinstance(nonce, bool) or not isinstance(nonce, int) or not 0 < nonce < (1 << 64):
        raise AnchorError("nonce must be a positive integer under 2**64")
    imprint = _der(0x30, _der(0x30, OID_SHA256 + b"\x05\x00") + _der(0x04, bytes.fromhex(digest)))
    body = _der_int(1) + imprint + _der_int(nonce)
    if cert_req:
        body += b"\x01\x01\xff"
    return _der(0x30, body)


def parse_tsa_request(der: bytes) -> dict:
    """{digest, nonce, cert_req} from a DER TimeStampReq, or AnchorError."""
    try:
        top = _expect(_read(der, 0), 0x30, "TimeStampReq")
        if top[3] != len(der):
            raise _Unreadable("trailing bytes")
        kids = _kids(der, top[2], top[3])
        if _int_of(der, kids[0]) != 1:
            raise _Unreadable("version is not 1")
        alg, hashed = _imprint(der, kids[1])
        if alg != "sha256":
            raise _Unreadable(f"messageImprint uses {alg}, not sha256")
        nonce, cert_req = None, False
        for t in kids[2:]:
            if t[0] == 0x02:
                nonce = _int_of(der, t)
            elif t[0] == 0x01:
                cert_req = der[t[2]:t[3]] != b"\x00"
    except (_Unreadable, IndexError) as e:
        raise AnchorError(f"not a TimeStampReq this reads ({e})") from None
    return {"digest": hashed.hex(), "nonce": nonce, "cert_req": cert_req}


def _imprint(buf: bytes, t: tuple) -> tuple[str, bytes]:
    _expect(t, 0x30, "MessageImprint")
    alg_seq, hashed = _kids(buf, t[2], t[3])
    oid = _oid_of(buf, _kids(buf, alg_seq[2], alg_seq[3])[0])
    _expect(hashed, 0x04, "hashedMessage")
    return _HASH_BY_OID.get(oid, "an unknown hash"), bytes(buf[hashed[2]:hashed[3]])


# --- the RFC 3161 token ---------------------------------------------------------------

def _token_from_reply(der: bytes) -> bytes:
    """The TimeStampToken (a CMS ContentInfo) from a TimeStampResp; a bare
    token comes back unchanged."""
    top = _expect(_read(der, 0), 0x30, "TimeStampResp")
    kids = _kids(der, top[2], top[3])
    if kids and kids[0][0] == 0x06:
        return bytes(der[top[1]:top[3]])       # already a ContentInfo
    status_kids = _kids(der, kids[0][2], kids[0][3])
    status = _int_of(der, status_kids[0])
    if status not in (0, 1):
        raise _Unreadable(f"the TSA did not grant a token (PKIStatus {status})")
    if len(kids) < 2:
        raise _Unreadable("granted, but no token in the reply")
    return bytes(der[kids[1][1]:kids[1][3]])


def _parse_token(tok: bytes) -> dict:
    ci = _expect(_read(tok, 0), 0x30, "ContentInfo")
    ct, content = _kids(tok, ci[2], ci[3])[:2]
    if _oid_of(tok, ct) != OID_SIGNED_DATA:
        raise _Unreadable("the token is not CMS SignedData")
    sd = _expect(_kids(tok, _expect(content, 0xA0, "content")[2], content[3])[0], 0x30,
                 "SignedData")
    sdk = _kids(tok, sd[2], sd[3])
    encap = _expect(sdk[2], 0x30, "EncapsulatedContentInfo")
    ek = _kids(tok, encap[2], encap[3])
    if _oid_of(tok, ek[0]) != OID_TSTINFO:
        raise _Unreadable("the signed content is not a TSTInfo")
    octets = _expect(_kids(tok, _expect(ek[1], 0xA0, "eContent")[2], ek[1][3])[0], 0x04,
                     "eContent")
    econtent = bytes(tok[octets[2]:octets[3]])
    certs, signer_infos = [], None
    for t in sdk[3:]:
        if t[0] == 0xA0:
            certs = [bytes(tok[c[1]:c[3]]) for c in _kids(tok, t[2], t[3]) if c[0] == 0x30]
        elif t[0] == 0x31:
            signer_infos = t
    tst = _expect(_read(econtent, 0), 0x30, "TSTInfo")
    tk = _kids(econtent, tst[2], tst[3])
    alg, hashed = _imprint(econtent, tk[2])
    gt = _expect(tk[4], 0x18, "genTime")
    gen_raw = econtent[gt[2]:gt[3]].decode("ascii")
    nonce = None
    for t in tk[5:]:
        if t[0] == 0x02:
            nonce = _int_of(econtent, t)
            break
    return {"tok": tok, "econtent": econtent, "certs": certs, "signer_infos": signer_infos,
            "imprint_alg": alg, "imprint": hashed, "gen_raw": gen_raw, "nonce": nonce,
            "serial": _int_of(econtent, tk[3])}


def _gen_time(raw: str) -> datetime:
    m = re.fullmatch(r"(\d{14})(\.\d{1,9})?Z", raw)
    if not m:
        raise _Unreadable(f"genTime {raw[:40]!r} is not a UTC GeneralizedTime")
    return datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


def check_tsa_token(token_der: bytes, digest: str, nonce: int, roots=None) -> dict:
    """Read an RFC 3161 reply (or a bare token) against the digest and nonce
    we sent, offline.

    steps.token      the DER parses as a granted TimeStampToken with a TSTInfo
    steps.imprint    messageImprint is sha256 and equals `digest`
    steps.nonce      the token carries our nonce (absent or other = BROKEN)
    steps.signature  the CMS signature covers this TSTInfo, the signer is a
                     time-stamping certificate valid at genTime, and it chains
                     to one of `roots` (PEM bytes of TSA roots the caller
                     pinned). No root pinned = COULD NOT LOOK.
    gen_time is reported as read; it is the TSA's clock, trusted only as far
    as the pinned root is."""
    r = {"verdict": None, "steps": {"token": None, "imprint": None, "nonce": None,
                                    "signature": None},
         "gen_time": None, "serial": None, "findings": []}
    try:
        tok = _parse_token(_token_from_reply(bytes(token_der)))
        gen = _gen_time(tok["gen_raw"])
    except (_Unreadable, IndexError, ValueError, TypeError) as e:
        r["steps"]["token"] = r["verdict"] = V.COULD_NOT_LOOK
        r["findings"].append(f"the token cannot be read ({e})")
        return r
    st = r["steps"]
    st["token"] = V.VERIFIED
    r["gen_time"] = gen.strftime("%Y-%m-%dT%H:%M:%SZ")
    r["serial"] = tok["serial"]
    if tok["imprint_alg"] != "sha256":
        st["imprint"] = V.COULD_NOT_LOOK
        r["findings"].append(f"messageImprint uses {tok['imprint_alg']}, not sha256")
    elif tok["imprint"].hex() == digest:
        st["imprint"] = V.VERIFIED
    else:
        st["imprint"] = V.BROKEN
        r["findings"].append("the token stamps another digest than this envelope's PAE")
    if tok["nonce"] is None:
        st["nonce"] = V.BROKEN
        r["findings"].append("the token carries no nonce, and the request sent one")
    elif tok["nonce"] == nonce:
        st["nonce"] = V.VERIFIED
    else:
        st["nonce"] = V.BROKEN
        r["findings"].append("the token's nonce is not the one the request sent")
    st["signature"] = _check_token_signature(r, tok, gen, roots)
    r["verdict"] = _roll(st.values())
    return r


def _check_token_signature(r: dict, tok: dict, gen: datetime, roots) -> str:
    if not roots:
        r["findings"].append("no TSA root pinned: the token's signature was not checked")
        return V.COULD_NOT_LOOK
    try:
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    except ImportError:
        r["findings"].append("no signature backend: pip install 'arcaeon[sign]'")
        return V.COULD_NOT_LOOK
    buf = tok["tok"]
    try:
        pinned = [x509.load_pem_x509_certificate(p) for p in roots]
        bundled = [x509.load_der_x509_certificate(c) for c in tok["certs"]]
        si_set = tok["signer_infos"]
        if si_set is None:
            raise _Unreadable("no signerInfos")
        si_list = _kids(buf, si_set[2], si_set[3])
        if len(si_list) != 1:
            raise _Unreadable(f"{len(si_list)} signers; a token has one")
        sk = _kids(buf, si_list[0][2], si_list[0][3])
        sid, dalg, attrs = sk[1], sk[2], sk[3]
        _expect(attrs, 0xA0, "signedAttrs")
        hname = _HASH_BY_OID.get(_oid_of(buf, _kids(buf, dalg[2], dalg[3])[0]))
        sig_t = next(t for t in sk[4:] if t[0] == 0x04)
        sig = bytes(buf[sig_t[2]:sig_t[3]])
        signed = b"\x31" + bytes(buf[attrs[1] + 1:attrs[3]])
        attr_map = {}
        for a in _kids(buf, attrs[2], attrs[3]):
            ak = _kids(buf, a[2], a[3])
            vals = _kids(buf, ak[1][2], ak[1][3])
            attr_map[_oid_of(buf, ak[0])] = bytes(buf[vals[0][1]:vals[0][3]]) if vals else b""
    except (_Unreadable, IndexError, ValueError, StopIteration) as e:
        r["findings"].append(f"the token's signer cannot be read ({e})")
        return V.COULD_NOT_LOOK
    if hname is None:
        r["findings"].append("the signer's digest algorithm is not one this reads")
        return V.COULD_NOT_LOOK
    if attr_map.get(OID_CONTENT_TYPE) != OID_TSTINFO:
        r["findings"].append("the signed content-type attribute is not TSTInfo")
        return V.BROKEN
    md = attr_map.get(OID_MESSAGE_DIGEST, b"")
    if md[:1] != b"\x04" or md[2:] != hashlib.new(hname, tok["econtent"]).digest():
        r["findings"].append("the TSTInfo was changed after the TSA signed it "
                             "(messageDigest does not match)")
        return V.BROKEN
    signer = _find_signer(buf, sid, bundled, pinned)
    if signer is None:
        r["findings"].append("the signer's certificate is not in the token or the pinned roots")
        return V.COULD_NOT_LOOK
    h = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}[hname]
    key = signer.public_key()
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(sig, signed, ec.ECDSA(h))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, signed, padding.PKCS1v15(), h)
        else:
            r["findings"].append("the TSA key type is not one this reads")
            return V.COULD_NOT_LOOK
    except InvalidSignature:
        r["findings"].append("the TSA signature does not verify")
        return V.BROKEN
    try:
        eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        stamping = any(u.dotted_string == OID_KP_TIMESTAMPING for u in eku)
    except x509.ExtensionNotFound:
        stamping = False
    if not stamping:
        r["findings"].append("the signer's certificate is not a time-stamping certificate")
        return V.BROKEN
    if not signer.not_valid_before_utc <= gen <= signer.not_valid_after_utc:
        r["findings"].append("genTime is outside the signer certificate's validity")
        return V.BROKEN
    if _chains_to(signer, bundled, pinned):
        return V.VERIFIED
    r["findings"].append("the TSA certificate does not chain to a root you pinned")
    return V.BROKEN


def _find_signer(buf, sid, bundled, pinned):
    from cryptography import x509
    cands = bundled + pinned
    if sid[0] == 0x30:     # IssuerAndSerialNumber
        issuer_t, serial_t = _kids(buf, sid[2], sid[3])[:2]
        issuer, serial = bytes(buf[issuer_t[1]:issuer_t[3]]), _int_of(buf, serial_t)
        for c in cands:
            if c.serial_number == serial and c.issuer.public_bytes() == issuer:
                return c
    elif sid[0] == 0x80:   # [0] SubjectKeyIdentifier
        ski = bytes(buf[sid[2]:sid[3]])
        for c in cands:
            try:
                if c.extensions.get_extension_for_class(
                        x509.SubjectKeyIdentifier).value.digest == ski:
                    return c
            except x509.ExtensionNotFound:
                continue
    return None


def _chains_to(cert, bundled, pinned, depth: int = 0) -> bool:
    """True when `cert` is a pinned root or is issued (directly, or through
    at most two certificates carried in the token) by one."""
    from cryptography.exceptions import InvalidSignature
    if any(cert == p for p in pinned):
        return True
    for p in pinned:
        try:
            cert.verify_directly_issued_by(p)
            return True
        except (ValueError, TypeError, InvalidSignature):
            continue
    if depth >= 2:
        return False
    for mid in bundled:
        if mid == cert:
            continue
        try:
            cert.verify_directly_issued_by(mid)
        except (ValueError, TypeError, InvalidSignature):
            continue
        if _chains_to(mid, bundled, pinned, depth + 1):
            return True
    return False


# --- sidecars and the bundle writer -----------------------------------------------------

def _beside(bundle_path, suffix: str) -> Path:
    p = Path(bundle_path)
    return p.with_name(p.name + suffix)


def ots_sidecar_path(bundle_path) -> Path:
    """BUNDLE.ots: the OpenTimestamps proof of the digest, beside the bundle."""
    return _beside(bundle_path, OTS_SUFFIX)


def tsa_sidecar_path(bundle_path) -> Path:
    """BUNDLE.tsr: the TSA's DER reply."""
    return _beside(bundle_path, TSR_SUFFIX)


def tsa_request_sidecar_path(bundle_path) -> Path:
    """BUNDLE.tsq: the DER request we sent (it holds the nonce)."""
    return _beside(bundle_path, TSQ_SUFFIX)


def rekor_sidecar_path(bundle_path) -> Path:
    """BUNDLE.rekor.json: the hashedrekord entry (and, once armed, the log's answer)."""
    return _beside(bundle_path, REKOR_SUFFIX)


def write_bundle(path, envelope: dict, *, force: bool = False) -> Path:
    """Write a one-signature bundle, refusing anything that is not exactly
    {mediaType, dsseEnvelope{payloadType, payload, signatures[{keyid, sig}]}}.
    A proof (OTS, RFC 3161, a Rekor entry) under any other key is refused by
    name: proofs ride in sidecars. Nothing is written on a refusal."""
    p = Path(path)
    if p.name.endswith(_SIDECAR_SUFFIXES):
        raise AnchorError(f"{p.name} is a sidecar name, not a bundle name")
    if not isinstance(envelope, dict):
        raise AnchorError("the bundle must be a JSON object")
    extra = sorted(set(envelope) - _BUNDLE_KEYS)
    dsse = envelope.get("dsseEnvelope")
    if isinstance(dsse, dict):
        extra += [f"dsseEnvelope.{k}" for k in sorted(set(dsse) - _DSSE_KEYS)]
        sigs = dsse.get("signatures")
        for i, s in enumerate(sigs if isinstance(sigs, list) else []):
            if isinstance(s, dict):
                extra += [f"signatures[{i}].{k}" for k in sorted(set(s) - _SIG_KEYS)]
    if extra:
        raise AnchorError(f"refused, fields that are not bundle fields: {', '.join(extra)}. "
                          f"An OTS proof, a TSA token or a Rekor entry rides in a sidecar "
                          f"beside the bundle, never inside it")
    if envelope.get("mediaType") != E.MEDIA_TYPE or not isinstance(dsse, dict):
        raise AnchorError(f"not an envelope bundle (mediaType must be {E.MEDIA_TYPE})")
    sigs = dsse.get("signatures")
    if not isinstance(sigs, list) or len(sigs) != 1 or not isinstance(sigs[0], dict):
        raise AnchorError("an anchored bundle holds exactly one signature; "
                          "split a multi-signature envelope with split_witnesses()")
    envelope_digest(envelope)
    if p.exists() and not force:
        raise AnchorError(f"{p.name} already exists; pass force=True to replace it")
    tmp = p.with_name(p.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(envelope, indent=1) + "\n")
    os.replace(tmp, p)
    return p


# --- multi-witness ----------------------------------------------------------------------

def split_witnesses(envelope: dict) -> list[dict]:
    """One bundle per signature: the same payload, one signature each, in the
    input's order. The input is not changed. Every part anchors the same
    digest. Refuses zero signatures and a key id that signs twice."""
    dsse = _dsse_of(envelope)
    sigs = dsse.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        raise AnchorError("no signatures to split")
    ids = [s.get("keyid") if isinstance(s, dict) else None for s in sigs]
    if None in ids or len(set(ids)) != len(ids):
        raise AnchorError("every signature needs its own keyid; one key signed twice "
                          "or a signature has no keyid")
    out = []
    for s in sigs:
        part = copy.deepcopy(envelope)
        target = part.get("dsseEnvelope", part) if isinstance(part, dict) else part
        target["signatures"] = [copy.deepcopy(s)]
        out.append(part)
    return out


def witness_bundle_path(file, keyid: str) -> Path:
    """FILE.<12 hex of sha256(keyid)>.envelope.json: one bundle per witness,
    stable for a key, distinct across keys, each with its own sidecars."""
    p = Path(file)
    tag = hashlib.sha256(str(keyid).encode("utf-8")).hexdigest()[:12]
    return p.with_name(f"{p.name}.{tag}{E.SUFFIX}")


# --- the reading ----------------------------------------------------------------------

def _read_small(p: Path) -> bytes:
    if p.stat().st_size > MAX_SIDECAR_BYTES:
        raise OSError(f"{p.name} is over {MAX_SIDECAR_BYTES} bytes; not read")
    return p.read_bytes()


def read_anchors(bundle_path, *, tsa_roots=None) -> dict:
    """Each anchor beside a bundle, read on its own and offline.

    NOT CLAIMED when its sidecar is absent. rekor: BROKEN when the entry is
    for another digest or its signature fails; otherwise COULD NOT LOOK,
    because log inclusion is not checked here. tsa: check_tsa_token's verdict
    against the request in BUNDLE.tsq (no .tsq = COULD NOT LOOK: the nonce is
    unknown). ots: COULD NOT LOOK when present (not read by this skeleton).
    There is no rolled-up verdict on purpose; the envelope verdict is
    arcaeon.prove.envelope.verify's and never waits on these."""
    b = Path(bundle_path)
    out = {"bundle": str(b), "anchors": {}, "details": {}}
    try:
        digest = envelope_digest(b)
    except AnchorError as e:
        digest, out["details"]["bundle"] = None, str(e)

    rp = rekor_sidecar_path(b)
    if not rp.exists():
        out["anchors"]["rekor"] = NOT_CLAIMED
    else:
        try:
            entry = json.loads(_read_small(rp).decode("utf-8"))
            res = check_hashedrekord(entry, b) if digest else None
        except (OSError, UnicodeDecodeError, ValueError) as e:
            res = {"verdict": V.COULD_NOT_LOOK, "findings": [f"unreadable ({type(e).__name__})"]}
        if res is None:
            res = {"verdict": V.COULD_NOT_LOOK, "findings": ["the bundle cannot be read"]}
        out["details"]["rekor"] = res
        out["anchors"]["rekor"] = V.BROKEN if res["verdict"] == V.BROKEN else V.COULD_NOT_LOOK

    tp, qp = tsa_sidecar_path(b), tsa_request_sidecar_path(b)
    if not tp.exists():
        out["anchors"]["tsa"] = NOT_CLAIMED
    else:
        word, detail = V.COULD_NOT_LOOK, None
        try:
            req = parse_tsa_request(_read_small(qp)) if qp.exists() else None
            if req is None:
                detail = {"findings": [f"no {qp.name}: the nonce sent is unknown"]}
            elif digest is None:
                detail = {"findings": ["the bundle cannot be read"]}
            elif req["digest"] != digest:
                word = V.BROKEN
                detail = {"findings": [f"{qp.name} asked for another digest"]}
            else:
                detail = check_tsa_token(_read_small(tp), digest, req["nonce"], roots=tsa_roots)
                word = detail["verdict"]
        except (OSError, AnchorError) as e:
            detail = {"findings": [str(e)]}
        out["details"]["tsa"], out["anchors"]["tsa"] = detail, word

    op = ots_sidecar_path(b)
    if not op.exists():
        out["anchors"]["ots"] = NOT_CLAIMED
    else:
        out["anchors"]["ots"] = V.COULD_NOT_LOOK
        out["details"]["ots"] = {"findings": ["present; the OTS proof is not read by this "
                                              "skeleton"]}
    return out


# --- the one network-capable function -----------------------------------------------------

def submit(entry: dict, *, i_have_his_go: bool = False, url: str = REKOR_V1_URL,
           timeout: float = 30.0) -> dict:
    """POST a hashedrekord entry to a Rekor v1 log. Refuses (NotArmed) unless
    the module constant ARMED is True AND i_have_his_go is True; neither alone
    sends anything. A public entry is permanent and cannot be withdrawn."""
    if not (ARMED and i_have_his_go):
        raise NotArmed("refused before sending: rekor_anchor is not armed (ARMED is False "
                       "or i_have_his_go was not given). A public log entry is permanent; "
                       "arming is the owner's call")
    _entry_parts(entry)
    import urllib.request
    req = urllib.request.Request(url.rstrip("/") + "/api/v1/log/entries",
                                 data=json.dumps(entry).encode("utf-8"),
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "arcaeon-rekor-anchor"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))
