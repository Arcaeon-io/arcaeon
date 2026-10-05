# SPDX-License-Identifier: MIT
"""arcaeon.remote.scitt: the witness pin statement as a SCITT-shaped Signed Statement, with RFC 9942-shaped receipts.

    arcaeon tally scitt-export S.json --key SEEDFILE --out FILE.scitt
                               [--proof INCLUSION.json --ts-key SEEDFILE]
                               [--iss ID] [--ts-iss ID]
    arcaeon tally scitt-verify FILE.scitt [--receipt FILE] [--ts-pub KEY]
                               [--issuer-pub KEY] [--statement S.json] [--json]

OFFLINE ONLY. Nothing here opens a socket; `scitt-export` writes one file and
sends nothing. It lives in arcaeon.remote because the receipt is the hosted
witness's to sign; this module only shapes and checks the bytes.

SHAPES (docs/design/SCITT_RECEIPTS.md has the table):
  Signed Statement  #6.18 COSE_Sign1; protected {alg 1: -8 (EdDSA, Ed25519),
                    kid 4: sha256(issuer public key), CWT_Claims 15: {iss 1,
                    sub 2}, 258: -16 (RFC 9995 payload hash alg SHA-256), 259:
                    "application/json"}; no content_type (3); unprotected {};
                    payload = sha256 of the pin statement's canonical bytes
                    (arcaeon.prove.tally_chain.statement_canonical).
  Receipt           #6.18 COSE_Sign1 by the Transparency Service; protected
                    {alg 1: -8, kid 4, CWT_Claims 15, vds 395: 1
                    (RFC9162_SHA256), -65537: [tree-size, leaf-index]
                    (private use, see H_ARCAEON_TREE_POSITION)}; unprotected {vdp 396: {-1: [[tree-size,
                    leaf-index, [path...]]]}}; payload detached (nil): the
                    verifier recomputes the RFC 9162 root and checks the
                    signature over it.
  Transparent       the Signed Statement with `394: [receipt bytes]` added to
  Statement         the UNPROTECTED header, so the issuer signature stands.

VERDICTS (verify_receipt): a bad signature, a proof that does not compute, a
statement that is not a COSE_Sign1 = BROKEN; an unknown vds or alg, no TS key,
no Ed25519 backend = COULD NOT LOOK. It never raises on hostile bytes.

OPEN ITEM, NOT A CONFORMANCE CLAIM. LEAF_PREIMAGE_RULE below (which bytes are
the Merkle leaf) is our choice, not yet pinned against RFC 9943 section 7 /
RFC 9942 section 5 verbatim or the scitt-cose vectors. Until those vectors
pass, this is "SCITT-shaped", not "RFC 9943 / RFC 9942 conformant".
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.remote import _cbor as C
from arcaeon.remote import merkle as M

__all__ = ["ScittError", "to_signed_statement", "to_receipt", "attach_receipt", "leaf_bytes",
           "verify_receipt", "sign1", "LEAF_PREIMAGE_RULE", "OPEN_ITEMS", "export_cli",
           "verify_cli"]

TAG_SIGN1 = 18
H_ALG, H_CONTENT_TYPE, H_KID, H_CWT = 1, 3, 4, 15
CWT_ISS, CWT_SUB = 1, 2
H_PAYLOAD_HASH_ALG, H_PREIMAGE_CONTENT_TYPE = 258, 259     # RFC 9995
H_RECEIPTS, H_VDS, H_VDP = 394, 395, 396                    # RFC 9943 / RFC 9942
ALG_EDDSA = -8
COSE_SHA256 = -16
VDS_RFC9162_SHA256 = 1
VDP_INCLUSION = -1
#: Private-use protected header (COSE: labels below -65536): [tree-size,
#: leaf-index], signed. RFC 9162's walk lets one path prove a leaf under
#: several tree sizes (leaf 2: sizes 5 to 8 give the same root), and the
#: receipt signs only the root, so the vdp size is otherwise unauthenticated.
#: Our receipts sign it here; the verifier checks it when present.
H_ARCAEON_TREE_POSITION = -65537
PREIMAGE_CONTENT_TYPE = "application/json"
VERIFY_KIND = "arcaeon.scitt.receipt.verify/v1"
MAX_FILE_BYTES = 1 << 20

#: OPEN ITEM (R01, UNVERIFIED): the Merkle leaf is the Signed Statement's
#: bytes with the receipts (394) taken out of the unprotected header, i.e.
#: the statement exactly as the issuer emitted it. Whether a SCITT entry's
#: leaf is those bytes, the bytes with the whole unprotected header emptied,
#: or a hash of them is not yet checked against RFC 9943 section 7, RFC 9942
#: section 5 and the scitt-cose vectors.
LEAF_PREIMAGE_RULE = "signed-statement-bytes-without-receipts (OPEN: not pinned to scitt-cose)"
OPEN_ITEMS = (
    "leaf preimage: the Merkle leaf is the Signed Statement's bytes without receipts (394); "
    "not yet pinned to RFC 9943 section 7 / RFC 9942 section 5 or the scitt-cose vectors",
    "inclusion-proof wrapping: vdp -1 is written as a bare [tree-size, leaf-index, path] "
    "array (R01); the reader also accepts each proof wrapped as a bstr .cbor, the other "
    "reading of the CDDL, until the vectors settle it",
)
_HEX64 = re.compile(r"[0-9a-f]{64}")


class ScittError(ValueError):
    """Refused before anything was signed or written."""


# --- signing -------------------------------------------------------------------------------

def _receipts_mod():
    from arcaeon.prove.vet import receipts as R
    try:
        R._require_backend()
    except R.ReceiptsUnavailable as e:
        raise ScittError(f"signing needs an Ed25519 backend: pip install 'arcaeon[sign]' "
                         f"({e})") from None
    return R


def _seed(key: Any) -> bytes:
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ScittError("a key is a 32-byte Ed25519 seed")
    return bytes(key)


def _sig_structure(protected: bytes, payload: bytes) -> bytes:
    return C.encode(["Signature1", protected, b"", payload])


def kid(pubkey: bytes) -> bytes:
    """Our kid: sha256 of the raw Ed25519 public key."""
    return hashlib.sha256(pubkey).digest()


def sign1(protected: dict, unprotected: dict, payload: bytes, key: bytes, *,
          detached: bool = False) -> bytes:
    """A tagged COSE_Sign1 (#6.18) signed with Ed25519 over Sig_structure
    ["Signature1", protected, h'', payload]. detached=True writes nil."""
    R = _receipts_mod()
    pb = C.encode(protected)
    sig = R._sign_bytes(_seed(key), _sig_structure(pb, bytes(payload)))
    return C.encode(C.Tag(TAG_SIGN1, [pb, dict(unprotected), None if detached else bytes(payload),
                                      sig]))


def _parse_sign1(data: Any, what: str) -> tuple[bytes, dict, dict, bytes | None, bytes]:
    if not isinstance(data, (bytes, bytearray)):
        raise ScittError(f"the {what} is not bytes")
    try:
        t = C.decode(bytes(data))
    except C.CBORError as e:
        raise ScittError(f"the {what} is not CBOR this reader takes ({e})") from None
    if not isinstance(t, C.Tag) or t.tag != TAG_SIGN1:
        raise ScittError(f"the {what} is not a tagged COSE_Sign1 (#6.18)")
    v = t.value
    if not isinstance(v, list) or len(v) != 4:
        raise ScittError(f"the {what} is not a four-item COSE_Sign1")
    pb, unprot, payload, sig = v
    if not isinstance(pb, bytes) or not isinstance(unprot, dict) or not isinstance(sig, bytes) \
            or not (payload is None or isinstance(payload, bytes)):
        raise ScittError(f"the {what}'s COSE_Sign1 items have the wrong types")
    try:
        prot = C.decode(pb) if pb else {}
    except C.CBORError as e:
        raise ScittError(f"the {what}'s protected header is not CBOR ({e})") from None
    if not isinstance(prot, dict):
        raise ScittError(f"the {what}'s protected header is not a map")
    return pb, prot, unprot, payload, sig


# --- building ------------------------------------------------------------------------------

def to_signed_statement(pin_statement: dict, key: bytes, *, iss: str | None = None,
                        sub: str | None = None) -> bytes:
    """The v2 pin statement as a Signed Statement (RFC 9995 hash envelope).
    iss defaults to the issuer key's did:key, sub to the statement's chain."""
    from arcaeon.prove import tally_chain as TC
    problem = TC._statement_problem(pin_statement)
    if problem:
        raise ScittError(f"not a v2 pin statement: {problem}")
    key = _seed(key)
    R = _receipts_mod()
    pub = R.public_key_from_seed(key)
    payload = hashlib.sha256(TC.statement_canonical(pin_statement).encode("utf-8")).digest()
    prot = {H_ALG: ALG_EDDSA, H_KID: kid(pub),
            H_CWT: {CWT_ISS: iss or R.did_key(pub), CWT_SUB: sub or pin_statement["chain"]},
            H_PAYLOAD_HASH_ALG: COSE_SHA256, H_PREIMAGE_CONTENT_TYPE: PREIMAGE_CONTENT_TYPE}
    return sign1(prot, {}, payload, key)


def leaf_bytes(statement: bytes) -> bytes:
    """The Merkle leaf for a (Signed or Transparent) Statement under
    LEAF_PREIMAGE_RULE (OPEN ITEM). Bytes with no receipts come back as given."""
    pb, _, unprot, payload, sig = _parse_sign1(statement, "statement")
    if H_RECEIPTS not in unprot:
        return bytes(statement)
    rest = {k: v for k, v in unprot.items() if k != H_RECEIPTS}
    return C.encode(C.Tag(TAG_SIGN1, [pb, rest, payload, sig]))


def _proof_parts(proof: Any) -> tuple[int, int, list[bytes]]:
    if not isinstance(proof, dict):
        raise ScittError("an inclusion proof is an object with tree_size, leaf_index, path")
    size, idx, path = proof.get("tree_size"), proof.get("leaf_index"), proof.get("path")
    for name, v in (("tree_size", size), ("leaf_index", idx)):
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise ScittError(f"{name} is not a non-negative integer")
    if not isinstance(path, list):
        raise ScittError("path is not a list")
    out = []
    for p in path:
        if isinstance(p, str) and _HEX64.fullmatch(p):
            out.append(bytes.fromhex(p))
        elif isinstance(p, (bytes, bytearray)) and len(p) == 32:
            out.append(bytes(p))
        else:
            raise ScittError("each path entry is 32 bytes (64 lower-case hex in JSON)")
    return size, idx, out


def to_receipt(leaf: bytes, inclusion_proof: dict, ts_key: bytes, *, iss: str | None = None,
               sub: str | None = None) -> bytes:
    """A receipt for `leaf` at the proof's index, signed by the TS key over
    the RFC 9162 root the proof computes. Refuses a proof that computes none."""
    size, idx, path = _proof_parts(inclusion_proof)
    root = M.root_from_inclusion_proof(bytes(leaf), idx, size, path)
    if root is None:
        raise ScittError(f"the inclusion proof computes no root (index {idx}, tree size "
                         f"{size}, {len(path)} path entries)")
    ts_key = _seed(ts_key)
    R = _receipts_mod()
    pub = R.public_key_from_seed(ts_key)
    prot = {H_ALG: ALG_EDDSA, H_KID: kid(pub),
            H_CWT: {CWT_ISS: iss or R.did_key(pub),
                    CWT_SUB: sub or "rfc9162-leaf:" + M.leaf_hash(bytes(leaf)).hex()},
            H_VDS: VDS_RFC9162_SHA256, H_ARCAEON_TREE_POSITION: [size, idx]}
    return sign1(prot, {H_VDP: {VDP_INCLUSION: [[size, idx, path]]}}, root, ts_key,
                 detached=True)


def attach_receipt(statement: bytes, receipt: bytes) -> bytes:
    """The Transparent Statement: `receipt` appended under unprotected 394."""
    pb, _, unprot, payload, sig = _parse_sign1(statement, "statement")
    _parse_sign1(receipt, "receipt")
    have = unprot.get(H_RECEIPTS, [])
    if not isinstance(have, list):
        raise ScittError("the statement's receipts (394) is not a list")
    unprot = dict(unprot)
    unprot[H_RECEIPTS] = have + [bytes(receipt)]
    return C.encode(C.Tag(TAG_SIGN1, [pb, unprot, payload, sig]))


# --- verifying -----------------------------------------------------------------------------

class _Verdict(Exception):
    def __init__(self, word: str, reason: str, reason_word: str | None = None,
                 looked_for: str | None = None):
        super().__init__(reason)
        self.word, self.reason, self.reason_word, self.looked_for = \
            word, reason, reason_word, looked_for


def _broken(reason: str) -> _Verdict:
    return _Verdict(V.BROKEN, reason)


def _cnl(reason: str, looked_for: str, reason_word: str = "missing") -> _Verdict:
    return _Verdict(V.COULD_NOT_LOOK, reason, reason_word, looked_for)


def _inclusion(vdp: Any) -> tuple[int, int, list[bytes]]:
    if not isinstance(vdp, dict) or not isinstance(vdp.get(VDP_INCLUSION), list) \
            or not vdp[VDP_INCLUSION]:
        raise _broken("the receipt carries no inclusion proof (vdp 396, label -1)")
    p = vdp[VDP_INCLUSION][0]
    if isinstance(p, bytes):                      # the bstr .cbor reading (OPEN_ITEMS)
        try:
            p = C.decode(p)
        except C.CBORError:
            raise _broken("the receipt's inclusion proof is not CBOR") from None
    if not (isinstance(p, list) and len(p) == 3 and isinstance(p[2], list)
            and all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in p[:2])
            and all(isinstance(x, bytes) for x in p[2])):
        raise _broken("the receipt's inclusion proof is not [tree-size, leaf-index, [bstr...]]")
    return p[0], p[1], p[2]


def _check_statement_header(prot: dict, unprot: dict) -> None:
    cwt = prot.get(H_CWT)
    if not (isinstance(cwt, dict) and isinstance(cwt.get(CWT_ISS), str)
            and isinstance(cwt.get(CWT_SUB), str)):
        raise _broken("the statement's protected header lacks CWT_Claims (15) with iss and sub")
    if H_PAYLOAD_HASH_ALG in prot and (H_CONTENT_TYPE in prot or H_CONTENT_TYPE in unprot):
        raise _broken("the statement carries content_type (3) beside a payload hash alg (258)")
    if H_PAYLOAD_HASH_ALG in unprot:
        raise _broken("the payload hash alg (258) sits in the unprotected header")


def _verify(statement, receipt, ts_pubkey, issuer_pubkey, pin_statement, r: dict) -> None:
    try:
        spb, sprot, sunprot, spayload, ssig = _parse_sign1(statement, "statement")
    except ScittError as e:
        raise _broken(str(e)) from None
    if receipt is None:
        rs = sunprot.get(H_RECEIPTS)
        if not isinstance(rs, list) or not rs or not isinstance(rs[0], bytes):
            raise _broken("no receipt given and the statement carries none under 394")
        receipt = rs[0]
        if len(rs) > 1:
            r["not_checked"].append(f"{len(rs) - 1} further receipt(s) under 394")
    try:
        rpb, rprot, runprot, rpayload, rsig = _parse_sign1(receipt, "receipt")
    except ScittError as e:
        raise _broken(str(e)) from None
    _check_statement_header(sprot, sunprot)
    if ts_pubkey is None:
        raise _cnl("no Transparency Service public key was given, so the receipt "
                   "signature cannot be checked", "the Transparency Service public key")
    if not isinstance(ts_pubkey, (bytes, bytearray)) or len(ts_pubkey) != 32:
        raise _cnl("the Transparency Service key is not a 32-byte Ed25519 public key",
                   "the Transparency Service public key", "unreadable")
    try:
        R = _receipts_mod()
    except ScittError as e:
        raise _cnl(str(e), "an Ed25519 backend") from None
    if rprot.get(H_ALG) != ALG_EDDSA:
        raise _cnl(f"the receipt's alg {rprot.get(H_ALG)!r} is not one this verifier checks "
                   f"(EdDSA, -8)", "a checker for the receipt's alg")
    if H_VDS not in rprot:
        raise _broken("the receipt's protected header has no vds (395)")
    if rprot[H_VDS] != VDS_RFC9162_SHA256:
        raise _cnl(f"the receipt's vds {rprot[H_VDS]!r} is not RFC9162_SHA256 (1); no "
                   f"checker for it here", "a checker for the receipt's vds")
    size, idx, path = _inclusion(runprot.get(H_VDP))
    r.update(tree_size=size, leaf_index=idx)
    leaf = leaf_bytes(statement)
    root = M.root_from_inclusion_proof(leaf, idx, size, path)
    if root is None:
        raise _broken(f"the inclusion proof computes no root for this statement (index "
                      f"{idx}, tree size {size}, {len(path)} path entries)")
    r["root"] = root.hex()
    if rpayload is not None and rpayload != root:
        raise _broken("the receipt carries a payload that is not the root its proof computes")
    if not R._verify_bytes(bytes(ts_pubkey), _sig_structure(rpb, root), rsig):
        raise _broken("the receipt signature does not verify over the root this statement "
                      "and proof compute: a changed statement, path, tree size or index, or "
                      "another TS key")
    r["checked"].append("receipt signature over the RFC 9162 root (vds 1)")
    pos = rprot.get(H_ARCAEON_TREE_POSITION)
    if pos is None:
        r["not_checked"].append("the tree size: this receipt signs only the root, and one "
                                "path can fit several sizes")
    elif pos != [size, idx]:
        raise _broken(f"the receipt's signed tree position {pos!r} is not the proof's "
                      f"[{size}, {idx}]")
    else:
        r["checked"].append("tree size and leaf index, signed in the receipt")
    if issuer_pubkey is not None:
        if sprot.get(H_ALG) != ALG_EDDSA or spayload is None:
            raise _cnl("the statement's alg is not EdDSA or its payload is detached; the "
                       "issuer signature is not checked here", "the issuer signature")
        if not (isinstance(issuer_pubkey, (bytes, bytearray)) and len(issuer_pubkey) == 32
                and R._verify_bytes(bytes(issuer_pubkey), _sig_structure(spb, spayload), ssig)):
            raise _broken("the issuer signature on the statement does not verify with the "
                          "given issuer key")
        r["checked"].append("issuer signature on the statement")
    else:
        r["not_checked"].append("the issuer signature (no issuer key given)")
    if pin_statement is not None:
        from arcaeon.prove import tally_chain as TC
        want = hashlib.sha256(TC.statement_canonical(pin_statement).encode("utf-8")).digest()
        if sprot.get(H_PAYLOAD_HASH_ALG) != COSE_SHA256 or spayload != want:
            raise _broken("the statement payload is not the sha256 of the given pin statement")
        r["checked"].append("payload = sha256 of the given pin statement")
    r["word"], r["why"] = V.VERIFIED, (
        f"the receipt signature verifies over the RFC 9162 root computed from this statement "
        f"at index {idx} of a tree of {size}")


def verify_receipt(statement: bytes, receipt: bytes | None, ts_pubkey: bytes | None, *,
                   issuer_pubkey: bytes | None = None, pin_statement: dict | None = None) -> dict:
    """VERIFIED / BROKEN / COULD NOT LOOK for one receipt over one statement.
    receipt=None reads the first receipt under the statement's 394."""
    r: dict = {"kind": VERIFY_KIND, "root": None, "tree_size": None, "leaf_index": None,
               "checked": [], "not_checked": [], "leaf_preimage_rule": LEAF_PREIMAGE_RULE}
    try:
        _verify(statement, receipt, ts_pubkey, issuer_pubkey, pin_statement, r)
        word, why, extra = r.pop("word"), r.pop("why"), {}
    except _Verdict as v:
        word, why, extra = v.word, v.reason, {}
        if v.word == V.COULD_NOT_LOOK:
            extra = V.could_not_look(v.looked_for, "the receipt", v.reason_word, v.reason)
    except Exception as e:  # noqa: BLE001  hostile bytes never raise out of here
        word, why, extra = V.BROKEN, f"the bytes could not be read ({type(e).__name__})", {}
    r["not_checked"] += ["leaf preimage: " + OPEN_ITEMS[0],
                         "consistency with any other root (no consistency proof is read)",
                         "that the TS key is the hosted witness's: it is the key you passed"]
    return {"verdict": word, "reason": why, **r, **extra}


# --- CLI -----------------------------------------------------------------------------------

_EXPORT_SPEC = {"--key": "value", "--proof": "value", "--ts-key": "value", "--out": "value",
                "--iss": "value", "--ts-iss": "value"}
_VERIFY_SPEC = {"--receipt": "value", "--ts-pub": "value", "--issuer-pub": "value",
                "--statement": "value", "--json": "bool"}
NOT_A_CLAIM = ("offline: nothing was sent. SCITT-shaped, not an RFC 9943 / RFC 9942 "
               "conformance claim: the leaf preimage rule is an open item "
               "(docs/design/SCITT_RECEIPTS.md)")


def _read(path: str, cap: int = MAX_FILE_BYTES) -> bytes:
    p = Path(path)
    if p.stat().st_size > cap:
        raise ValueError(f"{p.name} is over {cap} bytes")
    return p.read_bytes()


def _read_json(path: str) -> Any:
    from arcaeon.record.row import loads_strict
    return loads_strict(_read(path).decode("utf-8"))


def _pubkey(text: str) -> bytes:
    from arcaeon.prove.envelope import _pubkey_from_did
    t = text.strip()
    if _HEX64.fullmatch(t):
        return bytes.fromhex(t)
    if t.startswith("did:key:"):
        return _pubkey_from_did(t)
    raise ValueError("a public key is 64 lower-case hex or an Ed25519 did:key")


def export_cli(argv: list[str]) -> int:
    from arcaeon.prove import tally_chain as TC
    from arcaeon.prove.envelope import SealError, _load_seed
    pos, o = TC._parse(argv, _EXPORT_SPEC)
    if len(pos) != 1:
        raise TC.Usage("scitt-export takes one pin statement file")
    if "--key" not in o or "--out" not in o:
        raise TC.Usage("scitt-export needs --key SEEDFILE and --out FILE")
    if ("--proof" in o) != ("--ts-key" in o):
        raise TC.Usage("--proof and --ts-key go together")
    me = "arcaeon tally scitt-export"
    try:
        st = _read_json(pos[0])
        proof = _read_json(o["--proof"]) if "--proof" in o else None
    except (OSError, ValueError) as e:
        print(f"{me}: {V.COULD_NOT_LOOK}: an input could not be read ({type(e).__name__}: "
              f"{e}); nothing written", file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    try:
        key = _load_seed(o["--key"])
        ts_key = _load_seed(o["--ts-key"]) if proof is not None else None
        stmt = to_signed_statement(st, key, iss=o.get("--iss"))
        out, note = stmt, "a SCITT-shaped Signed Statement"
        if proof is not None:
            size, idx, path = _proof_parts(proof)
            want = proof.get("root")
            if want is not None and not (isinstance(want, str) and _HEX64.fullmatch(want)):
                raise ScittError("root in the proof file is not 64 lower-case hex")
            leaf = leaf_bytes(stmt)
            root = M.root_from_inclusion_proof(leaf, idx, size, path)
            if root is None or (want is not None and root.hex() != want):
                print(f"{me}: {V.BROKEN}: the inclusion proof does not lead from this "
                      f"statement to {'the root in the proof file' if want else 'any root'}; "
                      f"nothing written", file=sys.stderr)
                return V.EXIT_BAD
            rc = to_receipt(leaf, {"tree_size": size, "leaf_index": idx, "path": path}, ts_key,
                            iss=o.get("--ts-iss"))
            out = attach_receipt(stmt, rc)
            note = (f"a Transparent Statement with one RFC 9942-shaped receipt (vds 1, tree "
                    f"size {size}, index {idx}, root {root.hex()})")
    except (SealError, ScittError) as e:
        print(f"{me}: {e}; nothing written", file=sys.stderr)
        return V.EXIT_USAGE
    try:
        with open(o["--out"], "xb") as fh:
            fh.write(out)
    except FileExistsError:
        print(f"{me}: {Path(o['--out']).name} exists; an export is never overwritten",
              file=sys.stderr)
        return V.EXIT_USAGE
    except OSError as e:
        print(f"{me}: cannot write --out ({type(e).__name__})", file=sys.stderr)
        return V.EXIT_USAGE
    print(f"wrote {Path(o['--out']).name}: {note}; payload sha256 of pin statement "
          f"{TC.statement_sha256(st)}")
    print(NOT_A_CLAIM, file=sys.stderr)
    return V.EXIT_GOOD


def verify_cli(argv: list[str]) -> int:
    from arcaeon.prove import tally_chain as TC
    pos, o = TC._parse(argv, _VERIFY_SPEC)
    if len(pos) != 1:
        raise TC.Usage("scitt-verify takes one statement file")
    try:
        ts = _pubkey(o["--ts-pub"]) if "--ts-pub" in o else None
        issuer = _pubkey(o["--issuer-pub"]) if "--issuer-pub" in o else None
    except ValueError as e:
        raise TC.Usage(str(e)) from None
    try:
        stmt = _read(pos[0])
        rc = _read(o["--receipt"]) if "--receipt" in o else None
        st = _read_json(o["--statement"]) if "--statement" in o else None
    except (OSError, ValueError) as e:
        r = {"verdict": V.COULD_NOT_LOOK, "reason": f"an input could not be read "
             f"({type(e).__name__})"}
    else:
        r = verify_receipt(stmt, rc, ts, issuer_pubkey=issuer, pin_statement=st)
    if o.get("--json"):
        print(json.dumps(r, indent=1))
    else:
        print(f"{r['verdict']}: {r['reason']}")
        for x in r.get("checked", []):
            print(f"  checked: {x}")
        for x in r.get("not_checked", []):
            print(f"  not checked: {x}")
    return V.exit_for(r["verdict"])
