"""Ed25519 receipts over a grade artifact — C-agent-04, 2026-08-30.

WHY THIS EXISTS. The R2 agent-economy brief's verdict was that the audit space
is crowded on the *primitive* (sign-your-own-call receipts, hash-chained logs)
and near-empty on the *independent, re-testable public grade*. Checkpoint/KYA-OS
is the closest fellow-traveler and explicitly positions itself as *evidence for
auditors, not the auditor* — it makes the receipt, it does not decide whether
the server deserves trust. That is the seam. So the move is to emit OUR grade in
THEIR shape rather than mint a rival format: a grade nobody can re-verify is a
press release, and a receipt format nobody else reads is a private diary.

WHAT A RECEIPT IS AND IS NOT. It is a signed statement that *this tool, at this
version, ran these checks over these exact bytes and reached this verdict*. It
is NOT an assertion that the graded server is safe, and the signature adds no
authority the grade did not already have: it only makes the grade attributable
and tamper-evident. A forged grade and a wrong grade are different problems and
this module solves exactly one of them.

WHAT THE SIGNATURE ACTUALLY COVERS. The signed bytes are the RFC 8785 (JCS)
canonical serialization of `payload`. `payload` carries the five grade fields
(`source_sha256`, `verdict`, `checks_run`, `tool_version`, `ts`) AND
`responseHash`, a `sha256:<hex>` over the canonical form of the WHOLE grade
artifact. So the receipt is small but binds the entire grade: hand
`verify_receipt()` the grade too and it proves the receipt is about that grade,
not merely about a summary that happens to agree with it. Without the grade the
verification is bounded, and it SAYS so rather than returning a green.

--- CONFORMANCE, stated precisely -------------------------------------------

The KYA-OS spec was fetched on 2026-08-30 from
`decentralized-identity/kya-os-mcp` (SPEC.md; the Checkpoint blog names the
draft "KYA-OS · draft-04"). The claim names below are taken from it verbatim.
So the honest label is: **claim names conform, envelope does not.** Which is why
`format` says "checkpoint-kya-v1-compatible" and not "checkpoint-kya-v1", and
why `DIVERGENCES` is emitted inside every receipt instead of living in a README
nobody opens. Same rule the grade lives under: a receipt confesses its own gaps
in-band, every time.

Conforming (names + encoding taken from the spec):
  * `alg` is `"EdDSA"` — the spec's required algorithm.
  * Claims `iss`, `sub`, `aud`, `nonce`, `ts`, `requestHash`, `responseHash`,
    `outcome`, `prf` are the spec's names, with the spec's meanings.
  * Hashes are `sha256:<64-char-lowercase-hex>`, the spec's format.
  * Canonicalization is RFC 8785 (JCS) before hashing and before signing, the
    spec's rule.
  * `iss`/`sub` are `did:key` identifiers built from the Ed25519 public key by
    the standard multicodec (0xed01) + base58btc encoding, so the identifier is
    self-certifying: the key is IN the name, no resolution needed.

NOT conforming (each one a real difference, not a rounding):
  1. ENVELOPE. KYA carries a JOSE *detached compact JWS* in MCP's
     `_meta.proof` — `BASE64URL(header).BASE64URL(payload).BASE64URL(sig)`. We
     emit a plain JSON object `{payload, signature_b64, pubkey_b64, format}`,
     base64 standard alphabet, because that is what the calling surface here
     (an HTTP grade endpoint) hands back. A KYA verifier will not read ours
     as-is.
  2. SIGNING INPUT. KYA signs the JWS signing input (protected header, ".",
     payload). We sign the canonical payload bytes alone. The consequence is
     deliberate: there is no unsigned protected header for an attacker to swap
     an `alg` or `kid` into, because there is no protected header at all. The
     key identity lives INSIDE the signed payload (`iss`), and
     `verify_receipt()` checks that `pubkey_b64` is the key `iss` names — so
     substituting the key breaks the signature AND the binding.
  3. SESSION CLAIMS. `sessionId`, `scopeId`, `delegationRef`, `clientDid` are
     not emitted. A one-shot grade has no session, and inventing an empty one
     to look conformant is the kind of theater this project exists to complain
     about.
  4. KEY DISTRIBUTION. KYA resolves the public key from a *published* DID
     document. `did:key` needs no resolution, but nobody has registered,
     published, or attested this key anywhere: a verifier learns only that one
     key signed the grade, never that it is *our* key. Trust-on-first-use, and
     it is on us to publish a stable key before that claim can be made.
  5. EXTENSION CLAIMS. `source_sha256`, `verdict`, `checks_run`,
     `tool_version`, `target` are mcp_vet's own, not KYA claim names.

--- the optional dependency, and why it is optional -------------------------

Python's stdlib has no Ed25519. The scanner core stays stdlib-only (a checker
that drags in a dependency tree is a supply-chain surface of its own), so
signing lives in the `[receipts]` extra and takes whichever backend is present:
`cryptography` first, `pynacl` second. Neither installed means `sign_grade()`
RAISES — it does not return an unsigned object that looks like a receipt. The
one thing worse than no signature is a caller who believes there is one, which
is the same failure the audit trail's ON/OFF line exists to prevent.
"""
from __future__ import annotations

from arcaeon.record.row import canon_json

import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from . import __version__

#: Emitted in every receipt. The "-compatible" suffix is load-bearing: see the
#: conformance block above. Bump this string if the envelope ever changes shape.
RECEIPT_FORMAT = "checkpoint-kya-v1-compatible"

#: KYA's `prf` claim is a response-proof profile discriminator. Ours says what
#: kind of statement this is, so a verifier that meets an mcp_vet receipt in the
#: wild knows it is reading a grade attestation and not a tool-call proof.
RECEIPT_PROFILE = "mcp-vet-grade-v1"

#: Default audience when the caller names none. A receipt handed to the open
#: internet has no single recipient DID to bind to, and leaving `aud` out
#: entirely would quietly drop a claim the spec treats as meaningful — so it is
#: present and it says plainly that it is unbound.
PUBLIC_AUDIENCE = "urn:mcp-vet:public"

#: Environment override for the signing key: 32-byte seed, base64. Read at CALL
#: time, never cached at import — same rule as the audit ledger path, and for
#: the same reason (an operator who sets it in the launching shell must win).
RECEIPT_KEY_ENV = "MCP_VET_RECEIPT_KEY"

#: An explicit key FILE, set by a caller (the only other key source besides
#: the env var). There is deliberately NO default path: this module ships
#: in the public wheel, and a baked-in per-machine location would both leak
#: a private layout and let a stray file on a stranger's disk sign in our
#: name. None = no key file; with the env var also unset there is no key,
#: and `badge --receipt` reports UNSIGNED rather than inventing one.
RECEIPT_KEY_FILE: "Path | None" = None

DIVERGENCES = [
    "envelope: plain JSON {payload, signature_b64, pubkey_b64}, not KYA's "
    "detached compact JWS in MCP _meta.proof — a KYA verifier will not read "
    "this as-is",
    "signing input: the canonical payload bytes alone, not the JWS signing "
    "input (protected-header + '.' + payload); there is no protected header, "
    "so there is no unsigned alg/kid for an attacker to swap",
    "session claims sessionId / scopeId / delegationRef / clientDid are not "
    "emitted: a one-shot grade has no session and a hollow one is theater",
    "key distribution: the public key ships in the envelope and iss is a "
    "self-certifying did:key, but no DID document is published anywhere — a "
    "verifier learns that ONE key signed this, never that it is ours",
    "source_sha256 / verdict / checks_run / tool_version / target are mcp_vet "
    "extension claims, not KYA claim names",
]


# --- backend probe -----------------------------------------------------------
#
# Two backends, same 32-byte seed and same 32-byte public key on both, so a
# receipt signed on a `cryptography` box verifies on a `pynacl` box. That is
# asserted in the tests rather than assumed: "Ed25519 is Ed25519" is true and is
# still the kind of thing that quietly stops being true across a version bump.

def _probe() -> str | None:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
        return "cryptography"
    except ImportError:
        pass
    try:
        import nacl.signing  # noqa: F401
        return "pynacl"
    except ImportError:
        return None


#: Which backend is doing the math, or None. Probed once at import because the
#: answer cannot change inside a process without a reimport; the KEY, unlike
#: this, is read fresh on every call.
BACKEND = _probe()
RECEIPTS_AVAILABLE = BACKEND is not None


def receipts_status_line() -> str:
    """One line, ON or OFF, for anywhere an operator might look. Mirrors
    `server.audit_status_line()` deliberately: the same failure mode (believing
    a control is on when it is off) deserves the same countermeasure."""
    if RECEIPTS_AVAILABLE:
        return "grade receipts: ON (Ed25519 via %s)" % BACKEND
    return ("grade receipts: OFF, no Ed25519 backend (Python's stdlib has "
            "none). Install the extra: pip install 'arcaeon[sign]'")


class ReceiptsUnavailable(RuntimeError):
    """Raised instead of returning an unsigned object that looks like a
    receipt."""


def _require_backend() -> str:
    if BACKEND is None:
        raise ReceiptsUnavailable(receipts_status_line())
    return BACKEND


def _sign_bytes(seed: bytes, message: bytes) -> bytes:
    backend = _require_backend()
    if backend == "cryptography":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return Ed25519PrivateKey.from_private_bytes(seed).sign(message)
    import nacl.signing
    return nacl.signing.SigningKey(seed).sign(message).signature


def _verify_bytes(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    backend = _require_backend()
    if backend == "cryptography":
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False
    import nacl.exceptions
    import nacl.signing
    try:
        nacl.signing.VerifyKey(pubkey).verify(message, signature)
        return True
    except (nacl.exceptions.BadSignatureError, ValueError, TypeError):
        return False


def public_key_from_seed(seed: bytes) -> bytes:
    """The 32-byte raw Ed25519 public key for a 32-byte seed."""
    backend = _require_backend()
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes, got %d" % len(seed))
    if backend == "cryptography":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat)
        return (Ed25519PrivateKey.from_private_bytes(seed).public_key()
                .public_bytes(Encoding.Raw, PublicFormat.Raw))
    import nacl.signing
    return bytes(nacl.signing.SigningKey(seed).verify_key)


def generate_seed() -> bytes:
    """A fresh 32-byte signing seed. `secrets`, not `random`."""
    return secrets.token_bytes(32)


class NoReceiptKey(LookupError):
    """No signing key is configured: neither `$MCP_VET_RECEIPT_KEY` nor an
    explicit key file. The badge reports UNSIGNED on this, never a signature
    from a key nobody holds."""


def key_source(key_file: "str | Path | None" = None) -> "str | None":
    """Where a signing key would come from, or None when there is none.
    The env var always wins; then an explicit `key_file`; then the module's
    `RECEIPT_KEY_FILE` if a caller set one. There is no home-directory default."""
    if os.environ.get(RECEIPT_KEY_ENV):
        return "env:%s" % RECEIPT_KEY_ENV
    for cand in (key_file, RECEIPT_KEY_FILE):
        if cand is not None and Path(cand).is_file():
            return str(cand)
    return None


def load_seed(key_file: "str | Path | None" = None, *, ephemeral_ok: bool = True) -> bytes:
    """The signing seed from `$MCP_VET_RECEIPT_KEY` (32 bytes, base64); if
    unset, an explicit `key_file` (same shape, one line), else the module's
    `RECEIPT_KEY_FILE` when a caller has set one. There is NO default path on
    disk: the public wheel must not reach into a per-machine secrets folder.

    THE ENV VAR ALWAYS WINS: an operator who sets it in the launching shell
    must not be silently overridden by a file.

    With no key anywhere: `ephemeral_ok=True` (the library default, for tests
    and one-shot use) returns a fresh EPHEMERAL seed, which verifies and
    attributes to nobody; `ephemeral_ok=False` raises NoReceiptKey so the
    caller can say UNSIGNED instead. A key file that EXISTS but is malformed
    (wrong length, not base64) IS an error, same as a malformed env var."""
    raw = os.environ.get(RECEIPT_KEY_ENV)
    source = RECEIPT_KEY_ENV
    if not raw:
        raw = None
        for cand in (key_file, RECEIPT_KEY_FILE):
            if cand is None:
                continue
            try:
                raw = Path(cand).read_text(encoding="ascii").strip()
                source = str(cand)
                break
            except OSError:
                if cand is key_file and key_file is not None:
                    raise ValueError("key file %s could not be read" % cand)
                continue
    if not raw:
        if ephemeral_ok:
            return generate_seed()
        raise NoReceiptKey(
            "no signing key: set %s (32-byte seed, base64) or pass a key file"
            % RECEIPT_KEY_ENV)
    try:
        seed = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise ValueError(
            "%s is not valid base64: %s" % (source, exc)) from exc
    if len(seed) != 32:
        raise ValueError("%s must decode to 32 bytes, got %d"
                         % (source, len(seed)))
    return seed


# --- did:key, RFC 8785 -------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


def did_key(pubkey: bytes) -> str:
    """`did:key` for a raw Ed25519 public key: multicodec 0xed01 + base58btc,
    'z'-prefixed per the multibase spec. Self-certifying — the key is in the
    identifier, so `iss` needs no directory to resolve against."""
    return "did:key:z" + _b58encode(b"\xed\x01" + pubkey)


def _canonical(obj: Any) -> bytes:
    """RFC 8785 (JCS) canonical JSON bytes.

    `sort_keys` + no whitespace + UTF-8 is JCS for everything this module
    serializes. FLOATS ARE REFUSED rather than approximated: JCS pins number
    serialization to ECMAScript's algorithm, `json.dumps` does not implement
    it, and the two agree for integers and disagree for some floats. Emitting a
    hash over almost-canonical bytes would make every downstream verifier's
    "RFC 8785" claim a lie in exactly the cases nobody tests. A grade artifact
    contains no floats today; if one ever appears, this raises loudly instead
    of silently ending conformance."""
    _reject_floats(obj)
    return canon_json(obj)  # arcaeon.record.row: same bytes once floats are refused


def _reject_floats(obj: Any, path: str = "$") -> None:
    if isinstance(obj, float):
        raise ValueError(
            "RFC 8785 float serialization is not implemented here; refusing to "
            "emit a non-canonical hash. Offending value at %s: %r" % (path, obj))
    if isinstance(obj, dict):
        for k, v in obj.items():
            _reject_floats(v, "%s.%s" % (path, k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _reject_floats(v, "%s[%d]" % (path, i))


def canonical_sha256(obj: Any) -> str:
    """`sha256:<64-char-lowercase-hex>` over the JCS canonical bytes — the
    spec's hash format, spelled the spec's way."""
    return "sha256:" + hashlib.sha256(_canonical(obj)).hexdigest()


# --- signing -----------------------------------------------------------------

def _as_grade_dict(grade: Any) -> dict:
    """Accept a `Grade` dataclass or the dict it serializes to. The endpoint
    holds dicts, the CLI holds dataclasses, and making the caller convert is
    the kind of friction that ends with two code paths."""
    if isinstance(grade, dict):
        return grade
    to_json = getattr(grade, "to_json", None)
    if callable(to_json):
        return json.loads(to_json())
    raise TypeError("expected a grade dict or a Grade dataclass, got %r"
                    % type(grade).__name__)


def sign_grade(grade: Any, seed: bytes | None = None, *,
               audience: str | None = None, nonce: str | None = None,
               ts: int | None = None) -> dict:
    """Sign a grade artifact and return the receipt envelope.

    Returns `{payload, signature_b64, pubkey_b64, format, alg, canonicalization,
    divergences}`. Only `payload` is signed; everything beside it is either
    derived from the signature (`pubkey_b64`) or a hint a verifier must not
    trust — `verify_receipt()` re-derives rather than believes.

    Raises `ReceiptsUnavailable` when no Ed25519 backend is installed. It does
    not fall back to an unsigned envelope."""
    _require_backend()
    grade = _as_grade_dict(grade)
    for required in ("source_sha256", "verdict", "checks_run", "tool_version"):
        if required not in grade:
            raise ValueError("grade is missing %r — not a grade artifact"
                             % required)

    seed = generate_seed() if seed is None else seed
    pubkey = public_key_from_seed(seed)
    did = did_key(pubkey)

    payload = {
        # --- KYA-OS claim names, spec meanings ------------------------------
        "aud": audience or PUBLIC_AUDIENCE,
        "iss": did,
        "sub": did,
        "nonce": nonce or secrets.token_hex(16),
        # Unix epoch seconds, per the spec. An int, which also keeps the
        # canonical form float-free.
        "ts": int(time.time()) if ts is None else int(ts),
        # What was asked: the bytes, named. Not the whole file — the digest IS
        # the request as far as a grade is concerned.
        "requestHash": canonical_sha256({
            "target": grade.get("target"),
            "source_sha256": grade["source_sha256"],
        }),
        # What was answered: the ENTIRE grade artifact, blind spots included.
        # This is what makes a small receipt bind a large document.
        "responseHash": canonical_sha256(grade),
        "outcome": "allowed",
        "prf": RECEIPT_PROFILE,
        # --- mcp_vet extension claims ---------------------------------------
        "source_sha256": grade["source_sha256"],
        "verdict": grade["verdict"],
        "checks_run": list(grade["checks_run"]),
        "tool_version": grade["tool_version"],
        "target": grade.get("target"),
    }

    signature = _sign_bytes(seed, _canonical(payload))
    return {
        "format": RECEIPT_FORMAT,
        "alg": "EdDSA",
        "canonicalization": "RFC8785",
        "payload": payload,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "pubkey_b64": base64.b64encode(pubkey).decode("ascii"),
        # In-band, every time, for the same reason the grade carries its own
        # blind spots: a confession filed elsewhere is a confession nobody reads.
        "divergences": list(DIVERGENCES),
    }


# --- verification ------------------------------------------------------------

def verify_receipt_detail(receipt: Any, grade: Any = None, *,
                          expected_pubkey_b64: str | None = None,
                          expected_audience: str | None = None) -> dict:
    """The long form: `{verified, reasons, bound_to_grade, signer}`.

    `verified` is the signature question only — did the key in `pubkey_b64`
    sign these exact canonical payload bytes, and does that key match the
    `did:key` inside the signed payload. `bound_to_grade` is the separate
    question of whether the receipt is about the grade you are holding, and it
    is only True when a grade was actually supplied. A caller that verifies the
    signature and skips the binding has proved that somebody signed A grade,
    which is not the same as proving they signed THIS one — so the two answers
    stay separate instead of being averaged into one green light."""
    reasons: list[str] = []
    out = {"verified": False, "reasons": reasons, "bound_to_grade": None,
           "signer": None}

    if not isinstance(receipt, dict):
        reasons.append("not a receipt object: %r" % type(receipt).__name__)
        return out
    for field in ("payload", "signature_b64", "pubkey_b64"):
        if field not in receipt:
            reasons.append("missing %s" % field)
    if reasons:
        return out

    payload = receipt["payload"]
    if not isinstance(payload, dict):
        reasons.append("payload is not an object")
        return out

    # `alg` rides outside the signature, so it is a hint and never an input:
    # the code path below is Ed25519 unconditionally. It is checked only so a
    # receipt claiming some other algorithm is rejected rather than silently
    # verified as Ed25519 anyway.
    if receipt.get("alg", "EdDSA") != "EdDSA":
        reasons.append("alg is %r; only EdDSA is verified here"
                       % receipt.get("alg"))
        return out

    try:
        signature = base64.b64decode(receipt["signature_b64"], validate=True)
        pubkey = base64.b64decode(receipt["pubkey_b64"], validate=True)
    except Exception as exc:
        reasons.append("signature_b64/pubkey_b64 is not valid base64: %s" % exc)
        return out
    if len(pubkey) != 32:
        reasons.append("pubkey is %d bytes, an Ed25519 public key is 32"
                       % len(pubkey))
        return out

    if expected_pubkey_b64 is not None and \
            receipt["pubkey_b64"] != expected_pubkey_b64:
        reasons.append("signed by a different key than expected")

    # The key that ships in the envelope must be the key the SIGNED payload
    # names. Without this, swapping pubkey_b64 for another key is caught only by
    # the signature check — true, but it leaves `iss` free to say anything, and
    # `iss` is the field a reader's eye actually lands on.
    signer_did = payload.get("iss")
    if signer_did != did_key(pubkey):
        reasons.append("iss %r does not match the key in pubkey_b64 (%s)"
                       % (signer_did, did_key(pubkey)))
    out["signer"] = signer_did

    try:
        message = _canonical(payload)
    except ValueError as exc:
        reasons.append("payload is not canonicalizable: %s" % exc)
        return out

    if not _verify_bytes(pubkey, message, signature):
        reasons.append("signature does not verify over the canonical payload "
                       "(tampered payload, wrong key, or a different "
                       "canonicalization)")

    if expected_audience is not None and payload.get("aud") != expected_audience:
        reasons.append("aud is %r, expected %r"
                       % (payload.get("aud"), expected_audience))

    if grade is not None:
        try:
            grade_dict = _as_grade_dict(grade)
            actual = canonical_sha256(grade_dict)
        except (TypeError, ValueError) as exc:
            out["bound_to_grade"] = False
            reasons.append("grade could not be hashed: %s" % exc)
        else:
            out["bound_to_grade"] = actual == payload.get("responseHash")
            if not out["bound_to_grade"]:
                reasons.append(
                    "responseHash does not match the grade supplied: receipt "
                    "says %s, this grade hashes to %s"
                    % (payload.get("responseHash"), actual))

    out["verified"] = not reasons
    return out


def verify_receipt(receipt: Any, grade: Any = None, *,
                   expected_pubkey_b64: str | None = None,
                   expected_audience: str | None = None) -> bool:
    """True iff the receipt verifies (and, when a grade is supplied, is bound to
    it). `verify_receipt_detail()` for the reasons — and read them before
    reporting a red, because "wrong key" and "tampered" are different stories."""
    return verify_receipt_detail(
        receipt, grade, expected_pubkey_b64=expected_pubkey_b64,
        expected_audience=expected_audience)["verified"]
