# SPDX-License-Identifier: MIT
"""arcaeon.connector.opa_bundle: seal an Open Policy Agent policy bundle, so a
decision row can say WHICH bundle it was made under (the join is
arcaeon.connector.opa.join_bundles).

WHY. OPA decision logs are unsigned and name the policy only as
`bundles.<name>.revision`, the string from the bundle's `.manifest`. OPA signs
BUNDLES, not decisions. So "this decision was made under that signed policy"
holds only if we also hold the bundle's exact bytes and match its revision.

THE FORMAT, as OPA documents it (Bundles page, "Signing",
https://www.openpolicyagent.org/docs/management-bundles):

    .manifest          JSON {"revision": str, "roots": [str], "metadata": {...}}
    .signatures.json   JSON {"signatures": ["<JWT>"]}; one signature per bundle
    JWT header         alg, typ, kid
    JWT payload        files [{name, hash, algorithm}], optional keyid, scope, iat, iss
    file hash          unstructured files: hash of the bytes; JSON/YAML files:
                       parse, sort object keys recursively, then hash
    algorithms         MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
                       SHA-512-224, SHA-512-256

A bundle is a gzipped tarball or a directory of the same files.

THE STATEMENT (kind "policy.bundle.sealed"), every key always present:

    bundle_name            the caller's name for the bundle (the key in OPA's
                           `bundles` config and in decision logs)
    bundle_form            "tar.gz" | "directory" | None
    bundle_digest_scheme   "sha256:raw-bytes:v1" (a tarball: the exact bytes) or
                           "sha256:opa-bundle-dir:v1" (a directory: sha256 over
                           the sorted lines "<name>\\0<sha256 hex of its bytes>\\n")
    bundle_sha256          the hex digest under that scheme, or None
    bundle_bytes           the tarball's length, or a directory's file bytes in total
    revision, roots        from `.manifest`, or None when it cannot be read
    files                  how many regular files the bundle holds
    opa_signatures_present True when `.signatures.json` is in the bundle
    opa_signature_verified VERIFIED only when the JWT was checked with the
                           caller's key AND every file hash matched; BROKEN when
                           either fails; COULD NOT LOOK otherwise (no key, no
                           verifier for the algorithm, no signature, a hash we
                           cannot recompute)
    opa_signature_reason   one sentence why
    signature              {alg, kid, keyid, scope, iat, iss, jwt_sha256} or None
    file_hashes            {verdict, listed, matched, mismatched, missing, unlisted,
                           could_not_check}: each file the JWT lists, rehashed from
                           the bundle bytes (stdlib hashlib)
    seal                   VERIFIED: the bytes are held and the manifest was read.
                           COULD NOT LOOK (with `could_not_look`) otherwise. It
                           says nothing about the signature.
    active_from, active_until  the caller's declared window the bundle was in
                           force (RFC 3339), or None
    sealed_at              our clock

NEVER EXTRACTED. A tarball is read in memory, member by member. Any member name
with a `..` segment, a backslash, a drive letter or an empty segment, any link
or device member, or a name twice makes the whole bundle COULD NOT LOOK. A
leading "/" or "./" is dropped (OPA's own tarballs write "/.manifest"; this is
not in R14 and is tolerated, not required). Bounded: MAX_BUNDLE_BYTES as
received, MAX_TAR_BYTES inflated, MAX_FILES members.

Stdlib only; RS/PS/ES signatures use the optional `cryptography` package when it
is installed and say COULD NOT LOOK when it is not. No network.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import re
import tarfile
import zlib
from datetime import datetime
from typing import Any

from arcaeon.record.row import loads_strict
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED, could_not_look

from .core import _now_iso, _safe_str, _too_deep

__all__ = ["SEAL_KIND", "RAW_SCHEME", "DIR_SCHEME", "MAX_BUNDLE_BYTES", "MAX_TAR_BYTES",
           "MAX_FILES", "KEY_ALGORITHMS", "seal_bundle", "parse_ts"]

SEAL_KIND = "policy.bundle.sealed"
RAW_SCHEME = "sha256:raw-bytes:v1"
DIR_SCHEME = "sha256:opa-bundle-dir:v1"
#: A tarball over this (as received) is digested, never opened.
MAX_BUNDLE_BYTES = 16 << 20
#: A tarball inflating past this, or a directory holding more, is not read.
MAX_TAR_BYTES = 64 << 20
#: More members than this: not read.
MAX_FILES = 10000
#: Names listed per field in file_hashes; the counts are always whole.
_MAX_LISTED = 64

_HASHES = {"MD5": "md5", "SHA-1": "sha1", "SHA-224": "sha224", "SHA-256": "sha256",
           "SHA-384": "sha384", "SHA-512": "sha512", "SHA-512-224": "sha512_224",
           "SHA-512-256": "sha512_256"}
_HMAC = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
_ASYM = {f"{p}{n}": f"sha{n}" for p in ("RS", "PS", "ES") for n in (256, 384, 512)}
#: The key algorithms OPA documents for bundle signing keys.
KEY_ALGORITHMS = tuple(sorted(_HMAC) + sorted(_ASYM))

_MANIFEST = ".manifest"
_SIGNATURES = ".signatures.json"
_WHERE = "OPA bundle"


class _Unreadable(Exception):
    def __init__(self, word: str, reason: str):
        super().__init__(reason)
        self.word, self.reason = word, reason


def parse_ts(v: Any) -> datetime | None:
    """An RFC 3339 timestamp with a zone -> aware datetime, else None. Fractions past
    microseconds (OPA writes nanoseconds) are cut, not rounded."""
    if not isinstance(v, str) or len(v) > 64:
        return None
    s = re.sub(r"[zZ]$", "+00:00", v.strip())
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        return None
    return t if t.tzinfo is not None else None


def _member_name(n: Any) -> str | None:
    """A bundle-relative POSIX name, or None when it could escape or is ambiguous."""
    if not isinstance(n, str) or not n or "\\" in n or "\x00" in n:
        return None
    while n.startswith("./") or n.startswith("/"):
        n = n[2:] if n.startswith("./") else n[1:]
    parts = n.rstrip("/").split("/")
    if not n or ":" in parts[0] or any(p in ("", ".", "..") for p in parts):
        return None
    return "/".join(parts)


def _gunzip(raw: bytes) -> bytes:
    d = zlib.decompressobj(wbits=31)
    out = d.decompress(raw, MAX_TAR_BYTES + 1)
    if len(out) > MAX_TAR_BYTES:
        raise _Unreadable("bounded", f"the tarball inflates past {MAX_TAR_BYTES} bytes; not read")
    if not d.eof or d.unused_data or d.unconsumed_tail:
        raise _Unreadable("unreadable", "the gzip stream is truncated or has trailing bytes")
    return out


def _read_tar(raw: bytes) -> dict:
    if raw[:2] != b"\x1f\x8b":
        raise _Unreadable("unreadable", "not a gzipped tarball")
    try:
        body = _gunzip(raw)
    except (zlib.error, EOFError) as e:
        raise _Unreadable("unreadable", f"the gzip stream cannot be read: {type(e).__name__}")
    files: dict = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:") as tf:
            for i, m in enumerate(tf):
                if i >= MAX_FILES:
                    raise _Unreadable("bounded", f"more than {MAX_FILES} members; not read")
                name = _member_name(m.name)
                if name is None:
                    raise _Unreadable("unreadable", f"member {_safe_str(m.name)!r} names a path "
                                                    f"outside the bundle or an ambiguous one")
                if m.isdir():
                    continue
                if not m.isreg():
                    raise _Unreadable("unreadable", f"member {name!r} is a link or device, "
                                                    f"not a regular file")
                if name in files:
                    raise _Unreadable("unreadable", f"member {name!r} appears twice")
                f = tf.extractfile(m)
                files[name] = f.read() if f is not None else b""
    except tarfile.TarError as e:
        raise _Unreadable("unreadable", f"not a tarball: {type(e).__name__}")
    return files


def _read_dir(root: str) -> dict:
    files: dict = {}
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for d in list(dirnames):
            p = os.path.join(dirpath, d)
            if os.path.islink(p) or getattr(os.path, "isjunction", lambda _: False)(p):
                raise _Unreadable("unreadable", "the directory holds a link")
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                raise _Unreadable("unreadable", "the directory holds a link or a non-file")
            if len(files) >= MAX_FILES:
                raise _Unreadable("bounded", f"more than {MAX_FILES} files; not read")
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            name = _member_name(rel)
            if name is None:
                raise _Unreadable("unreadable", "a file name in the directory is ambiguous")
            total += os.path.getsize(p)
            if total > MAX_TAR_BYTES:
                raise _Unreadable("bounded", f"the directory holds over {MAX_TAR_BYTES} bytes")
            with open(p, "rb") as fh:
                files[name] = fh.read(MAX_TAR_BYTES + 1)
    return files


def _manifest(files: dict) -> tuple[str, list]:
    if _MANIFEST not in files:
        raise _Unreadable("missing", "the bundle has no .manifest, so no revision")
    try:
        doc = loads_strict(files[_MANIFEST].decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise _Unreadable("unreadable", f".manifest is not one unambiguous JSON value: "
                                        f"{type(e).__name__}")
    if not isinstance(doc, dict) or _too_deep(doc, 32):
        raise _Unreadable("unreadable", ".manifest is not a JSON object")
    rev, roots = doc.get("revision"), doc.get("roots")
    if not isinstance(rev, str):
        raise _Unreadable("unreadable" if "revision" in doc else "missing",
                          ".manifest revision is not a string")
    if not rev:
        raise _Unreadable("empty", ".manifest revision is empty")
    if roots is not None and not (isinstance(roots, list) and all(isinstance(r, str) for r in roots)):
        raise _Unreadable("unreadable", ".manifest roots is not a list of strings")
    return rev, roots


def _b64d(s: str) -> bytes:
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jwt(files: dict) -> tuple[list, dict, str]:
    """(parts, header+payload, raw jwt) from .signatures.json. Raises _Unreadable."""
    try:
        doc = loads_strict(files[_SIGNATURES].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _Unreadable("unreadable", ".signatures.json is not one unambiguous JSON value")
    sigs = doc.get("signatures") if isinstance(doc, dict) else None
    if not isinstance(sigs, list) or not sigs:
        raise _Unreadable("unreadable", ".signatures.json lists no signatures")
    if len(sigs) != 1:
        raise _Unreadable("unreadable", f".signatures.json lists {len(sigs)} signatures; "
                                        f"OPA supports one")
    tok = sigs[0]
    parts = tok.split(".") if isinstance(tok, str) else []
    if len(parts) != 3:
        raise _Unreadable("unreadable", "the signature is not a three-part JWT")
    try:
        head = loads_strict(_b64d(parts[0]).decode("utf-8"))
        body = loads_strict(_b64d(parts[1]).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _Unreadable("unreadable", "the JWT header or payload is not base64url JSON")
    if not isinstance(head, dict) or not isinstance(body, dict):
        raise _Unreadable("unreadable", "the JWT header or payload is not a JSON object")
    return parts, {"head": head, "body": body}, tok


def _sorted_json(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _sorted_json(v[k]) for k in sorted(v)}
    if isinstance(v, list):
        return [_sorted_json(x) for x in v]
    return v


def _candidates(name: str, data: bytes) -> tuple[list, bool]:
    """Byte strings OPA might have hashed for this file, and whether the file is
    structured (JSON/YAML). R14 documents "parse, sort keys, hash" but not the exact
    serialisation; we try the raw bytes and two compact sorted forms (plain, and Go's
    HTML-escaping json.Marshal, an inference). A match is a match; a structured file
    with no match is COULD NOT LOOK, never BROKEN."""
    low = name.rsplit("/", 1)[-1].lower()
    structured = low == _MANIFEST or low.endswith((".json", ".yaml", ".yml"))
    out = [data]
    if low == _MANIFEST or low.endswith(".json"):
        try:
            v = _sorted_json(loads_strict(data.decode("utf-8")))
            c = json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            out.append(c)
            out.append(c.replace(b"<", b"\\u003c").replace(b">", b"\\u003e")
                       .replace(b"&", b"\\u0026"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            pass
    return out, structured


def _file_hashes(files: dict, listed: Any, exclude: set) -> dict:
    out = {"verdict": COULD_NOT_LOOK, "listed": 0, "matched": 0, "mismatched": [],
           "missing": [], "unlisted": [], "could_not_check": []}
    if not isinstance(listed, list) or not listed:
        return out
    seen = set()
    for ent in listed[:MAX_FILES]:
        out["listed"] += 1
        e = ent if isinstance(ent, dict) else {}
        name = _member_name(e.get("name"))
        shown = name or _safe_str(e.get("name")) or "(unnamed)"
        algo = _HASHES.get(e.get("algorithm").upper()) if isinstance(e.get("algorithm"), str) else None
        want = e.get("hash").lower() if isinstance(e.get("hash"), str) else None
        if name is None or name in seen or algo is None or want is None:
            out["could_not_check"].append(shown)
            continue
        seen.add(name)
        if name not in files:
            out["missing"].append(name)
            continue
        cands, structured = _candidates(name, files[name])
        try:
            got = [hashlib.new(algo, c).hexdigest() for c in cands]
        except ValueError:
            out["could_not_check"].append(name)
            continue
        if any(hmac.compare_digest(g, want) for g in got):
            out["matched"] += 1
        elif structured:
            out["could_not_check"].append(name)
        else:
            out["mismatched"].append(name)
    out["unlisted"] = sorted(n for n in files if n not in seen and n != _SIGNATURES
                             and n not in exclude)
    if out["mismatched"] or out["missing"] or out["unlisted"]:
        out["verdict"] = BROKEN
    elif not out["could_not_check"] and out["matched"]:
        out["verdict"] = VERIFIED
    for k in ("mismatched", "missing", "unlisted", "could_not_check"):
        out[k] = sorted(out[k])[:_MAX_LISTED]
    return out


def _verify_jwt(parts: list, head: dict, key: Any, key_alg: str | None) -> tuple[str, str]:
    if key is None:
        return COULD_NOT_LOOK, "no verification key was supplied, so the JWT was not checked"
    alg = head.get("alg")
    if alg != key_alg:
        return BROKEN, f"the JWT says alg {_safe_str(alg)!r}; the key is {key_alg}"
    msg = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        sig = _b64d(parts[2])
    except ValueError:
        return BROKEN, "the JWT signature is not base64url"
    kb = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    if alg in _HMAC:
        ok = hmac.compare_digest(hmac.new(kb, msg, _HMAC[alg]).digest(), sig)
        return (VERIFIED, "the JWT HMAC matches the supplied key") if ok else (
            BROKEN, "the JWT HMAC does not match the supplied key")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    except ImportError:
        return COULD_NOT_LOOK, f"no verifier for {alg} is installed (the optional cryptography package)"
    try:
        pub = serialization.load_pem_public_key(kb)
    except Exception:  # noqa: BLE001 - a key we cannot read is not a check
        return COULD_NOT_LOOK, "the supplied key is not a PEM public key"
    h = getattr(hashes, _ASYM[alg].upper())()
    try:
        if alg[:2] in ("RS", "PS") and isinstance(pub, rsa.RSAPublicKey):
            pad = padding.PKCS1v15() if alg[:2] == "RS" else padding.PSS(
                mgf=padding.MGF1(h), salt_length=padding.PSS.DIGEST_LENGTH)
            pub.verify(sig, msg, pad, h)
        elif alg[:2] == "ES" and isinstance(pub, ec.EllipticCurvePublicKey):
            n = (pub.curve.key_size + 7) // 8
            if len(sig) != 2 * n:
                return BROKEN, "the JWT ECDSA signature has the wrong length"
            der = utils.encode_dss_signature(int.from_bytes(sig[:n], "big"),
                                             int.from_bytes(sig[n:], "big"))
            pub.verify(der, msg, ec.ECDSA(h))
        else:
            return COULD_NOT_LOOK, f"the supplied key is not a key for {alg}"
    except InvalidSignature:
        return BROKEN, "the JWT signature does not verify under the supplied key"
    return VERIFIED, "the JWT signature verifies under the supplied key"


def _statement(name: str, sealed_at: str, active_from, active_until) -> dict:
    return {"kind": SEAL_KIND, "bundle_name": name, "bundle_form": None,
            "bundle_digest_scheme": None, "bundle_sha256": None, "bundle_bytes": None,
            "revision": None, "roots": None, "files": None, "opa_signatures_present": False,
            "opa_signature_verified": COULD_NOT_LOOK,
            "opa_signature_reason": "the bundle was not read", "signature": None,
            "file_hashes": None, "seal": COULD_NOT_LOOK, "active_from": active_from,
            "active_until": active_until, "sealed_at": sealed_at}


def _cnl(st: dict, word: str, reason: str) -> dict:
    st["seal"] = COULD_NOT_LOOK
    st["revision"] = st["roots"] = None
    st["could_not_look"] = could_not_look("an OPA bundle with a readable .manifest", _WHERE,
                                          word, reason)
    return st


def _digest_file(path: str, st: dict) -> bytes | None:
    """The tarball's bytes, or None when over the limit (then digested in chunks)."""
    size = os.path.getsize(path)
    st["bundle_form"], st["bundle_digest_scheme"], st["bundle_bytes"] = "tar.gz", RAW_SCHEME, size
    if size <= MAX_BUNDLE_BYTES:
        with open(path, "rb") as fh:
            return fh.read(MAX_BUNDLE_BYTES + 1)
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    st["bundle_sha256"] = h.hexdigest()
    return None


def seal_bundle(source: Any, *, name: str, verification_key: Any = None,
                key_algorithm: str | None = None, exclude_files: Any = (),
                active_from: str | None = None, active_until: str | None = None,
                sealed_at: str | None = None) -> dict:
    """Seal one OPA bundle: `source` is the tarball's bytes, a path to a tarball, or
    a path to a bundle directory. Returns the statement (module docstring).

    `name`: the bundle's name as OPA's config and decision logs use it.
    `verification_key` + `key_algorithm` (one of KEY_ALGORITHMS): the public key
    (PEM) or HMAC secret the bundle should be signed with; without both the JWT is
    COULD NOT LOOK. `exclude_files`: exact bundle file names OPA was told not to
    verify. `active_from` / `active_until`: when the bundle was in force (RFC 3339),
    used by the join to call a conflicting revision BROKEN.
    Raises ValueError only on caller arguments; never on the bundle."""
    if not isinstance(name, str) or not name:
        raise ValueError("name: the bundle name must be a non-empty string")
    if key_algorithm is not None and key_algorithm not in KEY_ALGORITHMS:
        raise ValueError(f"key_algorithm must be one of {KEY_ALGORITHMS}")
    if (verification_key is None) != (key_algorithm is None):
        raise ValueError("verification_key and key_algorithm go together")
    for k, v in (("active_from", active_from), ("active_until", active_until)):
        if v is not None and parse_ts(v) is None:
            raise ValueError(f"{k}: not an RFC 3339 timestamp with a zone")
    if isinstance(exclude_files, str):
        exclude_files = (exclude_files,)
    exclude = {n for n in (_member_name(x) for x in exclude_files or ()) if n}
    st = _statement(name, sealed_at if isinstance(sealed_at, str) else _now_iso(),
                    active_from, active_until)
    try:
        if isinstance(source, (str, os.PathLike)) and not isinstance(source, bytes):
            path = os.fspath(source)
            if os.path.isdir(path):
                st["bundle_form"], st["bundle_digest_scheme"] = "directory", DIR_SCHEME
                files = _read_dir(path)
                lines = b"".join(n.encode("utf-8") + b"\0" + hashlib.sha256(files[n]).hexdigest()
                                 .encode() + b"\n" for n in sorted(files))
                st["bundle_sha256"] = hashlib.sha256(lines).hexdigest()
                st["bundle_bytes"] = sum(len(b) for b in files.values())
            elif os.path.isfile(path):
                raw = _digest_file(path, st)
                if raw is None:
                    return _cnl(st, "bounded", f"the tarball is {st['bundle_bytes']} bytes, over "
                                               f"the {MAX_BUNDLE_BYTES}-byte limit; digested, not read")
                st["bundle_sha256"] = hashlib.sha256(raw).hexdigest()
                files = _read_tar(raw)
            else:
                return _cnl(st, "missing", "no bundle file or directory at that path")
        elif isinstance(source, (bytes, bytearray)):
            raw = bytes(source)
            st["bundle_form"], st["bundle_digest_scheme"] = "tar.gz", RAW_SCHEME
            st["bundle_sha256"], st["bundle_bytes"] = hashlib.sha256(raw).hexdigest(), len(raw)
            if not raw:
                return _cnl(st, "empty", "the bundle is empty")
            if len(raw) > MAX_BUNDLE_BYTES:
                return _cnl(st, "bounded", f"the tarball is {len(raw)} bytes, over the "
                                           f"{MAX_BUNDLE_BYTES}-byte limit; digested, not read")
            files = _read_tar(raw)
        else:
            return _cnl(st, "unreadable", f"source is a {type(source).__name__}, not bytes or a path")
        st["files"] = len(files)
        st["revision"], st["roots"] = _manifest(files)
        st["seal"] = VERIFIED
    except _Unreadable as e:
        return _cnl(st, e.word, e.reason)
    except OSError as e:
        return _cnl(st, "unreadable", f"the bundle cannot be read: {type(e).__name__}")
    except Exception as e:  # noqa: BLE001 - never a traceback on a bundle
        return _cnl(st, "unreadable", f"the sealer failed: {type(e).__name__}")
    _signature(st, files, verification_key, key_algorithm, exclude)
    return st


def _signature(st: dict, files: dict, key: Any, key_alg: str | None, exclude: set) -> None:
    st["file_hashes"] = _file_hashes(files, None, exclude)
    if _SIGNATURES not in files:
        st["opa_signature_reason"] = "the bundle carries no .signatures.json"
        return
    st["opa_signatures_present"] = True
    try:
        parts, hb, tok = _jwt(files)
    except _Unreadable as e:
        st["opa_signature_reason"] = e.reason
        return
    head, body = hb["head"], hb["body"]
    st["signature"] = {"alg": _safe_str(head.get("alg")), "kid": _safe_str(head.get("kid")),
                       "keyid": _safe_str(body.get("keyid")), "scope": _safe_str(body.get("scope")),
                       "iat": body.get("iat") if isinstance(body.get("iat"), int)
                       and not isinstance(body.get("iat"), bool) else None,
                       "iss": _safe_str(body.get("iss")),
                       "jwt_sha256": hashlib.sha256(tok.encode("ascii", "replace")).hexdigest()}
    fh = _file_hashes(files, body.get("files"), exclude)
    st["file_hashes"] = fh
    try:
        jw, why = _verify_jwt(parts, head, key, key_alg)
    except Exception as e:  # noqa: BLE001
        jw, why = COULD_NOT_LOOK, f"the JWT check failed: {type(e).__name__}"
    if fh["verdict"] == BROKEN:
        st["opa_signature_verified"] = BROKEN
        st["opa_signature_reason"] = "a file in the bundle does not match the hash the JWT lists"
    elif jw == BROKEN:
        st["opa_signature_verified"], st["opa_signature_reason"] = BROKEN, why
    elif jw == VERIFIED and fh["verdict"] == VERIFIED:
        st["opa_signature_verified"] = VERIFIED
        st["opa_signature_reason"] = why + ", and every listed file hash matches"
    else:
        st["opa_signature_verified"] = COULD_NOT_LOOK
        st["opa_signature_reason"] = why if jw != VERIFIED else (
            "the JWT verifies but not every file hash could be recomputed")
