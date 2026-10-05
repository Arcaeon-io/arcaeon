# SPDX-License-Identifier: MIT
"""L2-01: seal an OPA policy bundle and join decision rows on its revision.

Bundles are built in-test from small files, deterministically (tar mtime 0, gzip
mtime 0). Shape from R14 (OPA's bundle docs: `.manifest` {revision, roots},
`.signatures.json` {"signatures": [JWT]} with payload files[{name, hash,
algorithm}]), not a live capture. Keys are test keys made here. No network, no
real OPA."""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import io
import json
import os
import tarfile
from pathlib import Path

import pytest

from arcaeon.connector import opa as O
from arcaeon.connector import opa_bundle as B
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

FIX = Path(__file__).resolve().parent / "fixtures" / "opa"
AT = "2026-10-05T12:00:00Z"
KEY = b"test-only-hmac-key-not-a-secret"
REGO = b"package authz\n\ndefault allow := false\n"
REV = "rev-synthetic-0001"


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _manifest(rev=REV, roots=("authz",)) -> bytes:
    return json.dumps({"revision": rev, "roots": list(roots)}).encode()


def _canon(b: bytes) -> bytes:
    return json.dumps(json.loads(b), sort_keys=True, separators=(",", ":")).encode()


def _hash(name: str, data: bytes) -> str:
    if name.endswith(".manifest") or name.endswith(".json"):
        data = _canon(data)
    return hashlib.sha256(data).hexdigest()


def _jwt(files: dict, key=KEY, alg="HS256", sign=None) -> str:
    head = _b64(json.dumps({"alg": alg, "typ": "JWT", "kid": "test"}).encode())
    body = _b64(json.dumps({"files": [{"name": n, "hash": _hash(n, d), "algorithm": "SHA-256"}
                                      for n, d in sorted(files.items())],
                            "keyid": "test", "scope": "write"}).encode())
    msg = f"{head}.{body}".encode()
    sig = sign(msg) if sign else hmac.new(key, msg, hashlib.sha256).digest()
    return f"{head}.{body}.{_b64(sig)}"


def _tar(entries, *, gz=True) -> bytes:
    """entries: list of (name, bytes) or (name, TarInfo-type, linkname)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for e in entries:
            ti = tarfile.TarInfo(e[0])
            ti.mtime = 0
            if len(e) == 3:
                ti.type, ti.linkname = e[1], e[2]
                tf.addfile(ti)
            else:
                ti.size = len(e[1])
                tf.addfile(ti, io.BytesIO(e[1]))
    raw = buf.getvalue()
    return gzip.compress(raw, mtime=0) if gz else raw


def _bundle(files=None, *, signed=True, sig_files=None, **kw) -> bytes:
    files = dict(files) if files is not None else {".manifest": _manifest(), "authz/policy.rego": REGO}
    entries = list(files.items())
    if signed:
        sigs = {"signatures": [_jwt(sig_files if sig_files is not None else files, **kw)]}
        entries.append((".signatures.json", json.dumps(sigs).encode()))
    return _tar(entries)


def _seal(raw, **kw):
    kw.setdefault("name", "authz")
    kw.setdefault("sealed_at", AT)
    return B.seal_bundle(raw, **kw)


def _decisions(*evs):
    return O.ingest(json.dumps(list(evs)).encode(), received_at=AT, allow_paths=("authz/allow",))


def _ev(rev=REV, ts="2026-10-04T11:00:00Z", name="authz"):
    e = {"decision_id": "d", "path": "authz/allow", "result": True, "timestamp": ts}
    if rev is not None:
        e["bundles"] = {name: {"revision": rev}}
    return e


# --- sealing -----------------------------------------------------------------------

def test_the_built_bundle_is_deterministic_and_the_digest_is_its_exact_bytes():
    a, b = _bundle(), _bundle()
    assert a == b
    s = _seal(a)
    assert s["kind"] == "policy.bundle.sealed"
    assert s["bundle_sha256"] == hashlib.sha256(a).hexdigest()
    assert s["bundle_bytes"] == len(a) and s["bundle_form"] == "tar.gz"
    assert s["bundle_name"] == "authz" and s["sealed_at"] == AT
    assert s["revision"] == REV and s["roots"] == ["authz"]
    assert s["seal"] == VERIFIED


def test_an_unsigned_bundle_says_no_signature_and_could_not_look():
    s = _seal(_bundle(signed=False))
    assert s["opa_signatures_present"] is False
    assert s["opa_signature_verified"] == COULD_NOT_LOOK
    assert s["file_hashes"]["verdict"] == COULD_NOT_LOOK


def test_signed_without_a_key_checks_file_hashes_but_not_the_jwt():
    s = _seal(_bundle())
    assert s["opa_signatures_present"] is True
    assert s["file_hashes"]["verdict"] == VERIFIED
    assert s["file_hashes"]["matched"] == 2
    assert s["opa_signature_verified"] == COULD_NOT_LOOK
    assert s["signature"]["alg"] == "HS256" and s["signature"]["keyid"] == "test"


def test_signed_with_the_hmac_key_supplied_is_verified():
    s = _seal(_bundle(), verification_key=KEY, key_algorithm="HS256")
    assert s["opa_signature_verified"] == VERIFIED


def test_wrong_key_or_wrong_algorithm_is_broken():
    assert _seal(_bundle(), verification_key=b"other", key_algorithm="HS256")[
        "opa_signature_verified"] == BROKEN
    assert _seal(_bundle(), verification_key=KEY, key_algorithm="RS256")[
        "opa_signature_verified"] == BROKEN


def test_rs256_with_a_test_key_is_verified_when_cryptography_is_present():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.public_key().public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
    raw = _bundle(alg="RS256", sign=lambda m: k.sign(m, padding.PKCS1v15(), hashes.SHA256()))
    assert _seal(raw, verification_key=pem, key_algorithm="RS256")[
        "opa_signature_verified"] == VERIFIED
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    pem2 = other.public_bytes(serialization.Encoding.PEM,
                              serialization.PublicFormat.SubjectPublicKeyInfo)
    assert _seal(raw, verification_key=pem2, key_algorithm="RS256")[
        "opa_signature_verified"] == BROKEN


def test_a_tampered_file_against_signatures_json_is_broken():
    good = {".manifest": _manifest(), "authz/policy.rego": REGO}
    bad = dict(good, **{"authz/policy.rego": REGO + b"allow := true\n"})
    s = _seal(_bundle(bad, sig_files=good), verification_key=KEY, key_algorithm="HS256")
    assert s["file_hashes"]["verdict"] == BROKEN
    assert s["file_hashes"]["mismatched"] == ["authz/policy.rego"]
    assert s["opa_signature_verified"] == BROKEN


def test_a_file_the_signature_does_not_list_is_broken_unless_excluded():
    files = {".manifest": _manifest(), "authz/policy.rego": REGO, "authz/extra.rego": REGO}
    raw = _bundle(files, sig_files={".manifest": _manifest(), "authz/policy.rego": REGO})
    s = _seal(raw)
    assert s["file_hashes"]["verdict"] == BROKEN and s["file_hashes"]["unlisted"] == ["authz/extra.rego"]
    assert _seal(raw, exclude_files=("authz/extra.rego",))["file_hashes"]["verdict"] == VERIFIED


def test_a_listed_file_missing_from_the_bundle_is_broken():
    files = {".manifest": _manifest()}
    s = _seal(_bundle(files, sig_files=dict(files, **{"authz/policy.rego": REGO})))
    assert s["file_hashes"]["verdict"] == BROKEN and s["file_hashes"]["missing"] == ["authz/policy.rego"]


@pytest.mark.parametrize("manifest", [b"not json", b"[1]", b'{"revision": 7}',
                                      b'{"revision": "r", "roots": "authz"}',
                                      b'{"revision": "a", "revision": "b"}'])
def test_a_malformed_manifest_is_could_not_look_with_no_revision(manifest):
    s = _seal(_bundle({".manifest": manifest, "authz/policy.rego": REGO}, signed=False))
    assert s["seal"] == COULD_NOT_LOOK and s["revision"] is None
    assert s["bundle_sha256"] == hashlib.sha256(_bundle(
        {".manifest": manifest, "authz/policy.rego": REGO}, signed=False)).hexdigest()


def test_no_manifest_is_could_not_look():
    s = _seal(_bundle({"authz/policy.rego": REGO}, signed=False))
    assert s["seal"] == COULD_NOT_LOOK and s["could_not_look"]["reason_word"] == "missing"


@pytest.mark.parametrize("raw", [b"", b"plain bytes, not a tarball", gzip.compress(b"not a tar"),
                                 gzip.compress(b"x")[:-4], None, 12])
def test_not_a_tarball_is_could_not_look(raw):
    s = _seal(raw)
    assert s["seal"] == COULD_NOT_LOOK and s["revision"] is None


@pytest.mark.parametrize("entry", [("../evil.rego", REGO), ("authz/../../evil.rego", REGO),
                                   ("C:/evil.rego", REGO), ("authz\\..\\evil.rego", REGO),
                                   ("link", tarfile.SYMTYPE, "../../etc"),
                                   ("hard", tarfile.LNKTYPE, ".manifest")])
def test_traversal_and_links_are_could_not_look_and_nothing_is_written(entry, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    raw = _tar([(".manifest", _manifest()), entry])
    s = _seal(raw)
    assert s["seal"] == COULD_NOT_LOOK and s["could_not_look"]["reason_word"] == "unreadable"
    assert s["revision"] is None
    assert list(tmp_path.iterdir()) == [] and not (tmp_path.parent / "evil.rego").exists()


def test_a_duplicate_member_name_is_could_not_look():
    s = _seal(_tar([(".manifest", _manifest()), (".manifest", _manifest("other"))]))
    assert s["seal"] == COULD_NOT_LOOK and s["revision"] is None


def test_a_leading_slash_member_name_is_the_same_file():
    s = _seal(_tar([("/.manifest", _manifest()), ("/authz/policy.rego", REGO)]))
    assert s["seal"] == VERIFIED and s["revision"] == REV


def test_oversized_and_bombs_are_bounded(monkeypatch):
    raw = _bundle()
    monkeypatch.setattr(B, "MAX_BUNDLE_BYTES", len(raw) - 1)
    s = _seal(raw)
    assert s["could_not_look"]["reason_word"] == "bounded"
    assert s["bundle_sha256"] == hashlib.sha256(raw).hexdigest()
    monkeypatch.undo()
    monkeypatch.setattr(B, "MAX_TAR_BYTES", 4096)
    s = _seal(_tar([(".manifest", _manifest()), ("big.json", b" " * 100000)]))
    assert s["could_not_look"]["reason_word"] == "bounded"
    monkeypatch.undo()
    monkeypatch.setattr(B, "MAX_FILES", 2)
    s = _seal(_tar([(".manifest", _manifest()), ("a.rego", REGO), ("b.rego", REGO)]))
    assert s["could_not_look"]["reason_word"] == "bounded"


def test_two_signatures_are_could_not_look():
    files = {".manifest": _manifest(), "authz/policy.rego": REGO}
    sig = json.dumps({"signatures": [_jwt(files), _jwt(files)]}).encode()
    s = _seal(_tar(list(files.items()) + [(".signatures.json", sig)]), verification_key=KEY,
              key_algorithm="HS256")
    assert s["opa_signatures_present"] is True
    assert s["opa_signature_verified"] == COULD_NOT_LOOK


def test_a_directory_bundle_is_sealed_by_its_listing(tmp_path):
    (tmp_path / "authz").mkdir()
    (tmp_path / ".manifest").write_bytes(_manifest())
    (tmp_path / "authz" / "policy.rego").write_bytes(REGO)
    s = _seal(str(tmp_path))
    assert s["bundle_form"] == "directory" and s["revision"] == REV and s["seal"] == VERIFIED
    assert s["bundle_digest_scheme"] == "sha256:opa-bundle-dir:v1"
    (tmp_path / "authz" / "policy.rego").write_bytes(REGO + b"#")
    assert _seal(str(tmp_path))["bundle_sha256"] != s["bundle_sha256"]


def test_a_tarball_path_is_read_as_its_bytes(tmp_path):
    raw = _bundle()
    p = tmp_path / "bundle.tar.gz"
    p.write_bytes(raw)
    assert _seal(str(p))["bundle_sha256"] == hashlib.sha256(raw).hexdigest()


# --- the join ----------------------------------------------------------------------

def test_a_decision_on_the_sealed_revision_joins_verified():
    seal = _seal(_bundle())
    [r] = O.join_bundles(_decisions(_ev()), [seal])
    assert r["policy_join"] == VERIFIED
    assert r["policy_bundle_sha256"] == seal["bundle_sha256"]
    assert r["signed_by_vendor"] is False
    assert r["relayed_verdict"] == VERIFIED and r["attestation"]["status"] == "NONE"
    pb = r["decision"]["policy_bundles"]["authz"]
    assert pb["join"] == VERIFIED and pb["opa_signature_verified"] == COULD_NOT_LOOK


def test_the_a06_fixture_joins_on_its_synthetic_revision():
    rows = O.ingest((FIX / "decision_log.json").read_bytes(), received_at=AT,
                    allow_paths=("authz/allow",), deny_paths=("authz/deny",))
    out = O.join_bundles(rows, [_seal(_bundle())])
    assert [r["policy_join"] for r in out] == [VERIFIED] * len(rows)


def test_an_unknown_revision_is_could_not_look():
    [r] = O.join_bundles(_decisions(_ev("rev-unknown")), [_seal(_bundle())])
    assert r["policy_join"] == COULD_NOT_LOOK and r["policy_bundle_sha256"] is None
    assert r["policy_join_could_not_look"]["reason_word"] == "name_not_found"


def test_a_revision_conflicting_with_the_seal_in_force_is_broken():
    seal = _seal(_bundle(), active_from="2026-10-04T00:00:00Z", active_until="2026-10-05T00:00:00Z")
    [r] = O.join_bundles(_decisions(_ev("rev-other")), [seal])
    assert r["policy_join"] == BROKEN and r["policy_bundle_sha256"] is None
    # outside that window there is no conflict, only no seal
    [r] = O.join_bundles(_decisions(_ev("rev-other", ts="2026-10-06T00:00:00Z")), [seal])
    assert r["policy_join"] == COULD_NOT_LOOK


def test_the_right_revision_outside_its_window_is_not_verified():
    seal = _seal(_bundle(), active_from="2026-10-04T00:00:00Z", active_until="2026-10-05T00:00:00Z")
    [r] = O.join_bundles(_decisions(_ev(ts="2026-10-06T00:00:00Z")), [seal])
    assert r["policy_join"] == COULD_NOT_LOOK
    [r] = O.join_bundles(_decisions(_ev(ts="2026-10-04T11:00:00.123456789Z")), [seal])
    assert r["policy_join"] == VERIFIED


@pytest.mark.parametrize("ev", [_ev(None), _ev(""), dict(_ev(), bundles={}),
                                dict(_ev(), bundles={"authz": {}})])
def test_a_decision_with_no_revision_is_could_not_look(ev):
    [r] = O.join_bundles(_decisions(ev), [_seal(_bundle())])
    assert r["policy_join"] == COULD_NOT_LOOK
    assert r["policy_join_could_not_look"]["reason_word"] == "missing"


def test_a_seal_for_another_bundle_name_does_not_join():
    [r] = O.join_bundles(_decisions(_ev(name="other")), [_seal(_bundle())])
    assert r["policy_join"] == COULD_NOT_LOOK


def test_two_different_bundles_with_one_revision_are_could_not_look():
    a = _seal(_bundle())
    b = _seal(_bundle({".manifest": _manifest(), "authz/policy.rego": REGO + b"#"}))
    assert a["bundle_sha256"] != b["bundle_sha256"]
    [r] = O.join_bundles(_decisions(_ev()), [a, b])
    assert r["policy_join"] == COULD_NOT_LOOK


def test_a_sealed_bundle_that_fails_its_own_signature_joins_broken():
    good = {".manifest": _manifest(), "authz/policy.rego": REGO}
    bad = dict(good, **{"authz/policy.rego": REGO + b"#"})
    [r] = O.join_bundles(_decisions(_ev()), [_seal(_bundle(bad, sig_files=good))])
    assert r["policy_join"] == BROKEN


def test_an_unreadable_seal_never_joins():
    [r] = O.join_bundles(_decisions(_ev()), [_seal(b"junk"), "junk", None, {"kind": "x"}])
    assert r["policy_join"] == COULD_NOT_LOOK


def test_join_never_raises_and_does_not_change_its_input():
    rows = _decisions(_ev())
    before = json.dumps(rows, sort_keys=True)
    out = O.join_bundles(rows + ["junk", None], None)
    assert json.dumps(rows, sort_keys=True) == before
    assert [r["policy_join"] for r in out[:1]] == [COULD_NOT_LOOK]
    assert O.join_bundles(None, [_seal(_bundle())]) == []


def test_the_seal_is_jcs_digestable():
    O.OPA.digest(_seal(_bundle()))
    O.OPA.digest(_seal(b"junk"))


# --- L2-01b: every accepted JWT algorithm, tested with throwaway in-test keys ---------

_HS = ("HS256", "HS384", "HS512")
_RSA_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")
_EC_ALGS = ("ES256", "ES384", "ES512")
TESTED_ALGS = _HS + _RSA_ALGS + _EC_ALGS


def test_every_accepted_algorithm_has_a_test_here():
    assert set(B.KEY_ALGORITHMS) == set(TESTED_ALGS)


def _pem(pub) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return pub.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


_KEYS: dict = {}


def _rsa(i: int):
    from cryptography.hazmat.primitives.asymmetric import rsa
    if ("rsa", i) not in _KEYS:
        _KEYS[("rsa", i)] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _KEYS[("rsa", i)]


_CURVE = {"ES256": "SECP256R1", "ES384": "SECP384R1", "ES512": "SECP521R1"}


def _ec(curve: str, i: int):
    from cryptography.hazmat.primitives.asymmetric import ec
    if (curve, i) not in _KEYS:
        _KEYS[(curve, i)] = ec.generate_private_key(getattr(ec, curve)())
    return _KEYS[(curve, i)]


def _signer(alg: str):
    """(sign(msg) -> JWS signature bytes, the right verification key, a wrong key of
    the same type)."""
    n = int(alg[2:])
    if alg in _HS:
        secret, other = os.urandom(32), os.urandom(32)
        h = getattr(hashlib, f"sha{n}")
        return (lambda m: hmac.new(secret, m, h).digest()), secret, other
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
    h = getattr(hashes, f"SHA{n}")()
    if alg in _RSA_ALGS:
        k = _rsa(0)
        pad = padding.PKCS1v15() if alg.startswith("RS") else padding.PSS(
            mgf=padding.MGF1(h), salt_length=h.digest_size)
        return (lambda m: k.sign(m, pad, h)), _pem(k.public_key()), _pem(_rsa(1).public_key())
    k = _ec(_CURVE[alg], 0)
    size = (k.curve.key_size + 7) // 8

    def sign(m):
        r, s = utils.decode_dss_signature(k.sign(m, ec.ECDSA(h)))
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")
    return sign, _pem(k.public_key()), _pem(_ec(_CURVE[alg], 1).public_key())


def _flip(sign):
    def f(m):
        b = bytearray(sign(m))
        b[len(b) // 2] ^= 0x01
        return bytes(b)
    return f


def _needs(alg):
    if alg not in _HS:
        pytest.importorskip("cryptography")


@pytest.mark.parametrize("alg", TESTED_ALGS)
def test_each_algorithm_valid_signature_is_verified(alg):
    _needs(alg)
    sign, key, _ = _signer(alg)
    s = _seal(_bundle(alg=alg, sign=sign), verification_key=key, key_algorithm=alg)
    assert s["opa_signature_verified"] == VERIFIED, s["opa_signature_reason"]
    assert s["signature"]["alg"] == alg


@pytest.mark.parametrize("alg", TESTED_ALGS)
def test_each_algorithm_one_flipped_signature_byte_is_broken(alg):
    _needs(alg)
    sign, key, _ = _signer(alg)
    s = _seal(_bundle(alg=alg, sign=_flip(sign)), verification_key=key, key_algorithm=alg)
    assert s["opa_signature_verified"] == BROKEN, s["opa_signature_reason"]


@pytest.mark.parametrize("alg", TESTED_ALGS)
def test_each_algorithm_wrong_key_is_broken(alg):
    _needs(alg)
    sign, _, wrong = _signer(alg)
    s = _seal(_bundle(alg=alg, sign=sign), verification_key=wrong, key_algorithm=alg)
    assert s["opa_signature_verified"] == BROKEN, s["opa_signature_reason"]


@pytest.mark.parametrize("alg", TESTED_ALGS)
def test_each_algorithm_the_jwt_naming_another_alg_is_broken(alg):
    _needs(alg)
    sign, key, _ = _signer(alg)
    other = "HS256" if alg != "HS256" else "HS384"
    s = _seal(_bundle(alg=other, sign=sign), verification_key=key, key_algorithm=alg)
    assert s["opa_signature_verified"] == BROKEN


def _wrong_type_keys(alg):
    """Keys of a type that cannot verify `alg`: refused, never checked."""
    rsa_pem = _pem(_rsa(0).public_key())
    p256 = _pem(_ec("SECP256R1", 0).public_key())
    if alg in _HS:
        return [rsa_pem, p256, rsa_pem.decode()]
    if alg in _RSA_ALGS:
        return [p256, _pem(_ec("SECP521R1", 0).public_key())]
    wrong_curve = {"ES256": "SECP384R1", "ES384": "SECP256R1", "ES512": "SECP384R1"}[alg]
    return [rsa_pem, _pem(_ec(wrong_curve, 0).public_key())]


@pytest.mark.parametrize("alg", TESTED_ALGS)
def test_each_algorithm_a_key_of_the_wrong_type_is_refused(alg):
    pytest.importorskip("cryptography")
    sign, _, _ = _signer(alg)
    raw = _bundle(alg=alg, sign=sign)
    for k in _wrong_type_keys(alg):
        s = _seal(raw, verification_key=k, key_algorithm=alg)
        assert s["opa_signature_verified"] == COULD_NOT_LOOK, (alg, s["opa_signature_reason"])
        assert "not a key for" in s["opa_signature_reason"]


def test_an_unsupported_algorithm_is_refused_by_the_caller_check():
    for alg in ("none", "EdDSA", "HS1", "RS1"):
        with pytest.raises(ValueError):
            _seal(_bundle(), verification_key=KEY, key_algorithm=alg)


def test_a_bundle_whose_jwt_says_an_unsupported_alg_is_broken_not_verified():
    s = _seal(_bundle(alg="none"), verification_key=KEY, key_algorithm="HS256")
    assert s["opa_signature_verified"] == BROKEN


def test_a_join_on_a_key_verified_bundle_is_still_not_signed_by_vendor():
    s = _seal(_bundle(), verification_key=KEY, key_algorithm="HS256")
    assert s["opa_signature_verified"] == VERIFIED
    r = O.join_bundles(_decisions(_ev()), [s])[0]
    assert r["policy_join"] == VERIFIED and r["signed_by_vendor"] is False
