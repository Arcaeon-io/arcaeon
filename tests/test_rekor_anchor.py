"""The Rekor anchor skeleton (docs/design/REKOR_REWRITE_PLAN.md).

Offline only. Every fixture under tests/fixtures/rekor_anchor/ is TEST-ONLY:
sample.txt.envelope.json was sealed once with a throwaway Ed25519 seed that
was deleted; sample.tsq / sample.tsr are a real RFC 3161 request and reply
made by `openssl ts` with a throwaway test TSA whose private keys were
deleted; test_only_tsa_root.pem is that test TSA's public root. Signing keys a
test needs are generated in memory and never written. No test here may touch
the network: the autouse fixture below makes any attempt fail loud."""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import secrets
import socket
import urllib.request
from pathlib import Path

import pytest

from arcaeon import verdict as V
from arcaeon.prove import envelope as E
from arcaeon.remote import rekor_anchor as RA

FX = Path(__file__).resolve().parent / "fixtures" / "rekor_anchor"
ENV_FX = FX / "sample.txt.envelope.json"
TSQ = FX / "sample.tsq"
TSR = FX / "sample.tsr"
ROOT_PEM = FX / "test_only_tsa_root.pem"
#: sha256(PAE) of the fixture envelope, and the nonce openssl put in sample.tsq.
DIGEST = "0b4b8bd514222c85799684cc9a1c2056d4c6d5be2a6eda4e0c649fc50d022640"
NONCE = 0xFC2C5F2A7D90C256
GEN_TIME = "2026-10-05T16:11:02Z"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("a rekor_anchor test tried to touch the network")
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def _fixture_env() -> dict:
    return json.loads(ENV_FX.read_text(encoding="utf-8"))


def _p256():
    ec = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ec")
    from cryptography.hazmat.primitives import serialization as S
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.public_key().public_bytes(S.Encoding.PEM, S.PublicFormat.SubjectPublicKeyInfo)
    return priv, pem


def _sign_pae(priv, env: dict) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    d = env["dsseEnvelope"]
    return priv.sign(E.pae(d["payloadType"], base64.b64decode(d["payload"])),
                     ec.ECDSA(hashes.SHA256()))


# --- the gate -------------------------------------------------------------------------

def test_armed_is_false_and_set_once_at_module_top():
    assert RA.ARMED is False
    src = Path(RA.__file__).read_text(encoding="utf-8")
    assert src.count("\nARMED = False\n") == 1
    assert "ARMED = True" not in src


def test_submit_refuses_while_unarmed_even_with_the_go_flag():
    entry = RA.compose_hashedrekord(DIGEST, b"\x30\x00", b"-----BEGIN PUBLIC KEY-----\nAA==\n"
                                    b"-----END PUBLIC KEY-----\n")
    with pytest.raises(RA.NotArmed):
        RA.submit(entry)
    with pytest.raises(RA.NotArmed):
        RA.submit(entry, i_have_his_go=True)


def test_submit_needs_both_the_constant_and_the_go_flag(monkeypatch):
    entry = RA.compose_hashedrekord(DIGEST, b"\x30\x00", b"-----BEGIN PUBLIC KEY-----\nAA==\n"
                                    b"-----END PUBLIC KEY-----\n")
    monkeypatch.setattr(RA, "ARMED", True)
    with pytest.raises(RA.NotArmed):
        RA.submit(entry)   # armed module, no go flag: still refused, nothing sent


def test_submit_is_the_only_function_that_can_reach_the_network():
    tree = ast.parse(Path(RA.__file__).read_text(encoding="utf-8"))
    net = {"urlopen", "Request", "HTTPSConnection", "HTTPConnection", "create_connection",
           "socket"}
    where = set()
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef):
            for node in ast.walk(fn):
                if isinstance(node, ast.Attribute) and node.attr in net:
                    where.add(fn.name)
                if isinstance(node, ast.Name) and node.id in net:
                    where.add(fn.name)
    assert where == {"submit"}, where


# --- the digest -----------------------------------------------------------------------

def test_digest_is_sha256_of_pae_of_a_freshly_sealed_envelope(tmp_path):
    pytest.importorskip("cryptography")
    k = tmp_path / "throwaway.key"
    k.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    f = tmp_path / "a.csv"
    f.write_bytes(b"x,y\n1,2\n")
    env = E.seal(f, key_file=k, label="l", audience="a", deal="d", purpose="p", not_after="7d")
    d = env["dsseEnvelope"]
    want = hashlib.sha256(E.pae(E.PAYLOAD_TYPE, base64.b64decode(d["payload"]))).hexdigest()
    assert RA.envelope_digest(env) == want
    assert RA.envelope_digest(E.envelope_path(f)) == want      # a path reads the same
    assert RA.envelope_digest(d) == want                       # a bare DSSE envelope too


def test_digest_of_the_fixture_envelope():
    assert RA.envelope_digest(_fixture_env()) == DIGEST


def test_digest_does_not_depend_on_the_signatures():
    env = _fixture_env()
    env["dsseEnvelope"]["signatures"] = []
    assert RA.envelope_digest(env) == DIGEST


@pytest.mark.parametrize("bad", [
    {"dsseEnvelope": {"payloadType": 7, "payload": "AA==", "signatures": []}},
    {"dsseEnvelope": {"payloadType": "t", "payload": "not base64!", "signatures": []}},
    {"something": "else"},
    [],
])
def test_digest_refuses_what_is_not_an_envelope(bad):
    with pytest.raises(RA.AnchorError):
        RA.envelope_digest(bad)


# --- the hashedrekord entry -----------------------------------------------------------

def test_hashedrekord_shape_is_v1_0_0_1_over_the_digest():
    pem = b"-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n"
    e = RA.compose_hashedrekord(DIGEST, b"sig-bytes", pem)
    assert e == {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": DIGEST}},
            "signature": {"content": base64.b64encode(b"sig-bytes").decode("ascii"),
                          "publicKey": {"content": base64.b64encode(pem).decode("ascii")}},
        },
    }


@pytest.mark.parametrize("digest,sig,pem", [
    ("AB" * 32, b"s", b"-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n"),
    ("ab" * 31, b"s", b"-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n"),
    ("ab" * 32, b"", b"-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n"),
    ("ab" * 32, b"s", b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"),
    ("ab" * 32, b"s", b"not a pem"),
])
def test_hashedrekord_refuses_a_bad_part(digest, sig, pem):
    with pytest.raises(RA.AnchorError):
        RA.compose_hashedrekord(digest, sig, pem)


def test_hashedrekord_offline_check_verified_and_broken():
    priv, pem = _p256()
    env = _fixture_env()
    entry = RA.compose_hashedrekord(RA.envelope_digest(env), _sign_pae(priv, env), pem)
    r = RA.check_hashedrekord(entry, env)
    assert r["verdict"] == V.VERIFIED, r
    assert r["steps"]["digest"] == V.VERIFIED and r["steps"]["signature"] == V.VERIFIED
    # inclusion in the log is a separate step this skeleton does not take
    assert r["inclusion"] == V.COULD_NOT_LOOK
    # the envelope changed after the anchor: the digest no longer matches
    other = _fixture_env()
    other["dsseEnvelope"]["payload"] = base64.b64encode(b"{}").decode("ascii")
    assert RA.check_hashedrekord(entry, other)["verdict"] == V.BROKEN
    # the signature does not verify under the entry's key
    _, other_pem = _p256()
    swapped = json.loads(json.dumps(entry))
    swapped["spec"]["signature"]["publicKey"]["content"] = base64.b64encode(
        other_pem).decode("ascii")
    assert RA.check_hashedrekord(swapped, env)["verdict"] == V.BROKEN


def test_hashedrekord_unreadable_entry_could_not_look():
    r = RA.check_hashedrekord({"kind": "dsse"}, _fixture_env())
    assert r["verdict"] == V.COULD_NOT_LOOK


# --- the RFC 3161 request ---------------------------------------------------------------

def test_tsa_request_is_byte_identical_to_openssl():
    assert RA.tsa_request(DIGEST, NONCE) == TSQ.read_bytes()


def test_tsa_request_round_trips():
    der = RA.tsa_request(DIGEST, 12345)
    assert RA.parse_tsa_request(der) == {"digest": DIGEST, "nonce": 12345, "cert_req": True}
    assert RA.parse_tsa_request(TSQ.read_bytes())["nonce"] == NONCE


@pytest.mark.parametrize("digest,nonce", [("ab" * 31, 1), ("ab" * 32, 0), ("ab" * 32, -5),
                                          ("ab" * 32, 1 << 200), ("ab" * 32, True)])
def test_tsa_request_refuses(digest, nonce):
    with pytest.raises(RA.AnchorError):
        RA.tsa_request(digest, nonce)


def test_new_nonce_is_a_positive_64_bit_int():
    n = RA.new_nonce()
    assert isinstance(n, int) and 0 < n < (1 << 64)


# --- the RFC 3161 token ---------------------------------------------------------------

def test_tsa_token_good_with_the_pinned_root():
    pytest.importorskip("cryptography")
    r = RA.check_tsa_token(TSR.read_bytes(), DIGEST, NONCE, roots=[ROOT_PEM.read_bytes()])
    assert r["verdict"] == V.VERIFIED, r
    assert r["steps"] == {"token": V.VERIFIED, "imprint": V.VERIFIED, "nonce": V.VERIFIED,
                          "signature": V.VERIFIED}
    assert r["gen_time"] == GEN_TIME


def test_tsa_token_with_no_root_pinned_is_could_not_look_on_the_signature():
    r = RA.check_tsa_token(TSR.read_bytes(), DIGEST, NONCE)
    assert r["steps"]["imprint"] == V.VERIFIED and r["steps"]["nonce"] == V.VERIFIED
    assert r["steps"]["signature"] == V.COULD_NOT_LOOK
    assert r["verdict"] == V.COULD_NOT_LOOK
    assert r["gen_time"] == GEN_TIME


def test_tsa_token_imprint_mismatch_is_broken():
    r = RA.check_tsa_token(TSR.read_bytes(), "cd" * 32, NONCE)
    assert r["verdict"] == V.BROKEN and r["steps"]["imprint"] == V.BROKEN


def test_tsa_token_wrong_nonce_is_broken():
    r = RA.check_tsa_token(TSR.read_bytes(), DIGEST, NONCE + 1)
    assert r["verdict"] == V.BROKEN and r["steps"]["nonce"] == V.BROKEN


@pytest.mark.parametrize("raw", [b"", b"\x00\x01garbage", None, b"\x30\x80\x00\x00"])
def test_tsa_token_unreadable_is_could_not_look(raw):
    data = TSR.read_bytes()[:200] if raw is None else raw
    r = RA.check_tsa_token(data, DIGEST, NONCE)
    assert r["verdict"] == V.COULD_NOT_LOOK and r["steps"]["token"] == V.COULD_NOT_LOOK


def test_tsa_token_tampered_after_signing_is_broken():
    pytest.importorskip("cryptography")
    raw = bytearray(TSR.read_bytes())
    at = raw.index(b"20261005161102Z")
    raw[at + 13] = ord("3")            # genTime ...02Z -> ...03Z inside the signed TSTInfo
    r = RA.check_tsa_token(bytes(raw), DIGEST, NONCE, roots=[ROOT_PEM.read_bytes()])
    assert r["verdict"] == V.BROKEN and r["steps"]["signature"] == V.BROKEN


def test_tsa_token_with_a_flipped_signature_byte_is_broken():
    pytest.importorskip("cryptography")
    raw = bytearray(TSR.read_bytes())
    raw[-5] ^= 1                       # inside the signerInfo's signature value
    r = RA.check_tsa_token(bytes(raw), DIGEST, NONCE, roots=[ROOT_PEM.read_bytes()])
    assert r["verdict"] == V.BROKEN and r["steps"]["signature"] == V.BROKEN


def test_tsa_token_from_a_root_you_did_not_pin_is_broken():
    pytest.importorskip("cryptography")
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization as S
    from cryptography.hazmat.primitives.asymmetric import ec
    k = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test-only other root")])
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(k.public_key()).serial_number(1).not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=3650)).sign(k, hashes.SHA256()))
    r = RA.check_tsa_token(TSR.read_bytes(), DIGEST, NONCE,
                           roots=[cert.public_bytes(S.Encoding.PEM)])
    assert r["verdict"] == V.BROKEN and r["steps"]["signature"] == V.BROKEN


def test_tsa_token_reads_a_bare_token_as_well_as_a_reply():
    reply = TSR.read_bytes()
    token = RA._token_from_reply(reply)
    r = RA.check_tsa_token(token, DIGEST, NONCE)
    assert r["steps"]["imprint"] == V.VERIFIED and r["gen_time"] == GEN_TIME


# --- sidecars and the bundle writer -----------------------------------------------------

def test_sidecar_names_sit_beside_the_bundle():
    b = Path("out") / "report.pdf.envelope.json"
    assert RA.ots_sidecar_path(b) == Path("out") / "report.pdf.envelope.json.ots"
    assert RA.tsa_sidecar_path(b) == Path("out") / "report.pdf.envelope.json.tsr"
    assert RA.tsa_request_sidecar_path(b) == Path("out") / "report.pdf.envelope.json.tsq"
    assert RA.rekor_sidecar_path(b) == Path("out") / "report.pdf.envelope.json.rekor.json"
    for p in (RA.ots_sidecar_path(b), RA.tsa_sidecar_path(b), RA.rekor_sidecar_path(b)):
        assert p.parent == b.parent and p != b


def test_bundle_writer_writes_a_clean_one_signature_bundle(tmp_path):
    out = RA.write_bundle(tmp_path / "s.envelope.json", _fixture_env())
    assert json.loads(out.read_text(encoding="utf-8")) == _fixture_env()


@pytest.mark.parametrize("where,key,value", [
    ("top", "ots", "AE9wZW5UaW1lc3RhbXBz"),
    ("top", "timestampVerificationData", {"rfc3161Timestamps": []}),
    ("top", "rekor", {"logIndex": 1}),
    ("dsse", "otsProof", "AA=="),
    ("sig", "tsa", "AA=="),
])
def test_bundle_writer_refuses_an_embedded_proof(tmp_path, where, key, value):
    env = _fixture_env()
    target = {"top": env, "dsse": env["dsseEnvelope"],
              "sig": env["dsseEnvelope"]["signatures"][0]}[where]
    target[key] = value
    dest = tmp_path / "s.envelope.json"
    with pytest.raises(RA.AnchorError, match=key):
        RA.write_bundle(dest, env)
    assert not dest.exists()


def test_bundle_writer_refuses_more_or_fewer_than_one_signature(tmp_path):
    env = _fixture_env()
    env["dsseEnvelope"]["signatures"] *= 2
    with pytest.raises(RA.AnchorError, match="one signature"):
        RA.write_bundle(tmp_path / "s.envelope.json", env)
    env["dsseEnvelope"]["signatures"] = []
    with pytest.raises(RA.AnchorError, match="one signature"):
        RA.write_bundle(tmp_path / "s.envelope.json", env)


def test_bundle_writer_refuses_a_sidecar_name(tmp_path):
    with pytest.raises(RA.AnchorError):
        RA.write_bundle(tmp_path / "s.envelope.json.ots", _fixture_env())


# --- multi-witness = N bundles --------------------------------------------------------

def test_split_witnesses_gives_one_bundle_per_signature():
    env = _fixture_env()
    sigs = [{"keyid": f"did:key:test-{i}", "sig": base64.b64encode(bytes([i]) * 64).decode()}
            for i in range(3)]
    env["dsseEnvelope"]["signatures"] = sigs
    parts = RA.split_witnesses(env)
    assert len(parts) == 3
    for i, b in enumerate(parts):
        assert b["dsseEnvelope"]["signatures"] == [sigs[i]]
        assert b["dsseEnvelope"]["payload"] == env["dsseEnvelope"]["payload"]
        assert RA.envelope_digest(b) == DIGEST       # every witness anchors one digest
    assert env["dsseEnvelope"]["signatures"] == sigs  # the input is not changed


def test_split_witnesses_refuses_none_and_duplicates():
    env = _fixture_env()
    env["dsseEnvelope"]["signatures"] = []
    with pytest.raises(RA.AnchorError):
        RA.split_witnesses(env)
    env = _fixture_env()
    env["dsseEnvelope"]["signatures"] *= 2
    with pytest.raises(RA.AnchorError):
        RA.split_witnesses(env)


def test_witness_bundle_paths_are_distinct_and_stable():
    a = RA.witness_bundle_path("x/f.csv", "did:key:one")
    b = RA.witness_bundle_path("x/f.csv", "did:key:two")
    assert a != b and a == RA.witness_bundle_path("x/f.csv", "did:key:one")
    assert a.parent == Path("x") and a.name.startswith("f.csv.") and a.name.endswith(".envelope.json")


# --- the reading: each anchor on its own ------------------------------------------------

def test_read_anchors_with_no_sidecars_is_not_claimed(tmp_path):
    b = RA.write_bundle(tmp_path / "s.envelope.json", _fixture_env())
    r = RA.read_anchors(b)
    assert r["anchors"] == {"rekor": RA.NOT_CLAIMED, "tsa": RA.NOT_CLAIMED,
                            "ots": RA.NOT_CLAIMED}


def test_read_anchors_reads_each_anchor_independently(tmp_path):
    pytest.importorskip("cryptography")
    b = RA.write_bundle(tmp_path / "s.envelope.json", _fixture_env())
    RA.tsa_sidecar_path(b).write_bytes(TSR.read_bytes())
    RA.tsa_request_sidecar_path(b).write_bytes(TSQ.read_bytes())
    # a rekor sidecar for some OTHER digest: BROKEN, and it must not touch the TSA reading
    priv, pem = _p256()
    entry = RA.compose_hashedrekord("ee" * 32, _sign_pae(priv, _fixture_env()), pem)
    RA.rekor_sidecar_path(b).write_text(json.dumps(entry), encoding="utf-8")
    RA.ots_sidecar_path(b).write_bytes(b"\x00OpenTimestamps\x00\x00Proof\x00")
    r = RA.read_anchors(b, tsa_roots=[ROOT_PEM.read_bytes()])
    assert r["anchors"]["tsa"] == V.VERIFIED
    assert r["anchors"]["rekor"] == V.BROKEN
    assert r["anchors"]["ots"] == V.COULD_NOT_LOOK      # present, not read by this skeleton
    assert "verdict" not in r                           # no rolled-up anchor verdict


def test_the_plan_doc_states_its_limits_and_the_gate():
    doc = (Path(__file__).resolve().parent.parent / "docs" / "design"
           / "REKOR_REWRITE_PLAN.md").read_text(encoding="utf-8")
    assert "## What it cannot prove" in doc and "ARMED = False" in doc
    assert "—" not in doc and "–" not in doc
    for word in ("VERIFIED", "BROKEN", "COULD NOT LOOK", "NOT CLAIMED"):
        assert word in doc


def test_read_anchors_tsr_without_its_request_could_not_look(tmp_path):
    b = RA.write_bundle(tmp_path / "s.envelope.json", _fixture_env())
    RA.tsa_sidecar_path(b).write_bytes(TSR.read_bytes())
    assert RA.read_anchors(b)["anchors"]["tsa"] == V.COULD_NOT_LOOK
