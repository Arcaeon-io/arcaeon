# SPDX-License-Identifier: MIT
"""L3-05: SCITT-shaped Signed Statements and RFC 9942-shaped receipts for the pin statement.

Every key is a throwaway seed made here (secrets.token_bytes); nothing is sent.
The COSE structure is checked three ways: by the module, by the small CBOR
reader below (written apart from the module's codec), and by cbor2 / pycose
when those are installed (skipped, with the reason, when not). NOT a
conformance test: the leaf preimage rule is an open item (docs/design/SCITT_RECEIPTS.md)."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import secrets

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import tally_chain as TC
from arcaeon.remote import _cbor as C
from arcaeon.remote import merkle as M
from arcaeon.remote import scitt as S

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

STATEMENT = {"chain": "arcaeon-tally", "chain_values_sha256": "a" * 64, "file_sha256": "b" * 64,
             "file_sha256_of": "lf", "prev_pin_sha256": None, "rows": 3,
             "stated_at": "2026-10-05T12:00:00+00:00", "tip": "c" * 64, "v": 2}


def pub(seed: bytes) -> bytes:
    from arcaeon.prove.vet import receipts as R
    return R.public_key_from_seed(seed)


@pytest.fixture
def k():
    issuer, ts = secrets.token_bytes(32), secrets.token_bytes(32)
    stmt = S.to_signed_statement(STATEMENT, issuer)
    leaf = S.leaf_bytes(stmt)
    log = [b"other-0", b"other-1", leaf, b"other-3", b"other-4"]
    proof = {"tree_size": 5, "leaf_index": 2, "path": M.inclusion_proof(log, 2)}
    rc = S.to_receipt(leaf, proof, ts)
    return {"issuer": issuer, "ts": ts, "stmt": stmt, "leaf": leaf, "log": log,
            "proof": proof, "receipt": rc, "root": M.root(log)}


# --- an independent CBOR reader (major types 0-5, 6 tags, simple 20-22) ---------------------

def rd(b: bytes, i: int = 0):
    ib = b[i]
    mt, ai = ib >> 5, ib & 31
    i += 1
    if ai < 24:
        n = ai
    else:
        w = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
        n = int.from_bytes(b[i:i + w], "big")
        i += w
    if mt == 0:
        return n, i
    if mt == 1:
        return -1 - n, i
    if mt in (2, 3):
        v = b[i:i + n]
        return (bytes(v) if mt == 2 else v.decode("utf-8")), i + n
    if mt == 4:
        out = []
        for _ in range(n):
            v, i = rd(b, i)
            out.append(v)
        return out, i
    if mt == 5:
        out = {}
        for _ in range(n):
            kk, i = rd(b, i)
            v, i = rd(b, i)
            out[kk] = v
        return out, i
    if mt == 6:
        v, i = rd(b, i)
        return ("TAG", n, v), i
    return {20: False, 21: True, 22: None}[ai], i


def full(b: bytes):
    v, end = rd(b)
    assert end == len(b), "trailing bytes"
    return v


# --- the codec ---------------------------------------------------------------------------

# RFC 8949 Appendix A (integers, strings, arrays, maps, a tag, simple values)
VECTORS = [(0, "00"), (1, "01"), (10, "0a"), (23, "17"), (24, "1818"), (25, "1819"),
           (100, "1864"), (1000, "1903e8"), (1000000, "1a000f4240"),
           (1000000000000, "1b000000e8d4a51000"), (18446744073709551615, "1bffffffffffffffff"),
           (-18446744073709551616, "3bffffffffffffffff"), (-1, "20"), (-10, "29"),
           (-100, "3863"), (-1000, "3903e7"), (b"", "40"), (b"\x01\x02\x03\x04", "4401020304"),
           ("", "60"), ("a", "6161"), ("IETF", "6449455446"), ("ü", "62c3bc"),
           ([], "80"), ([1, 2, 3], "83010203"), ([1, [2, 3], [4, 5]], "8301820203820405"),
           ({}, "a0"), ({1: 2, 3: 4}, "a201020304"), ({"a": 1, "b": [2, 3]}, "a26161016162820203"),
           (["a", {"b": "c"}], "826161a161626163"), (False, "f4"), (True, "f5"), (None, "f6"),
           (C.Tag(0, "2013-03-21T20:04:00Z"), "c074323031332d30332d32315432303a30343a30305a")]


@pytest.mark.parametrize("obj,hexed", VECTORS)
def test_cbor_rfc8949_vectors(obj, hexed):
    assert C.encode(obj).hex() == hexed
    assert C.decode(bytes.fromhex(hexed)) == obj


def test_cbor_map_keys_in_deterministic_order():
    # sorted by the bytes of the encoded key (RFC 8949 section 4.2.1): 0a, 1864, 20, 6161
    assert C.encode({"a": 3, 100: 4, -1: 2, 10: 1}).hex() == "a40a011864042002616103"


@pytest.mark.parametrize("hexed", ["", "18", "1a0000", "5f", "9f", "f97c00", "fb3ff0000000000000",
                                   "f7", "a20101" + "0102", "0001", "5affffffff00",
                                   "81" * 200 + "00", "a1f600"])
def test_cbor_decoder_refuses_hostile_or_unsupported_input(hexed):
    with pytest.raises(C.CBORError):
        C.decode(bytes.fromhex(hexed))


def test_cbor_encoder_refuses_floats_and_unknown_types():
    for bad in (1.5, object(), {1.5: 1}):
        with pytest.raises(C.CBORError):
            C.encode(bad)


# --- shapes ------------------------------------------------------------------------------

def test_signed_statement_shape_independently(k):
    tag, n, (prot_b, unprot, payload, sig) = full(k["stmt"])
    assert (tag, n) == ("TAG", 18)
    assert k["stmt"][0] == 0xD2 and k["stmt"][1] == 0x84      # #6.18, array of 4
    prot = full(prot_b)
    assert prot[1] == -8                                        # alg EdDSA (Ed25519)
    assert prot[4] == hashlib.sha256(pub(k["issuer"])).digest()  # kid
    from arcaeon.prove.vet import receipts as R
    assert prot[15] == {1: R.did_key(pub(k["issuer"])), 2: "arcaeon-tally"}   # CWT iss, sub
    assert prot[258] == -16                                     # RFC 9995: SHA-256
    assert prot[259] == "application/json"
    assert 3 not in prot and 3 not in unprot                    # no content_type with 258
    assert unprot == {}
    assert payload == hashlib.sha256(TC.statement_canonical(STATEMENT).encode()).digest()
    assert isinstance(sig, bytes) and len(sig) == 64


def test_receipt_shape_independently(k):
    tag, n, (prot_b, unprot, payload, sig) = full(k["receipt"])
    assert (tag, n) == ("TAG", 18)
    prot = full(prot_b)
    assert prot[1] == -8 and prot[395] == 1                     # alg, vds RFC9162_SHA256
    assert prot[4] == hashlib.sha256(pub(k["ts"])).digest()
    assert set(prot[15]) == {1, 2}
    assert prot[-65537] == [5, 2]       # private-use label: the signed tree size and index
    assert payload is None                                      # detached: the root
    (size, idx, path), = unprot[396][-1]
    assert (size, idx) == (5, 2)
    assert path == M.inclusion_proof(k["log"], 2)
    assert len(sig) == 64


def test_transparent_statement_puts_receipts_under_394_unprotected(k):
    t = S.attach_receipt(k["stmt"], k["receipt"])
    _, _, (prot_b, unprot, payload, sig) = full(t)
    _, _, (prot0, _, payload0, sig0) = full(k["stmt"])
    assert (prot_b, payload, sig) == (prot0, payload0, sig0)    # issuer signature untouched
    assert unprot[394] == [k["receipt"]]
    assert S.leaf_bytes(t) == k["leaf"] == k["stmt"]


def test_statement_refuses_a_non_v2_pin_statement():
    with pytest.raises(S.ScittError):
        S.to_signed_statement(dict(STATEMENT, v=1), secrets.token_bytes(32))


def test_receipt_refuses_a_proof_that_does_not_compute(k):
    with pytest.raises(S.ScittError):
        S.to_receipt(k["leaf"], dict(k["proof"], leaf_index=5), k["ts"])
    with pytest.raises(S.ScittError):
        S.to_receipt(k["leaf"], dict(k["proof"], path=k["proof"]["path"][:-1]), k["ts"])


# --- verdicts ----------------------------------------------------------------------------

def test_round_trip_verifies(k):
    r = S.verify_receipt(k["stmt"], k["receipt"], pub(k["ts"]), issuer_pubkey=pub(k["issuer"]),
                         pin_statement=STATEMENT)
    assert r["verdict"] == V.VERIFIED, r
    assert r["root"] == k["root"].hex()
    assert any("leaf preimage" in x for x in r["not_checked"])


def test_one_leaf_tree_has_an_empty_path_and_verifies(k):
    rc = S.to_receipt(k["leaf"], {"tree_size": 1, "leaf_index": 0, "path": []}, k["ts"])
    r = S.verify_receipt(k["stmt"], rc, pub(k["ts"]))
    assert r["verdict"] == V.VERIFIED and r["root"] == M.root([k["leaf"]]).hex()


def test_transparent_statement_alone_verifies(k):
    t = S.attach_receipt(k["stmt"], k["receipt"])
    assert S.verify_receipt(t, None, pub(k["ts"]))["verdict"] == V.VERIFIED


def test_tampered_statement_is_broken(k):
    other = S.to_signed_statement(dict(STATEMENT, rows=4), k["issuer"])
    assert S.verify_receipt(other, k["receipt"], pub(k["ts"]))["verdict"] == V.BROKEN
    flipped = bytearray(k["stmt"])
    flipped[-1] ^= 1                                            # issuer signature byte
    assert S.verify_receipt(bytes(flipped), k["receipt"], pub(k["ts"]))["verdict"] == V.BROKEN


def test_pin_statement_mismatch_and_bad_issuer_signature_are_broken(k):
    r = S.verify_receipt(k["stmt"], k["receipt"], pub(k["ts"]),
                         pin_statement=dict(STATEMENT, rows=9))
    assert r["verdict"] == V.BROKEN and "payload" in r["reason"]
    r = S.verify_receipt(k["stmt"], k["receipt"], pub(k["ts"]),
                         issuer_pubkey=pub(secrets.token_bytes(32)))
    assert r["verdict"] == V.BROKEN and "issuer" in r["reason"]


def _reshape(receipt: bytes, fn) -> bytes:
    t = C.decode(receipt)
    fn(t.value)
    return C.encode(t)


def test_tampered_path_is_broken(k):
    def flip(v):
        p = v[1][396][-1][0][2]
        p[0] = bytes([p[0][0] ^ 1]) + p[0][1:]
    r = S.verify_receipt(k["stmt"], _reshape(k["receipt"], flip), pub(k["ts"]))
    assert r["verdict"] == V.BROKEN


@pytest.mark.parametrize("size", [2, 3, 4, 6, 7, 8, 9])
def test_wrong_tree_size_is_broken(k, size):
    def resize(v):
        v[1][396][-1][0][0] = size
    r = S.verify_receipt(k["stmt"], _reshape(k["receipt"], resize), pub(k["ts"]))
    assert r["verdict"] == V.BROKEN, r


def test_wrong_leaf_index_is_broken(k):
    def reindex(v):
        v[1][396][-1][0][1] = 3
    assert S.verify_receipt(k["stmt"], _reshape(k["receipt"], reindex),
                            pub(k["ts"]))["verdict"] == V.BROKEN


def test_a_receipt_without_the_signed_position_says_the_size_was_not_checked(k):
    """Sizes 5..8 walk alike for leaf 2 (test_merkle_rfc9162), so a receipt that
    signs only the root cannot pin its size: VERIFIED, with that named."""
    prot = {1: -8, 395: 1, 15: {1: "ts", 2: "x"}}
    rc = S.sign1(prot, {396: {-1: [[8, 2, k["proof"]["path"]]]}}, k["root"], k["ts"],
                 detached=True)
    r = S.verify_receipt(k["stmt"], rc, pub(k["ts"]))
    assert r["verdict"] == V.VERIFIED
    assert any("tree size" in x for x in r["not_checked"])
    ours = S.verify_receipt(k["stmt"], k["receipt"], pub(k["ts"]))
    assert not any("tree size" in x for x in ours["not_checked"])


def test_wrong_ts_key_is_broken(k):
    r = S.verify_receipt(k["stmt"], k["receipt"], pub(secrets.token_bytes(32)))
    assert r["verdict"] == V.BROKEN and "signature" in r["reason"]


def test_missing_ts_key_could_not_look(k):
    r = S.verify_receipt(k["stmt"], k["receipt"], None)
    assert r["verdict"] == V.COULD_NOT_LOOK and r["reason_word"] == "missing"


def test_unknown_vds_could_not_look(k):
    prot = {1: -8, 395: 2, 15: {1: "ts", 2: "x"}}
    rc = S.sign1(prot, {396: {-1: [[5, 2, k["proof"]["path"]]]}}, k["root"], k["ts"],
                 detached=True)
    r = S.verify_receipt(k["stmt"], rc, pub(k["ts"]))
    assert r["verdict"] == V.COULD_NOT_LOOK and "vds" in r["reason"]


def test_unknown_alg_could_not_look(k):
    rc = S.sign1({1: -7, 395: 1}, {396: {-1: [[5, 2, k["proof"]["path"]]]}}, k["root"], k["ts"],
                 detached=True)
    assert S.verify_receipt(k["stmt"], rc, pub(k["ts"]))["verdict"] == V.COULD_NOT_LOOK


@pytest.mark.parametrize("junk", [b"", b"\x00", b"\xd2\x84", b"\xd1\x84\x40\xa0\xf6\x40",
                                  b"\xff" * 40])
def test_hostile_bytes_never_raise(k, junk):
    for args in ((junk, k["receipt"]), (k["stmt"], junk), (junk, None)):
        r = S.verify_receipt(*args, pub(k["ts"]))
        assert r["verdict"] in (V.BROKEN, V.COULD_NOT_LOOK)


def test_missing_vdp_or_a_transparent_statement_without_receipts_is_broken(k):
    rc = S.sign1({1: -8, 395: 1}, {}, k["root"], k["ts"], detached=True)
    assert S.verify_receipt(k["stmt"], rc, pub(k["ts"]))["verdict"] == V.BROKEN
    assert S.verify_receipt(k["stmt"], None, pub(k["ts"]))["verdict"] == V.BROKEN


# --- external oracles (only when installed) ------------------------------------------------

def test_cbor2_reads_the_same_structure(k):
    if importlib.util.find_spec("cbor2") is None:
        pytest.skip("cbor2 is not installed: the cbor2 cross-check did not run")
    import cbor2
    t = cbor2.loads(S.attach_receipt(k["stmt"], k["receipt"]))
    assert t.tag == 18 and len(t.value) == 4
    assert cbor2.loads(t.value[0])[1] == -8
    assert cbor2.dumps(cbor2.loads(k["stmt"]), canonical=True) == k["stmt"]
    rc = cbor2.loads(k["receipt"])
    assert cbor2.loads(rc.value[0])[395] == 1 and rc.value[2] is None


def test_pycose_checks_both_signatures(k):
    if importlib.util.find_spec("pycose") is None:
        pytest.skip("pycose is not installed: the pycose signature cross-check did not run")
    from pycose.keys import OKPKey
    from pycose.messages import Sign1Message
    st = Sign1Message.decode(k["stmt"])
    st.key = OKPKey(crv="Ed25519", x=pub(k["issuer"]))
    assert st.verify_signature()
    rc = Sign1Message.decode(k["receipt"])
    rc.key = OKPKey(crv="Ed25519", x=pub(k["ts"]))
    assert rc.verify_signature(detached_payload=k["root"])


# --- the CLI -------------------------------------------------------------------------------

def _keyfile(tmp_path, name, seed):
    p = tmp_path / name
    p.write_text(base64.b64encode(seed).decode("ascii") + "\n", encoding="ascii")
    return p


def test_cli_export_then_verify(k, tmp_path, capsys):
    s = tmp_path / "S.json"
    s.write_text(TC.statement_canonical(STATEMENT), encoding="utf-8")
    proof = tmp_path / "inclusion.json"
    proof.write_text(json.dumps({"tree_size": 5, "leaf_index": 2,
                                 "path": [p.hex() for p in k["proof"]["path"]],
                                 "root": k["root"].hex()}), encoding="utf-8")
    ik, tk = _keyfile(tmp_path, "i.key", k["issuer"]), _keyfile(tmp_path, "t.key", k["ts"])
    out = tmp_path / "S.scitt"
    rc = cli.main(["tally", "scitt-export", str(s), "--key", str(ik), "--proof", str(proof),
                   "--ts-key", str(tk), "--out", str(out)])
    err = capsys.readouterr()
    assert rc == 0, err
    assert out.read_bytes() == S.attach_receipt(k["stmt"], k["receipt"])
    assert "nothing was sent" in err.out + err.err
    rc = cli.main(["tally", "scitt-verify", str(out), "--ts-pub", pub(k["ts"]).hex(),
                   "--issuer-pub", pub(k["issuer"]).hex(), "--statement", str(s)])
    o = capsys.readouterr().out
    assert rc == 0 and o.startswith(V.VERIFIED), o
    # never overwrites
    rc = cli.main(["tally", "scitt-export", str(s), "--key", str(ik), "--out", str(out)])
    assert rc == V.EXIT_USAGE and out.read_bytes() == S.attach_receipt(k["stmt"], k["receipt"])


def test_cli_export_refuses_a_proof_for_another_root(k, tmp_path, capsys):
    s = tmp_path / "S.json"
    s.write_text(TC.statement_canonical(STATEMENT), encoding="utf-8")
    proof = tmp_path / "inclusion.json"
    proof.write_text(json.dumps({"tree_size": 5, "leaf_index": 2,
                                 "path": [p.hex() for p in k["proof"]["path"]],
                                 "root": "00" * 32}), encoding="utf-8")
    ik, tk = _keyfile(tmp_path, "i.key", k["issuer"]), _keyfile(tmp_path, "t.key", k["ts"])
    out = tmp_path / "S.scitt"
    rc = cli.main(["tally", "scitt-export", str(s), "--key", str(ik), "--proof", str(proof),
                   "--ts-key", str(tk), "--out", str(out)])
    assert rc == V.EXIT_BAD and not out.exists()


def test_cli_verify_without_ts_key_could_not_look(k, tmp_path, capsys):
    out = tmp_path / "S.scitt"
    out.write_bytes(S.attach_receipt(k["stmt"], k["receipt"]))
    assert cli.main(["tally", "scitt-verify", str(out)]) == V.EXIT_COULD_NOT_LOOK
    assert V.COULD_NOT_LOOK in capsys.readouterr().out


def test_cli_verify_wrong_ts_key_is_broken(k, tmp_path, capsys):
    out = tmp_path / "S.scitt"
    out.write_bytes(S.attach_receipt(k["stmt"], k["receipt"]))
    rc = cli.main(["tally", "scitt-verify", str(out), "--ts-pub",
                   pub(secrets.token_bytes(32)).hex()])
    assert rc == V.EXIT_BAD
