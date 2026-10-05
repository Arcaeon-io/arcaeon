"""The pure-Python Ed25519 fallback in arcaeon.checkin against RFC 8032.

The fallback (`_ed25519_verify_pure`, used only when `cryptography` is not
installed) stays in the package only while it passes the RFC 8032 section 7.1
test vectors and refuses the negative cases below. If any of these fail and
the fix is not small, the fallback goes, not the test.

TEST 1, 2, 3 and SHA(abc) are copied from RFC 8032 section 7.1 (public test
values, not keys of anyone's). Their public keys and signatures are also
cross-checked here against `cryptography` when it is installed. TEST 1024's
1023-byte message is not reproduced here; that vector is covered by its RFC
secret and public key plus a 1023-byte message signed with `cryptography`.
"""
from __future__ import annotations

import hashlib
import os

import pytest

from arcaeon import checkin

verify = checkin._ed25519_verify_pure

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493

# (name, secret, public, message, signature), hex, from RFC 8032 section 7.1.
RFC8032_7_1 = [
    ("TEST 1",
     "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("TEST 2",
     "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("TEST 3",
     "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ("TEST SHA(abc)",
     "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
     "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
     "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
]
TEST_1024_SECRET = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"
TEST_1024_PUBLIC = "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"

IDS = [v[0] for v in RFC8032_7_1]


def _vec(v):
    _, sk, pk, m, sig = v
    return bytes.fromhex(sk), bytes.fromhex(pk), bytes.fromhex(m), bytes.fromhex(sig)


def _ed():
    return pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")


def _pub_of(seed: bytes) -> bytes:
    ed = _ed()
    from cryptography.hazmat.primitives import serialization as S
    return ed.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        S.Encoding.Raw, S.PublicFormat.Raw)


def _flip(b: bytes, i: int, bit: int = 0) -> bytes:
    x = bytearray(b)
    x[i] ^= 1 << bit
    return bytes(x)


# --- the RFC 8032 section 7.1 vectors ---------------------------------------------------

@pytest.mark.parametrize("v", RFC8032_7_1, ids=IDS)
def test_rfc8032_vector_verifies(v):
    _, pub, msg, sig = _vec(v)
    assert verify(pub, msg, sig) is True


def test_sha_abc_vector_message_is_sha512_of_abc():
    assert RFC8032_7_1[3][3] == hashlib.sha512(b"abc").hexdigest()


@pytest.mark.parametrize("v", RFC8032_7_1, ids=IDS)
def test_rfc8032_vector_hex_matches_cryptography(v):
    """A typo in the copied hex would show here: the public key and the
    (deterministic) signature are recomputed from the RFC secret."""
    ed = _ed()
    seed, pub, msg, sig = _vec(v)
    assert _pub_of(seed) == pub
    assert ed.Ed25519PrivateKey.from_private_bytes(seed).sign(msg) == sig


def test_rfc8032_test_1024_key_with_a_1023_byte_message():
    ed = _ed()
    seed, pub = bytes.fromhex(TEST_1024_SECRET), bytes.fromhex(TEST_1024_PUBLIC)
    assert _pub_of(seed) == pub
    msg = hashlib.shake_256(b"arcaeon rfc8032 test 1024").digest(1023)
    sig = ed.Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
    assert verify(pub, msg, sig) is True
    assert verify(pub, msg[:-1], sig) is False
    assert verify(pub, _flip(msg, 511), sig) is False


def test_agrees_with_cryptography_on_fresh_material():
    ed = _ed()
    for n in (0, 1, 2, 63, 64, 1023, 4096):
        seed = hashlib.sha256(b"seed-%d" % n).digest()
        msg = os.urandom(n)
        sig = ed.Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
        assert verify(_pub_of(seed), msg, sig) is True


# --- negative cases ---------------------------------------------------------------------

@pytest.mark.parametrize("v", RFC8032_7_1, ids=IDS)
@pytest.mark.parametrize("where", ["R", "S"])
def test_a_flipped_bit_in_the_signature_is_refused(v, where):
    _, pub, msg, sig = _vec(v)
    base = 0 if where == "R" else 32
    for i, bit in ((base, 0), (base + 13, 5), (base + 31, 6)):
        assert verify(pub, msg, _flip(sig, i, bit)) is False


@pytest.mark.parametrize("v", RFC8032_7_1, ids=IDS)
def test_a_flipped_bit_in_the_message_is_refused(v):
    _, pub, msg, sig = _vec(v)
    assert verify(pub, msg + b"\x00", sig) is False
    if msg:
        assert verify(pub, _flip(msg, 0), sig) is False
        assert verify(pub, _flip(msg, len(msg) - 1, 7), sig) is False


@pytest.mark.parametrize("v", RFC8032_7_1, ids=IDS)
def test_a_flipped_bit_in_the_public_key_is_refused(v):
    _, pub, msg, sig = _vec(v)
    for i, bit in ((0, 0), (16, 3), (31, 7)):
        assert verify(_flip(pub, i, bit), msg, sig) is False


@pytest.mark.parametrize("v", RFC8032_7_1, ids=IDS)
def test_s_at_or_above_l_is_refused(v):
    _, pub, msg, sig = _vec(v)
    s = int.from_bytes(sig[32:], "little")
    for bad in (s + L, L, L + 1, 2 ** 256 - 1):
        if bad < 2 ** 256:
            assert verify(pub, msg, sig[:32] + bad.to_bytes(32, "little")) is False


def test_s_plus_l_is_the_same_scalar_and_still_refused():
    """S + L satisfies the group equation, so only the S < L check stops it."""
    _, pub, msg, sig = _vec(RFC8032_7_1[0])
    s = int.from_bytes(sig[32:], "little")
    assert s + L < 2 ** 256
    assert verify(pub, msg, sig[:32] + (s + L).to_bytes(32, "little")) is False


def _enc(y: int, sign: int = 0) -> bytes:
    return (y | (sign << 255)).to_bytes(32, "little")


@pytest.mark.parametrize("enc", [
    _enc(P),          # y = p: non-canonical encoding of y = 0
    _enc(P + 1),      # y = p + 1: non-canonical encoding of the identity (y = 1)
    _enc(2 ** 255 - 1),
    _enc(1, sign=1),  # x = 0 with the sign bit set ("negative zero")
    _enc(2),          # y = 2: not on the curve
], ids=["y=p", "y=p+1", "y=2^255-1", "x=0,sign=1", "not-on-curve"])
def test_a_noncanonical_or_invalid_point_is_refused(enc):
    _, pub, msg, sig = _vec(RFC8032_7_1[0])
    assert checkin._decompress(enc) is None
    assert verify(enc, msg, sig) is False          # as the public key
    assert verify(pub, msg, enc + sig[32:]) is False  # as R


@pytest.mark.parametrize("pub,sig", [(b"", b""), (b"\x00" * 31, b"\x00" * 64),
                                     (b"\x00" * 32, b"\x00" * 63), (b"\x00" * 33, b"\x00" * 64)])
def test_wrong_lengths_are_refused(pub, sig):
    assert verify(pub, b"", sig) is False
