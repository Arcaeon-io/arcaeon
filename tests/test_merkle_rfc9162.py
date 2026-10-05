# SPDX-License-Identifier: MIT
"""L3-05: the RFC 9162 Merkle tree under the SCITT receipts (arcaeon.remote.merkle).

The reference below is written from the RFC's definitions (section 2.1.1 MTH,
section 2.1.3.1 PATH), recursively, independent of the module's iterative code:
every index of trees of many sizes, powers of two and not, must agree."""
from __future__ import annotations

import hashlib

import pytest

from arcaeon.remote import merkle as M


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def ref_mth(d: list[bytes]) -> bytes:
    n = len(d)
    if n == 0:
        return _h(b"")
    if n == 1:
        return _h(b"\x00" + d[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return _h(b"\x01" + ref_mth(d[:k]) + ref_mth(d[k:]))


def ref_path(m: int, d: list[bytes]) -> list[bytes]:
    n = len(d)
    if n == 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if m < k:
        return ref_path(m, d[:k]) + [ref_mth(d[k:])]
    return ref_path(m - k, d[k:]) + [ref_mth(d[:k])]


def leaves(n: int) -> list[bytes]:
    return [f"leaf-{i}".encode() for i in range(n)]


SIZES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 16, 17, 31, 32, 33, 100]


def test_hash_prefixes_are_the_rfc_ones():
    assert M.leaf_hash(b"x") == _h(b"\x00x")
    assert M.node_hash(b"a" * 32, b"b" * 32) == _h(b"\x01" + b"a" * 32 + b"b" * 32)
    assert M.root([]) == _h(b"")


def test_known_vector_rfc6962_empty_and_single():
    # the CT test vectors: empty tree, and the one-leaf tree over the empty leaf
    assert M.root([]).hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert M.root([b""]).hex() == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"


@pytest.mark.parametrize("n", SIZES)
def test_root_matches_the_definition(n):
    assert M.root(leaves(n)) == ref_mth(leaves(n))


@pytest.mark.parametrize("n", SIZES)
def test_every_index_proof_matches_and_verifies(n):
    d = leaves(n)
    r = ref_mth(d)
    for i in range(n):
        p = M.inclusion_proof(d, i)
        assert p == ref_path(i, d), (n, i)
        assert M.root_from_inclusion_proof(d[i], i, n, ref_path(i, d)) == r, (n, i)
        assert M.verify_inclusion(d[i], i, n, p, r)


@pytest.mark.parametrize("n", [2, 5, 8, 17])
def test_wrong_leaf_index_size_or_path_fails(n):
    d = leaves(n)
    r = ref_mth(d)
    for i in range(n):
        p = ref_path(i, d)
        assert not M.verify_inclusion(b"other", i, n, p, r)
        assert not M.verify_inclusion(d[i], (i + 1) % n, n, p, r)
        assert not M.verify_inclusion(d[i], i, n, p[:-1], r)
        assert not M.verify_inclusion(d[i], i, n, p + [b"\x00" * 32], r)
        bad = list(p)
        bad[0] = bytes([bad[0][0] ^ 1]) + bad[0][1:]
        assert not M.verify_inclusion(d[i], i, n, bad, r)


def test_tree_size_only_shapes_the_walk():
    """A property of RFC 9162 section 2.1.3.2, pinned so nobody leans on it:
    the size only steers the walk, so one path proves leaf 2 under every size
    from 5 to 8 (same root out). A size that changes the walk (4, 3, 9) fails.
    A receipt that signs only the root does not authenticate its tree size;
    arcaeon's receipts sign it separately (arcaeon.remote.scitt)."""
    d = leaves(5)
    p, r = ref_path(2, d), ref_mth(d)
    for size in (5, 6, 7, 8):
        assert M.root_from_inclusion_proof(d[2], 2, size, p) == r
    for size in (3, 4, 9):
        assert M.root_from_inclusion_proof(d[2], 2, size, p) != r


def test_index_out_of_range_is_none_not_a_raise():
    assert M.root_from_inclusion_proof(b"x", 3, 3, []) is None
    assert M.root_from_inclusion_proof(b"x", 0, 0, []) is None
    assert M.root_from_inclusion_proof(b"x", -1, 3, []) is None
    with pytest.raises(ValueError):
        M.inclusion_proof(leaves(3), 3)
