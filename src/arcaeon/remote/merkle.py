# SPDX-License-Identifier: MIT
"""arcaeon.remote.merkle: the RFC 9162 (Certificate Transparency v2) Merkle tree, SHA-256.

    leaf_hash(d)  = SHA-256(0x00 || d)
    node_hash(l, r) = SHA-256(0x01 || l || r)
    root(leaves)  = MTH (section 2.1.1); the empty tree is SHA-256 of nothing
    inclusion_proof(leaves, m) = PATH(m, D[n]) (section 2.1.3.1)
    root_from_inclusion_proof(leaf, index, size, path)
                  = the section 2.1.3.2 verification walk; None when the proof
                    cannot compute a root (index out of range, wrong length)

This is the tree an RFC 9942 receipt with vds RFC9162_SHA256 (1) points into
(arcaeon.remote.scitt). Pure, offline, no dependency; never raises on a bad
proof (only inclusion_proof, the builder, raises on a bad index).
"""
from __future__ import annotations

import hashlib
import hmac

__all__ = ["leaf_hash", "node_hash", "root", "inclusion_proof", "root_from_inclusion_proof",
           "verify_inclusion"]


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + bytes(data)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """The largest power of two smaller than n (n > 1)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def _mth(hashes: list[bytes]) -> bytes:
    n = len(hashes)
    if n == 1:
        return hashes[0]
    k = _split(n)
    return node_hash(_mth(hashes[:k]), _mth(hashes[k:]))


def root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    return _mth([leaf_hash(x) for x in leaves])


def _path(m: int, hashes: list[bytes]) -> list[bytes]:
    n = len(hashes)
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return _path(m, hashes[:k]) + [_mth(hashes[k:])]
    return _path(m - k, hashes[k:]) + [_mth(hashes[:k])]


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """The audit path for leaves[index]; ValueError for an index outside the tree."""
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(leaves):
        raise ValueError(f"leaf index {index!r} is outside a tree of {len(leaves)} leaves")
    return _path(index, [leaf_hash(x) for x in leaves])


def root_from_inclusion_proof(leaf: bytes, index: int, size: int, path) -> bytes | None:
    """RFC 9162 section 2.1.3.2, steps 1-5, returning the computed root (or None)."""
    for v in (index, size):
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            return None
    if index >= size:
        return None
    try:
        path = [bytes(p) for p in path]
    except (TypeError, ValueError):
        return None
    if any(len(p) != 32 for p in path):
        return None
    fn, sn, r = index, size - 1, leaf_hash(leaf)
    for p in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def verify_inclusion(leaf: bytes, index: int, size: int, path, expected_root: bytes) -> bool:
    got = root_from_inclusion_proof(leaf, index, size, path)
    return got is not None and hmac.compare_digest(got, bytes(expected_root))
