# SPDX-License-Identifier: MIT
"""arcaeon.remote._cbor: the small CBOR subset COSE_Sign1 needs, so SCITT export needs no new dependency.

ENCODE is RFC 8949 section 4.2.1 core deterministic encoding: shortest-form
heads, definite lengths only, map keys sorted by the bytewise order of their
encoded form. Types: int (64-bit range), bytes, str, list/tuple, dict, None,
True/False, Tag. Floats and anything else raise CBORError: a COSE header
that held a float would be a header this module never wrote.

DECODE is strict and bounded for hostile input: definite lengths only, no
floats, no undefined or other simple values, map keys int or str and unique,
a length can never ask for more bytes than remain, nesting is capped at
MAX_DEPTH, and trailing bytes are refused. Non-shortest heads are read (a
foreign encoder may write them); signatures are always checked over the
bytes as received, never a re-encoding.

cbor2, when installed, is used only by the tests, as an outside reader.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["Tag", "CBORError", "encode", "decode", "MAX_DEPTH"]

MAX_DEPTH = 16


class CBORError(ValueError):
    """Not CBOR this module writes or reads."""


@dataclass(frozen=True)
class Tag:
    tag: int
    value: Any


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([major << 5 | ai]) + n.to_bytes(width, "big")
    raise CBORError("an integer outside the 64-bit CBOR range")


def _enc(obj: Any, out: bytearray) -> None:
    if obj is None:
        out.append(0xF6)
    elif obj is True:
        out.append(0xF5)
    elif obj is False:
        out.append(0xF4)
    elif isinstance(obj, int):
        out += _head(0, obj) if obj >= 0 else _head(1, -1 - obj)
    elif isinstance(obj, (bytes, bytearray)):
        out += _head(2, len(obj)) + bytes(obj)
    elif isinstance(obj, str):
        b = obj.encode("utf-8")
        out += _head(3, len(b)) + b
    elif isinstance(obj, (list, tuple)):
        out += _head(4, len(obj))
        for x in obj:
            _enc(x, out)
    elif isinstance(obj, dict):
        items = []
        for k, v in obj.items():
            if not isinstance(k, (int, str)) or isinstance(k, bool):
                raise CBORError(f"a map key must be int or str, not {type(k).__name__}")
            items.append((encode(k), v))
        items.sort(key=lambda kv: kv[0])
        out += _head(5, len(items))
        for kb, v in items:
            out += kb
            _enc(v, out)
    elif isinstance(obj, Tag):
        out += _head(6, obj.tag)
        _enc(obj.value, out)
    else:
        raise CBORError(f"cannot encode a {type(obj).__name__}")


def encode(obj: Any) -> bytes:
    out = bytearray()
    _enc(obj, out)
    return bytes(out)


def _dec(b: bytes, i: int, depth: int) -> tuple[Any, int]:
    if depth > MAX_DEPTH:
        raise CBORError(f"nested deeper than {MAX_DEPTH}")
    if i >= len(b):
        raise CBORError("truncated")
    ib = b[i]
    major, ai = ib >> 5, ib & 31
    i += 1
    if major == 7:
        if ai in (20, 21, 22):
            return (False, True, None)[ai - 20], i
        raise CBORError(f"simple value or float 0x{ib:02x} is not read here")
    if ai < 24:
        n = ai
    elif ai <= 27:
        w = 1 << (ai - 24)
        if i + w > len(b):
            raise CBORError("truncated")
        n = int.from_bytes(b[i:i + w], "big")
        i += w
    else:
        raise CBORError("indefinite length or reserved head")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        if n > len(b) - i:
            raise CBORError("a string longer than the bytes left")
        raw = b[i:i + n]
        if major == 2:
            return bytes(raw), i + n
        try:
            return raw.decode("utf-8"), i + n
        except UnicodeDecodeError:
            raise CBORError("a text string that is not UTF-8") from None
    if major == 4:
        if n > len(b) - i:
            raise CBORError("an array longer than the bytes left")
        arr = []
        for _ in range(n):
            v, i = _dec(b, i, depth + 1)
            arr.append(v)
        return arr, i
    if major == 5:
        if 2 * n > len(b) - i:
            raise CBORError("a map longer than the bytes left")
        m: dict = {}
        for _ in range(n):
            k, i = _dec(b, i, depth + 1)
            if not isinstance(k, (int, str)) or isinstance(k, bool):
                raise CBORError("a map key that is not int or str")
            if k in m:
                raise CBORError(f"duplicate map key {k!r}")
            m[k], i = _dec(b, i, depth + 1)
        return m, i
    v, i = _dec(b, i, depth + 1)   # major 6
    return Tag(n, v), i


def decode(data: bytes) -> Any:
    b = bytes(data)
    v, end = _dec(b, 0, 0)
    if end != len(b):
        raise CBORError(f"{len(b) - end} trailing bytes")
    return v
