# SPDX-License-Identifier: MIT
r"""arcaeon.prove.jcs: RFC 8785 JSON Canonicalization Scheme, stdlib only.

    canonicalize(value) -> bytes     the UTF-8 JCS form of a JSON value
    sha256_hex(value)   -> str       hex(SHA-256(JCS(value))), 64 hex

Rules, as RFC 8785 section 3.2 states them:

* no whitespace between tokens;
* object keys sorted by their UTF-16 code units (not by code point, not by
  locale), recursively; array order is kept;
* strings: U+0000 to U+001F escaped (\b \t \n \f \r, else \u00hh lower
  case), `"` and `\` escaped, every other code point as is;
* numbers in the ECMAScript Number-to-String form (ECMA-262 7.1.12.1).

What is REFUSED, never rounded or guessed (raises JcsError naming the path):

* NaN and Infinity (RFC 8785 3.2.2.3: "MUST cause ... an appropriate error");
* an integer outside -(2**53) .. 2**53: JCS numbers are IEEE 754 doubles, and
  such an integer cannot be written as one exactly;
* a lone surrogate in a string or key (RFC 8785 3.2.2.2);
* a key that is not a string, or a value that is not JSON (a set, bytes ...).
"""
from __future__ import annotations

import hashlib
import math
from typing import Any

__all__ = ["canonicalize", "sha256_hex", "number", "JcsError", "MAX_EXACT_INT"]

#: The largest integer magnitude an IEEE 754 double holds exactly with its
#: neighbours still distinct: 2**53.
MAX_EXACT_INT = 2 ** 53

_BS = chr(92)
_ESC = {0x08: _BS + "b", 0x09: _BS + "t", 0x0A: _BS + "n", 0x0C: _BS + "f",
        0x0D: _BS + "r", 0x22: _BS + '"', 0x5C: _BS + _BS}


class JcsError(ValueError):
    """A value JCS cannot serialize exactly. `path` names where, `why` says why."""

    def __init__(self, path: str, why: str):
        super().__init__(f"{path}: {why}")
        self.path = path
        self.why = why


def _string(s: str, path: str) -> str:
    out = ['"']
    for ch in s:
        c = ord(ch)
        if 0xD800 <= c <= 0xDFFF:
            raise JcsError(path, f"lone surrogate U+{c:04X} in a string")
        if c in _ESC:
            out.append(_ESC[c])
        elif c < 0x20:
            out.append(_BS + f"u{c:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def number(x: float) -> str:
    """ECMAScript Number::toString for a finite double (ECMA-262 7.1.12.1).

    Python's repr gives the shortest digit string that round-trips, and among
    equally short strings the one closest to the value (ECMA-262 "Note 2");
    only the layout differs, and this function lays it out the ECMAScript way.
    """
    if not math.isfinite(x):
        raise JcsError("$", "NaN or Infinity is not JSON")
    if x == 0:
        return "0"  # minus zero too
    if x < 0:
        return "-" + number(-x)
    mant, _, exp = repr(x).partition("e")
    whole, _, frac = mant.partition(".")
    # value == int(raw) * 10**scale
    raw, scale = whole + frac, (int(exp) if exp else 0) - len(frac)
    digits = raw.lstrip("0")
    stripped = digits.rstrip("0")
    scale += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = k + scale  # ECMA-262: value == 0.<digits> * 10**n
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    head = digits[0] + ("." + digits[1:] if k > 1 else "")
    return f"{head}e{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"


def _emit(v: Any, path: str, out: list[str]) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, int):
        if abs(v) > MAX_EXACT_INT:
            raise JcsError(path, f"integer {v} is outside +/-2**53 and cannot be a "
                                 "JCS number exactly")
        out.append(str(v))
    elif isinstance(v, float):
        if not math.isfinite(v):
            raise JcsError(path, "NaN or Infinity is not JSON")
        out.append(number(v))
    elif isinstance(v, str):
        out.append(_string(v, path))
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(",")
            _emit(item, f"{path}[{i}]", out)
        out.append("]")
    elif isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise JcsError(path, f"object key {k!r} is not a string")
        # UTF-16 code units compared as unsigned integers == UTF-16BE bytes.
        # surrogatepass lets a lone surrogate key reach _string, which refuses it.
        keys = sorted(v, key=lambda s: s.encode("utf-16-be", "surrogatepass"))
        out.append("{")
        for i, k in enumerate(keys):
            if i:
                out.append(",")
            sub = f"{path}.{k}"
            out.append(_string(k, sub))
            out.append(":")
            _emit(v[k], sub, out)
        out.append("}")
    else:
        raise JcsError(path, f"a {type(v).__name__} is not a JSON value")


def canonicalize(value: Any) -> bytes:
    """The RFC 8785 canonical form of `value`, UTF-8 encoded."""
    out: list[str] = []
    _emit(value, "$", out)
    return "".join(out).encode("utf-8")


def sha256_hex(value: Any) -> str:
    """hex(SHA-256(JCS(value))): 64 lower-case hex characters."""
    return hashlib.sha256(canonicalize(value)).hexdigest()
