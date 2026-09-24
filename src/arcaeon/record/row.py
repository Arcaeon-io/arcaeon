# SPDX-License-Identifier: MIT
"""arcaeon.record.row: the ledger row format, in one place.

Every Arcaeon tool that writes or reads a hash-chained JSONL row imports the
format from here: the ledger, the adapter (and its no-library fallback), the
small call records the MCP servers keep, receipt, reconcile, the witness pin
digest, audit, compact, continuity and distill. Before the merge the same
recipes lived in six places (the ledger, the adapter fallback, three
byte-identical `_ledger.py` copies in once, distill and continuity, and
receipt's pin-digest fallback), plus four separate copies of the json-c14n
canonicalization. MIGRATION.md names each old copy.

THE FORMAT, frozen (changing any of it breaks every existing log):

  row        one JSON object per line, UTF-8.
  chain      sha256(prev_chain + json.dumps(row_without_chain,
                                            ensure_ascii=False, sort_keys=True)
             ).hexdigest()[:32]; the first row's prev is "genesis".
             Python's DEFAULT ", " / ": " separators, NOT the compact
             json-c14n form below. The chain body is its own unversioned
             rule and always has been.
  digest     "sha256:json-c14n:v1:" + sha256(canonical).hexdigest(), where
             canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False)
             "sha256:raw-bytes:v1:" + sha256(bytes).hexdigest() for opaque bytes.
  pin self   the witness pin's own digest: the chain rule's body hash over the
             pin minus its derived fields `prev` and `self`, no prev prefix.

Reading rules, also shared: a line nested too deep to parse is a ValueError
(never a RecursionError that walks past every `except ValueError`), and the
strict reader refuses a duplicate key, because two honest parsers keep
different values for it.

Stdlib only. Importing this module imports nothing outside the standard library.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

__all__ = ["GENESIS", "CHAIN_LEN", "RESERVED_KEYS", "chain", "body_digest",
           "canon_json", "digest_json", "digest_bytes", "JSON_C14N_PREFIX",
           "RAW_BYTES_PREFIX", "DuplicateKeyError", "loads", "loads_strict"]

GENESIS = "genesis"
CHAIN_LEN = 32  # first N hex chars of the sha256; plenty for tamper-evidence

#: Keys the ledger stamps itself: `ts` and `chain` on every row, `authority`
#: when `append(authority=...)` is used. A caller's own fields must not use them.
RESERVED_KEYS = frozenset({"ts", "chain", "authority"})

JSON_C14N_PREFIX = "sha256:json-c14n:v1:"
RAW_BYTES_PREFIX = "sha256:raw-bytes:v1:"


def body_digest(obj: dict, exclude: Iterable[str] = ("chain",), prev: str = "",
                length: int = CHAIN_LEN) -> str:
    """sha256(prev + json.dumps(obj minus `exclude`, ensure_ascii=False,
    sort_keys=True)), first `length` hex chars.

    errors="surrogatepass" so a LONE SURROGATE cannot turn the verifier into a
    crash. JSON permits `\\udXXX` escapes and `json.dumps` emits them by
    default, so any cross-language writer or log-shipper can put an unpaired
    surrogate in a row that is perfectly valid JSON. Plain UTF-8 refuses to
    encode it, which raised UnicodeEncodeError and left a file append-able and
    iterable while `verify`, `head` and `bundle` were all dead on it (ledger
    0.5.8). surrogatepass is deterministic and byte-identical for every input
    that could already be encoded, so no honest historical digest moves.

    str(prev) is a no-op on every honest path (prev is always a hex string or
    'genesis'); it is a floor so no route to a non-string prev can crash the
    hash with `int + str` (ledger 0.5.5).
    """
    skip = set(exclude)
    body = json.dumps({k: v for k, v in obj.items() if k not in skip},
                      ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(
        (str(prev) + body).encode("utf-8", "surrogatepass")).hexdigest()[:length]


def chain(prev: str, obj: dict) -> str:
    """The row's chain link: body_digest(obj minus "chain", prefixed by prev)."""
    return body_digest(obj, ("chain",), prev)


def canon_json(value: Any) -> bytes:
    """The frozen json-c14n v1 canonicalization, byte for byte.

    Raises ValueError on NaN/Infinity (allow_nan=False) rather than emitting a
    token no other language's JSON parser accepts, and on a value nested too
    deeply to serialize (RecursionError retyped, ledger 2026-09-05 audit): a
    digest function's contract is a bounded digest or a typed failure, never a
    crash.
    """
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except RecursionError as e:
        raise ValueError(f"value nests too deeply to canonicalize: {e}") from None


def digest_json(value: Any) -> str:
    """Self-describing digest of a JSON value: `sha256:json-c14n:v1:<hex>`."""
    return JSON_C14N_PREFIX + hashlib.sha256(canon_json(value)).hexdigest()


def digest_bytes(data: bytes) -> str:
    """Self-describing digest of opaque bytes: `sha256:raw-bytes:v1:<hex>`."""
    return RAW_BYTES_PREFIX + hashlib.sha256(bytes(data)).hexdigest()


class DuplicateKeyError(ValueError):
    """A JSON object carried the same key twice. Python keeps the LAST value,
    a first-wins reader keeps the FIRST, so the line means two different
    things to two honest readers. A verifier must not pick one and say green."""


def _reject_duplicate_keys(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise DuplicateKeyError(f"duplicate key {k!r}")
        out[k] = v
    return out


def loads_strict(raw: str | bytes):
    """`loads`, plus: a duplicate key anywhere in the line is a DuplicateKeyError
    (a ValueError). Verifiers use this; readers that only iterate rows use `loads`."""
    try:
        return json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except RecursionError as e:
        raise ValueError(f"nesting too deep to parse: {e}") from None


def loads(raw: str | bytes):
    """json.loads that fails as ValueError on EVERY malformed line, including
    the one shape the stdlib does not: a pathologically nested array/object
    (100k '[') overflows the C decoder's stack and escapes as RecursionError,
    which every `except ValueError` walked straight past. One planted line then
    turned the verifier into a crash instead of a verdict (2026-09-01 audit).
    Retyped, not swallowed: the caller still sees a parse failure."""
    try:
        return json.loads(raw)
    except RecursionError as e:
        raise ValueError(f"nesting too deep to parse: {e}") from None
