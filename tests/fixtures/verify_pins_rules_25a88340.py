# SPDX-License-Identifier: MIT
"""FROZEN EXCERPT, not live code. Source: the operator's velouria repo, commit
25a88340, path bridge/witness/verify_pins.py (read with `git show`). The
statement and digest rules below are copied byte for byte from that file
(constants, _loads, canonical_bytes, chain_step, values_text, values_sha256,
walk_chain, _statement_problem); only `lf_prefix_sha256` at the end is an
adapter, lifting the W18 ("lf") branch of the nested prefix_sha() inside
_check_chain_file so a test can call it. Used by
tests/test_tally_chain_vs_verify_pins.py to check arcaeon.prove.tally_chain
agrees with the witness verifier. Do not edit to make a test pass: re-freeze
from a named commit instead.
"""
from __future__ import annotations

import hashlib
import json
import re

# --- verify_pins.py lines 172-182, 189 (25a88340) ---
PIN_FIELDS = ("chain", "chain_values_sha256", "file_sha256", "file_sha256_of",
              "prev_pin_sha256", "rows", "stated_at", "tip", "v")
# a pre-W18 (legacy) pin: no file_sha256_of; its file_sha256 is of the raw bytes
LEGACY_PIN_FIELDS = tuple(f for f in PIN_FIELDS if f != "file_sha256_of")
# D002: the W18 shape plus the listing of every earlier pin (see listing_text)
LISTING_FIELD = "public_listing_sha256"
LISTING_PIN_FIELDS = PIN_FIELDS + (LISTING_FIELD,)
FILE_SHA256_OF = "lf"
_HEX = re.compile(r"^[0-9a-f]{32,64}\Z")
_HEX64 = re.compile(r"^[0-9a-f]{64}\Z")
_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{4}Z\Z")
MAX_CHAIN_LINE_BYTES = 1 << 20          # 1 MiB per chain line


# --- verify_pins.py lines 220-226 ---
def _loads(text):
    """json.loads that never raises past ValueError: a document nested deeper
    than the interpreter's recursion limit is malformed input, not a crash."""
    try:
        return json.loads(text)
    except RecursionError:
        raise ValueError("JSON nested too deeply to parse") from None


# --- verify_pins.py lines 274-289 ---
def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def chain_step(prev: str, row: dict) -> str:
    body = json.dumps(row, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()[:32]


def values_text(values) -> str:
    return "".join(v + "\n" for v in values)


def values_sha256(values) -> str:
    return hashlib.sha256(values_text(values).encode("utf-8")).hexdigest()


# --- verify_pins.py lines 806-847 ---
def walk_chain(raw: bytes) -> dict:
    """Recompute the chain. -> {values, ends, first_break_row, unparseable_row,
    too_large_row, too_large_bytes}. `ends[k]` is the byte offset just past
    row k+1's line (its LF included). A line over MAX_CHAIN_LINE_BYTES stops
    the walk there (too_large_row), unparsed."""
    values, ends = [], []
    first_break = unparseable = too_large = None
    too_large_bytes = None
    prev = "genesis"
    pos = 0
    for line in raw.splitlines(keepends=True):
        pos += len(line)
        s = line.strip()
        if not s:
            continue
        row_no = len(values) + 1
        if len(line) > MAX_CHAIN_LINE_BYTES:
            too_large, too_large_bytes = row_no, len(line)
            break
        try:
            obj = _loads(s.decode("utf-8"))
            if not isinstance(obj, dict):
                raise ValueError("row is not an object")
            claimed = obj.pop("chain", None)
            step = chain_step(prev, obj)
        except (ValueError, UnicodeDecodeError, RecursionError):
            unparseable = unparseable or row_no
            values.append(None)
            ends.append(pos)
            continue
        if not isinstance(claimed, str) or step != claimed:
            first_break = first_break or row_no
        values.append(claimed if isinstance(claimed, str) else None)
        ends.append(pos)
        prev = claimed if isinstance(claimed, str) else prev
    return {"values": values, "ends": ends, "first_break_row": first_break,
            "unparseable_row": unparseable, "too_large_row": too_large,
            "too_large_bytes": too_large_bytes}


# ---------------------------------------------------------------------------
# verify


# --- verify_pins.py lines 1591-1618 ---
def _statement_problem(st) -> str | None:
    if not isinstance(st, dict):
        return f"a JSON {type(st).__name__}, not an object"
    if st.get("v") != 2 or set(st) not in (set(PIN_FIELDS), set(LEGACY_PIN_FIELDS),
                                           set(LISTING_PIN_FIELDS)):
        return f"v={st.get('v')!r}, fields {sorted(st)}"
    if LISTING_FIELD in st and (not isinstance(st[LISTING_FIELD], str)
                                or not _HEX64.match(st[LISTING_FIELD])):
        return f"{LISTING_FIELD} is not 64 hex"
    if "file_sha256_of" in st and st["file_sha256_of"] != FILE_SHA256_OF:
        return f"file_sha256_of={st['file_sha256_of']!r} (only {FILE_SHA256_OF!r} is defined)"
    if not isinstance(st["chain"], str) or not st["chain"]:
        return "chain id is not a string"
    if not isinstance(st["rows"], int) or isinstance(st["rows"], bool) or st["rows"] < 1:
        return f"rows={st['rows']!r} is not a positive integer"
    if not isinstance(st["tip"], str) or not _HEX.match(st["tip"]):
        return "tip is not hex"
    for k in ("chain_values_sha256", "file_sha256"):
        if not isinstance(st[k], str) or not _HEX64.match(st[k]):
            return f"{k} is not 64 hex"
    p = st["prev_pin_sha256"]
    if p is not None and (not isinstance(p, str) or not _HEX64.match(p)):
        return "prev_pin_sha256 is neither null nor 64 hex"
    try:
        canonical_bytes(st)
    except ValueError as e:     # a lone surrogate escape: JSON, but not UTF-8 text
        return f"not encodable as UTF-8 ({type(e).__name__})"
    return None


# --- ADAPTER (not verbatim): the W18 branch of prefix_sha() in _check_chain_file,
# verify_pins.py lines 1854-1857: prefix = craw[:walk["ends"][rows_i - 1]];
# lf_got = sha256(prefix with CRLF -> LF); file_sha256_of "lf" is compared strictly.
def lf_prefix_sha256(craw: bytes, walk: dict, rows_i: int) -> str:
    prefix = craw[:walk["ends"][rows_i - 1]]
    return hashlib.sha256(prefix.replace(b"\r\n", b"\n")).hexdigest()
