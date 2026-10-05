# SPDX-License-Identifier: MIT
"""arcaeon.connector.reported: the generic "reported by sender" adapter. For any
checker that has no adapter of its own, the sender hands a small documented JSON
row and this turns it into a relayed check.verdict row on the one adapter base
(arcaeon.connector.core.VendorAdapter).

Named for what every row it writes is: reported by the sender. Nothing here is
the checker's own signed word; it is the sender saying what a checker said.

THE SENDER'S ROW (one JSON object, or a JSON array of them, at most MAX_ROWS):

    vendor             string, required. Free text naming the checker, 1 to
                       MAX_VENDOR_CHARS characters after trimming. Recorded, never
                       used to pick code: a row naming "opa" is still a generic row.
    verdict            string, required. The checker's word; kept verbatim (cut to
                       256 characters) in `vendor_word`.
    input_sha256       64 hex characters: the SHA-256 of the bytes the checker judged.
    input_b64          the judged bytes themselves, standard base64. We hash them.
                       At least one of input_sha256 / input_b64 is required.
    vendor_request_id  string, optional: the checker's own id for the check.
    at                 string, optional: when the sender says the check ran (not parsed,
                       not checked).
    detail             string, optional: a short note (cut to 256 characters).

Any other key (signed_by_vendor, standing, signature, attestation, ...) is not read;
its name is listed in `reported.ignored_keys`.

THE WORD. TABLE, after trimming and casefolding:

    verified, pass, passed               -> VERIFIED
    broken, fail, failed                 -> BROKEN
    could not look, could_not_look       -> COULD NOT LOOK
    anything else, or not a string       -> COULD NOT LOOK

Bytes AND a claimed digest that differ: BROKEN, whatever the word, with
`reported.reason` "claimed digest does not match the bytes" and mapping rule
"digest_mismatch"; `input_sha256` is then the digest of the bytes.

THE ROW. The check.verdict.relayed row of arcaeon.connector.core, plus:

    input_sha256      hex SHA-256 of the judged input (ours over input_b64, else the
                      sender's claim), or None
    at                the sender's `at`, or None
    reported          {row_index, vendor, vendor_request_id, detail, input_source
                       ("bytes" | "claimed_sha256" | "bytes_and_claimed_sha256" | None),
                       input_bytes, claimed_input_sha256, reason, ignored_keys}
    signed_by_vendor  False. Always.
    standing          "reported_by_sender". Always.

    vendor       {"name": "reported", "adapter_version": "1"}: always this adapter
    vendor_id    the sender's vendor_request_id
    subject      {"name": "reported:input", "sha256": input_sha256}, or None
    attestation  always NONE, claimed None

`vendor`, `attestation`, `signed_by_vendor` and `standing` are written by ONE final
step (`_seal`) over every row ingest returns, after which only a clean reading of a
VERIFIED word on a known input can stay VERIFIED. `ingest` takes no argument that
changes them. `rollup` over these rows is never VERIFIED.

`recheck` says COULD NOT LOOK for these rows (one payload, many rows); re-run
`ingest` with the same bytes to compare. Never raises on what is sent. Stdlib only.
No network: this reads bytes you already hold.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any

from arcaeon.record.row import loads_strict
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED, could_not_look

from .core import (ATTESTATION_NONE, ROW_KIND, AdapterError, Extracted, VendorAdapter, _now_iso,
                   _safe_str, _too_deep, map_word, register)

__all__ = ["VENDOR", "ADAPTER_VERSION", "TABLE", "MAX_PAYLOAD_BYTES", "MAX_DEPTH", "MAX_ROWS",
           "MAX_VENDOR_CHARS", "STANDING", "DIGEST_MISMATCH", "ReportedBySenderAdapter",
           "REPORTED", "ingest", "rollup"]

VENDOR = "reported"
ADAPTER_VERSION = "1"
#: A body over this is digested, never read.
MAX_PAYLOAD_BYTES = 8 << 20
#: A sender row is flat; an array of them is two levels. Room for a little more.
MAX_DEPTH = 8
#: More rows than this in one body: the rest are not read, and a row says so.
MAX_ROWS = 1000
#: The sender's free-text vendor name, after trimming.
MAX_VENDOR_CHARS = 64
#: What every row of this adapter is.
STANDING = "reported_by_sender"
DIGEST_MISMATCH = "claimed digest does not match the bytes"

TABLE = {
    "verified": VERIFIED, "pass": VERIFIED, "passed": VERIFIED,
    "broken": BROKEN, "fail": BROKEN, "failed": BROKEN,
    "could not look": COULD_NOT_LOOK, "could_not_look": COULD_NOT_LOOK,
}

_KNOWN = ("vendor", "verdict", "input_sha256", "input_b64", "vendor_request_id", "at", "detail")
_WHERE = "reported row"
_HEX = frozenset("0123456789abcdef")


class ReportedBySenderAdapter(VendorAdapter):
    """The generic sender-reported adapter on the one base. Read with `ingest`, not
    import_verdict (whose `extract` refuses it)."""
    name = VENDOR
    version = ADAPTER_VERSION
    table = TABLE
    max_payload_bytes = MAX_PAYLOAD_BYTES
    max_depth = MAX_DEPTH
    one_row_per_payload = False

    def extract(self, doc: dict) -> Extracted:
        raise AdapterError("a reported row is read with arcaeon.connector.reported.ingest")


REPORTED = register(ReportedBySenderAdapter())

_cnl = REPORTED.mark_could_not_look


def _copy(row: dict) -> dict:
    return json.loads(json.dumps(row))


def _blank(index: int | None) -> dict:
    return {"row_index": index, "vendor": None, "vendor_request_id": None, "detail": None,
            "input_source": None, "input_bytes": None, "claimed_input_sha256": None,
            "reason": None, "ignored_keys": []}


def _hex64(v: Any) -> str | None:
    if isinstance(v, str) and len(v) == 64 and set(v.lower()) <= _HEX:
        return v.lower()
    return None


def _entry_row(base: dict, i: int, doc: Any) -> dict:
    row = _copy(base)
    rep = row["reported"] = _blank(i)
    where = f"{_WHERE}[{i}]"
    if not isinstance(doc, dict):
        return _cnl(row, "a reported row object", where, "unreadable",
                    "the entry is not a JSON object")
    rep["ignored_keys"] = sorted(s for s in (_safe_str(k) for k in doc if k not in _KNOWN)
                                 if s is not None)[:16]
    rep["vendor_request_id"] = _safe_str(doc.get("vendor_request_id"))
    row["vendor_id"] = rep["vendor_request_id"]
    row["at"] = _safe_str(doc.get("at"))
    rep["detail"] = _safe_str(doc.get("detail"))
    w = doc.get("verdict")
    row["vendor_word"] = _safe_str(w)

    # the vendor: free text, bounded, never a selector
    v = doc.get("vendor")
    if "vendor" not in doc or (isinstance(v, str) and not v.strip()):
        return _cnl(row, "the vendor name", where, "missing", "the row names no vendor")
    if not isinstance(v, str):
        return _cnl(row, "the vendor name", where, "unreadable", "the vendor is not a string")
    v = v.strip()
    if len(v) > MAX_VENDOR_CHARS:
        return _cnl(row, "the vendor name", where, "bounded",
                    f"the vendor name is over {MAX_VENDOR_CHARS} characters")
    rep["vendor"] = _safe_str(v)

    # the input: bytes we hash, a claimed digest, or both
    claimed = None
    if "input_sha256" in doc:
        claimed = _hex64(doc["input_sha256"])
        if claimed is None:
            return _cnl(row, "input_sha256", where, "unreadable",
                        "input_sha256 is not 64 hex characters")
        rep["claimed_input_sha256"] = claimed
    data = None
    if "input_b64" in doc:
        b = doc["input_b64"]
        if not isinstance(b, str):
            return _cnl(row, "input_b64", where, "unreadable", "input_b64 is not a string")
        if not b:
            return _cnl(row, "input_b64", where, "empty", "input_b64 is empty")
        try:
            data = base64.b64decode(b, validate=True)
        except (binascii.Error, ValueError):
            return _cnl(row, "input_b64", where, "unreadable", "input_b64 is not standard base64")
        rep["input_bytes"] = len(data)
    if claimed is None and data is None:
        return _cnl(row, "the judged input (input_sha256 or input_b64)", where, "missing",
                    "the row names no input, so the verdict is about nothing we can pin")
    ours = hashlib.sha256(data).hexdigest() if data is not None else None
    rep["input_source"] = ("bytes_and_claimed_sha256" if ours and claimed
                           else "bytes" if ours else "claimed_sha256")
    sha = ours or claimed
    row["input_sha256"] = sha
    row["subject"] = {"name": "reported:input", "sha256": sha}
    if ours and claimed and ours != claimed:
        rep["reason"] = DIGEST_MISMATCH
        row["mapping"] = {"rule": "digest_mismatch"}
        row["relayed_verdict"] = BROKEN
        return row

    word, rule = map_word(REPORTED, w)
    row["mapping"] = {"rule": rule}
    row["relayed_verdict"] = word
    if rule != "table":
        _cnl(row, "a verdict word this adapter's table holds", where, "name_not_found",
             f"vendor word {row['vendor_word']!r} is not in the reported table"
             if rule == "unknown_word" else "the verdict is not a word")
    return row


def _read(raw: Any, at: str) -> tuple[list, bytes | None]:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogatepass")
    if isinstance(raw, bytearray):
        raw = bytes(raw)
    if not isinstance(raw, bytes):
        return [_cnl(REPORTED.base_row(None, at), "reported row bytes", "argument",
                     "unreadable", f"payload is a {type(raw).__name__}, not bytes")], None
    base = REPORTED.base_row(raw, at)
    if not raw:
        return [_cnl(base, "a reported row", _WHERE, "empty", "the body is empty")], raw
    if len(raw) > MAX_PAYLOAD_BYTES:
        return [_cnl(base, "a reported row", _WHERE, "bounded",
                     f"body is {len(raw)} bytes, over the {MAX_PAYLOAD_BYTES}-byte "
                     f"limit; digested, not read")], raw
    try:
        doc = loads_strict(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        return [_cnl(base, "a reported row as JSON", _WHERE, "unreadable",
                     f"body is not one unambiguous UTF-8 JSON value: {type(e).__name__}")], raw
    if _too_deep(doc, MAX_DEPTH):
        return [_cnl(base, "a reported row as JSON", _WHERE, "unreadable",
                     f"body nests deeper than {MAX_DEPTH}")], raw
    if isinstance(doc, dict):
        return [_entry_row(base, 0, doc)], raw
    if not isinstance(doc, list):
        return [_cnl(base, "a reported row object or a list of them", _WHERE, "name_not_found",
                     f"body is a JSON {type(doc).__name__}")], raw
    if not doc:
        return [_cnl(base, "a reported row", _WHERE, "empty", "the body lists no rows")], raw
    rows = []
    for i, entry in enumerate(doc):
        if i >= MAX_ROWS:
            rows.append(_cnl(_copy(base), "every row in the body", _WHERE, "bounded",
                             f"more than {MAX_ROWS} rows; the rest were not read"))
            break
        rows.append(_entry_row(base, i, entry))
    return rows, raw


def _clean_verified(r: dict) -> bool:
    w = r.get("vendor_word")
    return (isinstance(w, str) and TABLE.get(w.strip().casefold()) == VERIFIED
            and r.get("mapping") == {"rule": "table"} and _hex64(r.get("input_sha256")) is not None
            and "could_not_look" not in r
            and not (isinstance(r.get("reported"), dict) and r["reported"].get("reason")))


def _seal(rows: list, raw: bytes | None) -> list:
    """The one final step: every row is this generic adapter's, unsigned, reported by
    the sender. Only a clean VERIFIED word on a pinned input can stay VERIFIED; a
    BROKEN stays BROKEN."""
    for r in rows:
        r["vendor"] = {"name": VENDOR, "adapter_version": ADAPTER_VERSION}
        r["attestation"] = {"status": ATTESTATION_NONE, "checked_by_us": False, "claimed": None}
        r.setdefault("input_sha256", None)
        r.setdefault("at", None)
        if not isinstance(r.get("reported"), dict):
            r["reported"] = _blank(None)
        if r.get("relayed_verdict") == VERIFIED and not _clean_verified(r):
            _cnl(r, "a VERIFIED word on a pinned input", _WHERE, "unreadable",
                 f"{r.get('vendor_word')!r} cannot relay as VERIFIED from this row")
        r["signed_by_vendor"] = False
        r["standing"] = STANDING
    return rows


def ingest(raw: Any, *, received_at: str | None = None) -> list:
    """A sender's reported row (one JSON object) or a JSON array of them, as the
    bytes you hold -> a list of relayed rows, one per entry. Never raises on the
    body; an unreadable body is one COULD NOT LOOK row. Every row is
    signed_by_vendor False, standing reported_by_sender."""
    at = received_at if isinstance(received_at, str) else _now_iso()
    data = None
    try:
        rows, data = _read(raw, at)
    except Exception as e:  # noqa: BLE001 - never a traceback on what is sent
        rows = [_cnl(REPORTED.base_row(data, at), "a reported row", _WHERE, "unreadable",
                     f"the adapter failed: {type(e).__name__}")]
    return _seal(rows, data)


def rollup(rows: Any) -> dict:
    """One word over a list of this adapter's rows. Never VERIFIED: rows the sender
    reported, unsigned, are not a check of our own (COULD NOT LOOK). BROKEN when at
    least one row is a relayed BROKEN. A row that is not this adapter's counts as
    COULD NOT LOOK. No bare `verdict` key, as on the rows."""
    counts = {VERIFIED: 0, BROKEN: 0, COULD_NOT_LOOK: 0}
    out = {"relayed_verdict": COULD_NOT_LOOK, "standing": STANDING, "signed_by_vendor": False,
           "counts": counts}
    for r in rows if isinstance(rows, list) else ():
        ok = (isinstance(r, dict) and r.get("kind") == ROW_KIND
              and isinstance(r.get("vendor"), dict) and r["vendor"].get("name") == VENDOR)
        v = r.get("relayed_verdict") if ok else COULD_NOT_LOOK
        counts[v if v in counts else COULD_NOT_LOOK] += 1
    if counts[BROKEN]:
        out["relayed_verdict"] = BROKEN
        out["reason"] = "the sender reported at least one BROKEN (relayed, unsigned)"
        return out
    out["reason"] = ("no relayed BROKEN; VERIFIED rows here are the sender's unsigned report, "
                     "and a rollup of reported rows is never VERIFIED by itself")
    out.update(could_not_look("a check of our own", "rows", "missing", out["reason"]))
    return out
