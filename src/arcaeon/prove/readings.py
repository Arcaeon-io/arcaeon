# SPDX-License-Identifier: MIT
"""arcaeon.prove.readings: the reading row, and the frozen criterion it cites.

A READING is one reader's answer to one frozen sentence about one claim:
`yes`, `no` or `undetermined`. It is not a finding about the claim. Two
readers who answer the same way have read one sentence the same way; that
measures how ambiguous the sentence is for those readers, and nothing about
whether the claim holds. No output of this module says otherwise.

THE ROW (format `arcaeon-reading/1`), one JSON object per ledger line:

    evt              "reading"
    format           "arcaeon-reading/1"
    claim_id         the caller's id for the claim (a non-empty string)
    claim_sha256     sha256 hex of the claim text as the reader saw it
    criterion_sha256 sha256 hex of the frozen criterion sentence (see below)
    reader           {id, provider, model, endpoint_host}
    reading          one of READING_WORDS
    near_match_id    optional: the id the reader said this claim almost matched
    rationale_sha256 sha256 hex of the reader's rationale, or null if none given
    rationale        the rationale text, ONLY when keep_text=True (--keep-text)
    prompt_sha256    sha256 hex of the exact prompt sent, or null (a person, or
                     an agent filing its own reading, sent no prompt of ours)
    ts               ISO-8601 UTC time the reading was taken

Rows go through the ordinary ledger append (`arcaeon.record.ledger.Ledger`),
so they are chained and `arcaeon verify` checks them like any other row.

Stdlib only.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arcaeon.record.ledger import Ledger

__all__ = ["READING_FORMAT", "READING_WORDS", "READER_FIELDS", "ReadingError",
           "sha256_text", "build_reading", "write_reading"]

READING_FORMAT = "arcaeon-reading/1"

#: The only three answers a reading may carry. Anything else is refused at
#: build time: a word a comparer cannot line up is not a reading.
READING_WORDS = ("yes", "no", "undetermined")

#: The reader object's keys. `id` and `provider` must be non-empty strings;
#: `model` and `endpoint_host` are strings or null (a person has neither).
READER_FIELDS = ("id", "provider", "model", "endpoint_host")

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


class ReadingError(ValueError):
    """A reading or criterion row that cannot be built as asked."""


def sha256_text(text: str) -> str:
    """sha256 hex of a string's UTF-8 bytes, exactly as given."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hex64(name: str, value: Any, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not _HEX64.match(value):
        raise ReadingError(f"{name} must be 64 lowercase hex characters (a sha256), got {value!r}")
    return value


def _reader(reader: Any) -> dict:
    if not isinstance(reader, dict):
        raise ReadingError("reader must be an object with keys " + ", ".join(READER_FIELDS))
    unknown = set(reader) - set(READER_FIELDS)
    if unknown:
        raise ReadingError(f"reader has unknown keys {sorted(unknown)}; expected {READER_FIELDS}")
    out = {}
    for key in READER_FIELDS:
        val = reader.get(key)
        if key in ("id", "provider"):
            if not isinstance(val, str) or not val.strip():
                raise ReadingError(f"reader.{key} must be a non-empty string")
        elif val is not None and not isinstance(val, str):
            raise ReadingError(f"reader.{key} must be a string or null")
        out[key] = val
    return out


def build_reading(*, claim_id: str, criterion_sha256: str, reader: dict, reading: str,
                  claim_text: str | None = None, claim_sha256: str | None = None,
                  near_match_id: str | None = None, rationale: str | None = None,
                  keep_text: bool = False, prompt_sha256: str | None = None,
                  ts: str | None = None) -> dict:
    """Build one `arcaeon-reading/1` row. Raises ReadingError on anything off.

    Give the claim as `claim_text` (hashed here) or as `claim_sha256`; if both
    are given they must agree. The rationale text is kept in the row only with
    `keep_text=True`; its digest is kept either way.
    """
    if reading not in READING_WORDS:
        raise ReadingError(f"unknown reading word {reading!r}; expected one of {READING_WORDS}")
    if not isinstance(claim_id, str) or not claim_id.strip():
        raise ReadingError("claim_id must be a non-empty string")
    if claim_text is not None:
        if not isinstance(claim_text, str):
            raise ReadingError("claim_text must be a string")
        digest = sha256_text(claim_text)
        if claim_sha256 is not None and claim_sha256 != digest:
            raise ReadingError("claim_sha256 does not match the sha256 of claim_text")
        claim_sha256 = digest
    if claim_sha256 is None:
        raise ReadingError("give the claim as claim_text or claim_sha256")
    _hex64("claim_sha256", claim_sha256)
    _hex64("criterion_sha256", criterion_sha256)
    _hex64("prompt_sha256", prompt_sha256, optional=True)
    if near_match_id is not None and (not isinstance(near_match_id, str) or not near_match_id):
        raise ReadingError("near_match_id must be a non-empty string or omitted")
    if rationale is not None and not isinstance(rationale, str):
        raise ReadingError("rationale must be a string")
    row: dict[str, Any] = {
        "evt": "reading",
        "format": READING_FORMAT,
        "claim_id": claim_id,
        "claim_sha256": claim_sha256,
        "criterion_sha256": criterion_sha256,
        "reader": _reader(reader),
        "reading": reading,
    }
    if near_match_id is not None:
        row["near_match_id"] = near_match_id
    row["rationale_sha256"] = sha256_text(rationale) if rationale is not None else None
    if keep_text and rationale is not None:
        row["rationale"] = rationale
    row["prompt_sha256"] = prompt_sha256
    row["ts"] = ts or _now_iso()
    return row


def write_reading(ledger: str | Path, row: dict) -> str:
    """Append a built reading row to `ledger`; returns its chain hash."""
    if row.get("evt") != "reading" or row.get("format") != READING_FORMAT:
        raise ReadingError("not a reading row; build it with build_reading()")
    if row.get("reading") not in READING_WORDS:
        raise ReadingError(f"unknown reading word {row.get('reading')!r}")
    path = Path(ledger)
    return Ledger(path).append(row)
