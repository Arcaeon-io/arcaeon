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

THE CRITERION (NP-12 point four). The sentence is frozen and hashed BEFORE any
reading is taken. A `criterion` row carries the sentence's sha256 and its text.
A reading must cite a criterion_sha256 that appears EARLIER in its own ledger;
a reading that cites one that does not is a reading of an unknown sentence,
and `load_readings` answers COULD NOT LOOK (`reason_word: "name_not_found"`)
rather than line it up. A revision is a NEW, dated criterion row (optionally
naming the one it `supersedes`); the old row stays where it is.

Stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as _v
from arcaeon.record.ledger import Ledger
from arcaeon.record.row import loads as _loads

__all__ = ["READING_FORMAT", "CRITERION_FORMAT", "READING_WORDS", "READER_FIELDS",
           "ReadingError", "UnknownCriterionError", "sha256_text", "build_reading",
           "write_reading", "build_criterion", "freeze_criterion", "normalize_criterion",
           "load_readings", "criterion_main"]

READING_FORMAT = "arcaeon-reading/1"
CRITERION_FORMAT = "arcaeon-criterion/1"

#: The only three answers a reading may carry. Anything else is refused at
#: build time: a word a comparer cannot line up is not a reading.
READING_WORDS = ("yes", "no", "undetermined")

#: The reader object's keys. `id` and `provider` must be non-empty strings;
#: `model` and `endpoint_host` are strings or null (a person has neither).
READER_FIELDS = ("id", "provider", "model", "endpoint_host")

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


class ReadingError(ValueError):
    """A reading or criterion row that cannot be built as asked."""


class UnknownCriterionError(ReadingError):
    """A reading cites a criterion_sha256 that is not earlier in its ledger."""


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


def _criteria_in(path: Path) -> set[str]:
    return {r.get("criterion_sha256") for r in Ledger(path)
            if isinstance(r, dict) and r.get("evt") == "criterion"}


def write_reading(ledger: str | Path, row: dict, *, check_criterion: bool = True) -> str:
    """Append a built reading row to `ledger`; returns its chain hash.

    With `check_criterion` (the default) the row is refused unless its
    criterion_sha256 was frozen earlier in the same ledger.
    """
    if row.get("evt") != "reading" or row.get("format") != READING_FORMAT:
        raise ReadingError("not a reading row; build it with build_reading()")
    if row.get("reading") not in READING_WORDS:
        raise ReadingError(f"unknown reading word {row.get('reading')!r}")
    path = Path(ledger)
    if check_criterion and row.get("criterion_sha256") not in _criteria_in(path):
        raise UnknownCriterionError(
            f"criterion {row.get('criterion_sha256')} is not frozen earlier in {path}; "
            "freeze it first (second-read criterion FILE --ledger L)")
    return Ledger(path).append(row)


def normalize_criterion(text: str) -> str:
    """The frozen form of a criterion: surrounding whitespace stripped, CRLF
    folded to LF. Everything inside is kept byte for byte."""
    return text.replace("\r\n", "\n").replace("\r", "\n").strip()


def build_criterion(text: str, *, supersedes: str | None = None, ts: str | None = None) -> dict:
    """Build one `criterion` row for the sentence `text` (normalized first)."""
    if not isinstance(text, str):
        raise ReadingError("criterion text must be a string")
    sentence = normalize_criterion(text)
    if not sentence:
        raise ReadingError("criterion text is empty")
    _hex64("supersedes", supersedes, optional=True)
    row: dict[str, Any] = {"evt": "criterion", "format": CRITERION_FORMAT,
                           "criterion_sha256": sha256_text(sentence), "text": sentence}
    if supersedes is not None:
        row["supersedes"] = supersedes
    row["ts"] = ts or _now_iso()
    return row


def freeze_criterion(ledger: str | Path, text: str, *, supersedes: str | None = None) -> dict:
    """Append a criterion row to `ledger`. Returns the row (with its chain).

    A revision is a new row; `supersedes` may name the old sha256, which must
    already be frozen in this ledger. Nothing earlier is touched.
    """
    path = Path(ledger)
    if supersedes is not None and supersedes not in _criteria_in(path):
        raise UnknownCriterionError(f"supersedes {supersedes} is not a criterion in {path}")
    row = build_criterion(text, supersedes=supersedes)
    row["chain"] = Ledger(path).append(row)
    return row


def load_readings(ledger: str | Path) -> dict:
    """Read every reading in a ledger, checking each cites an earlier criterion.

    Returns `{"ok": True, "readings": [...], "criteria": {sha: line}}` where
    each reading is the row plus `line` (1-based, the numbering verify uses).
    On a reading that cannot be lined up it returns `{"ok": False, ...}` with
    the COULD NOT LOOK keys (`looked_for`, `where`, `reason_word`, `reason`)
    and `line`. It does not check the chain; the comparer does that first.
    """
    path = Path(ledger)
    where = str(path)
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
    except FileNotFoundError:
        return {"ok": False, "line": None, **_v.could_not_look(
            "a readings ledger", where, "missing", f"{where} does not exist")}
    except OSError as e:
        return {"ok": False, "line": None, **_v.could_not_look(
            "a readings ledger", where, "unreadable", f"{where} could not be read [{e}]")}
    criteria: dict[str, int] = {}
    readings: list[dict] = []
    for i, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = _loads(raw)
        except ValueError:
            continue  # the chain check names unparseable lines; not ours to judge
        if not isinstance(obj, dict):
            continue
        evt = obj.get("evt")
        if evt == "criterion":
            sha = obj.get("criterion_sha256")
            if isinstance(sha, str) and _HEX64.match(sha):
                criteria.setdefault(sha, i)
            continue
        if evt != "reading":
            continue
        try:
            _check_row(obj)
        except ReadingError as e:
            return {"ok": False, "line": i, **_v.could_not_look(
                "a well-formed reading row", f"{where} line {i}", "unreadable",
                f"{where} line {i} is not a readable {READING_FORMAT} row [{e}]")}
        if obj["criterion_sha256"] not in criteria:
            return {"ok": False, "line": i, **_v.could_not_look(
                f"criterion {obj['criterion_sha256']}", f"{where} line {i}", "name_not_found",
                f"{where} line {i} cites criterion {obj['criterion_sha256'][:12]}..., "
                "which is not frozen earlier in that ledger")}
        readings.append({**obj, "line": i})
    return {"ok": True, "readings": readings, "criteria": criteria}


def _check_row(obj: dict) -> None:
    if obj.get("format") != READING_FORMAT:
        raise ReadingError(f"format is {obj.get('format')!r}, expected {READING_FORMAT!r}")
    if obj.get("reading") not in READING_WORDS:
        raise ReadingError(f"unknown reading word {obj.get('reading')!r}")
    if not isinstance(obj.get("claim_id"), str) or not obj["claim_id"]:
        raise ReadingError("claim_id missing")
    _hex64("claim_sha256", obj.get("claim_sha256"))
    _hex64("criterion_sha256", obj.get("criterion_sha256"))
    _reader(obj.get("reader"))
    nm = obj.get("near_match_id")
    if nm is not None and (not isinstance(nm, str) or not nm):
        raise ReadingError("near_match_id must be a non-empty string")


def criterion_main(argv: list[str] | None = None) -> int:
    """`second-read criterion FILE --ledger L [--supersedes SHA] [--json]`.

    Exit 0 the criterion row was written, 2 bad usage (no file, empty file,
    unknown --supersedes).
    """
    import json
    p = argparse.ArgumentParser(prog="arcaeon second-read criterion",
                                description="freeze a criterion sentence into a readings ledger")
    p.add_argument("file", help="a text file holding the criterion sentence")
    p.add_argument("--ledger", required=True, help="the readings ledger to append to")
    p.add_argument("--supersedes", default=None, help="sha256 of the criterion this revises")
    p.add_argument("--json", action="store_true", help="print the row as JSON")
    args = p.parse_args(argv)
    try:
        text = Path(args.file).read_text(encoding="utf-8")
    except OSError as e:
        print(f"arcaeon second-read criterion: cannot read {args.file} [{e}]", file=sys.stderr)
        return _v.EXIT_USAGE
    try:
        row = freeze_criterion(args.ledger, text, supersedes=args.supersedes)
    except ReadingError as e:
        print(f"arcaeon second-read criterion: {e}", file=sys.stderr)
        return _v.EXIT_USAGE
    if args.json:
        print(json.dumps(row, ensure_ascii=False, sort_keys=True))
    else:
        print(f"criterion frozen: {row['criterion_sha256']}")
    return _v.EXIT_GOOD
