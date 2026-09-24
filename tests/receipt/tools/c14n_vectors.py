"""Generate parity test vectors for the json-c14n v1 canonicalization recipe
used by arcaeon_ledger.digest_json (see arcaeon_ledger/artefact.py):

    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
    digest    = sha256(canonical.encode("utf-8"))

Each vector carries the INPUT AS RAW JSON TEXT, never as an ambiguous Python
object. That matters most for numbers: "1" and "1.0" are the same Python value
only if you squint, but "1" is an int (canonicalizes to "1") and "1.0" is a
float (canonicalizes to "1.0") -- the literal text is what carries that intent,
so a vector's `input_text` is exactly what a JSON parser (Python's, or the
verify page's own hand-rolled one) should consume.

Run as a script to write a JSON array of vectors to a path (or stdout):

    py tools/c14n_vectors.py                 # prints to stdout
    py tools/c14n_vectors.py out.json         # writes to out.json

Imported by tests/test_verify_page_parity.py, which checks both legs:
  1. Python: arcaeon_ledger.digest_json reproduces every vector's expected
     canonical string + sha256 hex.
  2. JS: the verify page's own canonicalizer (extracted from between the
     C14N-START / C14N-END markers in web/verify-receipt.html) reproduces the
     same canonical strings, run under Node if available.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import NamedTuple


class Vector(NamedTuple):
    name: str
    input_text: str
    expected_canonical: str
    expected_sha256_hex: str

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "input_text": self.input_text,
            "expected_canonical": self.expected_canonical,
            "expected_sha256_hex": self.expected_sha256_hex,
        }


def _c14n(value) -> str:
    """The exact recipe json-c14n v1 uses to build the canonical string."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


# Strings are built from Python values via json.dumps so the escaping is
# always correct JSON, then folded into _CASES below as (name, input_text).
_STRING_VALUES = [
    ("str_empty", ""),
    ("str_ascii", "hello world"),
    # quote, backslash, newline, CR, tab, backspace, formfeed -- the only
    # escapes json.dumps(ensure_ascii=False) ever emits besides \\uXXXX for
    # control points below 0x20.
    ("str_quote_backslash_controls", 'He said "hi"\\ line1\nline2\r\ttab\bBS\fFF'),
    # café (Latin-1 supplement), 中文 (CJK, still BMP), and an emoji (astral
    # plane, needs a UTF-16 surrogate pair when escaped) -- kept as literal
    # UTF-8 characters in the JSON text (ensure_ascii=False).
    ("str_unicode_literal_utf8", "café 中文 \U0001F600"),
    # low control chars 0x01/0x1f get \u00XX escaped; DEL (0x7f) does NOT,
    # per the recipe's own documented rule (only <0x20 is escaped).
    ("str_del_not_escaped", "\x01\x1f\x7fX"),
]

_CASES: list[tuple[str, str]] = [
    ("null", "null"),
    ("bool_true", "true"),
    ("bool_false", "false"),

    # --- integers: exact literal text is preserved, arbitrary precision ---
    ("int_zero", "0"),
    ("int_neg_zero", "-0"),                 # Python: int(-0) == 0 -> "0"
    ("int_positive", "42"),
    ("int_negative", "-17"),
    ("int_big", "12345678901234567890123456789"),
    ("int_big_negative", "-12345678901234567890123456789"),

    # --- floats: Python repr() shapes, including the ones the task names ---
    ("float_one", "1.0"),
    ("float_half", "0.5"),
    ("float_neg_2_25", "-2.25"),
    ("float_1e16", "1e16"),                 # no sign, no fraction
    ("float_1e16_explicit_plus", "1e+16"),
    ("float_1e-07", "1e-07"),
    ("float_1e-7_no_pad", "1e-7"),           # same value, unpadded exponent
    ("float_neg_zero", "-0.0"),              # Python keeps the sign: "-0.0"
    ("float_boundary_fixed_1e15", "1e15"),   # last magnitude Python keeps fixed
    ("float_large_precision", "12345678901234567.0"),

    # --- containers ---
    ("empty_object", "{}"),
    ("empty_array", "[]"),
    ("nested_sort_keys", '{"B":1,"a":2,"1":3,"_":4}'),
    ("duplicate_keys_last_wins", '{"a":1,"a":2}'),
    ("nested_mixed", '[1,2,[3,4],{"z":1,"a":[true,false,null]}]'),
    # same numeric value, different literal type -- must NOT canonicalize
    # the same way ("10" vs "10.0").
    ("object_with_float_and_int", '{"i":10,"f":10.0}'),
    # a real per-adapter digest SHAPE, not just synthetic primitives: the
    # arcaeon_receipt.ballot check object (K-012), nested object + array +
    # int + float + string sibling fields together, the way it actually
    # appears inside a receipt's `checks` list.
    ("kind_ballot_check_shape", json.dumps({
        "trainee": "a. writer", "scenario": "oral_board.set1",
        "grader": "ascenvo.vcs.oral_board", "timestamp": "2026-09-12T08:00:00Z",
        "ballot": {"overall": {"score": 82, "verdict": "GOOD", "summary": "Passes."},
                  "per_answer": [{"score": 82.0, "verdict": "GOOD"}]},
        "ballot_digest": "sha256:json-c14n:v1:deadbeef",
    }, ensure_ascii=False, sort_keys=False)),
    # the remaining four adapters' real check-object shapes (A-013), so every
    # digest shape actually issued by build_receipt has a vector, not just ballot.
    ("kind_cite_check_shape", json.dumps({
        "citation": "347 U.S. 483", "normalized": ["347 U.S. 483"], "span": [41, 53],
        "status": "found", "api_status": 200, "detail": "",
        "clusters": [{"case_name": "Brown v. Board of Education", "url": "https://www.courtlistener.com/x/"}],
        "flagged": False,
    }, ensure_ascii=False, sort_keys=False)),
    ("kind_call_check_shape", json.dumps({
        "method": "POST", "url": "https://x/api", "request_digest": "sha256:raw-bytes:v1:deadbeef",
        "response_status": 200, "response_digest": "sha256:raw-bytes:v1:beadfeed",
        "payment_header_digest": "sha256:raw-bytes:v1:c0ffee", "elapsed_ms": 12,
    }, ensure_ascii=False, sort_keys=False)),
    ("kind_approval_check_shape", json.dumps({
        "action_kind": "payment", "action_digest": "sha256:json-c14n:v1:deadbeef",
        "principal": "dana", "decision": "approved", "note": "looks right",
        "proposed_at": "2026-09-12T08:00:00Z", "decided_at": "2026-09-12T08:01:00Z",
        "executed_at": "2026-09-12T08:02:00Z", "executed_digest": "sha256:json-c14n:v1:deadbeef",
        "ran": True, "executed_as_approved": True, "outcome": "",
        "rows": {"proposed": "chain1", "decided": "chain2", "executed": "chain3"},
        "flagged": False,
    }, ensure_ascii=False, sort_keys=False)),
    ("kind_authorship_check_shape", json.dumps({
        "session": "abc123", "events": 3, "first_event": "2026-09-12T08:00:00Z",
        "last_event": "2026-09-12T08:01:00Z", "typed_chars": 12, "pasted_chars": 9,
        "paste_events": 1, "deleted_chars": 0, "pasted_share": 0.429,
        "final_text_sha256": "sha256:raw-bytes:v1:deadbeef", "final_text_chars": 21,
        "rolling_hash": "deadbeefcafe", "checkpoints": [{"events": 3, "rolling": "deadbeefcafe",
        "chain": "chain1", "at": "2026-09-12T08:01:00Z"}],
    }, ensure_ascii=False, sort_keys=False)),
] + [
    (name, json.dumps(value, ensure_ascii=False)) for name, value in _STRING_VALUES
] + [
    # the same unicode string, but escaped (\uXXXX, including a surrogate
    # pair for the emoji) instead of carried as literal UTF-8 bytes -- proves
    # the \u decoder handles astral characters, not just the BMP.
    ("str_unicode_escaped", json.dumps("café 中文 \U0001F600", ensure_ascii=True)),
]


def generate_vectors() -> list[Vector]:
    out = []
    for name, text in _CASES:
        value = json.loads(text)
        canonical = _c14n(value)
        digest_hex = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        out.append(Vector(name, text, canonical, digest_hex))
    return out


def vectors_as_json(indent: int | None = 2) -> str:
    return json.dumps([v.as_dict() for v in generate_vectors()], indent=indent,
                      ensure_ascii=False)


def main(argv: list[str]) -> int:
    text = vectors_as_json()
    if argv:
        Path(argv[0]).write_text(text + "\n", encoding="utf-8")
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
