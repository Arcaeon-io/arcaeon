# SPDX-License-Identifier: MIT
"""reconcile never raises: three inputs that made it raise, the nesting bound,
and a fuzz over byte and Unicode mutations of an honest tape pair.

The three inputs were found by the Node port of reconcile
(arcaeon-witness lib/_reconcile_tapes.js, RELEASE_NOTES_reconcile_2026-09-23.md,
"Three inputs make reconcile.py raise instead of answering"). On each one the
port answers COULD NOT LOOK and names the row and the cause; so does this
module now, in the port's words as far as they are true here.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

import arcaeon.prove.reconcile as R
from arcaeon.record.ledger import Ledger, digest_json


def _row(side, idx):
    rq = digest_json({"name": "echo", "arguments": {"text": f"call {idx}"}})
    rs = digest_json({"result": {"content": [{"type": "text", "text": f"call {idx}"}]}})
    return {"evt": "tape_call", "tape": R.TAPE_FORMAT, "side": side, "ns": f"demo-{side}",
            "idx": idx, "tool": "echo", "req": rq, "resp": rs, "status": "ok"}


def _tape(path: Path, side: str, n: int = 5) -> Path:
    path.touch()
    lg = Ledger(path)
    for k in range(1, n + 1):
        lg.append(_row(side, k))
    return path


def _honest(tmp: Path, n: int = 5) -> tuple[Path, Path]:
    return _tape(tmp / "agent.tape.jsonl", "agent", n), _tape(tmp / "tool.tape.jsonl", "tool", n)


def _cnl(r, *parts):
    assert r.verdict == R.COULD_NOT_LOOK, r.to_dict()
    assert r.exit_code == 3   # arcaeon 0.9: COULD NOT LOOK moved 2 -> 3 (arcaeon.verdict)
    for p in parts:
        assert p in r.reason, (p, r.reason)
    assert r.reason in r.could_not_look
    json.dumps(r.to_dict())   # the answer is always serializable


# -- (1) a duplicate key, then junk -------------------------------------------

def test_duplicate_key_then_trailing_junk_is_could_not_look(tmp_path):
    """Before the fix reconcile.py raised here, out of verify_file's except handler:

        arcaeon_ledger/__init__.py, in verify_file
            obj = _loads_strict(raw)
        arcaeon_ledger.DuplicateKeyError: duplicate key 'a'
        During handling of the above exception, another exception occurred:
        arcaeon_ledger/reconcile.py, in _load
            res = verify_file(t.path, strict=True)
        arcaeon_ledger/__init__.py, in verify_file
            obj = _loads(raw)
        json.decoder.JSONDecodeError: Extra data: line 1 column 15 (char 14)
    """
    a, t = _honest(tmp_path)
    with a.open("a", encoding="utf-8", newline="\n") as f:
        f.write('{"a":1,"a":2} x\n')
    r = R.reconcile(a, t)
    _cnl(r, "tape_a line 6 holds a duplicate key and does not parse", "duplicate_key_unparseable")
    # the other way round names the other label
    _cnl(R.reconcile(t, a), "tape_b line 6 holds a duplicate key")


def test_duplicate_key_that_parses_is_still_altered(tmp_path):
    """Control: a duplicate key on a line that DOES parse stays a named break
    (ALTERED), as before. Only the raise became COULD NOT LOOK."""
    a, t = _honest(tmp_path)
    with a.open("a", encoding="utf-8", newline="\n") as f:
        f.write('{"a":1,"a":2}\n')
    r = R.reconcile(a, t)
    assert r.verdict == R.ALTERED and "duplicate key" in r.reason


# -- (2) whitespace str.strip() removes and json.loads does not ---------------

@pytest.mark.parametrize("ws", ["\x0b", "\x0c", "\x1c", "\x1f", "\x85", "\xa0", " ", "　"])
@pytest.mark.parametrize("where", ["lead", "trail"])
def test_row_wrapped_in_python_only_whitespace_is_could_not_look(tmp_path, ws, where):
    """Before the fix reconcile.py raised on the second read of a row that verified:

        arcaeon_ledger/reconcile.py, in _load
            row = json.loads(raw)
        json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)

    (the trailing variant: "Extra data: line 1 column 392 (char 391)"). verify_file strips each line with
    str.strip(), which removes these; _load then read the UNSTRIPPED line.
    """
    a, t = _honest(tmp_path)
    lines = a.read_text(encoding="utf-8").split("\n")
    lines[1] = ws + lines[1] if where == "lead" else lines[1] + ws
    a.write_bytes("\n".join(lines).encode("utf-8"))
    r = R.reconcile(a, t)
    _cnl(r, "tape_a row 2 verifies but does not read a second time", "whitespace_outside_json")


# -- (3) nesting past CPython's recursion guard, and the 512 bound ------------

def test_row_nested_past_the_recursion_guard_is_could_not_look(tmp_path):
    """Before the fix reconcile.py raised in _peek_side, which caught ValueError only:

        arcaeon_ledger/reconcile.py, in _load
            t.side = _peek_side(t.path)
        arcaeon_ledger/reconcile.py, in _peek_side
            row = json.loads(raw)
        RecursionError: Stack overflow (used 2912 kB) while decoding a JSON array from a unicode string

    (Python 3.14.3 / Windows wording; older CPythons say "maximum recursion
    depth exceeded while decoding a JSON array from a unicode string".)
    """
    a, t = _honest(tmp_path)
    # FIRST, so _peek_side reaches it before any row that names a side
    a.write_bytes(b"[" * 100_000 + b"\n" + a.read_bytes())
    r = R.reconcile(a, t)
    _cnl(r, "tape_a line 1 is nested deeper than 512 levels", "nesting_too_deep")


def test_peek_side_survives_recursion_error_itself(tmp_path):
    """Belt and braces: _peek_side on its own does not raise on a deep line."""
    p = tmp_path / "deep.jsonl"
    p.write_text("[" * 100_000 + "\n" + json.dumps({"side": "tool"}) + "\n", encoding="utf-8")
    assert R._peek_side(p) == "tool"


@pytest.mark.parametrize("depth,deep", [(512, False), (513, True)])
def test_nesting_is_bounded_at_512(tmp_path, depth, deep):
    """513 levels is COULD NOT LOOK (nesting_too_deep), as in the Node port;
    512 is read as before (a bare array is not a row: ALTERED)."""
    a, t = _honest(tmp_path)
    with a.open("a", encoding="utf-8", newline="\n") as f:
        f.write("[" * depth + "]" * depth + "\n")
    r = R.reconcile(a, t)
    if deep:
        _cnl(r, "tape_a line 6 is nested deeper than 512 levels", "nesting_too_deep")
    else:
        assert r.verdict == R.ALTERED and "not a JSON object" in r.reason


def test_nesting_counts_objects_and_ignores_brackets_in_strings(tmp_path):
    a, t = _honest(tmp_path)
    inside = json.dumps({"s": "[" * 2000})           # brackets in a string are not nesting
    deep_obj = '{"k":' * 513 + "1" + "}" * 513        # objects count
    with a.open("a", encoding="utf-8", newline="\n") as f:
        f.write(inside + "\n" + deep_obj + "\n")
    r = R.reconcile(a, t)
    _cnl(r, "tape_a line 7 is nested deeper than 512 levels", "nesting_too_deep")


def test_nesting_after_a_syntax_error_is_not_counted(tmp_path):
    """The bound counts what the parser opened before it stopped: a line that is
    already unparseable at column 1 is a plain break, not nesting_too_deep."""
    a, t = _honest(tmp_path)
    with a.open("a", encoding="utf-8", newline="\n") as f:
        f.write("x" + "[" * 600 + "\n")
    r = R.reconcile(a, t)
    assert r.verdict == R.ALTERED and "unparseable" in r.reason


def test_first_unreadable_line_wins(tmp_path):
    """Like the port: the first line (in file order) that cannot be looked at names the reason."""
    a, t = _honest(tmp_path)
    with a.open("a", encoding="utf-8", newline="\n") as f:
        f.write("[" * 600 + "]" * 600 + "\n" + '{"a":1,"a":2} x\n')
    _cnl(R.reconcile(a, t), "line 6 is nested deeper", "nesting_too_deep")


# -- never raises -------------------------------------------------------------

_JUNK = ["\x00", "\x0b", "\x85", " ", "　", "\ud800", "﻿", "\U0001f600",
         "{", "}", "[", "]", '"', "\\", ",", ":", "\r", "\n", "1e999", "NaN", "-0",
         '"a":1,"a":2', "9" * 4400, "[" * 700, "[" * 20_000, "true", "null", "é"]


def _mutate(rng: random.Random, data: bytes) -> bytes:
    b = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        op = rng.randrange(7)
        pos = rng.randrange(len(b) + 1) if b else 0
        if op == 0 and b:                         # flip a byte
            b[min(pos, len(b) - 1)] = rng.randrange(256)
        elif op == 1:                             # insert random bytes
            b[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        elif op == 2:                             # insert a Unicode / JSON-shaped fragment
            s = rng.choice(_JUNK)
            b[pos:pos] = s.encode("utf-8", "surrogatepass")
        elif op == 3 and b:                       # delete a span
            del b[pos:pos + rng.randint(1, 40)]
        elif op == 4:                             # truncate
            del b[pos:]
        elif op == 5:                             # duplicate a line
            lines = bytes(b).split(b"\n")
            k = rng.randrange(len(lines))
            lines.insert(k, lines[k])
            b = bytearray(b"\n".join(lines))
        else:                                     # wrap a line in odd whitespace
            lines = bytes(b).split(b"\n")
            k = rng.randrange(len(lines))
            ws = rng.choice(["\x0b", "\x0c", "\x85", "\xa0", " ", "　", " ", "\t"]).encode()
            lines[k] = ws + lines[k] + ws
            b = bytearray(b"\n".join(lines))
    return bytes(b)


def test_fuzz_500_mutations_always_answer(tmp_path):
    """500 seeded byte and Unicode mutations of an honest pair (one side, the
    other, or both): every one returns a verdict dict with a known verdict and
    its exit code, and none reaches the internal-error fence (that fence exists
    so a user never sees a traceback; a test that hit it would be a bug here)."""
    a, t = _honest(tmp_path, 6)
    A, T = a.read_bytes(), t.read_bytes()
    rng = random.Random(20260923)
    pa, pt = tmp_path / "fa.jsonl", tmp_path / "ft.jsonl"
    seen = {}
    for i in range(500):
        which = i % 3
        pa.write_bytes(_mutate(rng, A) if which != 1 else A)
        pt.write_bytes(_mutate(rng, T) if which != 0 else T)
        r = R.reconcile(pa, pt)
        d = r.to_dict()
        assert isinstance(d, dict)
        assert d["verdict"] in R.EXIT_CODES and d["exit_code"] == R.EXIT_CODES[d["verdict"]]
        assert "internal_error" not in d["reason"], (i, d["reason"])
        json.dumps(d)
        seen[d["verdict"]] = seen.get(d["verdict"], 0) + 1
    # the fuzz reaches more than one answer, so it is not trivially one branch
    assert len(seen) >= 3, seen


def test_deep_pin_file_is_could_not_look_not_the_fence(tmp_path):
    """A pin file nested past the C recursion guard: pin unreadable, not a raise."""
    a, t = _honest(tmp_path)
    pin = tmp_path / "pin.json"
    pin.write_text("[" * 100_000, encoding="utf-8")
    r = R.reconcile(a, t, pin_path=pin)
    _cnl(r, "pin unreadable", "[nesting_too_deep]")


def test_internal_error_fence_answers_could_not_look(tmp_path, monkeypatch):
    """If something inside reconcile raises anyway, the answer is COULD NOT LOOK
    naming the exception type, never a traceback and never a green."""
    a, t = _honest(tmp_path)

    def boom(*_a, **_k):
        raise KeyError("x")
    monkeypatch.setattr(R, "_align", boom)
    r = R.reconcile(a, t)
    _cnl(r, "[internal_error]", "KeyError")
    assert "'x'" not in r.reason   # the exception's message (possibly tape bytes) is not echoed
