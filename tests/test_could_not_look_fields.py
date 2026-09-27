"""The additive could-not-look fields: REASON_WORDS and verdict.could_not_look.

A COULD NOT LOOK result names what it looked for, where it looked, and why it
could not look as one fixed machine word. The verdict words themselves do not
move.
"""
import re

import pytest

from arcaeon import verdict as V


def test_every_reason_word_is_lowercase_snake():
    assert V.REASON_WORDS
    for word in V.REASON_WORDS:
        assert re.fullmatch(r"[a-z]+(_[a-z]+)*", word), word
    assert len(set(V.REASON_WORDS)) == len(V.REASON_WORDS)


def test_the_helper_rejects_an_unknown_word():
    with pytest.raises(ValueError):
        V.could_not_look("x", "y", "gone_fishing", "nobody home")
    with pytest.raises(ValueError):
        V.could_not_look("x", "y", "Missing", "case matters")


@pytest.mark.parametrize("word", V.REASON_WORDS)
def test_the_returned_dict_carries_all_four_keys(word):
    got = V.could_not_look("order-17", "tape.jsonl", word, "a sentence")
    assert got == {"looked_for": "order-17", "where": "tape.jsonl",
                   "reason_word": word, "reason": "a sentence"}


def test_the_verdict_words_are_unchanged():
    assert V.WORDS == ("VERIFIED", "BROKEN", "COULD NOT LOOK", "MATCHED", "MISSING",
                       "ALTERED", "NO GRADEABLE FILES", "COMPARED")


# --- reconcile carries the fields ----------------------------------------------

import json
from pathlib import Path

from arcaeon.prove import reconcile as R
from arcaeon.record.ledger import Ledger, digest_json


def _row(side, idx, **swap):
    row = {"evt": "tape_call", "tape": R.TAPE_FORMAT, "side": side, "ns": f"demo-{side}",
           "idx": idx, "tool": "echo",
           "req": digest_json({"name": "echo", "arguments": {"text": f"call {idx}"}}),
           "resp": digest_json({"result": {"content": [{"type": "text", "text": f"call {idx}"}]}}),
           "status": "ok"}
    for old, new in swap.items():       # a recorder that spells a key its own way
        row[new] = row.pop(old)
    return row


def _tape(path: Path, side: str, n: int = 3, **swap) -> Path:
    path.touch()
    lg = Ledger(path)
    for k in range(1, n + 1):
        lg.append(_row(side, k, **swap))
    return path


def _fields(r):
    d = r.to_dict()
    assert d["verdict"] == R.COULD_NOT_LOOK and r.exit_code == 3, d
    assert d["reason_word"] in V.REASON_WORDS
    assert len(d["could_not_look_detail"]) == len(d["could_not_look"])
    for det, why in zip(d["could_not_look_detail"], d["could_not_look"]):
        assert set(det) == {"looked_for", "where", "reason_word", "reason"}
        assert det["reason"] == why and det["reason_word"] in V.REASON_WORDS
    json.dumps(d)
    return d


def test_name_not_found_names_the_made_up_key_verbatim(tmp_path):
    """exori's case (Colony, 2026-09-25): an instrument read a key named `votes`
    on a platform whose key is `ballots`, and answered an honest "could not
    look" about a name that does not exist. Exit 3 was true; the sentence it
    licensed was false. Here the tool tape's recorder wrote its request digest
    under `request_digest`, a name the tape format does not have, so the key
    reconcile went looking for (`req`) is not there. The refusal must carry
    reason_word name_not_found and the looked-for name verbatim, so the made-up
    name is inside the refusal instead of hiding behind it."""
    a = _tape(tmp_path / "agent.tape.jsonl", "agent")
    t = _tape(tmp_path / "tool.tape.jsonl", "tool", req="request_digest")
    r = R.reconcile(a, t)
    d = _fields(r)
    assert d["reason_word"] == "name_not_found"
    assert d["looked_for"] == "req"
    assert "tool.tape.jsonl row 1" in d["where"]
    # the old text line is untouched
    assert d["reason"] == f"tape_b row 1 is not an {R.TAPE_FORMAT} row"
    assert r.summary == f"COULD NOT LOOK: tape_b row 1 is not an {R.TAPE_FORMAT} row"


def test_missing_tape_is_reason_word_missing(tmp_path):
    a = _tape(tmp_path / "agent.tape.jsonl", "agent")
    d = _fields(R.reconcile(a, tmp_path / "gone.jsonl"))
    assert d["reason_word"] == "missing" and d["looked_for"] == "tape_b"
    assert d["where"].endswith("gone.jsonl")


def test_both_empty_is_reason_word_empty(tmp_path):
    a, t = tmp_path / "a.jsonl", tmp_path / "t.jsonl"
    a.touch()
    t.touch()
    assert _fields(R.reconcile(a, t))["reason_word"] == "empty"


def test_a_finding_carries_the_keys_as_none(tmp_path):
    a = _tape(tmp_path / "agent.tape.jsonl", "agent", 3)
    t = _tape(tmp_path / "tool.tape.jsonl", "tool", 2)
    d = R.reconcile(a, t).to_dict()
    assert d["verdict"] == R.MISSING
    assert d["reason_word"] is None and d["looked_for"] is None
    for f in d["findings"]:
        assert {"looked_for", "where", "reason_word"} <= set(f)


# --- parity with the hosted port: the three inputs that used to raise -----------
# arcaeon-witness RELEASE_NOTES_reconcile_2026-09-23.md, "Three inputs make
# reconcile.py raise instead of answering". The hosted port answers COULD NOT
# LOOK on each; so must Python, now with a reason word a script can branch on.

def _honest(tmp: Path):
    return _tape(tmp / "agent.tape.jsonl", "agent", 5), _tape(tmp / "tool.tape.jsonl", "tool", 5)


def test_reconcile_parity_duplicate_key_then_junk(tmp_path):
    """Input (1): a line whose strict read finds a duplicate key and whose plain
    read then fails, `{"a":1,"a":2} x`. verify_file used to re-read it inside its
    except handler and the JSONDecodeError escaped."""
    a, t = _honest(tmp_path)
    with a.open("a", encoding="utf-8", newline="\n") as f:
        f.write('{"a":1,"a":2} x\n')
    d = _fields(R.reconcile(a, t))
    assert d["reason_word"] == "unreadable" and d["looked_for"] == "tape_a line 6"
    assert "[duplicate_key_unparseable]" in d["reason"]


def test_reconcile_parity_python_only_whitespace(tmp_path):
    """Input (2): a row that verifies but is wrapped in whitespace str.strip()
    removes and json.loads does not (here \x0b); _load's second read raised."""
    a, t = _honest(tmp_path)
    lines = a.read_text(encoding="utf-8").split("\n")
    lines[1] = "\x0b" + lines[1]
    a.write_bytes("\n".join(lines).encode("utf-8"))
    d = _fields(R.reconcile(a, t))
    assert d["reason_word"] == "unreadable" and d["looked_for"] == "tape_a row 2"
    assert "[whitespace_outside_json]" in d["reason"]


def test_reconcile_parity_nested_past_the_recursion_guard(tmp_path):
    """Input (3): a row nested past CPython's C recursion guard reaching
    _peek_side, which caught ValueError and not RecursionError."""
    a, t = _honest(tmp_path)
    a.write_bytes(b"[" * 100_000 + b"\n" + a.read_bytes())
    d = _fields(R.reconcile(a, t))
    assert d["reason_word"] == "unreadable" and d["looked_for"] == "tape_a line 1"
    assert "[nesting_too_deep]" in d["reason"]
