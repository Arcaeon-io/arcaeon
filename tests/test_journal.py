"""arcaeon.journal: one JSON line per verb run, hash-only targets, never in the way."""
import hashlib
import json
import os

import pytest

from arcaeon import journal


@pytest.fixture
def home(tmp_path, monkeypatch):
    d = tmp_path / "arc_home"
    monkeypatch.setenv("ARCAEON_HOME", str(d))
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)
    return d


def _rows(home):
    return [json.loads(x) for x in (home / "activity.jsonl").read_text(encoding="utf-8").splitlines()]


def test_append_writes_one_line(home):
    assert journal.append("verify", "VERIFIED", 0, "a.jsonl") is True
    rows = _rows(home)
    assert len(rows) == 1
    r = rows[0]
    assert r["verb"] == "verify" and r["word"] == "VERIFIED" and r["exit"] == 0
    assert set(r) == {"t", "verb", "word", "exit", "target"}
    assert r["t"].endswith("Z")


def test_target_is_the_sha256_of_the_normalized_path(home):
    journal.append("verify", None, 0, "a.jsonl")
    journal.append("verify", None, 3, os.path.join(".", "a.jsonl"))
    rows = _rows(home)
    want = hashlib.sha256(os.path.normcase(os.path.abspath("a.jsonl")).encode()).hexdigest()
    assert rows[0]["target"] == rows[1]["target"] == want


def test_no_target_is_null(home):
    journal.append("credits", None, 0)
    journal.append("dedup", None, 0, "-")
    assert [r["target"] for r in _rows(home)] == [None, None]


def test_word_defaults_from_the_exit_code(home):
    journal.append("verify", None, 1, "x")
    journal.append("reconcile", None, 0, "x")
    journal.append("log", None, 3, "x")
    journal.append("log", None, 2, "x")
    assert [r["word"] for r in _rows(home)] == ["BROKEN", "MATCHED", "COULD NOT LOOK", "BAD USAGE"]


def test_default_home_is_dot_arcaeon(monkeypatch, tmp_path):
    monkeypatch.delenv("ARCAEON_HOME", raising=False)
    monkeypatch.setattr(journal.Path, "home", classmethod(lambda cls: tmp_path))
    assert journal.path() == tmp_path / ".arcaeon" / "activity.jsonl"


def test_read_skips_junk_lines(home):
    journal.append("verify", None, 0, "x")
    with open(home / "activity.jsonl", "a", encoding="utf-8") as f:
        f.write("not json\n[1,2]\n\n")
    journal.append("pin", None, 0, "x")
    assert [r["verb"] for r in journal.read()] == ["verify", "pin"]


def test_read_missing_file_is_empty(home):
    assert journal.read() == []
