"""arcaeon.words (K101): every verdict word has one plain sentence, and a new
word without one fails here."""
from __future__ import annotations

import pytest

from arcaeon import verdict as V
from arcaeon import words as W

NEVER = ("tamper-proof", "tamperproof", "independent witness", "compliant", "guarantee",
         "ai act ready", "truth", "—", "–")


def test_every_verdict_word_has_a_sentence():
    assert W.missing() == []
    for w in V.WORDS:
        assert W.SENTENCES[w].strip(), w


def test_a_new_word_without_a_sentence_fails(monkeypatch):
    monkeypatch.setattr(V, "WORDS", V.WORDS + ("SOMETHING NEW",))
    assert W.missing() == ["SOMETHING NEW"]
    monkeypatch.setattr(V, "WORDS", V.WORDS[:-1])
    monkeypatch.setitem(V.EXIT_BY_WORD, "ANOTHER NEW", 0)
    assert W.missing() == ["ANOTHER NEW"]


def test_every_uppercase_constant_in_verdict_is_covered():
    consts = {v for k, v in vars(V).items()
              if k.isupper() and isinstance(v, str) and v.isupper()
              and not k.startswith(("EXIT_", "LEGACY"))}
    assert consts - set(W.SENTENCES) == set()


def test_every_reason_word_has_a_sentence():
    assert set(W.REASON_SENTENCES) == set(V.REASON_WORDS)


@pytest.mark.parametrize("word", list(W.SENTENCES))
def test_sentences_make_no_forbidden_claim(word):
    s = W.SENTENCES[word].lower()
    for bad in NEVER:
        assert bad not in s, (word, bad)


def test_could_not_look_is_never_ok():
    for w in (V.COULD_NOT_LOOK, V.COULD_NOT_LOOK_TOKEN, V.NO_GRADEABLE_FILES):
        assert W.tone(w) == "unknown"
    assert W.tone("NOT A WORD") == "unknown"
    assert W.tone("NOT A WORD", 0) == "ok"     # an exit-0 journal word like OK
    assert W.tone(None) == "unknown"
    assert W.tone(V.VERIFIED) == "ok" and W.tone(V.BROKEN) == "bad"
    assert W.tone(V.MATCHED) == "ok" and W.tone(V.ALTERED) == "bad"
    assert W.tone_for_exit(True) == "unknown"


def test_sentence_fallbacks():
    assert W.sentence(V.BROKEN) == W.SENTENCES[V.BROKEN]
    assert W.sentence("OK", 0) == W.EXIT_SENTENCES[0]
    assert W.sentence("NOT A WORD") == W.UNKNOWN_WORD
    assert "not a pass" in W.UNKNOWN_WORD
    assert W.reason_sentence("missing") == "it was not there at all"
    assert W.reason_sentence("nope") is None
