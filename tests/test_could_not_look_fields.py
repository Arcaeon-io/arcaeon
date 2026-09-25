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
                       "ALTERED", "NO GRADEABLE FILES")
