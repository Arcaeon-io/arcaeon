# SPDX-License-Identifier: MIT
"""arcaeon.words: every verdict word as one plain sentence (K101).

One mapping, shared by the dashboard pages and anything else that shows a
verdict to a person. The words themselves live in arcaeon.verdict; this
module only says what each one tells you, in the terms of docs/WORDS.md.
Every word in arcaeon.verdict has a sentence here, and tests/test_words.py
fails when a new word arrives without one (`missing()`).

`tone(word)` is the display state a page gives the word: "ok" for exit 0,
"bad" for exit 1, "unknown" for everything else. COULD NOT LOOK, NO
GRADEABLE FILES and any word this table cannot read are "unknown", never
"ok": a look that did not finish is never shown green.
"""
from __future__ import annotations

from arcaeon import verdict as V

__all__ = ["SENTENCES", "REASON_SENTENCES", "EXIT_SENTENCES", "UNKNOWN_WORD",
           "sentence", "reason_sentence", "tone", "tone_for_exit", "missing"]

SENTENCES = {
    V.VERIFIED: ("Every row was checked and the chain holds from the first row to the "
                 "last. Rows cut off the end need a pin to catch."),
    V.BROKEN: ("A row no longer matches the chain. Something changed the record after "
               "it was written; treat what follows that line as unconfirmed."),
    V.COULD_NOT_LOOK: ("Nothing wrong was found, but not everything could be checked. "
                       "This is not a pass; find out what was not looked at first."),
    V.COULD_NOT_LOOK_TOKEN: ("Nothing wrong was found, but not everything could be "
                             "checked. This is not a pass; find out what was not "
                             "looked at first."),
    V.MATCHED: ("The two records agree on every step both were expected to hold. "
                "Agreement is what this shows, not that either record is right."),
    V.MISSING: ("A step one record holds has no partner on the other, or rows a pin "
                "once counted are gone."),
    V.ALTERED: ("Both records hold the step, but its contents differ between them. "
                "A person has to decide which one is right."),
    V.NO_GRADEABLE_FILES: ("The grader found no file it knows how to read, so nothing "
                           "was graded and nothing was cleared."),
    V.COMPARED: ("Both readings ledgers were read and lined up, claim by claim. It "
                 "says the readers were compared, not that any claim holds."),
}

#: The sentence for a word that is not in the table: never a pass.
UNKNOWN_WORD = ("This answer carries a word arcaeon does not know, so it is treated as "
                "COULD NOT LOOK: it is not a pass.")

REASON_SENTENCES = {
    "unreadable": "it was there but could not be read",
    "missing": "it was not there at all",
    "empty": "it was there and held nothing to check",
    "name_not_found": "it was read, but the name the check needed was not in it",
    "bounded": "only part of it could be checked",
    "network": "the request to the hosted witness never completed",
    "redirect_refused": "the endpoint redirected elsewhere and was not followed",
}

#: For answers that carry an exit code but no verdict word of their own
#: (the journal's OK, BAD FINDING, BAD USAGE).
EXIT_SENTENCES = {
    V.EXIT_GOOD: "The command did what it said.",
    V.EXIT_BAD: "The check found something wrong.",
    V.EXIT_USAGE: "The command could not start on what it was given.",
    V.EXIT_COULD_NOT_LOOK: SENTENCES[V.COULD_NOT_LOOK],
}


def _known_words() -> set[str]:
    return set(V.WORDS) | set(V.EXIT_BY_WORD) | set(V.COMPARE_WORDS)


def missing() -> list[str]:
    """Verdict words arcaeon.verdict knows that have no sentence here."""
    return sorted(w for w in _known_words() if w not in SENTENCES)


def sentence(word, exit_code=None) -> str:
    """The plain sentence for a verdict word. A word with no sentence falls
    back to its exit code's sentence, else UNKNOWN_WORD."""
    if isinstance(word, str) and word in SENTENCES:
        return SENTENCES[word]
    if isinstance(exit_code, int) and not isinstance(exit_code, bool) \
            and exit_code in EXIT_SENTENCES:
        return EXIT_SENTENCES[exit_code]
    return UNKNOWN_WORD


def reason_sentence(reason_word) -> str | None:
    return REASON_SENTENCES.get(reason_word) if isinstance(reason_word, str) else None


def tone_for_exit(exit_code) -> str:
    if exit_code == V.EXIT_GOOD and not isinstance(exit_code, bool):
        return "ok"
    if exit_code == V.EXIT_BAD and not isinstance(exit_code, bool):
        return "bad"
    return "unknown"


def tone(word, exit_code=None) -> str:
    """"ok", "bad" or "unknown" for a verdict word. A known word decides by its
    own exit code; an unknown one by `exit_code` if given, else "unknown"."""
    if isinstance(word, str) and word in SENTENCES:
        return tone_for_exit(V.exit_for(word))
    return tone_for_exit(exit_code)
