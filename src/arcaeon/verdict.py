# SPDX-License-Identifier: MIT
"""arcaeon.verdict: the words every Arcaeon check prints, and ONE exit-code table.

THE WORDS. A record check answers VERIFIED, BROKEN or COULD NOT LOOK. A
completeness check (reconcile) answers MATCHED, MISSING, ALTERED or COULD NOT
LOOK. A source grader that found nothing it can grade answers NO GRADEABLE
FILES, which is a could-not-look, not a pass.

THE EXIT CODES, the same for every `arcaeon` verb:

    0  good: VERIFIED, MATCHED, a clean grade, the command did what it said
    1  a bad finding: BROKEN, MISSING, ALTERED, a high-severity grade,
       a receipt that does not verify or carries a flagged check
    2  bad usage: the verb could not start on what it was given
    3  COULD NOT LOOK: nothing wrong was found, and not everything could be
       checked. Never a green. A CI gate that treats only 0 as green fails
       loud on it, which is the point.

Before 0.9 the old tools disagreed on 3 of these. `arcaeon-ledger verify`
already used 3 for COULD NOT LOOK, `arcaeon-ledger reconcile` used 2,
arcaeon-audit used 2, arcaeon-receipt used 4 (and 3 for a flagged citation),
and mcp-vet used 3 for NO GRADEABLE FILES but 2 for a probe that could not
connect. Their moved code still returns its old code; the `arcaeon` front
door translates it through LEGACY below. `--legacy-exit` on a verb skips the
translation for one release (0.9.x) so a CI gate wired to an old code keeps
its meaning while it is rewired; it goes away in 1.0.0.

Reconcile is the one moved module that speaks this table natively (its
EXIT_CODES come from here): `reconcile(...).exit_code` is 3 for COULD NOT
LOOK, and `arcaeon.prove.reconcile.main(argv)` honours `--legacy-exit` itself.
"""
from __future__ import annotations

__all__ = ["VERIFIED", "BROKEN", "COULD_NOT_LOOK", "MATCHED", "MISSING", "ALTERED",
           "NO_GRADEABLE_FILES", "COULD_NOT_LOOK_TOKEN", "WORDS", "EXIT_GOOD", "EXIT_BAD", "EXIT_USAGE",
           "EXIT_COULD_NOT_LOOK", "EXIT_BY_WORD", "LEGACY", "LEGACY_EXIT_FLAG",
           "exit_for", "unify", "pop_legacy_flag"]

VERIFIED = "VERIFIED"
BROKEN = "BROKEN"
COULD_NOT_LOOK = "COULD NOT LOOK"
MATCHED = "MATCHED"
MISSING = "MISSING"
ALTERED = "ALTERED"
NO_GRADEABLE_FILES = "NO GRADEABLE FILES"

#: The machine spelling reconcile's JSON (and the hosted reconcile service)
#: has always carried in its `verdict` field. Same word, same exit code.
COULD_NOT_LOOK_TOKEN = "COULD_NOT_LOOK"

#: Every verdict word, in the order a reader meets them.
WORDS = (VERIFIED, BROKEN, COULD_NOT_LOOK, MATCHED, MISSING, ALTERED, NO_GRADEABLE_FILES)

EXIT_GOOD = 0
EXIT_BAD = 1
EXIT_USAGE = 2
EXIT_COULD_NOT_LOOK = 3

#: The one table: a verdict word -> its exit code.
EXIT_BY_WORD = {
    VERIFIED: EXIT_GOOD,
    MATCHED: EXIT_GOOD,
    BROKEN: EXIT_BAD,
    MISSING: EXIT_BAD,
    ALTERED: EXIT_BAD,
    COULD_NOT_LOOK: EXIT_COULD_NOT_LOOK,
    COULD_NOT_LOOK_TOKEN: EXIT_COULD_NOT_LOOK,
    NO_GRADEABLE_FILES: EXIT_COULD_NOT_LOOK,
}

#: What each moved tool's own exit codes meant, translated into the table above.
#: Keyed by `arcaeon` verb, then by subcommand where the old tool's codes
#: differed per subcommand ("*" = every subcommand). A code not listed passes
#: through unchanged (0 and 1 already meant good and bad everywhere).
#: Reconcile is not listed: it returns this table's codes itself (2 -> 3 moved
#: inside arcaeon.prove.reconcile), so a 2 from it now means bad usage.
#: An argparse usage error (SystemExit 2) is never translated either.
LEGACY = {
    # arcaeon-audit: 2 was "the check could not complete" (verify on a
    # bounded log, export with an unreadable witness or notes, bad usage).
    "audit": {"*": {2: EXIT_COULD_NOT_LOOK}},
    # arcaeon-receipt: 2 verify failed, 3 a flagged check (cite), 4 COULD NOT
    # LOOK at one or more receipts (--batch, roster-report, archive).
    "receipt": {"*": {2: EXIT_BAD, 3: EXIT_BAD, 4: EXIT_COULD_NOT_LOOK}},
    # mcp-vet: badge 2 = path trouble (usage), 3 = NO GRADEABLE FILES,
    # 4 = a refused --sealed (the free badge printed; nothing was sealed:
    # could not look at the paid half). verify 2 = the grade did not
    # reproduce (bad). audit-verify 2 = broken chain (bad), 3 bounded.
    # probe 2 = could not connect or no command (could not look).
    "vet": {
        "badge": {4: EXIT_COULD_NOT_LOOK},
        "verify": {2: EXIT_BAD},
        "audit-verify": {2: EXIT_BAD},
        "probe": {2: EXIT_COULD_NOT_LOOK},
    },
    "badge": {"*": {4: EXIT_COULD_NOT_LOOK}},
}

LEGACY_EXIT_FLAG = "--legacy-exit"


def exit_for(word: str) -> int:
    """The exit code for a verdict word. An unknown word is COULD NOT LOOK:
    a verdict this table cannot read must never gate green."""
    return EXIT_BY_WORD.get(word, EXIT_COULD_NOT_LOOK)


def unify(verb: str, code: int, subcommand: str | None = None, *, legacy: bool = False) -> int:
    """Translate a moved tool's own exit code into the one table.

    `legacy=True` (the `--legacy-exit` flag) returns the old code untouched.
    """
    if legacy or not isinstance(code, int):
        return code
    table = LEGACY.get(verb, {})
    per = table.get(subcommand or "", table.get("*", {}))
    return per.get(code, code)


def pop_legacy_flag(argv: list[str]) -> tuple[list[str], bool]:
    """Remove `--legacy-exit` from argv; say whether it was there."""
    argv = list(argv)
    legacy = LEGACY_EXIT_FLAG in argv
    return [a for a in argv if a != LEGACY_EXIT_FLAG], legacy
