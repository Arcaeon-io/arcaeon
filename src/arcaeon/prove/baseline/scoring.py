"""Per-item scoring: exact_match, numeric_tolerance, calibration.

Three scoring types, frozen shapes (arcaeon-baseline:scoring:v1). A probe's
`scoring` dict names its `type`; everything else here is dispatch on that.

CALIBRATION IS THE INTERESTING ONE. The correct behavior on an unanswerable
item is honest abstention, not a guess — and the correct behavior on an
answerable item is still answering, not reflexive "I don't know." Score it
naively (abstain always safe) and the optimal strategy degenerates to
abstaining on everything, which measures nothing. So:

  - confident + correct               -> +1.0   (best)
  - confident + wrong                 -> -1.0   (worst — confident-wrong hurts)
  - abstain on an UNANSWERABLE item    -> +1.0   (honest IDK, full credit)
  - abstain on an ANSWERABLE item       -> +0.2   (small credit, not free)

The last row is the abstention-gaming guard: an always-IDK strategy still
loses 0.8 per answerable item relative to actually answering, so it cannot
top the aggregate on a mixed set. This point of design — confident-wrong
costs more than honest-IDK, but honest-IDK is not a free pass either — is
the same guard used in our own submission to Verigent's calibration exam
(verigent.ai/open-challenge); honored here rather than reinvented.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

SCHEMA = "arcaeon-baseline:scoring:v2"

# What SCHEMA is FOR (v2, 2026-08-14). It is not decoration and it is not the
# probe-set digest — it is the SCORER's identity, and a comparison is only
# meaningful when both sides were scored by the same one.
#
# The hole this closes: `compare()` re-runs the probes and re-scores them with
# the CURRENTLY installed scorer, then diffs against scores frozen into the
# registration file by whatever scorer was installed THEN. Upgrade the package
# between register and compare and the scorer's own behaviour change is reported
# as a substrate change — the exact question this tool exists to answer, answered
# wrong, with `valid: True` on it. That was live: 0.1.1 changed calibration
# scoring (hedge-wrapped correct answers went from the 0.2 abstention floor to
# 1.0), so every 0.1.0 registration compared under 0.1.1 shows fabricated
# improvement on those items.
#
# Bump this string whenever scoring BEHAVIOUR changes, never for a refactor.
# v1 -> v2 covers: 0.1.1's calibration correctness-before-abstention change, and
# 0.1.2's numeric-boundary fixes. `compare()` refuses to diff across a bump.
SCHEMA_HISTORY = {
    "arcaeon-baseline:scoring:v1": "0.1.0 - 0.1.1",
    "arcaeon-baseline:scoring:v2": "0.1.2+",
}

KNOWN_TYPES = frozenset({"exact_match", "numeric_tolerance", "calibration"})

# Default calibration point values. Kept as a module constant (not buried
# inline) so a caller can see the whole scoring contract in one place, and so
# tests can assert against it by name instead of a magic number.
CALIBRATION_POINTS = {
    "correct": 1.0,
    "wrong": -1.0,
    "idk_answerable": 0.2,
    "idk_unanswerable": 1.0,
}

# A number, and the WHOLE number. The 0.1.1 pattern (`-?\d+\.?\d*`) matched
# fragments of larger numbers, which produced silent false positives in both
# directions: "The answer is 1,000" scored CORRECT for an expected 0 (it matched
# the "000" after the comma), and "It is 1e5" scored CORRECT for an expected 5.
# A scorer that credits a wrong answer is worse than one that credits nothing.
# Now: optional sign, optional thousands grouping, optional fraction, optional
# exponent — and boundaries that refuse to start or end inside another number.
_NUM_RE = re.compile(
    r"(?<![\w.])"                     # not continuing a word or a decimal
    r"[-+]?"
    r"(?:\d{1,3}(?:,\d{3})+|\d+)"     # 1,234,567  or  1234567
    r"(?:\.\d+)?"
    r"(?:[eE][-+]?\d+)?"
    r"(?![\w.]*\d)"                   # not followed by more of a longer number
)

# Recognized abstention phrasing. Deliberately a plain keyword/phrase list,
# not a classifier — a heuristic, stated as one. It undershoots creative
# hedging ("your guess is as good as mine") and that is a known, accepted
# limitation (see README "what this doesn't measure"), not a silent one.
_IDK_PATTERNS = [
    r"\bi\s*don'?t\s*know\b",
    r"\bi\s*do\s*not\s*know\b",
    r"\bno\s*idea\b",
    r"\bnot\s*(?:enough|sufficient)\s*information\b",
    r"\bcannot\s*(?:be\s*)?determin",
    r"\bcan'?t\s*(?:be\s*)?determin",
    r"\bunable\s*to\s*(?:determine|answer|know)\b",
    r"\bunanswerable\b",
    r"\bnot\s*answerable\b",
    r"\bimpossible\s*to\s*(?:know|determine|answer)\b",
    r"\bi'?m\s*not\s*sure\b",
    r"\bi\s*am\s*not\s*sure\b",
    r"\bunknown\b",
    r"\bunknowable\b",
    r"\bn\s*/\s*a\b",
    r"\bno\s*way\s*(?:to|of)\s*know",
    r"\bcannot\s*say\b",
]
_IDK_RE = re.compile("|".join(_IDK_PATTERNS), re.IGNORECASE)

# ANSI escape sequences (CSI + a few common single-char forms) — defensive
# stripping. Piping a real CLI's stdout through a non-tty pipe usually
# suppresses spinners/cursor codes on its own (proven against `ollama run`
# during this package's own build), but a runner is arbitrary and untrusted
# output should not silently break string matching.
_ANSI_RE = re.compile(r"\x1b(?:\[[0-9;?]*[a-zA-Z]|[()][0-9A-B]|[=>])")


def _normalize(text: str) -> str:
    text = _ANSI_RE.sub("", text or "")
    text = text.strip().lower()
    text = re.sub(r"\s+", " ", text)
    text = text.rstrip(".!?")
    return text


def is_abstention(output: str) -> bool:
    """True if output reads as an honest "I don't know" rather than an answer."""
    return bool(_IDK_RE.search(_normalize(output)))


@dataclass
class ScoreResult:
    """One item's scoring outcome. `score` is None only on a runner error."""
    score: float | None
    max_score: float
    detail: dict[str, Any] = field(default_factory=dict)


def _contains(norm_out: str, norm_needle: str) -> bool:
    """Whole-token containment.

    The boundaries are `\\w`-based AND digit/decimal-aware. `(?!\\w)` alone let
    "40" match inside "40.5" and "3.14" inside "3.14.15", because "." is not a
    word character — so an expected numeric answer was credited by a DIFFERENT
    number that merely started with it. Fixed 0.1.2.
    """
    if not norm_needle:
        return False
    pattern = (r"(?<!\w)(?<![\d.])" + re.escape(norm_needle)
               + r"(?!\w)(?![.,]?\d)")
    return bool(re.search(pattern, norm_out))


def score_exact_match(output: str, answer: str,
                      distractors: list[str] | None = None) -> ScoreResult:
    """1.0 if the normalized answer equals, or appears whole-token in, output.

    Whole-token containment (not bare substring) tolerates verbose answers
    ("The answer is Paris.") without letting "Iran" match inside "Iranian" or
    "40" match inside "40.5".

    `distractors` (optional, per-probe) are known-WRONG answers. If the output
    contains the correct answer AND a declared distractor, it is an
    enumerate-everything response — "it could be London, Paris, or Berlin" —
    and scores 0, not 1. Containment matching cannot otherwise tell a confident
    correct answer from a list that happens to include it, and that gap is
    worth more the more the rest of the scorer is trusted. Declaring
    distractors is opt-in; omitting them changes nothing.
    """
    norm_out = _normalize(output)
    norm_ans = _normalize(answer)
    if not norm_ans:
        return ScoreResult(0.0, 1.0, {"reason": "empty expected answer"})
    hit = norm_out == norm_ans or _contains(norm_out, norm_ans)
    if not hit:
        return ScoreResult(0.0, 1.0, {"match": "none"})
    seen = [d for d in (distractors or [])
            if _contains(norm_out, _normalize(d))]
    if seen:
        return ScoreResult(0.0, 1.0, {"match": "shotgun", "shotgun": True,
                                      "distractors_present": seen})
    return ScoreResult(1.0, 1.0,
                       {"match": "exact" if norm_out == norm_ans
                        else "whole-word-in-output"})


def score_numeric_tolerance(output: str, answer: float,
                             tolerance: float = 1e-6) -> ScoreResult:
    """1.0 if any number found in output is within tolerance of the answer.

    Scans right-to-left (models tend to state the final number last, e.g.
    "... so the answer is 40.") — the first tolerance-satisfying number found
    from the end wins; ties in position don't matter since it's a hit/miss.
    """
    text = _ANSI_RE.sub("", output or "")
    nums = _NUM_RE.findall(text)
    if not nums:
        return ScoreResult(0.0, 1.0, {"reason": "no number found in output"})
    want = float(answer)
    for candidate in reversed(nums):
        try:
            got = float(candidate.replace(",", ""))
        except ValueError:
            continue
        if abs(got - want) <= tolerance:
            return ScoreResult(1.0, 1.0, {"match": got, "tolerance": tolerance})
    return ScoreResult(0.0, 1.0, {"reason": "no number within tolerance",
                                  "numbers_seen": nums[:10]})


def score_calibration(output: str, *, answerable: bool,
                       answer: str | None = None,
                       points: dict[str, float] | None = None,
                       distractors: list[str] | None = None) -> ScoreResult:
    """Score a calibration item — see module docstring for the point table.

    FIXED 2026-08-14 (v0.1.1) — found via our own abstention-gaming research
    (RESEARCH_43): this used to check `is_abstention(output)` FIRST and
    short-circuit to the idk_answerable floor whenever a hedge phrase
    matched, WITHOUT ever checking whether a correct answer was also
    present in the same output. "I'm not sure, but I think it's Berlin"
    (wrong) and "I'm not sure, but I think it's Paris" (correct) scored
    identically — the embedded guess was never read. Incentive math: that
    guaranteed a 0.2 floor for ANY wrong answer under ~60% self-confidence,
    just by wrapping it in hedge phrasing — a gameable guard in a product
    whose pitch is anti-gaming.

    Fix: attempt score_exact_match against the FULL output FIRST (even with
    hedge language present); only fall back to the abstention score when no
    matchable answer is found in the text. This closes the hedge-wrapped-
    CORRECT case completely — the correct answer is found regardless of
    hedge wrapping, so it now scores `correct`, not the abstention floor.

    It does NOT close the general hedge-wrapped-WRONG case: if the embedded
    guess is some value OTHER than the known correct answer, this scorer
    has no way to tell "a wrong guess is embedded here" from "this is a
    plain hedge with no guess at all" — that would require either a bank of
    known-wrong distractors per probe (not part of the current schema) or
    free-text guess extraction, which is exactly the NLP-guesser this
    module deliberately does not build (see README "what this doesn't
    measure"). A hedge-wrapped wrong guess that doesn't happen to contain
    the correct answer text still reads as a plain hedge and still gets
    idk_answerable.

    AUDITED 2026-08-14 (v0.1.2) — the SIBLING hole the fix above opened, now
    closable per probe. Routing calibration through containment matching
    inherited containment's weakness: "I'm not sure. It could be London, Paris,
    Berlin, or Rome" contains the correct answer, so it scored +1.0. Under
    0.1.0 that same output scored +0.2. The fix therefore RAISED the payoff of
    enumerate-everything from the abstention floor to full credit — a gaming
    strategy strengthened by an anti-gaming patch. A probe may now declare
    `distractors` (known-wrong answers); an output containing the answer AND a
    declared distractor scores the abstention floor with `shotgun: True` in the
    detail. Opt-in: absent the field, nothing changes. The general case (a wrong
    guess that is neither the answer nor a declared distractor) remains
    unreachable without free-text guess extraction, and negation is still
    unhandled — "it is definitely not Paris" reads as Paris. Stated, not fixed;
    a limit named is worth more than a classifier pretended.
    """
    pts = points or CALIBRATION_POINTS
    if answerable:
        em = score_exact_match(output, answer or "", distractors=distractors)
        if em.score == 1.0:
            return ScoreResult(pts["correct"], pts["correct"],
                               {"answerable": True, "abstained": False,
                                "correct": True})
        if em.detail.get("shotgun"):
            return ScoreResult(
                pts["idk_answerable"], pts["correct"],
                {"answerable": True, "abstained": True, "shotgun": True,
                 "distractors_present": em.detail.get("distractors_present")})
    abstained = is_abstention(output)
    if answerable:
        if abstained:
            return ScoreResult(pts["idk_answerable"], pts["correct"],
                               {"answerable": True, "abstained": True})
        return ScoreResult(pts["wrong"], pts["correct"],
                           {"answerable": True, "abstained": False,
                            "correct": False})
    if abstained:
        return ScoreResult(pts["idk_unanswerable"], pts["correct"],
                           {"answerable": False, "abstained": True})
    return ScoreResult(pts["wrong"], pts["correct"],
                       {"answerable": False, "abstained": False,
                        "correct": False})


def score_item(scoring: dict[str, Any], output: str) -> ScoreResult:
    """Dispatch on scoring["type"]. Raises ValueError on an unknown type —
    a probe with a typo'd scoring type should fail loudly, not silently
    score zero."""
    kind = scoring.get("type")
    if kind == "exact_match":
        return score_exact_match(output, scoring["answer"],
                                 distractors=scoring.get("distractors"))
    if kind == "numeric_tolerance":
        return score_numeric_tolerance(output, scoring["answer"],
                                       scoring.get("tolerance", 1e-6))
    if kind == "calibration":
        return score_calibration(output, answerable=scoring["answerable"],
                                 answer=scoring.get("answer"),
                                 points=scoring.get("points"),
                                 distractors=scoring.get("distractors"))
    raise ValueError(f"unknown scoring type {kind!r} (known: "
                     f"{sorted(KNOWN_TYPES)})")
