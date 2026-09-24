"""arcaeon-dedup — strip repeated text from an agent's context before it costs tokens.

Retrieved chunks, tool outputs, conversation history, and memory stores fill up
with literal repeats — the same doc pulled twice by two retrievers, the same
boilerplate header on every result, a chunk that overlaps its neighbour, the
same error line logged forty times. Every redundant copy is pure token waste you
pay for on every call.

`dedupe()` finds them with **SimHash** as a fast candidate filter and then
**verifies every candidate pair by direct feature overlap** before dropping
anything. **No LLM call, no embeddings, no network: pure stdlib.** That's the
point — it costs essentially nothing to run, so it's cheap enough to put in
front of every context assembly.

    from arcaeon.save.dedup import dedupe
    kept, report = dedupe([
        "Docs: the API returns 200 on success. See the reference for details.",
        "Docs: the API returns 200 on success.  See the reference for details.",  # same doc, refetched
        "The database connection timed out after 30 seconds.",
    ])
    # kept -> 2 items (the repeat dropped)
    # report -> DedupeReport(kept=2, removed=1, chars_saved=..., est_tokens_saved=...)

WHAT IT REMOVES, AND WHAT IT WILL NOT — the boundary is the product:

  1. It removes NEAR-VERBATIM repeats: identical text, text differing only in
     whitespace, case, punctuation, or wrapper noise, and chunks whose content
     is substantially the same string. That is the common, expensive case.
  2. It does NOT collapse paraphrase, and it must not pretend to. No lexical
     distance separates "reworded, same meaning" from "one word changed,
     opposite meaning" — "Charge the customer $19" and "Refund the customer
     $19" are lexically CLOSER than any two honest paraphrases of the same
     sentence. A deduper that collapses the second collapses the first, and
     then it is deleting facts. For paraphrase, you need semantics: embeddings.
  3. The one case it can still get wrong: a single inserted or substituted
     token inside a LONG document leaves the two strings overwhelmingly
     identical, so at some length a one-word change reads as a repeat. There
     is no threshold that fixes this in general (it is the same theorem as
     #2). If one-token inversions are load-bearing in your corpus — medical,
     legal, financial records — pass `min_overlap=1.0`, which drops only
     items whose normalized feature sets match exactly.

Zero dependencies. MIT. Built by Arcaeon — the evidence layer for AI.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass

__version__ = "0.1.5"
__all__ = ["dedupe", "simhash", "hamming", "DedupeReport"]

_WORD = re.compile(r"\w+", re.UNICODE)
_BITS = 64
_MASK = (1 << _BITS) - 1
_CHAR_GRAM = 4


def _normalize(text: str) -> str:
    """Word characters only, NFKC-folded, casefolded, single-spaced.

    Punctuation, emoji, and whitespace runs are noise for repeat detection;
    NFKC folds the compatibility forms so a full-width or decomposed copy of
    the same sentence isn't read as different text.

    Uses `str.casefold()`, not `str.lower()` (H-dedup-1, 2026-08-16, found by
    property testing): `.lower()` does not round-trip German eszett -- "ß"
    stays "ß" but "SS".lower() is "ss", so "straße" and "STRASSE" (an
    ordinary all-caps case variant of the same word) normalized to DIFFERENT
    word tokens and were never even considered as duplicate candidates,
    contradicting this package's own documented "differing only in ... case
    ... collapse" claim. `casefold()` is the Unicode-standard case-INsensitive
    comparison primitive (TR21) built for exactly this
    (`"ß".casefold() == "SS".casefold() == "ss"`); for plain ASCII text it is
    identical to `.lower()`, so this changes nothing for the common case and
    only strictly widens what counts as a case-variant match.
    """
    return " ".join(_WORD.findall(unicodedata.normalize("NFKC", text).casefold()))


def _char_grams(norm: str) -> set:
    if not norm:
        return set()
    if len(norm) <= _CHAR_GRAM:
        return {norm}
    return {norm[i:i + _CHAR_GRAM] for i in range(len(norm) - _CHAR_GRAM + 1)}


def _word_bigrams(norm: str) -> set:
    words = norm.split(" ") if norm else []
    return set(zip(words, words[1:]))


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _overlap(x: str, y: str) -> float:
    """Verified similarity of two documents, in [0, 1]. 1.0 = identical after
    normalization — EXACTLY that, since the 2026-08-24 audit (F1): a score of
    1.0 is now reachable only when the normalized STRINGS are equal, never
    merely their feature sets. Before, a periodic string saturated both gram
    sets, so "word word" vs "word word word" scored 1.0 and collapsed at
    min_overlap=1.0 — the setting the README tells medical/legal/financial
    users means "drops only exact matches." The lost information in that
    domain is the repeat COUNT ("3 retries" vs "2 retries"), which is exactly
    the class routed to that setting. Non-identical strings with identical
    feature sets now score just under 1.0, so every documented surface
    ("exact match after normalization") is the delivered predicate.

    The MINIMUM of two independent views — character 4-grams and word bigrams
    — so a pair has to look like a repeat under both to be treated as one.
    Character grams keep short strings and space-free scripts (CJK, Thai)
    measurable; word bigrams carry word order, which is what catches
    "Alice owes Bob" against "Bob owes Alice" (identical bag of words,
    disjoint bigrams).
    """
    nx, ny = _normalize(x), _normalize(y)
    if not nx and not ny:
        # Both are content-empty after normalization (emoji-only, symbol-only,
        # punctuation-only — a 5-star vs 1-star rating, a rocket vs a heart).
        # Their feature sets are both empty, so every Jaccard below reads 1.0
        # and they would ALL collapse into one. With no word content to compare,
        # the only defensible "duplicate" is an identical original; anything
        # else is distinct content we cannot tell apart, so we must keep it.
        # Whitespace is the one thing we DO fold here (0.1.5): the package
        # promises that copies "differing only in whitespace" collapse, and
        # a byte-identity test broke that promise for "" vs "\n" and for a
        # symbol string vs the same string with a trailing space -- the
        # same whitespace-run folding `_normalize` applies to word content.
        return 1.0 if " ".join(x.split()) == " ".join(y.split()) else 0.0
    if nx == ny:
        return 1.0
    score = _jaccard(_char_grams(nx), _char_grams(ny))
    bx, by = _word_bigrams(nx), _word_bigrams(ny)
    if bx or by:
        score = min(score, _jaccard(bx, by))
    # F1: identical feature sets from NON-identical normalized strings (the
    # periodic-string case) must not reach the exact-match score. Capping
    # just below 1.0 keeps them collapsible at every default-range threshold
    # (0.9995 > any practical min_overlap < 1.0) while making 1.0 mean what
    # three documentation surfaces say it means.
    return min(score, 0.9995)


def _shingles(text: str, k: int = 3) -> list[str]:
    """The features SimHash weighs: word k-grams, or character 4-grams when
    there aren't enough words (short strings, and scripts written without
    spaces — a CJK sentence is one `\\w+` token, which would collapse SimHash
    to a plain hash and silently stop detecting anything)."""
    if k < 1:
        raise ValueError("k must be >= 1")
    norm = _normalize(text)
    words = norm.split(" ") if norm else []
    if len(words) >= max(k, 2):
        return [" ".join(words[i:i + k]) for i in range(len(words) - k + 1)]
    return sorted(_char_grams(norm))


def _feature_hash(feature: str) -> int:
    return int.from_bytes(hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest(), "big")


def simhash(text: str, k: int = 3) -> int:
    """64-bit SimHash of text — near-identical text yields near-identical
    hashes. A CANDIDATE filter, never a verdict: see `_overlap`."""
    v = [0] * _BITS
    shingles = _shingles(text, k)
    if not shingles:
        return 0
    for sh in shingles:
        h = _feature_hash(sh)
        for i in range(_BITS):
            v[i] += 1 if (h >> i) & 1 else -1
    out = 0
    for i in range(_BITS):
        if v[i] > 0:
            out |= (1 << i)
    return out & _MASK


def hamming(a: int, b: int) -> int:
    """Number of differing bits — the near-duplicate distance. 0 = identical fingerprint."""
    return bin(a ^ b).count("1")


@dataclass
class DedupeReport:
    kept: int
    removed: int
    chars_saved: int
    est_tokens_saved: int
    removed_indices: list[int]

    def __str__(self) -> str:
        return (f"deduped: kept {self.kept}, removed {self.removed} repeat(s); "
                f"~{self.chars_saved:,} chars / ~{self.est_tokens_saved:,} tokens saved")


def dedupe(items: list[str], *, max_hamming: int = 12, k: int = 1,
           keep: str = "first", min_overlap: float = 0.95
           ) -> tuple[list[str], DedupeReport]:
    """Remove near-verbatim repeats from a list of strings, preserving order.

    Two steps, and the second one is the safety:

      1. CANDIDATES — SimHashes within `max_hamming` bits (of 64). Cheap, wide,
         and on its own wildly over-eager: at 12 bits it will hand you pairs
         that share no words at all.
      2. VERIFICATION — the candidate pair is dropped only if `_overlap` (the
         minimum of character-4-gram and word-bigram Jaccard) is at least
         `min_overlap`. Raising `max_hamming` widens the candidate set; it does
         NOT weaken this gate.

    `min_overlap=0.95` (default) means near-verbatim: whitespace, case,
    punctuation, and small wrapper differences collapse; different facts do
    not. `min_overlap=1.0` drops only exact matches after normalization — use
    it when a one-token difference is never noise. Values below ~0.7 start
    deleting content that is merely related, which is silent data loss; the
    knob is there, but that is what it does.

    `k` is the SimHash shingle width for candidate generation only (1 =
    bag-of-words, wide recall). `keep="first"` keeps the earliest of each
    cluster (best for chronological context); `keep="longest"` keeps the most
    complete phrasing — clusters are formed against fixed representatives
    first and the longest member chosen after, so nothing is ever dropped
    against an item it was not verified against.

    Returns (kept_items, DedupeReport). Pure stdlib: no LLM, no embeddings,
    no network.
    """
    if keep not in ("first", "longest"):
        raise ValueError("keep must be 'first' or 'longest'")
    if isinstance(items, (str, bytes, bytearray)):
        raise TypeError("items must be a list of strings, not a bare string "
                        "(a string would be deduplicated character by character)")
    try:
        items = list(items)
    except TypeError as e:
        raise TypeError(f"items must be an iterable of str, got "
                        f"{type(items).__name__}") from e
    for i, s in enumerate(items):
        if not isinstance(s, str):
            raise TypeError(f"items[{i}] must be str, got {type(s).__name__}")
    if not isinstance(k, int) or isinstance(k, bool) or k < 1:
        raise ValueError("k must be an int >= 1")
    if not isinstance(max_hamming, int) or isinstance(max_hamming, bool) \
            or not 0 <= max_hamming <= _BITS:
        raise ValueError(f"max_hamming must be an int in 0..{_BITS}")
    if not isinstance(min_overlap, (int, float)) or isinstance(min_overlap, bool) \
            or not 0.0 <= float(min_overlap) <= 1.0:
        raise ValueError("min_overlap must be a float in 0.0..1.0")

    fps = [simhash(s, k) for s in items]

    # Pass 1: assign every item to a cluster against FROZEN representatives.
    # (Mutating the representative mid-scan is what let membership chain
    # transitively, dropping items 15+ bits from anything they were compared
    # against.)
    reps: list[int] = []                    # index of each cluster's representative
    members: list[list[int]] = []
    for i in range(len(items)):
        cluster = None
        for ci, rep in enumerate(reps):
            if hamming(fps[i], fps[rep]) <= max_hamming and \
                    _overlap(items[i], items[rep]) >= min_overlap:
                cluster = ci
                break
        if cluster is None:
            reps.append(i)
            members.append([i])
        else:
            members[cluster].append(i)

    # Pass 2: choose each cluster's survivor.
    survivors: list[int] = []
    removed_idx: list[int] = []
    chars_saved = 0
    for group in members:
        if keep == "longest":
            winner = max(group, key=lambda i: (len(items[i]), -i))
        else:
            winner = group[0]
        survivors.append(winner)
        for i in group:
            if i != winner:
                removed_idx.append(i)
                chars_saved += len(items[i])

    kept_items = [items[i] for i in sorted(survivors)]
    report = DedupeReport(
        kept=len(kept_items), removed=len(removed_idx),
        chars_saved=chars_saved, est_tokens_saved=chars_saved // 4,  # ~4 chars/token
        removed_indices=sorted(removed_idx))
    return kept_items, report
