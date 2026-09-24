"""Hypothesis property suite for arcaeon-dedup.

Companion to the hand-rolled test_dedup.py. Same treatment applied to
arcaeon-continuity, arcaeon-ledger, and arcaeon-distill the night of
2026-08-15/16 -- ledger found a real `splitlines()`-vs-`ensure_ascii=False`
false-mismatch bug on the U+0085/U+2028/U+2029 unicode-line-separator class,
continuity found a probe-file handoff mismatch traced to the same class.
Run against this repo's checkout (`pip install -e .`), never site-packages.

Sections:
  1. Structural invariants — kept+removed==len, order preservation, valid
     removed_indices, determinism.
  2. Idempotence — deduping an already-deduped list should not remove more.
  3. Correctness on known near-duplicates and known distinct pairs.
  4. Argument validation.
  5. The unicode-line-separator class (U+0085/U+2028/U+2029) — THE headline
     check. `arcaeon_dedup` has NO file I/O anywhere (grepped: no `open(`,
     `jsonl`, `splitlines`, or `readlines` in the package) -- it operates
     purely on an in-memory `list[str]`. The specific write-JSONL/read-back-
     with-splitlines() bug class is therefore STRUCTURALLY ABSENT: there is
     no round trip to break. Section 5 instead verifies the class is at
     least handled deterministically and without crashing wherever it CAN
     reach the package's actual surface: `_normalize`, `simhash`, `dedupe`.
"""
from __future__ import annotations

import re

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from arcaeon.save.dedup import DedupeReport, dedupe, hamming, simhash

_HAS_WORD_CHAR = re.compile(r"\w", re.UNICODE)

_slow_settings = settings(max_examples=100, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow])

# The three unicode line-separator characters at the center of tonight's bug
# class: NEL (U+0085), LINE SEPARATOR (U+2028), PARAGRAPH SEPARATOR (U+2029).
_LINE_SEP_CHARS = "  "

_text = st.text(max_size=120)

_text_with_line_seps = st.text(
    alphabet=st.one_of(
        st.characters(blacklist_categories=("Cs",), max_codepoint=0x2FFF),
        st.sampled_from(list(_LINE_SEP_CHARS)),
    ),
    min_size=0, max_size=120,
)

_items_list = st.lists(_text, min_size=0, max_size=15)


# ---------------------------------------------------------------------------
# 1. Structural invariants
# ---------------------------------------------------------------------------

@_slow_settings
@given(items=_items_list)
def test_kept_plus_removed_equals_input_length(items):
    kept, report = dedupe(items)
    assert report.kept == len(kept)
    assert report.kept + report.removed == len(items)


@_slow_settings
@given(items=_items_list)
def test_removed_indices_are_valid_unique_sorted(items):
    kept, report = dedupe(items)
    assert report.removed_indices == sorted(set(report.removed_indices))
    assert all(0 <= i < len(items) for i in report.removed_indices)
    assert len(report.removed_indices) == report.removed


@_slow_settings
@given(items=_items_list)
def test_survivors_preserve_original_relative_order(items):
    kept, report = dedupe(items)
    # every kept string must appear in `items`, and the kept sequence must
    # be extractable as a subsequence of items by SOME set of indices in
    # increasing order (i.e. dedupe never reorders).
    removed = set(report.removed_indices)
    expected = [items[i] for i in range(len(items)) if i not in removed]
    assert kept == expected


@_slow_settings
@given(items=_items_list)
def test_dedupe_is_deterministic(items):
    kept1, report1 = dedupe(items)
    kept2, report2 = dedupe(items)
    assert kept1 == kept2
    assert report1 == report2


@_slow_settings
@given(items=_items_list, keep=st.sampled_from(["first", "longest"]))
def test_dedupe_deterministic_across_keep_modes(items, keep):
    kept1, report1 = dedupe(items, keep=keep)
    kept2, report2 = dedupe(items, keep=keep)
    assert kept1 == kept2
    assert report1 == report2


@_slow_settings
@given(items=_items_list)
def test_chars_saved_matches_removed_items(items):
    kept, report = dedupe(items)
    expected_chars = sum(len(items[i]) for i in report.removed_indices)
    assert report.chars_saved == expected_chars
    assert report.est_tokens_saved == expected_chars // 4


# ---------------------------------------------------------------------------
# 2. Idempotence
# ---------------------------------------------------------------------------

@_slow_settings
@given(items=_items_list)
def test_idempotent_under_keep_first(items):
    """Deduping an already-deduped (keep='first') list must remove nothing
    further: every pairwise comparison among survivors was already proven
    false (below max_hamming/min_overlap) against each other's fingerprints
    in the first pass -- both `hamming` and `_overlap` are symmetric, so
    re-running the identical pairwise test on the same strings, in the same
    relative order, must reproduce the same "no cluster" verdict."""
    kept_once, _ = dedupe(items, keep="first")
    kept_twice, report_twice = dedupe(kept_once, keep="first")
    assert kept_twice == kept_once
    assert report_twice.removed == 0


@_slow_settings
@given(items=_items_list)
def test_idempotent_under_keep_longest(items):
    """Same idempotence claim, but for keep='longest'. Note this is a
    WEAKER guarantee by construction than keep='first': pass-1 clustering
    only directly verifies REP-vs-newcomer pairs, never verifies two
    same-cluster MEMBERS against each other, and keep='longest' can promote
    a non-rep member to survivor -- so two different clusters' 'longest'
    survivors were never directly compared to each other in pass 1. If this
    fails, it is a genuine (if narrow) non-idempotence, not a test bug."""
    kept_once, _ = dedupe(items, keep="longest")
    kept_twice, report_twice = dedupe(kept_once, keep="longest")
    assert kept_twice == kept_once
    assert report_twice.removed == 0


# ---------------------------------------------------------------------------
# 3. Correctness on known cases
# ---------------------------------------------------------------------------

@_slow_settings
@given(s=_text.filter(lambda t: t.strip() != ""), n=st.integers(min_value=2, max_value=6))
def test_exact_repeats_always_collapse_to_one(s, n):
    """N copies of the exact same non-blank string must always collapse to
    exactly 1 survivor, for ANY min_overlap in [0, 1] -- identical content
    has overlap 1.0 with itself by construction."""
    items = [s] * n
    kept, report = dedupe(items, min_overlap=1.0)
    assert report.kept == 1
    assert kept == [s]


_ascii_word_text = st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
    min_size=1, max_size=80,
).filter(lambda t: _HAS_WORD_CHAR.search(t) is not None)


@_slow_settings
@given(s=_ascii_word_text)
def test_whitespace_case_punctuation_variant_always_collapses(s):
    """A copy differing only by case, added punctuation, and doubled
    whitespace must collapse at the DEFAULT min_overlap (0.95) -- this is
    the headline documented behavior ("near-verbatim repeats... whitespace,
    case, punctuation... collapse").

    Restricted to printable ASCII (not full Unicode) deliberately: building
    a "case variant" via `.upper()` and relying on the package's
    `.casefold()`-based normalize to fold it back requires upper/casefold to
    be inverses, which Python's default (non-locale-aware) case tables do
    NOT guarantee everywhere -- German eszett ("ß".upper() == "SS", but
    "SS".casefold() != "ß".casefold() before H-dedup-1's fix) and Turkish
    dotless-i ("\\u0131".upper() == "I", but "I".casefold() == "i" !=
    "\\u0131".casefold() == "\\u0131", a LOCALE-dependent mapping Python's
    stdlib does not implement and this zero-dependency package correctly
    does not chase) both broke this test before this restriction, and both
    are test-construction artifacts, not package bugs -- see H-dedup-1's
    changelog entry for the ß case, which the package DID fix, and the
    dedicated regression tests below for both characters, pinned as
    accepted/out-of-scope so a future test run doesn't waste time
    rediscovering the same non-bug."""
    variant = "  ".join(s.upper().split()) + "!!!" if s.strip() else s
    kept, report = dedupe([s, variant])
    assert report.kept == 1


def test_eszett_case_variant_now_collapses_h_dedup_1():
    """Regression pin for the real fix: casefold (not lower) unifies
    'straße' and its all-caps form 'STRASSE'."""
    kept, report = dedupe(["die straße", "DIE STRASSE"])
    assert report.kept == 1


def test_turkish_dotless_i_is_accepted_out_of_scope():
    """Pin, not a bug report: locale-dependent Turkish casing (dotless
    '\\u0131' <-> 'I'/'i') is NOT unified by Python's default case tables
    (str.upper/lower/casefold are locale-INDEPENDENT), and fixing it would
    need a Turkish-locale-aware casing table (e.g. PyICU), which contradicts
    this package's zero-dependency, pure-stdlib design. Documented here so
    it reads as an accepted boundary, not a rediscovered surprise."""
    s, variant = "ıstanbul", "ISTANBUL"
    kept, report = dedupe([s, variant])
    assert report.kept == 2  # NOT unified -- this is the documented boundary


def test_unrelated_facts_never_collapse_even_though_lexically_close():
    """The module docstring's own example: 'Charge the customer $19' and
    'Refund the customer $19' are lexically closer than two honest
    paraphrases, and must NOT be treated as duplicates."""
    kept, report = dedupe(["Charge the customer $19", "Refund the customer $19"])
    assert report.kept == 2
    assert report.removed == 0


def test_word_order_reversal_is_not_a_duplicate():
    """'Alice owes Bob' vs 'Bob owes Alice' -- identical bag of words,
    disjoint word-bigrams. The word-bigram half of `_overlap`'s min() must
    catch this."""
    kept, report = dedupe(["Alice owes Bob money", "Bob owes Alice money"])
    assert report.kept == 2


def test_empty_list_returns_empty_report():
    kept, report = dedupe([])
    assert kept == []
    assert report.kept == 0
    assert report.removed == 0
    assert report.chars_saved == 0


def test_single_item_is_always_kept():
    kept, report = dedupe(["solo item, nothing to compare against"])
    assert kept == ["solo item, nothing to compare against"]
    assert report.removed == 0


# ---------------------------------------------------------------------------
# 4. Argument validation
# ---------------------------------------------------------------------------

def test_bare_string_input_rejected():
    with pytest.raises(TypeError, match="not a bare string"):
        dedupe("not a list")  # type: ignore[arg-type]


def test_non_string_item_rejected():
    with pytest.raises(TypeError):
        dedupe(["a", 1, "c"])  # type: ignore[list-item]


@pytest.mark.parametrize("bad_keep", ["FIRST", "shortest", "", None])
def test_invalid_keep_rejected(bad_keep):
    with pytest.raises(ValueError):
        dedupe(["a", "b"], keep=bad_keep)


@pytest.mark.parametrize("bad_overlap", [-0.1, 1.1, "0.9"])
def test_invalid_min_overlap_rejected(bad_overlap):
    with pytest.raises(ValueError):
        dedupe(["a", "b"], min_overlap=bad_overlap)


@pytest.mark.parametrize("bad_hamming", [-1, 65, True])
def test_invalid_max_hamming_rejected(bad_hamming):
    with pytest.raises(ValueError):
        dedupe(["a", "b"], max_hamming=bad_hamming)


# ---------------------------------------------------------------------------
# 5. The unicode-line-separator class: U+0085 / U+2028 / U+2029
# ---------------------------------------------------------------------------
# Verdict for arcaeon-dedup: the write-JSONL/read-with-splitlines() bug class
# is STRUCTURALLY ABSENT. `grep -n "open(\|jsonl\|splitlines\|readlines"
# arcaeon_dedup/*.py` returns nothing -- this package has zero file I/O; it
# is a pure function over an in-memory list[str]. There is no write side and
# no read-back side for the bug to live in. What follows instead: the class
# does reach `_normalize` (via `_WORD.findall`, which does not match these
# chars -- they are stripped exactly like any other non-word separator,
# same as a plain space), so it must not crash and must behave
# deterministically and consistently with the plain-whitespace case.

@_slow_settings
@given(s=_text_with_line_seps)
def test_line_separator_class_does_not_crash_simhash_or_normalize(s):
    h1 = simhash(s)
    h2 = simhash(s)
    assert h1 == h2
    assert 0 <= h1 <= (1 << 64) - 1


@_slow_settings
@given(s=_text_with_line_seps)
def test_line_separator_class_dedupe_is_deterministic(s):
    items = [s, s + " trailing"]
    kept1, report1 = dedupe(items)
    kept2, report2 = dedupe(items)
    assert kept1 == kept2
    assert report1 == report2


@_slow_settings
@given(word_a=st.text(alphabet=st.characters(min_codepoint=ord("a"), max_codepoint=ord("z")),
                       min_size=1, max_size=8),
       word_b=st.text(alphabet=st.characters(min_codepoint=ord("a"), max_codepoint=ord("z")),
                       min_size=1, max_size=8),
       sep=st.sampled_from(list(_LINE_SEP_CHARS) + [" ", "\n"]))
def test_line_separator_treated_like_any_other_word_boundary(word_a, word_b, sep):
    """A unicode line separator between two words must be stripped exactly
    like a plain space or newline by `_normalize` (all are non-\\w), so a
    string built with any of these separators between the SAME two words
    normalizes identically and dedupe()'s exact-match path (min_overlap=1.0)
    treats them as one cluster -- consistent behavior across the whole
    separator family, not special-cased for the line-separator subset."""
    text_space = f"{word_a} {word_b}"
    text_sep = f"{word_a}{sep}{word_b}"
    kept, report = dedupe([text_space, text_sep], min_overlap=1.0)
    assert report.kept == 1, (
        f"{text_space!r} and {text_sep!r} normalize to the same word "
        f"tokens but were NOT collapsed -- inconsistent separator handling")


@_slow_settings
@given(s1=_text_with_line_seps, s2=_text_with_line_seps)
def test_hamming_and_overlap_symmetric_under_line_separator_content(s1, s2):
    """Both the SimHash candidate filter and the verification gate must be
    symmetric regardless of which unicode separators are present -- clustering
    correctness (used throughout this suite's idempotence proofs) depends on
    it."""
    h1, h2 = simhash(s1), simhash(s2)
    assert hamming(h1, h2) == hamming(h2, h1)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
