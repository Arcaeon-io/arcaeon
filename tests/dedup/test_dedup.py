"""Tests for arcaeon-dedup. The product claim is "removes repeats, never
facts", so the load-bearing tests are the NEGATIVE ones: the pairs that must
SURVIVE. The 0.1.0 suite had none, which is why it passed on a library that
deleted 99.7% of distinct 20-word inputs.

Run: python test_dedup.py
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from arcaeon.save.dedup import dedupe, simhash, hamming


def test_quickstart_removes_the_refetched_doc():
    doc = ("Docs: the API returns 200 on success. See the reference for details.")
    kept, report = dedupe([
        doc,
        doc.replace(". ", ".  "),          # same doc, refetched, whitespace noise
        "The database connection timed out after 30 seconds.",
    ])
    assert len(kept) == 2, kept
    assert report.removed == 1 and report.removed_indices == [1]
    print("PASS the quickstart: a refetched doc collapses, the distinct one stays")


# --- audit 2026-08-14: it was deleting content that was not duplicated ------
#
# SimHash is a CANDIDATE filter. Used as the verdict, it collapses anything
# whose words mostly overlap, and "mostly the same words" is not "the same
# meaning" — it is where the meaning usually lives. These are the pairs that
# must survive, and every one of them was being deleted at stock defaults.

MUST_SURVIVE = [
    ("permutation", "Alice owes Bob $100.", "Bob owes Alice $100."),
    ("direction", "Transfer 500 from savings to checking",
     "Transfer 500 from checking to savings"),
    ("failover", "Server A failed over to server B",
     "Server B failed over to server A"),
    ("negation", "Deploy to production.", "Do not deploy to production."),
    ("negation-long", "The patient is allergic to penicillin",
     "The patient is not allergic to penicillin"),
    ("antonym", "Charge the customer $19", "Refund the customer $19"),
    ("dosage", "Patient 4471, dosage 25 mg once daily, no known allergies.",
     "Patient 4472, dosage 50 mg twice daily, no known allergies."),
    ("log-line",
     "2026-08-14 order 88214 payment declined for customer bob@corp.com amount 12.50",
     "2026-08-14 order 88216 payment declined for customer dave@corp.com amount 18400.00"),
    ("json-row", '{"user_id": 2, "name": "Bob", "role": "viewer", "active": true}',
     '{"user_id": 3, "name": "Carol", "role": "editor", "active": true}'),
]


def test_distinct_content_is_never_silently_dropped():
    for name, a, b in MUST_SURVIVE:
        kept, report = dedupe([a, b])
        assert len(kept) == 2, (
            "SILENT DATA LOSS (%s): %r and %r are different facts, and one was "
            "deleted. hamming=%d" % (name, a, b, hamming(simhash(a, 1), simhash(b, 1))))
        assert report.removed == 0, name
    print("PASS %d distinct-but-similar pairs all survive (permutation, "
          "negation, antonym, ids, amounts)" % len(MUST_SURVIVE))


def test_real_duplicates_still_collapse():
    """The gate must not turn the library into a no-op: verbatim repeats,
    whitespace/case/punctuation noise, and repeated boilerplate still go."""
    doc = ("The database connection timed out after 30 seconds. Retrying with "
           "exponential backoff, three attempts, then failing the request.")
    cases = [
        ("verbatim", doc, doc),
        ("whitespace", doc, doc.replace(" ", "  ")),
        ("case", doc, doc.upper()),
        ("trailing punctuation", doc, doc + "!!"),
        ("wrapper noise", doc, "\n\n" + doc + "\n"),
    ]
    for name, a, b in cases:
        kept, report = dedupe([a, b])
        assert len(kept) == 1, "%s: a real duplicate survived" % name
        assert report.removed == 1, name
    print("PASS verbatim/whitespace/case/punctuation duplicates still collapse")


def test_unrelated_documents_never_collide():
    """At max_hamming=12 over 64 bits the ball is big enough that O(n^2) pairs
    finds a collision between documents sharing ZERO words."""
    import random
    rnd = random.Random(7)
    vocab = ["w%d" % i for i in range(4000)]
    docs = [" ".join(rnd.sample(vocab, 40)) for _ in range(1200)]
    kept, report = dedupe(docs)
    assert report.removed == 0, (
        "collided %d independent documents: indices %s"
        % (report.removed, report.removed_indices[:5]))
    print("PASS 1200 independent random documents: zero collisions")


def test_input_validation_is_typed():
    for bad, exc in [("a bare string", TypeError), (b"bytes", TypeError),
                     (None, TypeError), (123, TypeError)]:
        try:
            dedupe(bad)
            assert False, "accepted %r as a list of documents" % (bad,)
        except exc:
            pass
    for bad in ([None], [123], [b"x"], ["ok", None]):
        try:
            dedupe(bad)
            assert False, "accepted %r as documents" % (bad,)
        except TypeError:
            pass
    for kw in ({"k": 0}, {"k": -1}, {"max_hamming": -1}, {"max_hamming": 65},
               {"min_overlap": 1.5}, {"min_overlap": -0.1}):
        try:
            dedupe(["a b c", "a b c"], **kw)
            assert False, "accepted %r" % (kw,)
        except ValueError:
            pass
    assert dedupe([]) == ([], dedupe([])[1])
    print("PASS bare strings, non-str entries, and out-of-range knobs are typed errors")


def test_k_zero_no_longer_collapses_everything():
    """`if len(words) < k` is False for k=0, so words[i:i+0] yielded '' for
    every position and every document fingerprinted identically."""
    try:
        dedupe(["the quick brown fox", "a totally different sentence"], k=0)
        assert False, "k=0 accepted"
    except ValueError:
        pass
    print("PASS k=0 is refused instead of collapsing the entire input to one item")


def test_keep_longest_respects_the_documented_contract():
    """keep='longest' swapped the cluster representative mid-scan, so
    membership chained transitively: an item 15 bits from the survivor got
    deleted against a representative it was never a duplicate of.

    REBUILT 2026-08-24 (audit F2): the previous fixture never clustered at
    default thresholds (measured overlaps 0.76/0.38/0.54, all below 0.95),
    so report.removed was 0 and the only real assertion loop never ran --
    the test passed with keep='longest' entirely disabled. Now the fixture
    MEASURABLY clusters (b-c overlap 0.9405, empirically measured, gate
    0.93 explicit), a fixture guard asserts something was actually removed
    (the guard immediately caught the FIRST rebuild of this fixture not
    clustering either -- it earns its keep), and the dead nested loop is
    gone. The verified-dup assertion uses the same 0.93 the dedupe ran
    with; _verified_dup's fixed 0.95 would be a different predicate."""
    base = "the quick brown fox jumps over the lazy dog near the river bank today"
    b = base + " and then it rained."
    c = base + " and then it rained hard."
    unrelated = "completely different content about database connection pooling limits"
    items = [b, c, unrelated]
    kept, report = dedupe(items, keep="longest", min_overlap=0.93)
    assert report.removed > 0, (
        "fixture guard: nothing clustered, so the contract below is untested "
        "-- rebuild the fixture (this is exactly how the old version went "
        "vacuous)")
    assert unrelated in kept, "the unrelated item must never cluster"
    # whatever clusters, nothing may be dropped against an item it is not a
    # verified duplicate of, AT THE THRESHOLD THE RUN USED
    from arcaeon.save.dedup import _overlap
    for idx in report.removed_indices:
        dropped = items[idx]
        assert any(_overlap(dropped, s) >= 0.93 for s in kept), (
            "dropped %r with no verified duplicate among the survivors" % dropped)
    # keep='longest' must have kept the longer member of the cluster
    assert c in kept and b not in kept, (
        "keep='longest' did not keep the longest cluster member")
    print("PASS keep='longest' never drops an item against a non-duplicate representative")


def test_min_overlap_one_is_exact_match_only():
    """Audit F1 (2026-08-24, HIGH): min_overlap=1.0 is documented on three
    surfaces as 'drops only exact matches after normalization' -- the escape
    hatch the README routes medical/legal/financial users to. A periodic
    string saturates both gram sets, so 'word word' vs 'word word word'
    scored overlap 1.0 and collapsed at the exact-only setting, silently
    losing the repeat COUNT ('3 retries' vs '2 retries'). Now 1.0 is
    reachable only for equal normalized strings."""
    kept, report = dedupe(["word word", "word word word"], min_overlap=1.0)
    assert report.removed == 0, (
        "different repeat counts collapsed at min_overlap=1.0 -- the "
        "'exact matches only' promise is false (F1)")
    kept2, report2 = dedupe(
        ["ERROR timeout ERROR timeout ERROR timeout",
         "ERROR timeout ERROR timeout"], min_overlap=1.0)
    assert report2.removed == 0, "repeat-count difference lost at exact-only (F1)"
    # Green control: a genuinely exact (post-normalization) duplicate still
    # collapses at 1.0 -- the fix must not break the setting's real purpose.
    kept3, report3 = dedupe(["Same  text  here", "same text here"],
                            min_overlap=1.0)
    assert report3.removed == 1, (
        "control: an exact-after-normalization duplicate no longer collapses "
        "at min_overlap=1.0 -- the fix overshot")
    # And the periodic pair still collapses at DEFAULT thresholds -- capping
    # just below 1.0 must not un-dedupe ordinary near-repeats.
    kept4, report4 = dedupe(["word word", "word word word"])
    assert report4.removed == 1, (
        "control: the near-repeat no longer collapses at defaults -- the cap "
        "was set too low")
    print("PASS min_overlap=1.0 means exact-after-normalization, both directions controlled")


def test_unicode_and_pathological_input():
    from arcaeon.save.dedup import _shingles
    # CJK has no spaces: \w+ made the whole sentence ONE feature, so SimHash
    # degenerated to a plain hash and near-duplicate detection silently died.
    assert len(_shingles("你好世界这是一个测试句子", 3)) > 1, "CJK is one feature"
    kept, _ = dedupe(["你好世界这是一个测试句子", "你好世界这是一个测试句子"])
    assert len(kept) == 1, "identical CJK text did not collapse"
    kept, _ = dedupe(["ship it", "ship it???!!!"])
    assert len(kept) == 1, "punctuation-only difference survived"
    kept, _ = dedupe(["\U0001f600" * 3, "totally different words here entirely"])
    assert len(kept) == 2
    big = "word " * 50000
    kept, _ = dedupe([big, big])
    assert len(kept) == 1
    kept, _ = dedupe(["", "", "real content here"])
    assert len(kept) == 2, "empty strings should collapse together, content kept"
    print("PASS CJK/emoji/punctuation/huge/empty inputs behave, no crash")


def test_symbol_only_items_are_not_all_collapsed():
    """0.1.1 bug: any string that normalizes to empty (emoji-only, symbol-only,
    punctuation-only) had an empty feature set, so _overlap read 1.0 against
    EVERY other such string and they all collapsed into one. A five-star and a
    one-star rating, a rocket and a heart, are distinct content."""
    items = ["\U0001f600\U0001f600", "❤❤", "\U0001f525",
             "★★★★★", "★☆☆☆☆"]
    kept, report = dedupe(items)
    assert len(kept) == len(items), (
        "SILENT DATA LOSS: distinct symbol-only items collapsed -> %r" % (kept,))
    # byte-identical symbol-only strings must still collapse
    kept, _ = dedupe(["\U0001f525\U0001f525", "\U0001f525\U0001f525"])
    assert len(kept) == 1, "identical emoji should still collapse"
    # empty strings still collapse together, real content kept
    kept, _ = dedupe(["", "", "real content here"])
    assert len(kept) == 2
    print("PASS distinct symbol/emoji-only items survive; identical ones still collapse")


def test_content_empty_items_differing_only_in_whitespace_collapse():
    """0.1.5 (sell-code audit, 2026-09-01): the 0.1.2 symbol-only fix made
    content-empty strings collapse only when BYTE-identical, so "" vs "\\n"
    (an empty tool result vs its newline-terminated twin) and an emoji vs
    the same emoji with a trailing space both survived as two items --
    contradicting the documented "differing only in whitespace ... collapse"
    claim that holds for every string WITH word content. Whitespace runs are
    now folded before the identity check; symbol content itself is still
    compared exactly, so distinct symbols still survive."""
    kept, report = dedupe(["", "   ", "\n"])
    assert len(kept) == 1, "whitespace-only variants of empty did not collapse: %r" % (kept,)
    kept, report = dedupe(["\U0001f525", "\U0001f525 ", "\n\U0001f525\n"])
    assert len(kept) == 1, "whitespace-wrapped copies of one emoji survived: %r" % (kept,)
    kept, report = dedupe(["★  ★", "★ ★"])
    assert len(kept) == 1, "an internal whitespace run difference survived"
    # controls: distinct symbol content still survives, with or without spaces
    kept, _ = dedupe(["★★★★★", "★☆☆☆☆"])
    assert len(kept) == 2, "distinct symbol-only items collapsed (0.1.2 regression)"
    kept, _ = dedupe(["★ ★", "★★"])
    assert len(kept) == 2, "a space BETWEEN symbols is a boundary, not noise (matches word handling)"
    print("PASS content-empty items differing only in whitespace collapse; distinct symbols survive")


def _verified_dup(a: str, b: str) -> bool:
    from arcaeon.save.dedup import _overlap
    return _overlap(a, b) >= 0.95


def test_overlap_gate_is_min_not_max_the_and_not_the_or():
    """Mutation-testing find (2026-08-16): `_overlap`'s combining rule is
    `score = min(char_gram_jaccard, word_bigram_jaccard)` -- a pair must look
    like a repeat under BOTH views to collapse. A `min` -> `max` mutant
    SURVIVED the whole suite: nothing in MUST_SURVIVE actually needs the AND
    gate to be an AND, because their char-gram scores are already too low on
    their own. This pair is built so the gate is the ONLY thing standing
    between "kept" and "silently merged": swapping two same-length words
    ("cat"/"mat") deep inside a long shared sentence barely disturbs the
    character stream (char-gram Jaccard == 1.0 -- a SET of substrings, so
    reordering two equal-length tokens changes nothing) but scrambles word
    order enough to drop word-bigram Jaccard to ~0.87, under the default
    0.95 threshold. Correct code: min(1.0, 0.87) = 0.87 -> kept distinct.
    A `max` mutant: max(1.0, 0.87) = 1.0 -> wrongly merged, silent data loss
    on two sentences that report DIFFERENT facts (the cat on the mat is not
    the mat on the cat)."""
    pad = ("according to the quarterly compliance audit report filed this "
           "morning by the operations team ")
    x = pad + "the cat sat on the mat while everyone in the room quietly watched and waited patiently"
    y = pad + "the mat sat on the cat while everyone in the room quietly watched and waited patiently"
    kept, report = dedupe([x, y])
    assert len(kept) == 2, (
        "SILENT DATA LOSS (overlap-gate): %r and %r report different facts "
        "and one was deleted -- the char/word-bigram AND gate did not hold"
        % (x, y))
    assert report.removed == 0
    print("PASS the char-gram/word-bigram overlap gate is a real AND (min), "
          "not a false OR (max): a word-order swap with char-gram==1.0 still "
          "keeps both sentences distinct")


def test_jaccard_both_empty_sets_are_identical_by_contract():
    """Mutation-testing find (2026-08-16): `_jaccard`'s own both-empty guard
    (`if not a and not b: return 1.0`) is UNREACHABLE through every current
    caller in the module -- `_overlap` pre-filters the fully-empty-after-
    normalize case before ever calling `_jaccard`, and the word-bigram call
    site is itself guarded by `if bx or by`. A mutant that flips this
    return to 0.0 SURVIVED the entire suite because nothing calls `_jaccard`
    directly. Pinned here as a direct contract test of the documented
    behavior ("1.0 = identical after normalization") so the branch has a
    reader even though today it is dead code reached from no live path --
    and so a future caller that removes one of the two upstream guards
    inherits a tested invariant instead of a silent wrong answer."""
    from arcaeon.save.dedup import _jaccard
    assert _jaccard(set(), set()) == 1.0, (
        "two empty feature sets must be reported as identical (1.0), not distinct")
    assert _jaccard({"a"}, set()) == 0.0, "one empty, one non-empty must be 0.0 (unaffected control case)"
    print("PASS _jaccard(set(), set()) == 1.0 by contract (dead-code branch, now pinned)")


def test_keep_longest_tiebreak_prefers_earliest_on_length_tie():
    """Mutation-testing find (2026-08-16): `keep='longest'` picks
    `max(group, key=lambda i: (len(items[i]), -i))` -- when lengths tie, the
    `-i` term prefers the EARLIEST occurrence (largest -i == smallest i). A
    mutant that drops the negation (`i` instead of `-i`) SURVIVED: no
    existing test put 3+ equal-length near-duplicates in one cluster under
    keep='longest'. Three same-length variants (only a trailing V1/V2/V3
    token differs) built with a shared min_overlap=0.9 threshold so they
    verifiably cluster into one group; correct code keeps the FIRST
    (index 0, 'V1'), the negation-dropped mutant keeps the LAST ('V3') --
    silently changing which near-duplicate the caller gets back."""
    base = ("incident resolved successfully at zero four hundred hours today "
            "during the morning shift after the operations team completed a "
            "full diagnostic sweep of every affected node in the cluster ")
    s0, s1, s2 = base + "v1", base + "v2", base + "v3"
    assert len(s0) == len(s1) == len(s2), "fixture drifted: variants must tie on length"
    kept, report = dedupe([s0, s1, s2], keep="longest", min_overlap=0.9)
    assert len(kept) == 1, "fixture drifted: the three variants no longer cluster into one"
    assert kept[0] == s0, (
        "keep='longest' with a length tie kept %r, expected the EARLIEST "
        "occurrence %r" % (kept[0], s0))
    print("PASS keep='longest' breaks a length tie toward the earliest occurrence")


def test_simhash_bit_polarity_strict_positive_not_non_negative():
    """Mutation-testing find (2026-08-16): `simhash`'s bit-decision rule is
    `out |= (1 << i) if v[i] > 0` -- strictly positive, so a bit whose signed
    shingle-vote sum lands exactly on zero stays UNSET. A `> 0` -> `>= 0`
    mutant SURVIVED the whole suite because no existing case forces any
    vote sum to land exactly on zero.

    `_shingles("hotel bravo", k=1)` yields exactly two single-word shingles,
    `["hotel", "bravo"]`. At bit index 4 their blake2b feature hashes
    disagree (one contributes +1, the other -1), summing to precisely 0 --
    the only value a two-term +/-1 sum can take besides +/-2. Correct code:
    `0 > 0` is False -> bit 4 stays unset. Mutant: `0 >= 0` is True -> bit 4
    gets set, producing a different 64-bit fingerprint for identical
    reasons a >=/> boundary bug always produces a different fingerprint:
    silently, on the one case no hand-written pair happens to hit."""
    from arcaeon.save.dedup import _shingles, _feature_hash
    text, k, bit = "hotel bravo", 1, 4
    shingles = _shingles(text, k)
    assert shingles == ["hotel", "bravo"], "fixture drifted: shingle set changed"
    votes = sum(1 if (_feature_hash(sh) >> bit) & 1 else -1 for sh in shingles)
    assert votes == 0, (
        "fixture drifted: bit %d no longer nets to an exact zero vote (%d)"
        % (bit, votes))
    fp = simhash(text, k)
    assert (fp >> bit) & 1 == 0, (
        "bit %d is SET despite a zero vote sum -- simhash's polarity rule "
        "is no longer strictly '> 0'" % bit)
    print("PASS simhash bit-decision is strict '> 0': an exact-zero vote "
          "sum stays unset")


# --- E3 fixture: a hamming==max_hamming==12 candidate-gate boundary pair ---
#
# Built, not hand-written: a long filler document (2600 unique tokens, so
# word-bigram Jaccard tolerates a lot of edits) with a 4-word phrase
# inserted 61 times. Substituting the SAME word in 60 of the 61 occurrences
# (deliberately leaving exactly one intact) means the two bigrams that word
# touches are never actually removed from the document's bigram SET -- only
# new bigrams get added to the union -- which keeps `_overlap` right at the
# 0.95 edge even after 60 edits. The specific 60 replacement tokens below
# were found by brute-force search (a few thousand trials) to land the
# resulting SimHash distance at exactly 12, the default `max_hamming`.
_E3_N_FILLER = 2600
_E3_SNIPPET = ["please", "target", "the", "summary"]
_E3_K = 61
_E3_REPL = [
    "bkqy", "bjdp", "bjpj", "bkth", "bjvb", "bjfg", "bbcg", "bhwq", "bktc",
    "bjkx", "bdmb", "bgdp", "bfcm", "bcqv", "blmz", "bcbc", "bfzj", "bjlq",
    "bhmj", "bgwb", "bkcw", "bjkx", "bbyd", "blwd", "bhjy", "blwd", "bbjy",
    "bccd", "bfzj", "bdfb", "bgxm", "bgck", "bktc", "bkth", "bjmp", "bkft",
    "bbrf", "bgbt", "blmq", "blmq", "bdkx", "bhmd", "bfpn", "bgbt", "bktc",
    "bbdz", "bjvy", "bhmj", "bfcm", "bhmd", "bhvp", "bgrh", "bkrd", "blyw",
    "bbyd", "bcwn", "bgbz", "bjpj", "bdrd", "bkhg",
]


def _e3_build_pair():
    filler = ["f%d" % i for i in range(_E3_N_FILLER)]
    words = list(filler)
    step = max(1, len(words) // (_E3_K + 1))
    positions = [min(len(words), step * (i + 1)) for i in range(_E3_K)]
    for pos in sorted(positions, reverse=True):
        words[pos:pos] = list(_E3_SNIPPET)
    n = len(_E3_SNIPPET)
    starts = [i for i in range(len(words) - n + 1) if words[i:i + n] == _E3_SNIPPET]
    target_positions = [s + 1 for s in starts][:_E3_K - 1]  # leave one intact
    assert len(target_positions) == len(_E3_REPL) == 60, "fixture drifted"
    a = " ".join(words)
    words_b = list(words)
    for pos, r in zip(target_positions, _E3_REPL):
        words_b[pos] = r
    b = " ".join(words_b)
    return a, b


def test_clustering_candidate_gate_boundary_hamming_equals_max_hamming():
    """Mutation-testing find (2026-08-16): the clustering candidate gate is
    `hamming(fps[i], fps[rep]) <= max_hamming` -- inclusive, so a pair whose
    SimHash fingerprints differ by EXACTLY `max_hamming` bits (12, the
    default) is still admitted as a candidate, subject to `_overlap`'s
    separate verification. A `<=` -> `<` mutant SURVIVED the whole suite
    because no existing pair pins the boundary at hamming == 12 precisely --
    hitting that exactly (out of 64 bits) while also keeping `_overlap` at
    or above the 0.95 verification threshold is a search problem, not
    something hand-constructible. See `_e3_build_pair` above for how the
    fixture pair was built and found."""
    from arcaeon.save.dedup import _overlap
    a, b = _e3_build_pair()
    ov = _overlap(a, b)
    h = hamming(simhash(a, 1), simhash(b, 1))
    assert h == 12, "fixture drifted: SimHash distance is no longer exactly 12 (got %d)" % h
    assert ov >= 0.95, "fixture drifted: overlap dropped below the verification gate (%r)" % ov

    kept, report = dedupe([a, b])  # default max_hamming=12, k=1, min_overlap=0.95
    assert len(kept) == 1, "a pair at hamming == max_hamming must still be a candidate"
    assert report.removed == 1

    kept11, _ = dedupe([a, b], max_hamming=11)
    assert len(kept11) == 2, "one bit tighter (max_hamming=11) must NOT admit this pair"
    print("PASS clustering candidate gate is <= (inclusive) at hamming==max_hamming==12")


if __name__ == "__main__":
    test_quickstart_removes_the_refetched_doc()
    test_distinct_content_is_never_silently_dropped()
    test_real_duplicates_still_collapse()
    test_unrelated_documents_never_collide()
    test_input_validation_is_typed()
    test_k_zero_no_longer_collapses_everything()
    test_keep_longest_respects_the_documented_contract()
    test_min_overlap_one_is_exact_match_only()
    test_unicode_and_pathological_input()
    test_symbol_only_items_are_not_all_collapsed()
    test_content_empty_items_differing_only_in_whitespace_collapse()
    test_overlap_gate_is_min_not_max_the_and_not_the_or()
    test_jaccard_both_empty_sets_are_identical_by_contract()
    test_keep_longest_tiebreak_prefers_earliest_on_length_tie()
    test_simhash_bit_polarity_strict_positive_not_non_negative()
    test_clustering_candidate_gate_boundary_hamming_equals_max_hamming()
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    print(chr(10) + "ALL %d TESTS PASSED" % len(fns))
