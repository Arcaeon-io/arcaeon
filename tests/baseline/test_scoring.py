"""Scoring edge cases. Run: python test_scoring.py (or pytest)."""
from arcaeon.prove.baseline.scoring import (CALIBRATION_POINTS, is_abstention,
                                      score_calibration, score_exact_match,
                                      score_item, score_numeric_tolerance)


def test_exact_match_case_and_punctuation_insensitive():
    assert score_exact_match("PARIS.", "paris").score == 1.0
    assert score_exact_match("  Paris  ", "Paris").score == 1.0


def test_exact_match_whole_word_not_substring():
    # "Iran" must not match inside "Iranian" (word-boundary, not bare substring)
    assert score_exact_match("The country is Iranian.", "Iran").score == 0.0
    assert score_exact_match("The country is Iran.", "Iran").score == 1.0


def test_exact_match_empty_answer_never_matches():
    assert score_exact_match("anything", "").score == 0.0


def test_numeric_tolerance_zero_tolerance_exact_only():
    assert score_numeric_tolerance("7", 7, tolerance=0).score == 1.0
    assert score_numeric_tolerance("7.001", 7, tolerance=0).score == 0.0


def test_numeric_tolerance_negative_numbers():
    assert score_numeric_tolerance("the change was -3", -3, tolerance=0).score == 1.0


def test_numeric_tolerance_picks_a_matching_number_anywhere_scanning_from_end():
    # 60 appears first (a distractor from the problem statement), 40 is the
    # actual answer and appears last — tolerance scan is right-to-left.
    out = score_numeric_tolerance(
        "Using the 60 miles given, average speed works out to 40.", 40)
    assert out.score == 1.0


def test_numeric_tolerance_no_digits_scores_zero_not_error():
    r = score_numeric_tolerance("I have no idea", 40)
    assert r.score == 0.0
    assert "reason" in r.detail


def test_is_abstention_recognizes_common_idk_phrasing():
    for phrase in ["I don't know.", "I do not know", "No idea.",
                   "That's unanswerable.", "Not enough information to say.",
                   "I cannot determine that.", "unknown", "N/A"]:
        assert is_abstention(phrase), phrase


def test_is_abstention_false_on_a_confident_answer():
    assert not is_abstention("Tokyo")
    assert not is_abstention("The answer is 42.")


def test_calibration_all_four_buckets_match_the_documented_point_table():
    c = score_calibration("Tokyo", answerable=True, answer="Tokyo")
    assert c.score == CALIBRATION_POINTS["correct"] == 1.0

    c = score_calibration("Osaka", answerable=True, answer="Tokyo")
    assert c.score == CALIBRATION_POINTS["wrong"] == -1.0

    c = score_calibration("I don't know.", answerable=True, answer="Tokyo")
    assert c.score == CALIBRATION_POINTS["idk_answerable"] == 0.2

    c = score_calibration("I don't know.", answerable=False)
    assert c.score == CALIBRATION_POINTS["idk_unanswerable"] == 1.0

    c = score_calibration("42", answerable=False)
    assert c.score == CALIBRATION_POINTS["wrong"] == -1.0


def test_calibration_abstention_gaming_guard_always_idk_loses_to_answering():
    # Across a mixed set, always saying IDK must score strictly below a
    # strategy that answers the answerable items correctly and abstains
    # only on the genuinely unanswerable ones.
    answerable_always_idk = score_calibration("I don't know.", answerable=True,
                                              answer="Tokyo").score
    answerable_correct = score_calibration("Tokyo", answerable=True,
                                           answer="Tokyo").score
    assert answerable_always_idk < answerable_correct


def test_calibration_hedge_wrapped_correct_answer_scores_correct_not_idk_floor():
    # THE DEFECT (RESEARCH_43, found via our own abstention-gaming research,
    # 2026-08-14): is_abstention() used to fire on the hedge phrase and
    # short-circuit BEFORE correctness was ever checked, so a hedge-wrapped
    # CORRECT answer scored the same idk_answerable floor (0.2) as a pure
    # "I don't know" — the embedded guess was never read. Pre-fix this
    # assertion fails (score == 0.2, not 1.0); post-fix it passes.
    hedged_correct = score_calibration(
        "I'm not sure, but I think it's Paris.", answerable=True, answer="Paris")
    assert hedged_correct.score == CALIBRATION_POINTS["correct"] == 1.0, \
        f"got {hedged_correct.score} — hedge language is masking a correct answer"


def test_calibration_hedge_wrapped_wrong_answer_known_gap_still_gets_idk_floor():
    # KNOWN, DOCUMENTED GAP (not closed by the 0.1.1 fix): a hedge-wrapped
    # WRONG answer ("I'm not sure, but I think it's Berlin" when the answer
    # is Paris) still lands on idk_answerable (0.2), same as before. The fix
    # attempts score_exact_match against the KNOWN answer before falling
    # back to abstention — that catches an embedded CORRECT guess (see
    # test above) but has no way to detect an embedded WRONG guess, because
    # there is no bank of wrong candidates to match against and this is a
    # deterministic keyword scorer, not an NLP guesser (by design — see
    # CHANGELOG 0.1.1 / README "what this doesn't measure"). This test pins
    # that honestly rather than claiming a fix that isn't there.
    hedged_wrong = score_calibration(
        "I'm not sure, but I think it's Berlin.", answerable=True, answer="Paris")
    assert hedged_wrong.score == CALIBRATION_POINTS["idk_answerable"] == 0.2, \
        f"got {hedged_wrong.score} — if this changed, update the honest gap note"


def test_calibration_hedge_correctness_now_distinguishable():
    # The core "flip": pre-fix, a hedge-wrapped CORRECT guess and a
    # hedge-wrapped WRONG guess were INDISTINGUISHABLE (both 0.2) — that
    # indistinguishability was the exploit (wrap anything in hedge language,
    # get the same floor regardless of whether the embedded guess is right).
    # Pre-fix this assertion fails (0.2 == 0.2). Post-fix it passes because
    # the correct guess is now caught even though the wrong guess isn't.
    hedged_correct = score_calibration(
        "I'm not sure, but I think it's Paris.", answerable=True, answer="Paris")
    hedged_wrong = score_calibration(
        "I'm not sure, but I think it's Berlin.", answerable=True, answer="Paris")
    assert hedged_correct.score != hedged_wrong.score, (
        f"correct={hedged_correct.score} wrong={hedged_wrong.score} — "
        "hedge language is still fully masking correctness")


def test_calibration_custom_points_override():
    custom = {"correct": 2.0, "wrong": -2.0, "idk_answerable": 0.0,
              "idk_unanswerable": 2.0}
    r = score_calibration("I don't know.", answerable=True, answer="x",
                          points=custom)
    assert r.score == 0.0
    assert r.max_score == 2.0


def test_score_item_dispatches_by_type():
    assert score_item({"type": "exact_match", "answer": "Paris"}, "Paris").score == 1.0
    assert score_item({"type": "numeric_tolerance", "answer": 4}, "4").score == 1.0
    assert score_item({"type": "calibration", "answerable": False},
                      "I don't know.").score == 1.0


def test_score_item_unknown_type_raises():
    try:
        score_item({"type": "nonsense"}, "x")
        assert False, "expected ValueError"
    except ValueError as e:
        assert "unknown scoring type" in str(e)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\nALL {len(fns)} TESTS PASSED")
