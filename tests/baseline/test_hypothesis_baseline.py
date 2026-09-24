"""Hypothesis property suite for arcaeon-baseline.

Companion to the hand-rolled test_probes.py / test_registration.py /
test_scoring.py / test_scoring_integrity.py / test_cli.py. Same pass applied
across arcaeon-continuity, arcaeon-ledger, arcaeon-distill, and arcaeon-dedup
the nights of 2026-08-15/16 -- ledger found a real `splitlines()`-vs-
`ensure_ascii=False` false-mismatch bug on the U+0085/U+2028/U+2029 unicode-
line-separator class, and continuity found a probe-file handoff mismatch
traced to the same class. Run against this repo's checkout
(`pip install -e .`), never against a stale site-packages copy.

Sections:
  1. Probe registration determinism + order-sensitivity (what the docstring
     actually promises, not an assumed order-independence).
  2. Scoring determinism, including the normalization invariants that stand
     in for "paraphrase" variation (real semantic paraphrasing isn't
     Hypothesis-generatable; literal surface-form variants are).
  3. Forged-probe detection -- the SECURITY-CRITICAL property. This package
     exists to catch a substrate swap that quietly changed something; that
     only works if the stored record of "before" is itself tamper-evident.
     Found and fixed a real hole here: `compare()` used to trust
     `reg["items"]`/`reg["aggregate"]` straight off disk with no check
     against anything, so editing the registration JSON file in place (flip
     a wrong item's score to correct, swap two items' scores, truncate the
     set) was silently accepted as genuine and reported `valid: True`. See
     `_items_digest` and the ledger-tamper check in `compare()` for the fix.
  4. The unicode-line-separator class (U+0085/U+2028/U+2029) -- headline
     check. VERDICT: present, and fixed this pass. `load_probes()` read
     probe `.jsonl` files with `text.splitlines()`, which breaks on these
     three characters even though `json.dumps(..., ensure_ascii=False)`
     (the idiom any JSONL-writing tool -- including this package's own
     probe-authoring examples -- would reasonably use) does not escape them.
     A single well-formed probe whose prompt legitimately contained U+2028
     raised "Unterminated string" on load, before the fix. Fixed by
     switching to `text.split("\\n")`, mirroring the already-fixed idiom in
     arcaeon-ledger's `Ledger.__iter__` / `verify_file`.
"""
from __future__ import annotations

import copy
import json
import os
import string
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, assume, given, settings, strategies as st

from arcaeon.record.ledger import Ledger

from arcaeon.prove.baseline import (CallableRunner, Probe, compare, load_probes,
                              probe_set_digest, register)
from arcaeon.prove.baseline.scoring import _normalize, score_exact_match, score_item

# Cheap pure-function properties (scoring, digesting): higher example count,
# no I/O.
_pure_settings = settings(max_examples=100, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow])

# Properties that register()/compare() through real temp-dir file + ledger
# I/O per example: fewer examples (still well above the sibling-repo floor),
# generous deadline. Stress-run at 300-500 while developing this file (see
# report); settled here at the CI-reasonable end of that range.
_io_settings = settings(max_examples=60, deadline=None,
                        suppress_health_check=[HealthCheck.too_slow,
                                              HealthCheck.function_scoped_fixture])

# The three unicode line-separator characters at the center of the bug class:
# NEL (U+0085), LINE SEPARATOR (U+2028), PARAGRAPH SEPARATOR (U+2029).
_LINE_SEP_CHARS = "  "

_id_alphabet = string.ascii_letters + string.digits + "-_"
_probe_id = st.text(alphabet=_id_alphabet, min_size=1, max_size=16)
_plain_text = st.text(max_size=60)
_nonblank_text = st.text(min_size=1, max_size=30).filter(lambda s: s.strip() != "")

_text_with_line_seps = st.text(
    alphabet=st.one_of(
        st.characters(blacklist_categories=("Cs",), max_codepoint=0x2FFF),
        st.sampled_from(list(_LINE_SEP_CHARS)),
    ),
    min_size=1, max_size=60,
)

_exact_scoring = st.builds(
    lambda answer, distractors: {"type": "exact_match", "answer": answer,
                                 **({"distractors": distractors} if distractors else {})},
    _nonblank_text, st.lists(_nonblank_text, max_size=3))

_numeric_scoring = st.builds(
    lambda answer, tolerance: {"type": "numeric_tolerance", "answer": answer,
                               "tolerance": tolerance},
    st.floats(allow_nan=False, allow_infinity=False, min_value=-1e6, max_value=1e6),
    st.floats(allow_nan=False, allow_infinity=False, min_value=0, max_value=10))

_calibration_scoring = st.one_of(
    st.builds(lambda answer: {"type": "calibration", "answerable": True, "answer": answer},
             _nonblank_text),
    st.just({"type": "calibration", "answerable": False}),
)

_scoring_strategy = st.one_of(_exact_scoring, _numeric_scoring, _calibration_scoring)

_probe_strategy = st.builds(Probe, id=_probe_id, prompt=_plain_text, scoring=_scoring_strategy)

_probe_set_strategy = st.lists(_probe_strategy, min_size=1, max_size=8,
                               unique_by=lambda p: p.id)


def _write_probes(path: Path, probes: list[Probe]) -> None:
    path.write_text(
        "\n".join(json.dumps(p.as_dict(), ensure_ascii=False) for p in probes) + "\n",
        encoding="utf-8")


def _stable_runner() -> CallableRunner:
    """A deterministic in-process 'model' -- reverses the prompt. Content
    doesn't matter for these properties, only that it's a pure function of
    the prompt (no clock, no randomness) so register()/compare() calls are
    reproducible."""
    return CallableRunner(lambda p: p[::-1], label="stable-reverse")


# ---------------------------------------------------------------------------
# 1. Registration determinism + order-sensitivity
# ---------------------------------------------------------------------------

@_io_settings
@given(probes=_probe_set_strategy)
def test_registration_deterministic_same_order(probes):
    """Same probe set, same order, same runner -> byte-identical digest,
    items, and aggregate across two independent register() calls (different
    temp dirs, so only registered_at/_file legitimately differ)."""
    runner = _stable_runner()
    with tempfile.TemporaryDirectory() as d:
        td = Path(d)
        reg1, _ = register(list(probes), label="det", runner=runner,
                           out_dir=td / "r1", ledger_path=None)
        reg2, _ = register(list(probes), label="det", runner=runner,
                           out_dir=td / "r2", ledger_path=None)
    assert reg1["probe_set_digest"] == reg2["probe_set_digest"]
    assert reg1["items"] == reg2["items"]
    assert reg1["aggregate"] == reg2["aggregate"]
    assert reg1["items_digest"] == reg2["items_digest"]


@_io_settings
@given(probes=_probe_set_strategy, data=st.data())
def test_probe_set_digest_order_independent_items_order_follows_input(probes, data):
    """What the module actually promises (per `probe_set_digest`'s and
    `load_probes`'s docstrings): the DIGEST is canonicalized by sorting on
    id, so reordering the probe set doesn't change it. NOT promised, and not
    true: that `register()`'s output `items` list is reordered the same way
    when given an already-loaded list directly (as opposed to going through
    `load_probes`, which does canonicalize). `run_probes` iterates the probes
    in the order it's handed them. This pins the real, narrower contract
    instead of assuming a blanket order-independence the code doesn't
    provide for this path."""
    assume(len(probes) >= 2)
    shuffled = data.draw(st.permutations(probes))
    assume([p.id for p in shuffled] != [p.id for p in probes])

    d1 = probe_set_digest(probes)
    d2 = probe_set_digest(shuffled)
    assert d1 == d2, "probe_set_digest must be order-independent (canonicalized by id)"

    runner = _stable_runner()
    with tempfile.TemporaryDirectory() as d:
        td = Path(d)
        reg1, _ = register(list(probes), label="order-a", runner=runner,
                           out_dir=td / "r1", ledger_path=None)
        reg2, _ = register(list(shuffled), label="order-b", runner=runner,
                           out_dir=td / "r2", ledger_path=None)

    # aggregate is a sum/count over the same multiset -> order-independent
    assert reg1["aggregate"]["mean"] == reg2["aggregate"]["mean"]
    assert reg1["aggregate"]["n"] == reg2["aggregate"]["n"]
    # but the ITEMS list order follows input order, not canonicalized --
    # pinning the real (undocumented-as-order-independent) behavior
    assert [it["id"] for it in reg1["items"]] == [p.id for p in probes]
    assert [it["id"] for it in reg2["items"]] == [p.id for p in shuffled]


@_io_settings
@given(probes=_probe_set_strategy, data=st.data())
def test_load_probes_canonicalizes_order_from_file(probes, data):
    """`load_probes`'s own docstring: probes are returned sorted by id --
    canonicalized, not file order -- specifically so the digest (and the
    run) is stable against a probe set being reordered in the source file
    without its content changing. Verify that promise directly: two files
    holding the same probes in different orders load to the identical
    canonical order."""
    assume(len(probes) >= 2)
    shuffled = data.draw(st.permutations(probes))
    with tempfile.TemporaryDirectory() as d:
        td = Path(d)
        f1, f2 = td / "a.jsonl", td / "b.jsonl"
        _write_probes(f1, list(probes))
        _write_probes(f2, list(shuffled))
        loaded1 = load_probes(f1)
        loaded2 = load_probes(f2)
    assert [p.id for p in loaded1] == [p.id for p in loaded2]
    assert [p.id for p in loaded1] == sorted(p.id for p in probes)
    assert probe_set_digest(loaded1) == probe_set_digest(loaded2)


# ---------------------------------------------------------------------------
# 2. Scoring determinism
# ---------------------------------------------------------------------------

@_pure_settings
@given(scoring=_scoring_strategy, output=st.text(max_size=200))
def test_score_item_deterministic_across_repeated_calls(scoring, output):
    """Fixed scoring config + fixed (byte-identical) response text ->
    byte-identical ScoreResult, every time, no hidden state."""
    r1 = score_item(scoring, output)
    r2 = score_item(scoring, output)
    r3 = score_item(scoring, output)
    assert r1.score == r2.score == r3.score
    assert r1.max_score == r2.max_score == r3.max_score
    assert r1.detail == r2.detail == r3.detail


@_pure_settings
@given(answer=st.text(alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E),
                      min_size=1, max_size=20)
      .filter(lambda s: s.strip(".!?") != ""),
      lead_ws=st.text(alphabet=" \t", max_size=5),
      trail_ws=st.text(alphabet=" \t", max_size=5),
      trail_punct=st.sampled_from(["", ".", "!", "?", "..", "?!"]))
def test_exact_match_normalization_invariant_across_surface_variants(
       answer, lead_ws, trail_ws, trail_punct):
    """Stand-in for 'paraphrase' testing: real semantic paraphrases aren't
    Hypothesis-generatable, but literal surface-form variants that the
    scorer's own documented normalization (`_normalize`: strip, casefold-ish
    lower, collapse whitespace, strip trailing .!?) claims to treat as
    identical are. Wrapping the same answer in whitespace/case/punctuation
    noise must score identically to the bare answer -- and must do so
    deterministically.

    The answer is filtered to exclude punctuation-only strings (e.g. a bare
    "!"): `_normalize`'s own `.rstrip(".!?")` legitimately reduces those to
    an empty string, which `score_exact_match` special-cases to a 0.0 "empty
    expected answer" -- a real, sane design choice (an all-punctuation
    expected answer can never match anything), not the normalization
    invariant this test is checking. Found by an early run of this test;
    it's a test-construction gap, not a package bug -- see the report."""
    output = lead_ws + answer.upper() + trail_ws + trail_punct
    r1 = score_exact_match(output, answer)
    r2 = score_exact_match(output, answer)
    assert r1.score == r2.score == 1.0
    assert r1.detail == r2.detail


@_io_settings
@given(probes=_probe_set_strategy)
def test_run_probes_scoring_deterministic_across_repeated_registrations(probes):
    """The full pipeline version of determinism: registering the identical
    probe set against the identical runner twice must produce identical
    per-item scores -- not just identical scoring-function output in
    isolation, but identical output through the real register() call path
    (load -> run -> score -> aggregate)."""
    runner = _stable_runner()
    with tempfile.TemporaryDirectory() as d:
        td = Path(d)
        reg1, _ = register(list(probes), label="run-det", runner=runner,
                           out_dir=td / "r1", ledger_path=None)
        reg2, _ = register(list(probes), label="run-det", runner=runner,
                           out_dir=td / "r2", ledger_path=None)
    scores1 = [it["score"] for it in reg1["items"]]
    scores2 = [it["score"] for it in reg2["items"]]
    assert scores1 == scores2


# ---------------------------------------------------------------------------
# 3. Forged-probe detection -- the security-critical property
# ---------------------------------------------------------------------------

@_io_settings
@given(probes=_probe_set_strategy, data=st.data())
def test_any_content_tampering_is_detected_never_silently_accepted(probes, data):
    """The invariant this package's whole pitch depends on: a stored
    registration is supposed to be a trustworthy 'before' snapshot to diff
    a substrate swap against. Any tampering with the STORED scored content
    (an item's score, an item's output, the item ORDER, or dropping items
    off the end) -- applied directly to the registration JSON file on disk,
    exactly as an attacker or a corrupting bug would -- must be reliably
    reported as `valid: False` by compare(), never silently accepted as a
    genuine 'before' state feeding into a `valid: True` diff.

    This is a REAL, FIXED bug, not a pre-existing pass: before this pass,
    compare() read reg["items"]/reg["aggregate"] straight off disk with zero
    verification against anything (the ledger chained only the aggregate
    MEAN, and compare() never even looked at the ledger). Every mutation
    kind exercised here was silently accepted as `valid: True` on the
    unfixed code -- confirmed by hand before writing the fix (see the
    report's before/after repro)."""
    runner = _stable_runner()
    with tempfile.TemporaryDirectory() as d:
        td = Path(d)
        probes_file = td / "probes.jsonl"
        _write_probes(probes_file, list(probes))
        loaded = load_probes(probes_file)
        reg, path = register(loaded, label="forge-target", runner=runner,
                             out_dir=td / "r", ledger_path=td / "l.jsonl",
                             probes_path=probes_file)
        raw = json.loads(path.read_text(encoding="utf-8"))
        n = len(raw["items"])
        assert n >= 1

        kinds = ["flip_score", "reword_output", "truncate"]
        if n >= 2:
            kinds += ["reorder", "swap_scores"]
        kind = data.draw(st.sampled_from(kinds))

        mutated = copy.deepcopy(raw)
        if kind == "flip_score":
            idx = data.draw(st.integers(min_value=0, max_value=n - 1))
            old = mutated["items"][idx]["score"]
            new = data.draw(
                st.floats(allow_nan=False, allow_infinity=False,
                         min_value=-100, max_value=100).filter(lambda x: x != old))
            mutated["items"][idx]["score"] = new
        elif kind == "reword_output":
            idx = data.draw(st.integers(min_value=0, max_value=n - 1))
            old = mutated["items"][idx].get("output") or ""
            mutated["items"][idx]["output"] = old + "FORGED-BY-PROPERTY-TEST"
        elif kind == "truncate":
            mutated["items"] = mutated["items"][:-1]
        elif kind == "reorder":
            mutated["items"] = list(reversed(mutated["items"]))
            assume(mutated["items"] != raw["items"])
        elif kind == "swap_scores":
            i = data.draw(st.integers(min_value=0, max_value=n - 1))
            j = data.draw(st.integers(min_value=0, max_value=n - 1))
            assume(i != j)
            mutated["items"][i]["score"], mutated["items"][j]["score"] = (
                mutated["items"][j]["score"], mutated["items"][i]["score"])
            assume(mutated["items"] != raw["items"])

        assume(mutated != raw)  # only assert on mutations that changed something
        path.write_text(json.dumps(mutated, indent=2, ensure_ascii=False),
                        encoding="utf-8")

        report, _ = compare(path, runner=runner, probes_path=probes_file,
                            out_dir=td / "c", ledger_path=td / "l.jsonl")
    assert report["valid"] is False, (
        f"tampering ({kind}) on a chained registration went UNDETECTED -- "
        f"forged content was scored as genuine (valid: True)")
    assert report.get("reason")


def test_tamper_check_still_fires_when_against_path_form_differs_from_recorded():
    """B-1 (product audit 2026-08-23): the tamper check above only runs if
    the ledger row's `registration_file` string-matches `against`. register()
    records whatever form `out_dir` was given -- an absolute tempdir path
    here, matching the CLI's realistic default of a RELATIVE "registrations/"
    -- and a caller that passes `--against` in a *different* form (the
    ordinary case for automation resolving a path before using it) must not
    silently skip the check just because the two strings don't match byte
    for byte. Register with the absolute form, tamper the file, then compare
    against a RELATIVE re-spelling of the exact same file -- the tamper must
    still be caught."""
    runner = _stable_runner()
    with tempfile.TemporaryDirectory() as d:
        td = Path(d)
        probes_file = td / "probes.jsonl"
        probes_file.write_text(
            json.dumps({"id": "a", "prompt": "Paris",
                       "scoring": {"type": "exact_match", "answer": "Paris"}},
                      ensure_ascii=False) + "\n",
            encoding="utf-8")
        loaded = load_probes(probes_file)
        reg, path = register(loaded, label="path-form-target", runner=runner,
                             out_dir=td / "r", ledger_path=td / "l.jsonl",
                             probes_path=probes_file)
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["items"][0]["score"] = 0.0 if raw["items"][0]["score"] != 0.0 else 1.0
        path.write_text(json.dumps(raw, indent=2, ensure_ascii=False),
                        encoding="utf-8")

        # A different STRING form of the identical file -- exactly what an
        # automation script produces resolving a path it was handed, or a
        # relative respelling under the same cwd. `str(Path(against))` alone
        # (the pre-fix match key) would not equal the absolute string
        # register() recorded, even though it is the same file on disk.
        relative_against = os.path.relpath(path, start=Path.cwd())

        report, _ = compare(relative_against, runner=runner,
                            probes_path=probes_file, out_dir=td / "c",
                            ledger_path=td / "l.jsonl")
    assert report["valid"] is False, (
        "tampering went UNDETECTED when --against was spelled in a "
        "different (but equivalent) path form than register() recorded "
        "-- B-1: the tamper check was silently skipped, not merely lenient")
    assert report.get("invalid_kind") == "registration_tampered"


def test_tamper_check_still_fires_across_a_working_directory_change():
    """B-1 RESIDUAL, found by Fable's independent review (2026-08-24) after
    the first B-1 fix landed: `.resolve()` closes the relative-vs-absolute
    FORM mismatch, but a resolved path is only correct relative to the
    CURRENT cwd. If register() and compare() use relative out_dir/ledger_path
    defaults (this CLI's own defaults) and run from DIFFERENT working
    directories, the ledger's relative-recorded path and the current
    --against both resolve against the wrong cwd and disagree again --
    the exact same silent-skip shape as the original B-1, one level down.
    compare() must now REFUSE (chain_unlocatable) rather than silently pass
    when a chain was requested (ledger_path given, ledger exists, verifies
    clean) but no matching row can be found."""
    runner = _stable_runner()
    orig_cwd = Path.cwd()
    dir_a = tempfile.mkdtemp()
    dir_c = tempfile.mkdtemp()
    try:
        os.chdir(dir_a)
        probes_file = Path("probes.jsonl")
        probes_file.write_text(
            json.dumps({"id": "a", "prompt": "Paris",
                       "scoring": {"type": "exact_match", "answer": "Paris"}},
                      ensure_ascii=False) + "\n",
            encoding="utf-8")
        loaded = load_probes(probes_file)
        # Relative out_dir/ledger_path -- this CLI's own defaults -- recorded
        # into the ledger row as relative strings, correct only from dir_a.
        reg, path = register(loaded, label="cwd-target", runner=runner,
                             out_dir="regs", ledger_path="ledger.jsonl",
                             probes_path=probes_file)
        abs_reg_path = path.resolve()
        abs_ledger_path = Path("ledger.jsonl").resolve()
        abs_probes_path = probes_file.resolve()

        raw = json.loads(abs_reg_path.read_text(encoding="utf-8"))
        raw["items"][0]["score"] = 0.0 if raw["items"][0]["score"] != 0.0 else 1.0
        abs_reg_path.write_text(json.dumps(raw, indent=2, ensure_ascii=False),
                                encoding="utf-8")

        # Move to an unrelated cwd. --against and ledger_path are passed as
        # ABSOLUTE so the files themselves are still readable -- only the
        # ledger's OWN relative-recorded registration_file, resolved against
        # the new cwd, now points nowhere near the real file.
        os.chdir(dir_c)
        report, _ = compare(str(abs_reg_path), runner=runner,
                            probes_path=str(abs_probes_path), out_dir="cmp",
                            ledger_path=str(abs_ledger_path))
    finally:
        os.chdir(orig_cwd)
    assert report["valid"] is False, (
        "tampering went UNDETECTED across a working-directory change -- "
        "B-1 residual: the tamper check was silently skipped again")
    assert report.get("invalid_kind") == "chain_unlocatable"


@_io_settings
@given(probes=_probe_set_strategy)
def test_untampered_chained_registration_still_compares_clean(probes):
    """The other side of the invariant: the tamper check must not be a
    trigger-happy false-positive machine. A genuine, untouched, chained
    registration compared with the same runner must still report
    `valid: True`, zero flips, zero delta -- exactly as it did before this
    pass added the check."""
    runner = _stable_runner()
    with tempfile.TemporaryDirectory() as d:
        td = Path(d)
        probes_file = td / "probes.jsonl"
        _write_probes(probes_file, list(probes))
        loaded = load_probes(probes_file)
        reg, path = register(loaded, label="clean", runner=runner,
                             out_dir=td / "r", ledger_path=td / "l.jsonl",
                             probes_path=probes_file)
        report, _ = compare(path, runner=runner, probes_path=probes_file,
                            out_dir=td / "c", ledger_path=td / "l.jsonl")
    assert report["valid"] is True
    assert report["n_flips"] == 0
    assert report["aggregate_delta"]["mean"] == 0.0


@_io_settings
@given(probes=_probe_set_strategy)
def test_tampering_a_ledger_file_directly_is_also_detected(probes):
    """The chain itself is the other half of the trust anchor: hand-editing
    a row already written into the ledger file (not just the registration
    JSON) must break `Ledger.verify()`, and `compare()` must refuse to
    proceed against a broken chain rather than silently trusting a
    ledger-chained `items_digest` from a chain that no longer verifies."""
    runner = _stable_runner()
    with tempfile.TemporaryDirectory() as d:
        td = Path(d)
        probes_file = td / "probes.jsonl"
        _write_probes(probes_file, list(probes))
        loaded = load_probes(probes_file)
        ledger_path = td / "l.jsonl"
        reg, path = register(loaded, label="ledger-tamper", runner=runner,
                             out_dir=td / "r", ledger_path=ledger_path,
                             probes_path=probes_file)
        # Hand-edit the raw ledger file: change the chained items_digest to
        # a plausible-looking but wrong value, exactly as an attacker
        # rewriting the row (without recomputing the chain) would.
        lines = ledger_path.read_text(encoding="utf-8").splitlines()
        assert lines
        row = json.loads(lines[-1])
        row["items_digest"] = "sha256:json-c14n:v1:" + "0" * 64
        lines[-1] = json.dumps(row, ensure_ascii=False)
        ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        assert not Ledger(ledger_path).verify().ok

        report, _ = compare(path, runner=runner, probes_path=probes_file,
                            out_dir=td / "c", ledger_path=ledger_path)
    assert report["valid"] is False


# ---------------------------------------------------------------------------
# 4. The unicode-line-separator class: U+0085 / U+2028 / U+2029
# ---------------------------------------------------------------------------
# VERDICT: present in `load_probes` before this pass, fixed this pass.
# `grep -n "ensure_ascii\|splitlines\|readlines" arcaeon_baseline/*.py`
# found exactly one splitlines() call, in `load_probes`, reading probe
# `.jsonl` files written (by any tool, including this package's own
# `.as_dict()` + `json.dumps(..., ensure_ascii=False)` idiom used
# throughout its own test suite) without escaping these three characters.
# `register()`/`compare()`'s OWN writes (the registration/diff JSON files)
# were never at risk -- those are read back with `json.loads(full_text)`,
# not a line-oriented reader. arcaeon-ledger's Ledger.__iter__/verify_file
# already carry the fix (checked: uses `.split("\\n")`, not `.splitlines()`,
# confirmed via `git log`/inline comments dated 2026-08-15, "Fixed,
# unreleased" -- active because this repo's arcaeon-ledger dependency is
# editable-installed against the live checkout, not a stale release).

@_io_settings
@given(prompt=_text_with_line_seps, answer=_text_with_line_seps)
def test_unicode_line_separators_round_trip_through_register_and_compare(prompt, answer):
    """End-to-end: a probe whose prompt/answer legitimately contains
    U+0085/U+2028/U+2029 must load, register, and compare cleanly, with
    content preserved exactly and the ledger staying green throughout."""
    # Fable's independent review (2026-08-24) confirmed this reproduces on
    # pre-fix code too -- a test-strategy gap, not a product bug.
    # `answer.strip() != ""` isn't the right filter: `score_exact_match`
    # scores against `_normalize(answer)`, which also rstrips ".!?" -- an
    # answer of bare "?" survives `.strip()` but normalizes to "", and
    # `_normalize`'s own "empty expected answer" refusal (documented,
    # deliberate) then correctly scores 0.0 against this test's implicit
    # assumption of a perfect-echo 1.0. Filter on the actual predicate the
    # scorer uses, not an approximation of it.
    assume(_normalize(answer) != "")
    with tempfile.TemporaryDirectory() as d:
        td = Path(d)
        probes_file = td / "probes.jsonl"
        row = {"id": "u1", "prompt": prompt,
              "scoring": {"type": "exact_match", "answer": answer}}
        probes_file.write_text(json.dumps(row, ensure_ascii=False) + "\n",
                               encoding="utf-8")

        probes = load_probes(probes_file)
        assert len(probes) == 1
        assert probes[0].prompt == prompt
        assert probes[0].scoring["answer"] == answer

        runner = CallableRunner(lambda p, a=answer: a)
        reg, path = register(probes, label="unicode-line-sep", runner=runner,
                             out_dir=td / "r", ledger_path=td / "l.jsonl",
                             probes_path=probes_file)
        assert reg["aggregate"]["n"] == 1
        assert reg["aggregate"]["n_scored"] == 1
        assert reg["items"][0]["score"] == 1.0

        assert Ledger(td / "l.jsonl").verify().ok

        report, _ = compare(path, runner=runner, probes_path=probes_file,
                            out_dir=td / "c", ledger_path=td / "l.jsonl")
        assert report["valid"] is True
        assert report["n_flips"] == 0
        assert Ledger(td / "l.jsonl").verify().ok


@_io_settings
@given(prompts=st.lists(_text_with_line_seps, min_size=1, max_size=6),
      answers=st.lists(_text_with_line_seps.filter(lambda s: s.strip() != ""),
                       min_size=1, max_size=6))
def test_unicode_line_separators_preserve_record_count_and_boundaries(prompts, answers):
    """The corruption shape this bug class produces isn't a crash on every
    input -- with MULTIPLE probes in one file, a separator can silently
    slice one JSON object into fragments that merge into or split from a
    neighboring line, changing the RECORD COUNT without necessarily raising.
    Confirm N probes in, N probes out, with the right ids and content, for
    probe sets that legitimately contain the class throughout."""
    n = min(len(prompts), len(answers))
    assume(n >= 1)
    rows = [{"id": f"p{i:03d}", "prompt": prompts[i],
            "scoring": {"type": "exact_match", "answer": answers[i]}}
           for i in range(n)]
    text = "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n"
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "probes.jsonl"
        f.write_text(text, encoding="utf-8")
        probes = load_probes(f)
    assert len(probes) == n
    assert [p.id for p in probes] == sorted(f"p{i:03d}" for i in range(n))
    by_id = {p.id: p for p in probes}
    for i in range(n):
        pid = f"p{i:03d}"
        assert by_id[pid].prompt == prompts[i]
        assert by_id[pid].scoring["answer"] == answers[i]


def test_unicode_line_separator_repro_before_fix_documented():
    """Not a property test -- a fixed-input pin of the exact repro used to
    find and confirm this bug by hand before writing the property tests
    above (a single probe, U+2028 in the prompt). Kept as a cheap, always-
    run regression guard alongside the property-generalized versions."""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "probes.jsonl"
        row = {"id": "p1", "prompt": "first line second thirdfourth",
              "scoring": {"type": "exact_match", "answer": "ok"}}
        f.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
        probes = load_probes(f)
    assert len(probes) == 1
    assert probes[0].prompt == row["prompt"]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
