"""Regression tests for the 0.1.2 scoring audit.

Written FAILING against 0.1.1. The headline one is the comparison-validity
hole: this package exists to answer "did the substrate change?", and it would
happily report its OWN scorer upgrade as a substrate change, with valid=True.

Run: python -m pytest test_scoring_integrity.py
"""
import json
import tempfile
from pathlib import Path

import pytest

from arcaeon.prove.baseline import (CallableRunner, compare, register,
                              SCORING_SEMANTICS)
from arcaeon.prove.baseline.scoring import (score_exact_match, score_numeric_tolerance,
                                      score_calibration)


# --------------------------------------------------------------------------
# 1. A scorer change must not be reported as a substrate change
# --------------------------------------------------------------------------

def _fixture(td, output):
    probes = td / "probes.jsonl"
    probes.write_text(json.dumps({
        "id": "p1", "prompt": "Capital of France?",
        "scoring": {"type": "calibration", "answerable": True, "answer": "Paris"},
    }) + "\n", encoding="utf-8")
    runner = CallableRunner(lambda _p: output, label="frozen")
    return probes, runner


def test_registration_records_the_scoring_semantics():
    with tempfile.TemporaryDirectory() as d:
        td = Path(d)
        probes, runner = _fixture(td, "Paris")
        reg, path = register(probes, label="x", runner=runner,
                             out_dir=td / "r", ledger_path=td / "l.jsonl")
        assert reg["scoring_semantics"] == SCORING_SEMANTICS
        assert reg["tool_version"]


def test_compare_refuses_when_the_scorer_changed_under_it():
    """The runner returns identical bytes both times — nothing about the
    substrate changed. Only the scorer version differs. That must not be
    reported as a measured delta."""
    with tempfile.TemporaryDirectory() as d:
        td = Path(d)
        probes, runner = _fixture(td, "I'm not sure, but I think it's Paris")
        reg, path = register(probes, label="pre-swap", runner=runner,
                             out_dir=td / "r", ledger_path=td / "l.jsonl")

        # rewrite the registration as if it had been made by an older scorer
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["scoring_semantics"] = "arcaeon-baseline:scoring:v1"
        raw["items"][0]["score"] = 0.2
        raw["items"][0]["detail"] = {"answerable": True, "abstained": True}
        raw["aggregate"]["mean"] = 0.2
        path.write_text(json.dumps(raw, indent=2), encoding="utf-8")

        diff, _ = compare(path, runner=runner, probes_path=probes,
                          out_dir=td / "c", ledger_path=td / "l.jsonl")
        assert diff["valid"] is False, "a scorer change was reported as a valid diff"
        assert "scoring" in diff["reason"].lower(), diff["reason"]
        assert diff["registered_scoring_semantics"] == "arcaeon-baseline:scoring:v1"
        assert diff["current_scoring_semantics"] == SCORING_SEMANTICS
        assert "aggregate_delta" not in diff


def test_compare_flags_a_registration_with_no_recorded_semantics():
    """Registrations written before 0.1.2 carry no field. They cannot be
    assumed compatible — 0.1.1 changed calibration scoring silently."""
    with tempfile.TemporaryDirectory() as d:
        td = Path(d)
        probes, runner = _fixture(td, "Paris")
        reg, path = register(probes, label="legacy", runner=runner,
                             out_dir=td / "r", ledger_path=td / "l.jsonl")
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw.pop("scoring_semantics")
        path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
        diff, _ = compare(path, runner=runner, probes_path=probes,
                          out_dir=td / "c", ledger_path=td / "l.jsonl")
        assert diff["valid"] is False
        assert diff["registered_scoring_semantics"] is None


def test_compare_still_works_when_semantics_match():
    with tempfile.TemporaryDirectory() as d:
        td = Path(d)
        probes, runner = _fixture(td, "Paris")
        reg, path = register(probes, label="ok", runner=runner,
                             out_dir=td / "r", ledger_path=td / "l.jsonl")
        diff, _ = compare(path, runner=runner, probes_path=probes,
                          out_dir=td / "c", ledger_path=td / "l.jsonl")
        assert diff["valid"] is True
        assert diff["n_flips"] == 0
        assert diff["aggregate_delta"]["mean"] == 0.0


# --------------------------------------------------------------------------
# 2. Numeric false positives
# --------------------------------------------------------------------------

@pytest.mark.parametrize("output,answer", [
    ("The result is 40.5 units", "40"),
    ("about 1.9x", "1"),
    ("we saw 100,000 hits", "100"),
    ("version 3.14.15", "3.14"),
])
def test_exact_match_does_not_credit_a_number_it_only_prefixes(output, answer):
    assert score_exact_match(output, answer).score == 0.0, (output, answer)


@pytest.mark.parametrize("output,answer", [
    ("The result is 40", "40"),
    ("The answer is 40.", "40"),
    ("40", "40"),
    ("It costs 3.14 dollars", "3.14"),
])
def test_exact_match_still_credits_a_real_numeric_hit(output, answer):
    assert score_exact_match(output, answer).score == 1.0, (output, answer)


@pytest.mark.parametrize("output,answer", [
    ("The answer is 1,000", 0.0),      # "000" was read as 0
    ("It is 1e5", 5.0),                # "5" was read out of the exponent
    ("roughly 2,500 items", 500.0),
])
def test_numeric_tolerance_rejects_fragments_of_a_larger_number(output, answer):
    assert score_numeric_tolerance(output, answer).score == 0.0, (output, answer)


@pytest.mark.parametrize("output,answer", [
    ("The answer is 1,000", 1000.0),   # grouped digits now parse correctly
    ("It is 1e5", 100000.0),
    ("so the answer is 40.", 40.0),
    ("-3.5 degrees", -3.5),
    ("about 12", 12.0),
])
def test_numeric_tolerance_reads_real_numbers(output, answer):
    assert score_numeric_tolerance(output, answer).score == 1.0, (output, answer)


# --------------------------------------------------------------------------
# 3. Distractors: the opt-in guard against enumerate-everything answers
# --------------------------------------------------------------------------

def test_shotgun_output_is_not_credited_when_distractors_are_declared():
    shotgun = "I'm not sure. It could be London, Paris, Berlin, or Rome."
    r = score_calibration(shotgun, answerable=True, answer="Paris",
                          distractors=["London", "Berlin", "Rome"])
    assert r.score == score_calibration("I don't know", answerable=True,
                                        answer="Paris").score
    assert r.detail.get("shotgun") is True


def test_a_clean_correct_answer_is_unaffected_by_declared_distractors():
    r = score_calibration("I'm not sure, but I think it's Paris", answerable=True,
                          answer="Paris", distractors=["London", "Berlin"])
    assert r.score == 1.0
    assert r.detail.get("correct") is True


def test_exact_match_distractors_do_the_same():
    assert score_exact_match("Paris, London, or Berlin", "Paris",
                             distractors=["London", "Berlin"]).score == 0.0
    assert score_exact_match("The answer is Paris.", "Paris",
                             distractors=["London", "Berlin"]).score == 1.0


def test_no_distractors_means_no_behaviour_change():
    shotgun = "It could be London, Paris, Berlin, or Rome."
    assert score_exact_match(shotgun, "Paris").score == 1.0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


# --- 0.1.5: a comparison that could not score every probe must say so ---------
# The defect: `valid` answers "did the exam stay the same underneath us", never
# "was every probe scored". An unscorable probe records score=None; a flip is a
# CHANGE in score, so None-vs-None can never flip; and the mean is over
# n_scored, so it stays 1.0. A model that began REFUSING half the probe set
# returned valid=True / n_flips=0 / mean=1.0 -- a perfect no-drift report over
# half an exam. This is the same bounded-scan-minting-a-green defect that
# arcaeon-ledger refuses by contract and that arcaeon-continuity 0.2.2 had to
# fence at its own layer; the root of it lives here.

import json as _json
import tempfile as _tempfile
from pathlib import Path as _Path

import arcaeon.prove.baseline as _ab
from arcaeon.prove.baseline import RunnerError as _RunnerError


class _PartialRunner:
    """Answers p1, refuses p2 -- an ordinary flaky/refusing model."""
    def describe(self):
        return {"name": "partial", "version": "1"}

    def run(self, prompt):
        if prompt == "boom":
            raise _RunnerError("model refused / API error")
        return "ok"


class _FullRunner:
    def describe(self):
        return {"name": "full", "version": "1"}

    def run(self, prompt):
        return "ok"


def _probe_file(d):
    p = _Path(d) / "p.jsonl"
    p.write_text("\n".join(_json.dumps(x) for x in [
        {"id": "p1", "prompt": "say ok", "scoring": {"type": "exact_match", "answer": "ok"}},
        {"id": "p2", "prompt": "boom", "scoring": {"type": "exact_match", "answer": "ok"}},
    ]) + "\n", encoding="utf-8")
    return p


def test_unscored_probes_make_the_comparison_bounded_not_clean():
    with _tempfile.TemporaryDirectory() as d:
        probes = _probe_file(d)
        r = _PartialRunner()
        reg, regpath = _ab.register(str(probes), runner=r, out_dir=str(_Path(d) / "b"),
                                    label="v1", ledger_path=str(_Path(d) / "l.jsonl"))
        rep, _ = _ab.compare(str(regpath), runner=r, out_dir=str(_Path(d) / "c"),
                             ledger_path=str(_Path(d) / "l.jsonl"))
        # The comparison genuinely IS valid and genuinely found no flips ...
        assert rep["valid"] is True
        assert rep["n_flips"] == 0
        assert rep["aggregate_after"]["mean"] == 1.0
        # ... over one probe out of two, and it must now say exactly that.
        assert rep["aggregate_after"]["n_errors"] == 1
        assert rep["verified_scope"] == "bounded_both_unscored", rep["verified_scope"]
        assert rep["coverage_note"] and "could not be scored" in rep["coverage_note"]


def test_a_fully_scored_comparison_is_full_scope_and_silent():
    with _tempfile.TemporaryDirectory() as d:
        probes = _probe_file(d)
        r = _FullRunner()
        reg, regpath = _ab.register(str(probes), runner=r, out_dir=str(_Path(d) / "b"),
                                    label="v1", ledger_path=str(_Path(d) / "l.jsonl"))
        rep, _ = _ab.compare(str(regpath), runner=r, out_dir=str(_Path(d) / "c"),
                             ledger_path=str(_Path(d) / "l.jsonl"))
        assert rep["verified_scope"] == "full", rep["verified_scope"]
        assert rep["coverage_note"] is None
        assert rep["aggregate_after"]["n_errors"] == 0


def test_a_baseline_registered_partial_is_flagged_even_when_now_complete():
    """The registered side can be the partial one -- you are comparing against
    a yardstick that was itself only half measured."""
    with _tempfile.TemporaryDirectory() as d:
        probes = _probe_file(d)
        reg, regpath = _ab.register(str(probes), runner=_PartialRunner(),
                                    out_dir=str(_Path(d) / "b"), label="v1",
                                    ledger_path=str(_Path(d) / "l.jsonl"))
        rep, _ = _ab.compare(str(regpath), runner=_FullRunner(),
                             out_dir=str(_Path(d) / "c"),
                             ledger_path=str(_Path(d) / "l.jsonl"))
        assert rep["verified_scope"] == "bounded_before_unscored", rep["verified_scope"]
        assert "registered baseline" in rep["coverage_note"]
