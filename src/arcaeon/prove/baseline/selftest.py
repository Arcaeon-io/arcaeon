"""Self-test: golden scoring vectors + a full register/compare round-trip.

    python -m arcaeon.prove.baseline selftest
    python -m arcaeon.prove.baseline.selftest

Ships in the package rather than living only in CI, so a stranger runs it on
THEIR machine and trusts their own output, not ours. Everything here runs
in-process (a `CallableRunner` wrapping a plain Python function standing in
for "the model") — no subprocess, no network, no ollama required — so it
passes anywhere Python does. Exit code 0 = every check passed.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from . import Probe, compare, load_probes, probe_set_digest, register
from .runner import CallableRunner
from .scoring import (score_calibration, score_exact_match,
                      score_numeric_tolerance)

FIXTURE = [
    Probe("f01", "capital of France?", {"type": "exact_match", "answer": "Paris"}),
    Probe("f02", "2 + 2?", {"type": "numeric_tolerance", "answer": 4, "tolerance": 0}),
    Probe("f03", "boiling point of water C?",
         {"type": "calibration", "answerable": True, "answer": "100"}),
    Probe("f04", "what number am I thinking of?",
         {"type": "calibration", "answerable": False}),
]


def _write_fixture(dirpath: Path) -> Path:
    p = dirpath / "fixture.jsonl"
    p.write_text("\n".join(
        __import__("json").dumps(pr.as_dict()) for pr in FIXTURE) + "\n",
        encoding="utf-8")
    return p


def _good_model(prompt: str) -> str:
    if "France" in prompt:
        return "The answer is Paris."
    if "2 + 2" in prompt:
        return "4"
    if "boiling point" in prompt:
        return "100"
    if "thinking of" in prompt:
        return "I don't know, that's not something I can determine."
    return "???"


def _degraded_model(prompt: str) -> str:
    if "France" in prompt:
        return "Lyon"                       # now wrong
    if "2 + 2" in prompt:
        return "4"                          # unchanged
    if "boiling point" in prompt:
        return "I don't know."              # answerable item, now abstains
    if "thinking of" in prompt:
        return "42"                         # unanswerable item, now confident-wrong
    return "???"


def run() -> int:
    failures = 0

    def check(name: str, ok: bool, extra: str = "") -> None:
        nonlocal failures
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{('  ' + extra) if extra and not ok else ''}")

    print("== golden scoring vectors ==")
    check("exact_match: exact", score_exact_match("Paris", "Paris").score == 1.0)
    check("exact_match: whole-word-in-output",
         score_exact_match("The answer is Paris.", "Paris").score == 1.0)
    check("exact_match: substring-but-not-whole-word rejected",
         score_exact_match("Iranian", "Iran").score == 0.0)
    check("exact_match: no match",
         score_exact_match("London", "Paris").score == 0.0)

    check("numeric_tolerance: exact",
         score_numeric_tolerance("40", 40).score == 1.0)
    check("numeric_tolerance: within tolerance",
         score_numeric_tolerance("about 40.3 mph", 40, tolerance=0.5).score == 1.0)
    check("numeric_tolerance: outside tolerance",
         score_numeric_tolerance("41", 40, tolerance=0.5).score == 0.0)
    check("numeric_tolerance: trailing number preferred ('... = 40')",
         score_numeric_tolerance("Step 1 uses 60, so the answer is 40.", 40).score == 1.0)
    check("numeric_tolerance: no number found",
         score_numeric_tolerance("no idea", 40).score == 0.0)

    correct = score_calibration("Tokyo", answerable=True, answer="Tokyo")
    idk_answerable = score_calibration("I don't know.", answerable=True, answer="Tokyo")
    wrong = score_calibration("Osaka", answerable=True, answer="Tokyo")
    idk_unanswerable = score_calibration("I don't know.", answerable=False)
    confident_wrong = score_calibration("42", answerable=False)
    check("calibration: confident correct = +1.0", correct.score == 1.0)
    check("calibration: IDK on answerable = +0.2 (not free, not zero)",
         idk_answerable.score == 0.2)
    check("calibration: confident wrong (answerable) = -1.0", wrong.score == -1.0)
    check("calibration: honest IDK on unanswerable = +1.0",
         idk_unanswerable.score == 1.0)
    check("calibration: confident wrong (unanswerable) = -1.0",
         confident_wrong.score == -1.0)
    check("abstention-gaming guard holds: always-IDK scores below always-correct",
         (idk_answerable.score + idk_unanswerable.score) <
         (correct.score + idk_unanswerable.score))

    print("== hedge-wrapped-answer guard (found via our own abstention-gaming "
         "research, RESEARCH_43, fixed in v0.1.1) ==")
    hedge_correct = score_calibration(
        "I'm not sure, but I think it's Tokyo.", answerable=True, answer="Tokyo")
    hedge_wrong = score_calibration(
        "I'm not sure, but I think it's Osaka.", answerable=True, answer="Tokyo")
    check("hedge-wrapped CORRECT guess is caught: scores correct (+1.0), "
         "not the idk floor (the planted gaming case this fix closes)",
         hedge_correct.score == 1.0, f"got {hedge_correct.score}")
    check("a hedge-wrapped correct guess and a hedge-wrapped wrong guess are "
         "no longer indistinguishable (both used to score 0.2 flat)",
         hedge_correct.score != hedge_wrong.score,
         f"correct={hedge_correct.score} wrong={hedge_wrong.score}")
    print(f"  NOTE (documented gap, NOT closed by this fix): a hedge-wrapped "
         f"WRONG guess still lands on the idk_answerable floor "
         f"(scored {hedge_wrong.score} here) when the embedded guess isn't "
         f"the known answer — a deterministic keyword scorer can't tell "
         f"'wrong guess' from 'no guess' without an NLP guesser. See README.")

    print("== enumerate-everything guard (v0.1.2 — the sibling the v0.1.1 fix "
         "opened; opt-in per probe via `distractors`) ==")
    shotgun = "I'm not sure. It could be Osaka, Tokyo, Kyoto, or Nagoya."
    shot_undeclared = score_calibration(shotgun, answerable=True, answer="Tokyo")
    shot_declared = score_calibration(shotgun, answerable=True, answer="Tokyo",
                                      distractors=["Osaka", "Kyoto", "Nagoya"])
    check("without distractors, an enumerate-everything answer still scores "
         "correct (+1.0) — the honest, unclosed default",
         shot_undeclared.score == 1.0, f"got {shot_undeclared.score}")
    check("with distractors declared, it drops to the abstention floor "
         "instead of farming full credit",
         shot_declared.score == 0.2 and shot_declared.detail.get("shotgun") is True,
         f"got {shot_declared.score} detail={shot_declared.detail}")
    check("declaring distractors does NOT punish a genuine hedged-correct answer",
         score_calibration("I'm not sure, but I think it's Tokyo.",
                           answerable=True, answer="Tokyo",
                           distractors=["Osaka", "Kyoto"]).score == 1.0)

    print("== numeric boundaries (v0.1.2 — fragments of a larger number) ==")
    check("'1,000' is not read as 0 for an expected 0",
         score_numeric_tolerance("The answer is 1,000", 0.0).score == 0.0)
    check("'1,000' IS read as 1000",
         score_numeric_tolerance("The answer is 1,000", 1000.0).score == 1.0)
    check("'1e5' is not read as 5 for an expected 5",
         score_numeric_tolerance("It is 1e5", 5.0).score == 0.0)
    check("exact_match: '40' does not match inside '40.5'",
         score_exact_match("The result is 40.5 units", "40").score == 0.0)

    print("== probe set digest ==")
    d1 = probe_set_digest(FIXTURE)
    d2 = probe_set_digest(list(reversed(FIXTURE)))
    check("digest: order-invariant (canonicalized by id)", d1 == d2)
    mutated = list(FIXTURE)
    mutated[0] = Probe(mutated[0].id, "a different prompt entirely", mutated[0].scoring)
    check("digest: content-sensitive (edit flips it)", probe_set_digest(mutated) != d1)
    check("digest: self-describing (sha256:json-c14n:v1: prefix)",
         d1.startswith("sha256:json-c14n:v1:"))

    print("== load_probes validation ==")
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        bad = tdp / "bad.jsonl"
        bad.write_text('{"id": "x", "prompt": "p"}\n', encoding="utf-8")  # missing scoring
        try:
            load_probes(bad)
            check("load_probes rejects a probe missing 'scoring'", False)
        except ValueError:
            check("load_probes rejects a probe missing 'scoring'", True)

        dup = tdp / "dup.jsonl"
        dup.write_text(
            '{"id": "x", "prompt": "a", "scoring": {"type": "exact_match", "answer": "a"}}\n'
            '{"id": "x", "prompt": "b", "scoring": {"type": "exact_match", "answer": "b"}}\n',
            encoding="utf-8")
        try:
            load_probes(dup)
            check("load_probes rejects a duplicate id", False)
        except ValueError:
            check("load_probes rejects a duplicate id", True)

    print("== end-to-end: register -> compare (in-process, no subprocess) ==")
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        probes_file = _write_fixture(tdp)
        probes = load_probes(probes_file)
        ledger = tdp / "ledger.jsonl"

        reg, reg_path = register(
            probes, label="selftest-baseline", runner=CallableRunner(_good_model),
            out_dir=tdp / "registrations", ledger_path=ledger,
            probes_path=probes_file)
        check("register: writes a file", reg_path.exists())
        check("register: aggregate mean is 1.0 on the good model "
             "(3 correct-confident + 1 honest IDK, all top marks)",
             reg["aggregate"]["mean"] == 1.0, f"got {reg['aggregate']['mean']}")
        check("register: chained into the ledger", "_ledger_chain" in reg)

        same, _ = compare(reg_path, runner=CallableRunner(_good_model),
                          probes_path=probes_file, out_dir=tdp / "comparisons",
                          ledger_path=ledger)
        check("compare: unchanged model -> valid", same["valid"])
        check("compare: unchanged model -> zero flips", same["n_flips"] == 0,
             f"got {same['n_flips']}")
        check("compare: unchanged model -> delta ~0",
             abs(same["aggregate_delta"]["mean"]) < 1e-9)

        degraded, _ = compare(reg_path, runner=CallableRunner(_degraded_model),
                              probes_path=probes_file, out_dir=tdp / "comparisons",
                              ledger_path=ledger)
        check("compare: degraded model -> valid (same probe set)", degraded["valid"])
        check("compare: degraded model -> catches the flips (>=3 of 4 items moved)",
             degraded["n_flips"] >= 3, f"got {degraded['n_flips']}")
        check("compare: degraded model -> negative delta",
             degraded["aggregate_delta"]["mean"] < 0,
             f"got {degraded['aggregate_delta']['mean']}")
        check("compare: calibration_shift reports the abstention swap",
             degraded["calibration_shift"] is not None)
        check("compare: significance_note present for a smoke-test n",
             degraded["significance_note"] is not None)

        # Mutate the probe file between register and compare: the digest-
        # mismatch guard this whole product exists to prove.
        probes_file.write_text(
            probes_file.read_text(encoding="utf-8") + '\n', encoding="utf-8")  # no-op first
        mutated_file = tdp / "fixture.jsonl"
        text = mutated_file.read_text(encoding="utf-8")
        mutated_file.write_text(text.replace("Paris", "Lyon"), encoding="utf-8")
        invalid, _ = compare(reg_path, runner=CallableRunner(_good_model),
                             probes_path=mutated_file, out_dir=tdp / "comparisons",
                             ledger_path=ledger)
        check("compare: changed probe set -> valid=False", invalid["valid"] is False)
        check("compare: changed probe set -> names the reason",
             "changed" in invalid.get("reason", ""))

    print(f"\n{'ALL CHECKS PASSED' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
