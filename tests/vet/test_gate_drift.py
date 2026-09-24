"""Tests for mcp_vet.gate_drift (task 073) — the differential accept-set check
for pattern gates. Spec: memory/FINDING_regex_gate_drift_is_a_real_check_class_2026-09-12.md.

Three things this file proves, not just exercises:

1. Every REAL registered gate (badge.py / checks.py patterns this project
   actually ships) is clean against its committed baseline right now. This is
   the test CI runs on every push/PR that touches projects/mcp_vet/**
   (.github/workflows/mcp_vet-tests.yml) — the scheduled reminder the module
   docstring promises exists.
2. The check can go RED in both directions on the real code, not a toy
   pattern: a narrowed DETECTOR (Stripe live-key quantifier tightened, the
   exact worked example in the finding) and a widened ALLOWLIST
   (_PUBLIC_PREFIXES gains an entry). Each sabotage is applied via
   monkeypatch (auto-reverted) and re-checked green after.
3. An empty corpus and a missing baseline are both LOUD, distinct statuses —
   never silently "ok", never silently "no flips".
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest

from arcaeon.prove.vet import gate_drift as gd
from arcaeon.prove.vet import checks as _checks


# --- 1. the real gates, checked on every CI run -------------------------------

@pytest.mark.parametrize("name", sorted(gd.GATES))
def test_registered_real_gates_are_clean_against_committed_baseline(name):
    report = gd.check_gate(name)
    assert report.status == gd.STATUS_OK, (
        f"{name}: {report.status} — {report.message}\n"
        "If this pattern was deliberately widened/narrowed, run "
        "`python -m arcaeon.prove.vet.gate_drift --update-baseline` and commit the "
        "resulting baseline diff as the declaration.")


def test_every_registered_gate_has_a_non_empty_corpus_file():
    """A gate with no corpus file cannot be checked at all — catch that at
    registration time, not by noticing the CLI print NO_COVERAGE later."""
    for name in gd.GATES:
        corpus = gd.load_corpus(name)
        assert corpus, f"{name}: corpus is empty or missing at {gd._corpus_path(name)}"


def test_every_registered_gate_corpus_has_at_least_one_true_and_one_false():
    """A corpus that is all-positive or all-negative cannot see a flip in one
    of the two directions even in principle — it isn't a differential corpus,
    it's a smoke test wearing one."""
    for name in gd.GATES:
        gate = gd.GATES[name]
        matcher = gd.resolve_matcher(gate)
        corpus = gd.load_corpus(name)
        verdicts = {matcher(s) for s in corpus}
        assert verdicts == {True, False}, (
            f"{name}: corpus must contain at least one accepted and one "
            f"refused string, got only {verdicts}")


# --- 2a. sabotage proof: a NARROWED detector ----------------------------------

def test_narrowing_the_stripe_live_key_quantifier_is_caught(monkeypatch):
    """This is the finding's own worked example: tightening {24,} to {32,}
    reads as hardening and is a silent hole — a real 28-character key stops
    being flagged. Nothing else in the suite would notice."""
    import re as _re

    name = "checks.secret_stripe_live_key_shape"
    baseline_before = gd.check_gate(name)
    assert baseline_before.status == gd.STATUS_OK

    with monkeypatch.context() as m:
        narrowed = _re.compile(r"\bsk_live_[0-9a-zA-Z]{32,}\b")
        sabotaged = [(label, narrowed if label == "Stripe live secret key" else pattern)
                     for label, pattern in _checks._VENDOR_SHAPES]
        m.setattr(_checks, "_VENDOR_SHAPES", sabotaged)

        report = gd.check_gate(name)
        assert report.status == gd.STATUS_DRIFT, report.message
        assert report.lost == ["sk_live_A1b2C3d4E5f6G7h8I9j0K1L2M3n4"], report.lost
        assert report.gained == [], report.gained
        assert "NARROWED" in report.message

    # monkeypatch context exited — real pattern restored, must be green again
    restored = gd.check_gate(name)
    assert restored.status == gd.STATUS_OK, restored.message


# --- 2b. sabotage proof: a WIDENED allowlist ----------------------------------

def test_widening_the_public_prefix_allowlist_is_caught(monkeypatch):
    """_PUBLIC_PREFIXES exists to exempt test/publishable-shaped values from
    the secret-in-code check. Adding a prefix that matches a live-secret shape
    silently un-flags a real-looking key -- the allowlist-widening half of the
    class, on the one real allowlist gate this project ships."""
    name = "checks.secret_public_prefix_exemption"
    baseline_before = gd.check_gate(name)
    assert baseline_before.status == gd.STATUS_OK

    with monkeypatch.context() as m:
        m.setattr(_checks, "_PUBLIC_PREFIXES", _checks._PUBLIC_PREFIXES + ("sk_live_abcd",))

        report = gd.check_gate(name)
        assert report.status == gd.STATUS_DRIFT, report.message
        assert report.gained == ["sk_live_abcdEFGH12345678ijklMNOP"], report.gained
        assert report.lost == [], report.lost
        assert "WIDENED" in report.message

    restored = gd.check_gate(name)
    assert restored.status == gd.STATUS_OK, restored.message


# --- 3. loud, not green: empty corpus and missing baseline --------------------

def test_empty_corpus_reports_no_coverage_never_ok_or_silent_pass():
    name = "checks.secret_stripe_live_key_shape"
    report = gd.check_gate(name, corpus=[])
    assert report.status == gd.STATUS_NO_COVERAGE
    assert report.status != gd.STATUS_OK
    assert "no change" not in report.message.lower()  # that phrase is reserved for a real, checked "ok"
    assert "empty" in report.message.lower()


def test_missing_baseline_reports_no_baseline_not_ok(tmp_path, monkeypatch):
    import re as _re
    monkeypatch.setattr(gd, "_FIXTURE_ROOT", tmp_path)
    gd.register_gate("test.scratch_gate", "detector", lambda: _re.compile(r"x"))
    # corpus present, baseline absent
    (tmp_path / "test.scratch_gate.corpus.json").write_text('["ax", "bb"]', encoding="utf-8")
    try:
        report = gd.check_gate("test.scratch_gate")
        assert report.status == gd.STATUS_NO_BASELINE
        assert report.status != gd.STATUS_OK
    finally:
        gd.GATES.pop("test.scratch_gate", None)


def test_unknown_corpus_entries_are_reported_but_are_not_a_flip(tmp_path, monkeypatch):
    """A corpus that grew since the last baseline update is not a drift — it
    has nothing to compare the new strings against — but it must still be
    visible in the report, not swallowed."""
    import re as _re
    monkeypatch.setattr(gd, "_FIXTURE_ROOT", tmp_path)
    gd.register_gate("test.growth_gate", "detector", lambda: _re.compile(r"x"))
    try:
        gd.write_baseline("test.growth_gate", {"ax": True, "bb": False})
        report = gd.check_gate("test.growth_gate", corpus=["ax", "bb", "new-xylophone"])
        assert report.status == gd.STATUS_OK  # ax/bb unchanged, no flip
        assert report.new_corpus_entries == ["new-xylophone"]
        assert "uncompared" in report.message
    finally:
        gd.GATES.pop("test.growth_gate", None)


# --- baseline file format: diffable in git ------------------------------------

def test_baseline_file_is_sorted_and_pretty_printed():
    p = gd._baseline_path("checks.secret_stripe_live_key_shape")
    text = p.read_text(encoding="utf-8")
    assert text.endswith("\n")
    import json
    data = json.loads(text)
    assert list(data) == sorted(data), "baseline keys must be sorted for a minimal git diff"


def test_update_baseline_refuses_on_empty_corpus(tmp_path, monkeypatch):
    import re as _re
    monkeypatch.setattr(gd, "_FIXTURE_ROOT", tmp_path)
    gd.register_gate("test.empty_gate", "detector", lambda: _re.compile(r"x"))
    try:
        report = gd.update_baseline_from_corpus("test.empty_gate")
        assert report.status == gd.STATUS_NO_COVERAGE
        assert not gd._baseline_path("test.empty_gate").exists()
    finally:
        gd.GATES.pop("test.empty_gate", None)


# --- CLI smoke ------------------------------------------------------------------

def test_cli_list_exits_zero(capsys):
    rc = gd.main(["--list"])
    assert rc == 0
    out = capsys.readouterr().out
    for name in gd.GATES:
        assert name in out


def test_cli_check_all_exits_zero_when_clean(capsys):
    rc = gd.main([])
    assert rc == 0


def test_cli_unknown_gate_exits_nonzero():
    assert gd.main(["no.such.gate"]) != 0
