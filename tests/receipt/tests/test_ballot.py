"""Ballot Receipt: a tampered ballot fails verify, the scope-enforcement raise
in core.py fires through ballot_receipt (not just through build_receipt
called directly), and two ballots for the same trainee at different
timestamps both receipt cleanly with no anti-redo claim made (matching
does_not_prove: 'the sim was not attempted before')."""
from __future__ import annotations

import copy
import json
import subprocess
import sys

import pytest

from arcaeon.record.receipt import ballot
from arcaeon.record.receipt.core import load_receipt, verify_receipt

_BALLOT_TEMPLATE = {"per_answer": [{"score": 82, "verdict": "GOOD"}],
                    "overall": {"score": 82, "verdict": "GOOD", "summary": "Passes."}}


def _ballot() -> dict:
    # build_receipt/ballot_receipt store the ballot object BY REFERENCE (same
    # as call.py/cite.py's checks), so every test gets its own fresh copy --
    # otherwise one test's in-place tamper would corrupt a shared fixture.
    return copy.deepcopy(_BALLOT_TEMPLATE)


def test_tampered_ballot_fails_verify(tmp_path):
    rc = ballot.ballot_receipt(_ballot(), trainee="a. writer", scenario="oral_board.set1",
                               ledger_path=tmp_path / "l.jsonl", grader="ascenvo.vcs.oral_board",
                               timestamp="2026-09-12T08:00:00Z", witness=False, anchor=False)
    assert verify_receipt(rc, ledger_path=tmp_path / "l.jsonl")["ok"]

    # one score digit changed inside the sealed ballot object
    rc["checks"][0]["ballot"]["overall"]["score"] = 99
    res = verify_receipt(rc, ledger_path=tmp_path / "l.jsonl")
    assert not res["ok"]
    assert not res["body_digest_ok"]


def test_scope_enforcement_raise_fires_through_ballot_receipt(tmp_path, monkeypatch):
    # ballot_receipt does not accept a caller-supplied scope (same pattern as
    # cite/call/approval/authorship: the scope is the product, not an option) --
    # so proving core.py:192's raise actually reaches through this adapter,
    # rather than being caught or bypassed by ballot.py's own call site, means
    # breaking the module-level SCOPE it passes to build_receipt and confirming
    # the same ValueError still surfaces from ballot_receipt itself.
    monkeypatch.setattr(ballot, "SCOPE", {"proves": [], "does_not_prove": []})
    with pytest.raises(ValueError):
        ballot.ballot_receipt(_ballot(), trainee="a. writer", scenario="oral_board.set1",
                              ledger_path=tmp_path / "l.jsonl", witness=False, anchor=False)


def test_two_ballots_same_trainee_different_timestamps_both_receipt_cleanly(tmp_path):
    lp = tmp_path / "l.jsonl"
    rc1 = ballot.ballot_receipt(_ballot(), trainee="a. writer", scenario="oral_board.set1",
                                ledger_path=lp, timestamp="2026-09-12T08:00:00Z",
                                witness=False, anchor=False)
    rc2 = ballot.ballot_receipt(_ballot(), trainee="a. writer", scenario="oral_board.set1",
                                ledger_path=lp, timestamp="2026-09-12T09:30:00Z",
                                witness=False, anchor=False)
    assert verify_receipt(rc1, ledger_path=lp)["ok"]
    assert verify_receipt(rc2, ledger_path=lp)["ok"]
    assert rc1["body_digest"] != rc2["body_digest"]
    assert rc1["issued_at"] != rc2["issued_at"]
    # no anti-redo claim is made anywhere on either receipt
    both_scopes = " ".join(rc1["scope"]["proves"] + rc1["scope"]["does_not_prove"])
    assert "not attempted before" in rc1["scope"]["does_not_prove"][1]
    assert "first attempt" not in both_scopes.lower()


def test_ballot_exhibit_prints_score_and_scope_before_results(tmp_path):
    rc = ballot.ballot_receipt(_ballot(), trainee="a. writer", scenario="oral_board.set1",
                               ledger_path=tmp_path / "l.jsonl", grader="ascenvo.vcs.oral_board",
                               timestamp="2026-09-12T08:00:00Z", witness=False, anchor=False)
    ex = ballot.exhibit(rc)
    assert "a. writer" in ex and "82" in ex
    assert ex.index("DOES NOT PROVE") < ex.index("RESULTS")


def test_ballot_cli_subprocess_exit_codes(tmp_path):
    # A-010's pattern: invoked as a real subprocess (`python -m arcaeon_receipt.cli`),
    # not by calling cli_main() directly, so this exercises the actual entry
    # point a trainer script or CI step would call.
    ballot_path = tmp_path / "ballot.json"
    ballot_path.write_text(json.dumps(_ballot()), encoding="utf-8")
    out = tmp_path / "r.json"
    ledger = tmp_path / "l.jsonl"

    proc = subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", "ballot", str(ballot_path),
         "--trainee", "a. writer", "--scenario", "oral_board.set1",
         "--grader", "ascenvo.vcs.oral_board", "--timestamp", "2026-09-12T08:00:00Z",
         "--ledger", str(ledger), "--out", str(out), "--no-anchor", "--no-witness"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert out.exists()
    rc = load_receipt(out)
    assert rc["kind"] == ballot.KIND

    # verify subcommand on the freshly-minted receipt: exit 0
    verify_proc = subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", "verify", str(out), "--ledger", str(ledger)],
        capture_output=True, text=True, timeout=30,
    )
    assert verify_proc.returncode == 0, verify_proc.stderr

    # a malformed JSON ballot file: exit 1, not a crash
    bad_path = tmp_path / "bad.json"
    bad_path.write_text("{not json", encoding="utf-8")
    bad_proc = subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", "ballot", str(bad_path),
         "--trainee", "x", "--scenario", "y", "--ledger", str(tmp_path / "l2.jsonl"),
         "--no-anchor", "--no-witness"],
        capture_output=True, text=True, timeout=30,
    )
    assert bad_proc.returncode == 1
    assert "error" in bad_proc.stderr.lower()
