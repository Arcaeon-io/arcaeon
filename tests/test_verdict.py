"""arcaeon.verdict: the words, the ONE exit-code table, and --legacy-exit.

could-not-look = 3 everywhere. Reconcile moved from 2 to 3 and keeps 2 under
--legacy-exit for the 0.9.x release; audit (2), receipt (2/3/4) and vet
(badge 4, verify 2, audit-verify 2, probe 2) are translated at the `arcaeon`
front door, and --legacy-exit hands back their old codes untouched.
"""
import json
from pathlib import Path

import pytest

import _arcaeon_chain as C
from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import reconcile as R


# --- the table itself ---------------------------------------------------------

def test_the_one_table():
    assert (V.EXIT_GOOD, V.EXIT_BAD, V.EXIT_USAGE, V.EXIT_COULD_NOT_LOOK) == (0, 1, 2, 3)
    assert V.exit_for(V.VERIFIED) == V.exit_for(V.MATCHED) == 0
    assert V.exit_for(V.BROKEN) == V.exit_for(V.MISSING) == V.exit_for(V.ALTERED) == 1
    assert V.exit_for(V.COULD_NOT_LOOK) == V.exit_for(V.COULD_NOT_LOOK_TOKEN) == 3
    assert V.exit_for(V.NO_GRADEABLE_FILES) == 3


def test_an_unknown_word_never_gates_green():
    assert V.exit_for("LOOKS FINE") == V.EXIT_COULD_NOT_LOOK


def test_the_words_are_the_words():
    assert V.WORDS == ("VERIFIED", "BROKEN", "COULD NOT LOOK", "MATCHED", "MISSING",
                       "ALTERED", "NO GRADEABLE FILES")


def test_every_legacy_could_not_look_code_becomes_3():
    assert V.unify("audit", 2) == 3
    assert V.unify("receipt", 4) == 3
    assert V.unify("vet", 2, "probe") == 3
    assert V.unify("vet", 4, "badge") == 3
    assert V.unify("badge", 4) == 3


def test_legacy_bad_findings_become_1():
    assert V.unify("receipt", 2) == 1      # verify failed
    assert V.unify("receipt", 3) == 1      # a flagged citation check
    assert V.unify("vet", 2, "verify") == 1
    assert V.unify("vet", 2, "audit-verify") == 1


def test_codes_that_already_agreed_pass_through():
    for verb in ("audit", "receipt", "vet", "badge", "once", "meter"):
        assert V.unify(verb, 0) == 0
        assert V.unify(verb, 1) == 1
    assert V.unify("vet", 3, "badge") == 3        # NO GRADEABLE FILES was already 3
    assert V.unify("vet", 3, "audit-verify") == 3  # bounded was already 3


def test_legacy_flag_returns_the_old_code_untouched():
    assert V.unify("audit", 2, legacy=True) == 2
    assert V.unify("receipt", 4, legacy=True) == 4
    argv, legacy = V.pop_legacy_flag(["verify", "--legacy-exit", "x"])
    assert argv == ["verify", "x"] and legacy is True
    argv, legacy = V.pop_legacy_flag(["verify", "x"])
    assert argv == ["verify", "x"] and legacy is False


def test_reconcile_is_not_double_translated():
    """reconcile returns the table's codes natively; the front door must not
    map its 2 (bad usage) onto 3."""
    assert "reconcile" not in V.LEGACY


# --- reconcile, natively ----------------------------------------------------------

@pytest.fixture()
def tapes(tmp_path):
    return C.record_session(tmp_path / "s")


def test_reconcile_exit_codes_match_the_table(tapes, tmp_path):
    assert R.EXIT_CODES == {R.MATCHED: 0, R.MISSING: 1, R.ALTERED: 1, R.COULD_NOT_LOOK: 3}
    assert R.LEGACY_EXIT_CODES[R.COULD_NOT_LOOK] == 2
    assert R.reconcile(tapes["agent_tape"], tapes["tool_tape"]).exit_code == 0
    gone = tmp_path / "no-such-tape.jsonl"
    r = R.reconcile(tapes["agent_tape"], gone)
    assert r.verdict == R.COULD_NOT_LOOK and r.exit_code == 3


def test_reconcile_main_could_not_look_is_3_and_legacy_is_2(tapes, tmp_path, capsys):
    gone = str(tmp_path / "no-such-tape.jsonl")
    assert R.main([str(tapes["agent_tape"]), gone]) == 3
    assert R.main([str(tapes["agent_tape"]), gone, "--legacy-exit"]) == 2
    assert R.main([str(tapes["agent_tape"]), str(tapes["tool_tape"])]) == 0
    assert R.main([str(tapes["agent_tape"]), str(tapes["tool_tape"]), "--legacy-exit"]) == 0
    capsys.readouterr()


def test_reconcile_bad_usage_is_2_either_way(capsys):
    assert R.main(["only-one"]) == 2
    assert R.main(["only-one", "--legacy-exit"]) == 2
    capsys.readouterr()


def test_arcaeon_reconcile_verb(tapes, tmp_path, capsys):
    gone = str(tmp_path / "missing.jsonl")
    assert cli.main(["reconcile", str(tapes["agent_tape"]), gone]) == 3
    assert cli.main(["reconcile", str(tapes["agent_tape"]), gone, "--legacy-exit"]) == 2
    assert cli.main(["reconcile", str(tapes["agent_tape"]), str(tapes["tool_tape"])]) == 0
    capsys.readouterr()


# --- the other translated verbs, end to end through `arcaeon` -----------------------------

def _bounded_log(p: Path) -> Path:
    """One unchained legacy row, then chained rows: verify can only speak for
    part of it, which is COULD NOT LOOK, not VERIFIED."""
    from arcaeon.record.ledger import Ledger
    p.write_text(json.dumps({"legacy": True}) + "\n", encoding="utf-8")
    Ledger(p).append({"op": "after"})
    return p


def test_arcaeon_verify_bounded_is_3(tmp_path, capsys):
    p = _bounded_log(tmp_path / "b.jsonl")
    assert cli.main(["verify", str(p)]) == 3
    assert cli.main(["verify", str(p), "--strict"]) == 1
    capsys.readouterr()


def test_arcaeon_audit_could_not_complete_is_3_legacy_2(tmp_path, capsys):
    p = _bounded_log(tmp_path / "b.jsonl")
    assert cli.main(["audit", "verify", str(p)]) == 3
    assert cli.main(["audit", "verify", str(p), "--legacy-exit"]) == 2
    capsys.readouterr()


def test_arcaeon_receipt_verify_failed_is_1_legacy_2(tmp_path, capsys):
    from arcaeon.record.receipt.call import call_receipt
    from arcaeon.record.receipt.core import save_receipt
    led = tmp_path / "r.jsonl"
    rec = call_receipt({"method": "GET", "url": "https://example.test/x"},
                       {"status": 200, "body": {"ok": True}}, ledger_path=led,
                       witness=False, anchor=False)
    good = save_receipt(rec, tmp_path / "good.json")
    assert cli.main(["receipt", "verify", str(good), "--ledger", str(led)]) == 0
    rec["subject"]["seller"] = "someone else"
    bad = save_receipt(rec, tmp_path / "bad.json")
    assert cli.main(["receipt", "verify", str(bad), "--ledger", str(led)]) == 1
    assert cli.main(["receipt", "verify", str(bad), "--ledger", str(led), "--legacy-exit"]) == 2
    capsys.readouterr()


def test_arcaeon_badge_on_nothing_gradeable_is_3(tmp_path, capsys):
    empty = tmp_path / "empty-server"
    empty.mkdir()
    (empty / "README.md").write_text("nothing to grade", encoding="utf-8")
    assert cli.main(["badge", str(empty)]) == 3
    capsys.readouterr()
