"""Vendor-branded ballots, issued across a class.

Four things are proven here, in the order the product depends on them:

  1. The branding is INSIDE the digest. Proven by sabotage, not by assertion:
     a minted branded receipt verifies, the issuer string is edited by one
     word, verification FAILS, the original is restored, verification passes
     again. A vendor name that survives an edit is a letterhead, not a seal.
  2. An UNBRANDED receipt is byte-identical to what this adapter produced
     before branding existed -- checked against the ten example receipts
     committed to examples/ballots/ before this change, re-minted from their
     own committed inputs.
  3. A ten-row roster mints ten receipts in one command, into one ledger.
  4. A malformed roster row is refused WITH ITS ROW NUMBER, and nothing is
     written: a class that comes out silently one receipt short is the
     failure a roster driver must not have.
"""
from __future__ import annotations

import copy
import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

from arcaeon.record.receipt import ballot
from arcaeon.record.receipt.core import load_receipt, verify_receipt

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples" / "ballots"
ROSTER = EXAMPLES / "roster_example.csv"

ISSUER = "Westbrook Regional Training Academy"
COHORT = "WRTA-2026-OB-14"

_BALLOT_TEMPLATE = {"per_answer": [{"score": 82, "verdict": "GOOD"}],
                    "overall": {"score": 82, "verdict": "GOOD", "summary": "Passes."}}


def _ballot() -> dict:
    return copy.deepcopy(_BALLOT_TEMPLATE)


def _branded(tmp_path, **kw) -> dict:
    return ballot.ballot_receipt(
        _ballot(), trainee="p. lindqvist", scenario="oral_board.set1",
        grader="ascenvo.vcs.oral_board", ledger_path=tmp_path / "cohort.jsonl",
        namespace="wrta-ob-14", timestamp="2026-09-13T17:41:02Z",
        witness=False, anchor=False, issuer=ISSUER, cohort=COHORT, **kw)


# --------------------------------------------------------------------------
# 1. the issuer is inside the digest, proven by sabotage
# --------------------------------------------------------------------------

def test_issuer_sabotage_breaks_verification_and_restoring_it_passes(tmp_path):
    lp = tmp_path / "cohort.jsonl"
    rc = _branded(tmp_path)
    assert rc["extra"] == {"issuer": ISSUER, "cohort": COHORT}

    before = verify_receipt(rc, ledger_path=lp)
    assert before["ok"] and before["body_digest_ok"], before

    # SABOTAGE: one word of the academy's name, nothing else touched.
    original = rc["extra"]["issuer"]
    rc["extra"]["issuer"] = "Eastbrook Regional Training Academy"
    broken = verify_receipt(rc, ledger_path=lp)
    assert not broken["ok"]
    assert not broken["body_digest_ok"]
    assert any("body digest mismatch" in n for n in broken["notes"]), broken["notes"]

    # RESTORE: byte-for-byte back, and the receipt verifies again -- so the
    # failure above was the edit, not a side effect of having touched it.
    rc["extra"]["issuer"] = original
    after = verify_receipt(rc, ledger_path=lp)
    assert after["ok"] and after["body_digest_ok"], after


def test_cohort_sabotage_also_breaks_verification(tmp_path):
    """The class id is sealed on the same terms as the issuer. A vendor could
    otherwise re-label which cohort a receipt belonged to after the fact."""
    lp = tmp_path / "cohort.jsonl"
    rc = _branded(tmp_path)
    rc["extra"]["cohort"] = "WRTA-2026-OB-15"
    assert not verify_receipt(rc, ledger_path=lp)["body_digest_ok"]


def test_adding_a_branding_field_to_an_unbranded_receipt_breaks_it(tmp_path):
    """The other direction: you cannot BRAND a finished receipt either. An
    unbranded receipt that could be stamped with an academy's name after
    issue would let anyone hand out that academy's paper."""
    lp = tmp_path / "l.jsonl"
    rc = ballot.ballot_receipt(_ballot(), trainee="p. lindqvist", scenario="oral_board.set1",
                               ledger_path=lp, timestamp="2026-09-13T17:41:02Z",
                               witness=False, anchor=False)
    assert rc["extra"] == {}
    assert verify_receipt(rc, ledger_path=lp)["ok"]
    rc["extra"]["issuer"] = ISSUER
    assert not verify_receipt(rc, ledger_path=lp)["body_digest_ok"]


# --------------------------------------------------------------------------
# 2. unbranded output is unchanged
# --------------------------------------------------------------------------

EXAMPLE_RECEIPTS = sorted(p for p in EXAMPLES.glob("[0-1][0-9]_*.receipt.json")
                          if ".anchored." not in p.name and "branded" not in p.name)


def test_the_ten_committed_examples_are_actually_there():
    """LAW OF THE THIRD VERDICT: the parametrized test below would pass
    vacuously if the glob found nothing. Ten unbranded examples were
    committed before branding existed; this says so out loud."""
    assert len(EXAMPLE_RECEIPTS) == 10, [p.name for p in EXAMPLE_RECEIPTS]


@pytest.mark.parametrize("example", EXAMPLE_RECEIPTS, ids=lambda p: p.name.split(".")[0])
def test_unbranded_receipt_byte_identical_to_pre_branding_example(example, tmp_path):
    """Re-mint each example from its own committed input, with the subject and
    timestamp the committed receipt itself declares, and require an identical
    body and an identical body_digest.

    These ten receipts were minted before `issuer`/`cohort` existed. If the
    branding change altered one byte of an unbranded body -- an `extra` key
    written as null instead of absent, a reordered field, anything -- the
    digest below would differ and this test would fail. Passing is the
    byte-identity claim, checked against artifacts this change cannot edit
    without breaking them.

    Fixture note: examples 01, 02, 03 and 10 were re-minted on 2026-09-13
    because their inputs' `baseline_provenance` named an employing agency the
    privacy rule forbids in any output, and that string was sealed inside the
    body digest -- so input and receipt were updated together, deliberately;
    changing only one side still fails this test, which was checked.
    """
    committed = load_receipt(example)
    assert committed["extra"] == {}, "this example was already branded; wrong fixture"
    src = EXAMPLES / "inputs" / (example.name.replace(".receipt.json", ".json"))
    ballot_obj = json.loads(src.read_text(encoding="utf-8"))
    check = committed["checks"][0]

    rc = ballot.ballot_receipt(
        ballot_obj, trainee=check["trainee"], scenario=check["scenario"],
        grader=check.get("grader", ""), timestamp=check.get("timestamp"),
        ledger_path=tmp_path / "l.jsonl", namespace=committed["ledger"]["namespace"],
        witness=False, anchor=False)

    body_fields = ("receipt_version", "kind", "issued_at", "subject", "checks", "scope", "extra")
    for field in body_fields:
        assert rc[field] == committed[field], f"{example.name}: body field {field!r} changed"
    assert rc["body_digest"] == committed["body_digest"], (
        f"{example.name}: unbranded body_digest moved -- it was "
        f"{committed['body_digest']}, it is now {rc['body_digest']}")


def test_unbranded_exhibit_keeps_the_hardcoded_title_and_adds_no_lines(tmp_path):
    rc = ballot.ballot_receipt(_ballot(), trainee="p. lindqvist", scenario="oral_board.set1",
                               ledger_path=tmp_path / "l.jsonl",
                               timestamp="2026-09-13T17:41:02Z", witness=False, anchor=False)
    ex = ballot.exhibit(rc)
    assert ex.startswith("BALLOT RECEIPT  (arcaeon-receipt)")
    assert "Issued by:" not in ex and "Class:" not in ex


# --------------------------------------------------------------------------
# the exhibit carries the branding when it is there
# --------------------------------------------------------------------------

def test_branded_exhibit_shows_issuer_and_cohort_above_the_scope_block(tmp_path):
    ex = ballot.exhibit(_branded(tmp_path))
    assert ex.startswith(f"{ISSUER} - BALLOT RECEIPT  (arcaeon-receipt)")
    assert f"Issued by: {ISSUER}" in ex
    assert f"Class: {COHORT}" in ex
    # the limits still arrive before the result, branded or not
    assert ex.index("Issued by:") < ex.index("WHAT THIS RECEIPT DOES NOT PROVE")
    assert ex.index("DOES NOT PROVE") < ex.index("RESULTS")
    # and the scope wording is untouched: never "correct"
    assert "the score is correct" in ex.split("DOES NOT PROVE")[1].split("Method:")[0]


def test_blank_issuer_is_absent_not_a_vendor_named_nothing(tmp_path):
    rc = ballot.ballot_receipt(_ballot(), trainee="x", scenario="y",
                               ledger_path=tmp_path / "l.jsonl", witness=False, anchor=False,
                               issuer="   ", cohort="")
    assert rc["extra"] == {}
    assert ballot.exhibit(rc).startswith("BALLOT RECEIPT")


# --------------------------------------------------------------------------
# 3. the cohort driver
# --------------------------------------------------------------------------

def test_shipped_example_roster_has_ten_rows():
    rows = list(csv.DictReader(ROSTER.read_text(encoding="utf-8-sig").splitlines()))
    assert len(rows) == 10, f"examples/ballots/roster_example.csv has {len(rows)} rows"


def test_ten_row_roster_mints_ten_receipts_in_one_cli_call(tmp_path):
    """The real entry point, as a subprocess, against the shipped example
    roster: ten inputs in, ten receipt/exhibit pairs out, one ledger, one
    namespace, one summary line."""
    out_dir = tmp_path / "class"
    ledger = tmp_path / "wrta-ob-14.jsonl"
    proc = subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", "ballot", "--roster", str(ROSTER),
         "--issuer", ISSUER, "--cohort", COHORT, "--namespace", "wrta-ob-14",
         "--ledger", str(ledger), "--out-dir", str(out_dir),
         "--no-anchor", "--no-witness"],
        capture_output=True, text=True, timeout=180, cwd=str(ROOT),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert proc.returncode == 0, proc.stderr

    receipts = sorted(out_dir.glob("*.receipt.json"))
    exhibits = sorted(out_dir.glob("*.exhibit.txt"))
    assert len(receipts) == 10, [p.name for p in receipts]
    assert len(exhibits) == 10, [p.name for p in exhibits]

    # one summary LINE, not ten
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    assert len(lines) == 1, proc.stdout
    assert "10 ballot receipts issued" in lines[0]
    assert f"cohort={COHORT}" in lines[0] and f"issuer={ISSUER}" in lines[0]
    assert "rows=10" in lines[0]

    # every one of them verifies against the one shared chain, and every one
    # carries the branding inside its own body
    chains = set()
    for p in receipts:
        rc = load_receipt(p)
        assert rc["extra"] == {"issuer": ISSUER, "cohort": COHORT}, p.name
        res = verify_receipt(rc, ledger_path=ledger)
        assert res["ok"], (p.name, res)
        assert res["ledger"]["status"] == "consistent", (p.name, res)
        chains.add(rc["ledger"]["chain"])
    # ten distinct positions on ONE chain: the cohort's issue order is a fact
    # the ledger carries, which is the thing 2.2 sells.
    assert len(chains) == 10
    assert {load_receipt(p)["ledger"]["rows"] for p in receipts} == set(range(1, 11))


def test_roster_cli_verifies_on_the_cli_verify_subcommand(tmp_path):
    """Requirement 4's CLI half: a branded receipt is verified by the shipped
    `verify` subcommand with no special handling for branding."""
    out_dir = tmp_path / "class"
    ledger = tmp_path / "l.jsonl"
    subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", "ballot", "--roster", str(ROSTER),
         "--issuer", ISSUER, "--cohort", COHORT, "--ledger", str(ledger),
         "--out-dir", str(out_dir), "--no-anchor", "--no-witness"],
        capture_output=True, text=True, timeout=180, cwd=str(ROOT), check=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    one = sorted(out_dir.glob("*.receipt.json"))[0]
    ok = subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", "verify", str(one), "--ledger", str(ledger)],
        capture_output=True, text=True, timeout=60, cwd=str(ROOT),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr

    # and the same receipt with one branded byte changed exits 2
    rc = load_receipt(one)
    rc["extra"]["issuer"] = "Someone Else Academy"
    tampered = tmp_path / "tampered.receipt.json"
    tampered.write_text(json.dumps(rc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    bad = subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", "verify", str(tampered),
         "--ledger", str(ledger)],
        capture_output=True, text=True, timeout=60, cwd=str(ROOT),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert bad.returncode == 2, bad.stdout + bad.stderr


# --------------------------------------------------------------------------
# 4. a malformed row is refused with its number, and nothing is written
# --------------------------------------------------------------------------

def _roster(tmp_path, body: str) -> Path:
    p = tmp_path / "roster.csv"
    p.write_text("trainee,ballot_path,scenario\n" + body, encoding="utf-8")
    return p


GOOD_ROW = "a. one,{src},oral_board.set1\n"


def _src() -> str:
    return str(EXAMPLES / "inputs" / "01_oral_board_pass_clean.json").replace("\\", "/")


@pytest.mark.parametrize("bad_row,expect_row,fragment", [
    (",{src},oral_board.set1\n", 3, "trainee is empty"),
    ("b. two,,oral_board.set1\n", 3, "ballot_path is empty"),
    ("b. two,{src}.missing,oral_board.set1\n", 3, "ballot file not found"),
    ("b. two,{src},\n", 3, "no scenario"),
])
def test_malformed_roster_row_is_refused_with_its_row_number(tmp_path, bad_row, expect_row,
                                                             fragment):
    src = _src()
    path = _roster(tmp_path, GOOD_ROW.format(src=src) + bad_row.format(src=src)
                   + "c. three,{s},oral_board.set1\n".format(s=src))
    with pytest.raises(ballot.RosterError) as ei:
        ballot.read_roster(path)
    assert ei.value.row == expect_row, str(ei.value)
    assert f"roster row {expect_row}" in str(ei.value)
    assert fragment in str(ei.value)


def test_unreadable_json_row_is_refused_with_its_row_number(tmp_path):
    junk = tmp_path / "junk.json"
    junk.write_text("{not json", encoding="utf-8")
    path = _roster(tmp_path, GOOD_ROW.format(src=_src())
                   + f"b. two,{str(junk).replace(chr(92), '/')},oral_board.set1\n")
    with pytest.raises(ballot.RosterError) as ei:
        ballot.read_roster(path)
    assert ei.value.row == 3 and "not readable JSON" in str(ei.value)


def test_duplicate_trainee_is_refused_naming_both_rows(tmp_path):
    src = _src()
    path = _roster(tmp_path, GOOD_ROW.format(src=src) + f"A. One,{src},oral_board.set2\n")
    with pytest.raises(ballot.RosterError) as ei:
        ballot.read_roster(path)
    assert ei.value.row == 3 and "collides with row 2" in str(ei.value)


def test_missing_required_column_is_refused_before_any_row(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text("name,file\na,b\n", encoding="utf-8")
    with pytest.raises(ballot.RosterError) as ei:
        ballot.read_roster(p)
    assert "trainee" in str(ei.value) and "ballot_path" in str(ei.value)


def test_a_refused_row_writes_nothing_at_all(tmp_path):
    """All-or-nothing. Six sealed receipts and a chain that stops mid-cohort
    is worse than a refusal, because nobody can tell from the outside which
    trainees are missing paper."""
    src = _src()
    out_dir = tmp_path / "class"
    ledger = tmp_path / "l.jsonl"
    path = _roster(tmp_path, GOOD_ROW.format(src=src)
                   + f"b. two,{src},oral_board.set1\n"
                   + f"c. three,{src}.missing,oral_board.set1\n")
    proc = subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", "ballot", "--roster", str(path),
         "--ledger", str(ledger), "--out-dir", str(out_dir), "--no-anchor", "--no-witness"],
        capture_output=True, text=True, timeout=60, cwd=str(ROOT),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert proc.returncode == 1
    assert "roster row 4" in proc.stderr, proc.stderr
    written = list(out_dir.glob("*.receipt.json")) if out_dir.exists() else []
    assert written == [], f"a refused roster wrote receipts anyway: {written}"
    assert not ledger.exists(), "a refused roster must not have appended a ledger row"


def test_blank_line_in_a_roster_is_spacing_not_a_refusal(tmp_path):
    src = _src()
    path = _roster(tmp_path, GOOD_ROW.format(src=src) + "\n"
                   + f"b. two,{src},oral_board.set1\n")
    rows = ballot.read_roster(path)
    assert [r["trainee"] for r in rows] == ["a. one", "b. two"]


def test_empty_roster_is_refused(tmp_path):
    path = _roster(tmp_path, "")
    with pytest.raises(ballot.RosterError) as ei:
        ballot.read_roster(path)
    assert "no trainee rows" in str(ei.value)


def test_roster_and_single_ballot_arguments_together_are_refused(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", "ballot", _src(),
         "--roster", str(ROSTER), "--trainee", "x", "--scenario", "y",
         "--ledger", str(tmp_path / "l.jsonl"), "--no-anchor", "--no-witness"],
        capture_output=True, text=True, timeout=60, cwd=str(ROOT),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert proc.returncode == 1 and "roster" in proc.stderr.lower()


def test_single_ballot_without_trainee_is_refused_not_crashed(tmp_path):
    """--trainee/--scenario stopped being argparse-required when --roster made
    them optional; the refusal has to still happen, with a message."""
    proc = subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", "ballot", _src(),
         "--ledger", str(tmp_path / "l.jsonl"), "--no-anchor", "--no-witness"],
        capture_output=True, text=True, timeout=60, cwd=str(ROOT),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert proc.returncode == 1
    assert "--trainee" in proc.stderr and "--scenario" in proc.stderr


# --------------------------------------------------------------------------
# the shipped branded example stays verifiable
# --------------------------------------------------------------------------

def test_shipped_branded_example_verifies_against_the_shared_example_ledger():
    p = EXAMPLES / "11_branded_academy_cohort.receipt.json"
    rc = load_receipt(p)
    assert rc["extra"] == {"issuer": ISSUER, "cohort": COHORT}
    res = verify_receipt(rc, ledger_path=EXAMPLES / "ledger.jsonl")
    assert res["ok"] and res["ledger"]["status"] == "consistent", res
    ex = (EXAMPLES / "11_branded_academy_cohort.exhibit.txt").read_text(encoding="utf-8")
    assert ISSUER in ex and COHORT in ex
