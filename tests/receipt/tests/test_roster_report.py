"""The roster report: one page for the person who runs the class.

The third member of the cohort family. `test_ballot_cohort.py` proves a
roster becomes ten sealed receipts in one command; `test_verify_batch.py`
proves those receipts become one verdict line; this proves they become the
table a training coordinator works from, and that the table is honest about
three specific things:

  1. It says what was ISSUED and whether it VERIFIES, and nothing about how
     the class did. No average, no pass rate, no ranking. Proven by a grep
     over the real output AND by sabotage: adding a mean-score column to
     roster_report.py turns the grep test red.
  2. A FAIL is a row. One edited receipt in a ten-row class shows exactly one
     FAIL, the counts read 9 verified / 1 failed / 0 undetermined, the exit
     code is nonzero, and the failing trainee's own row still carries their
     label and their score -- a failure moved to a footnote is a failure
     nobody reads.
  3. The third verdict survives the trip. A receipt whose ledger row is not
     in the export comes back `undetermined`, never `ok`, with its body
     digest untouched.

And one thing about its own shape: a 25-receipt class is reported in two
passes of 20 and 5, every receipt verified, with the pass structure printed
on the face of the report. No pass ever exceeds the published cap -- proven
by watching the calls, not by reading the code.
"""
from __future__ import annotations

import csv
import io
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from arcaeon.record.receipt import ballot, roster_report, verify_batch

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples" / "ballots"
ROSTER = EXAMPLES / "roster_example.csv"
EXAMPLE_REPORT = EXAMPLES / "roster_report_example.csv"

ISSUER = "Westbrook Regional Training Academy"
COHORT = "WRTA-2026-OB-14"

#: The words this report is not allowed to contain, in any case. Each one is
#: a sentence about competence that the scope block denies making
#: (VENDOR_PACKAGE_SPEC 6.1: "It does not grade, and it does not improve
#: grading").
FORBIDDEN = ("average", "pass rate", "rank", "mean score", "median")


def run_cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", *[str(a) for a in args]],
        capture_output=True, text=True, timeout=300, cwd=str(cwd or ROOT),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def parse_csv(text: str):
    """(header dict, columns, rows) out of the rendered CSV."""
    rows = list(csv.reader(io.StringIO(text)))
    header, i = {}, 0
    while i < len(rows) and rows[i] and rows[i][0].startswith("# "):
        header[rows[i][0][2:]] = rows[i][1]
        i += 1
    assert rows[i] == [], rows[i]          # the blank line between the two blocks
    cols = rows[i + 1]
    data = [dict(zip(cols, r)) for r in rows[i + 2:] if r]
    return header, cols, data


@pytest.fixture(scope="module")
def minted_cohort(tmp_path_factory) -> Path:
    """The ten-row example roster, minted through the real CLI into one
    ledger under one namespace -- a vendor's export directory, exactly."""
    out = tmp_path_factory.mktemp("cohort") / "class"
    out.mkdir()
    proc = run_cli("ballot", "--roster", ROSTER, "--issuer", ISSUER, "--cohort", COHORT,
                   "--namespace", "wrta-ob-14", "--ledger", out / "ledger.jsonl",
                   "--out-dir", out, "--no-witness", "--no-anchor")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert len(list(out.glob("*.receipt.json"))) == 10, sorted(p.name for p in out.iterdir())
    return out


def stage(minted_cohort: Path, tmp_path: Path) -> Path:
    dest = tmp_path / "class"
    shutil.copytree(minted_cohort, dest)
    return dest


def report_of(target, *extra):
    """Run the CLI and hand back (returncode, header, columns, rows)."""
    proc = run_cli("roster-report", target, *extra)
    if proc.returncode == 1:
        return proc.returncode, {}, [], [], proc
    header, cols, rows = parse_csv(proc.stdout)
    return proc.returncode, header, cols, rows, proc


# --------------------------------------------------------------------------
# 1. the ten-row cohort
# --------------------------------------------------------------------------

def test_ten_row_cohort_is_ten_rows_and_a_header(minted_cohort):
    code, header, cols, rows, proc = report_of(minted_cohort)
    assert code == 0, proc.stdout + proc.stderr
    assert len(rows) == 10, [r["file"] for r in rows]
    assert (header["receipts_counted"], header["verified"], header["failed"],
            header["undetermined"]) == ("10", "10", "0", "0")
    assert header["issuer"] == ISSUER and header["cohort"] == COHORT
    assert header["report"] == roster_report.REPORT_NAME
    assert list(cols) == list(roster_report.COLUMNS)
    # every trainee on the roster is on the report, labelled the way the
    # ballot carries them
    with ROSTER.open(encoding="utf-8-sig") as fh:
        expected = {r["trainee"] for r in csv.DictReader(fh)}
    assert {r["trainee"] for r in rows} == expected
    assert all(r["verdict"] == "ok" and r["ledger"] == "consistent" for r in rows), rows


def test_the_header_carries_the_scope_block_verbatim(minted_cohort):
    _, header, _, _, _ = report_of(minted_cohort)
    assert header["scope_proves"] == "; ".join(ballot.SCOPE["proves"])
    assert header["scope_does_not_prove"] == "; ".join(ballot.SCOPE["does_not_prove"])
    # not paraphrased from the code: the same string is inside the receipts
    rc = json.loads(next(minted_cohort.glob("*.receipt.json")).read_text(encoding="utf-8"))
    assert rc["scope"]["does_not_prove"] == ballot.SCOPE["does_not_prove"]
    assert "the score is correct" in header["scope_does_not_prove"]


def test_the_score_column_is_the_number_the_exhibit_shows():
    """The report and the trainee's own exhibit must read the same number the
    same way. `score_of()` mirrors `ballot._line()`'s fallback chain by hand
    (three real grader shapes, including the seq scorer that carries no
    `overall` key at all); this holds the mirror against every committed
    example instead of trusting the comment that says it does."""
    seen = set()
    for p in sorted(EXAMPLES.glob("*.receipt.json")):
        rc = json.loads(p.read_text(encoding="utf-8"))
        check = rc["checks"][0]
        score = roster_report.score_of(check["ballot"])
        assert f"score={score} " in ballot._line(check), (p.name, score)
        seen.add(score)
    assert len(seen) > 3, seen  # several real shapes, not one repeated fixture


def test_pointing_at_the_class_ledger_reports_the_directory_it_lives_in(minted_cohort):
    code, header, _, rows, proc = report_of(minted_cohort / "ledger.jsonl")
    assert code == 0, proc.stdout + proc.stderr
    assert len(rows) == 10
    assert header["ledger"] == "ledger.jsonl"


def test_an_empty_target_is_refused_not_reported_as_a_clean_class(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    proc = run_cli("roster-report", empty)
    assert proc.returncode == 1
    assert "no receipts under" in proc.stderr
    assert proc.stdout.strip() == ""


# --------------------------------------------------------------------------
# 2. one edited receipt: 9 / 1 / 0, and the FAIL is a row
# --------------------------------------------------------------------------

EDITED = "m_chen.receipt.json"


def _edit(target: Path) -> bytes:
    """One word added to one scope sentence -- the smallest edit a reader
    would never notice and the digest cannot miss. Returns the original
    bytes so the sabotage can be undone exactly."""
    original = target.read_bytes()
    rc = json.loads(target.read_text(encoding="utf-8"))
    rc["scope"]["does_not_prove"][0] += " (edited)"
    target.write_text(json.dumps(rc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return original


def test_one_edited_receipt_is_exactly_one_fail_and_the_counts_say_nine_one_zero(
        minted_cohort, tmp_path):
    staged = stage(minted_cohort, tmp_path)
    _edit(staged / EDITED)

    code, header, _, rows, proc = report_of(staged)
    assert code == 2, (code, proc.stdout, proc.stderr)
    assert (header["receipts_counted"], header["verified"], header["failed"],
            header["undetermined"]) == ("10", "9", "1", "0")
    failed = [r for r in rows if r["verdict"] == "FAIL"]
    assert len(failed) == 1 and failed[0]["file"] == EDITED, rows
    assert "body digest mismatch" in failed[0]["reason"]
    # a FAIL is a ROW: same columns, same trainee label, same stated score as
    # any passing row -- not a footnote, not an asterisk, not dropped
    assert failed[0]["trainee"] == "m. chen"
    assert failed[0]["score"] == "23"
    assert failed[0]["issued_at"] and failed[0]["receipt_id"]
    assert len(rows) == 10


def test_restoring_the_edited_receipt_makes_the_report_green_again(minted_cohort, tmp_path):
    """The other half of the sabotage. Without it, a report that fails for an
    unrelated reason reads as a successful detection."""
    staged = stage(minted_cohort, tmp_path)
    original = _edit(staged / EDITED)
    assert report_of(staged)[0] == 2

    (staged / EDITED).write_bytes(original)
    code, header, _, rows, proc = report_of(staged)
    assert code == 0, proc.stdout + proc.stderr
    assert (header["verified"], header["failed"], header["undetermined"]) == ("10", "0", "0")
    assert {r["verdict"] for r in rows} == {"ok"}


# --------------------------------------------------------------------------
# 3. the third verdict travels
# --------------------------------------------------------------------------

def test_a_receipt_whose_ledger_row_is_not_in_the_export_is_undetermined(
        minted_cohort, tmp_path):
    """One receipt's ledger row is not reachable from this export. Its body
    digest is untouched and still recomputes, so it is not a FAIL; its
    sequence claim was never checked, so it is not `ok` either. Third
    verdict, its own count, its own exit code.

    The `ledger` block sits OUTSIDE the body digest (core.BODY_FIELDS), which
    is why renaming the file it points at models a missing ledger row rather
    than tampering -- and the `undetermined` verdict below is the proof that
    nothing in the sealed body moved."""
    staged = stage(minted_cohort, tmp_path)
    target = staged / "k_patel.receipt.json"
    rc = json.loads(target.read_text(encoding="utf-8"))
    rc["ledger"]["path"] = "removed_from_this_export.jsonl"
    target.write_text(json.dumps(rc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    code, header, _, rows, proc = report_of(staged)
    assert code == 4, (code, proc.stdout, proc.stderr)
    assert (header["verified"], header["failed"], header["undetermined"]) == ("9", "0", "1")
    und = [r for r in rows if r["verdict"] == "undetermined"]
    assert len(und) == 1 and und[0]["file"] == "k_patel.receipt.json", rows
    assert und[0]["ledger"] == "not_checked"
    assert "ledger sequence claim is unchecked" in und[0]["reason"]
    assert und[0]["trainee"] == "k. patel"


# --------------------------------------------------------------------------
# 4. paging: 25 receipts, two passes, no pass over the cap
# --------------------------------------------------------------------------

def stage_n(tmp_path: Path, n: int) -> Path:
    out = tmp_path / f"n{n}"
    out.mkdir()
    src = EXAMPLES / "05_call_taking_weak.receipt.json"
    shutil.copy2(EXAMPLES / "ledger.jsonl", out / "ledger.jsonl")
    for i in range(n):
        shutil.copy2(src, out / f"r{i:03d}.receipt.json")
    return out


def test_twenty_five_receipts_are_reported_in_two_passes_of_twenty_and_five(tmp_path):
    staged = stage_n(tmp_path, 25)
    code, header, _, rows, proc = report_of(staged)
    assert code == 0, proc.stdout + proc.stderr
    assert len(rows) == 25
    assert header["receipts_counted"] == "25" and header["verified"] == "25"
    assert header["verification_passes"] == \
        "2 passes of at most 20 (20, 5); every receipt was verified"


def test_no_single_verification_pass_ever_exceeds_the_published_cap(tmp_path, monkeypatch):
    """Watched, not read. Every call into verify_batch is recorded with the
    number of receipts handed to it and the cap it was given."""
    staged = stage_n(tmp_path, 25)
    seen = []
    real = verify_batch.verify_batch

    def spy(targets, **kw):
        targets = list(targets)
        seen.append((len(targets), kw.get("cap")))
        return real(targets, **kw)

    monkeypatch.setattr(roster_report.verify_batch, "verify_batch", spy)
    report = roster_report.build_report(staged)
    assert seen == [(20, 20), (5, 20)], seen
    assert all(n <= verify_batch.CAP for n, _ in seen), seen
    assert len(report["rows"]) == 25


def test_the_page_size_is_the_published_cap():
    """The report pages at the same number the spec publishes. If the cap
    moves, the paging moves with it or the report is quietly verifying more
    per pass than the surface says is free."""
    assert roster_report.PAGE == verify_batch.CAP == 20


def test_a_class_of_exactly_twenty_is_one_pass(tmp_path):
    """The boundary from the other side: 20 is one pass, so the two-page split
    above is the cap doing its job rather than an off-by-one."""
    _, header, _, rows, _ = report_of(stage_n(tmp_path, 20))
    assert len(rows) == 20
    assert header["verification_passes"] == \
        "1 pass of at most 20 (20); every receipt was verified"


# --------------------------------------------------------------------------
# 5. JSON mirrors CSV exactly
# --------------------------------------------------------------------------

def test_json_and_csv_are_the_same_table(minted_cohort, tmp_path):
    staged = stage(minted_cohort, tmp_path)
    _edit(staged / EDITED)  # with a FAIL in it: parity must hold on the bad row too

    as_csv = run_cli("roster-report", staged)
    as_json = run_cli("roster-report", staged, "--json")
    assert as_csv.returncode == as_json.returncode == 2

    header, cols, rows = parse_csv(as_csv.stdout)
    doc = json.loads(as_json.stdout)

    # generated_at is a clock reading, and the two runs are seconds apart
    assert set(doc["header"]) == set(header)
    for key in header:
        if key == "generated_at":
            continue
        assert doc["header"][key] == header[key], key
    assert doc["columns"] == cols
    assert doc["rows"] == rows
    # every value on both sides is a string: the JSON is the same table, not
    # a richer one that could disagree with the CSV about a type
    assert all(isinstance(v, str) for v in doc["header"].values())
    assert all(isinstance(v, str) for r in doc["rows"] for v in r.values())


# --------------------------------------------------------------------------
# 6. no aggregate that implies competence
# --------------------------------------------------------------------------

def test_the_report_carries_no_aggregate_about_scores(minted_cohort, tmp_path):
    """The grep. VENDOR_PACKAGE_SPEC's scope block denies exactly one thing --
    "the score is correct" -- and an average, a pass rate or a ranking asserts
    its opposite by arithmetic. Run over the real rendered output in both
    formats and over the committed example report."""
    staged = stage(minted_cohort, tmp_path)
    texts = [run_cli("roster-report", staged).stdout,
             run_cli("roster-report", staged, "--json").stdout,
             EXAMPLE_REPORT.read_text(encoding="utf-8")]
    for text in texts:
        low = text.lower()
        for word in FORBIDDEN:
            assert word not in low, (word, text[:400])


def test_no_column_is_an_aggregate(minted_cohort):
    _, _, cols, _, _ = report_of(minted_cohort)
    for col in cols:
        low = col.lower()
        for word in ("avg", "mean", "average", "rate", "rank", "total", "pct"):
            assert word not in low, col
    # the only counts on the page are verdict counts, never score statistics
    assert set(roster_report.HEADER_KEYS) & {"verified", "failed", "undetermined"}


# --------------------------------------------------------------------------
# 7. the committed example stays true
# --------------------------------------------------------------------------

def test_the_committed_example_report_matches_a_fresh_run():
    """The example beside the cohort is regenerated, not hand-written. If a
    change to this module would make the shipped example wrong, this goes red
    before a buyer ever opens it."""
    committed_header, committed_cols, committed_rows = parse_csv(
        EXAMPLE_REPORT.read_text(encoding="utf-8"))
    proc = run_cli("roster-report", "examples/ballots/")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    header, cols, rows = parse_csv(proc.stdout)
    assert cols == committed_cols
    assert rows == committed_rows
    for key in committed_header:
        if key == "generated_at":
            continue
        assert header[key] == committed_header[key], key
