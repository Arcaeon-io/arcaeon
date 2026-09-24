"""The bulk export: one portable file, checkable by a stranger with no tools.

The fourth member of the cohort family. `test_ballot_cohort.py` proves a
roster becomes sealed receipts in one command, `test_verify_batch.py` proves
those receipts become one verdict line, `test_roster_report.py` proves they
become the coordinator's page, and this proves the whole thing leaves the
building in a form that still works after we do.

Five things are held here, and each one is a promise the archive would be
worthless without:

  1. Every file round-trips by sha256. What goes in comes out, byte for
     byte, receipts included: an archive that re-serialized a receipt on the
     way in would still verify and would still be the wrong artifact.
  2. It verifies OFFLINE. The zip is extracted into a temp directory with
     the network monkeypatched shut, and `verify_batch` reads every receipt
     against the BUNDLED ledger. That is the whole product claim -- "a form
     they own and can hand to anybody, including us going away"
     (VENDOR_PACKAGE_SPEC 2.5) -- and it is checked by doing it, not by
     reading the packing code.
  3. A FAIL is packed. One tampered receipt: the archive still builds, the
     receipt is inside it, and the manifest carries its FAIL. Sabotaged by
     making the builder drop failing receipts, which turns this red.
  4. No aggregate about scores. A grep over every text file in a real
     archive. Sabotaged by adding a score statistic to the manifest.
  5. Deterministic. The same cohort archived twice with the same stamp is
     the same bytes, and with two different stamps differs only in
     `generated_at`.

The example set is `examples/ballots/`, which today holds 12 receipts across
11 numbered scenarios (01 appears twice: once plain, once anchored). The
counts below are written against what is actually in that directory rather
than against a remembered number.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from arcaeon.record.receipt import archive, roster_report, verify_batch

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples" / "ballots"
EXAMPLE_ARCHIVE = ROOT / "examples" / "class_archive_example.zip"

#: The committed example is built from this exact target string, so the
#: `source` line in its manifest is reproducible from the command in the
#: README rather than from somebody's local absolute path.
EXAMPLE_TARGET = "examples/ballots/"

#: Same list as `test_roster_report.FORBIDDEN`, for the same reason: each one
#: is a sentence about competence the scope block denies making.
FORBIDDEN = ("average", "pass rate", "rank", "mean score", "median")

STAMP = "2026-09-13T00:00:00Z"


def run_cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", *[str(a) for a in args]],
        capture_output=True, text=True, timeout=300, cwd=str(cwd or ROOT),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entries_of(zip_path: Path) -> dict:
    with zipfile.ZipFile(zip_path) as z:
        return {n: z.read(n) for n in z.namelist()}


def manifest_of(zip_path: Path) -> dict:
    with zipfile.ZipFile(zip_path) as z:
        return json.loads(z.read(archive.MANIFEST_NAME))


@pytest.fixture(scope="module")
def built(tmp_path_factory) -> Path:
    """The committed example set, archived through the real CLI."""
    out = tmp_path_factory.mktemp("archive") / "class.zip"
    proc = run_cli("archive", EXAMPLE_TARGET, "--out", out)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out


def staged_copy(tmp_path: Path, name: str = "class") -> Path:
    """A writable copy of the example cohort, so a test can tamper with it."""
    dest = tmp_path / name
    dest.mkdir()
    for p in EXAMPLES.iterdir():
        if p.is_file() and p.suffix != ".lock":
            shutil.copy2(p, dest / p.name)
    return dest


# --------------------------------------------------------------------------
# 1. the example set archives, and every file round-trips by sha256
# --------------------------------------------------------------------------

def test_the_example_set_archives_and_holds_every_receipt(built):
    entries = entries_of(built)
    src_receipts = sorted(p.name for p in EXAMPLES.glob("*.receipt.json"))
    assert len(src_receipts) == 12, src_receipts      # 11 scenarios, 01 twice
    for name in src_receipts:
        assert f"{archive.COHORT_DIR}/{name}" in entries
    assert archive.MANIFEST_NAME in entries
    assert archive.README_NAME in entries
    assert archive.ROSTER_NAME in entries
    # both example ledgers travel: the class ledger and the anchored receipt's
    # own, each with its witness sidecar beside it
    assert f"{archive.COHORT_DIR}/ledger.jsonl" in entries
    assert f"{archive.COHORT_DIR}/ledger.jsonl.witness.jsonl" in entries
    assert (f"{archive.COHORT_DIR}/01_oral_board_pass_clean.anchored.ledger.jsonl"
            in entries)
    # nothing that is not a real artifact
    assert not [n for n in entries if n.endswith(".lock")]


def test_every_file_round_trips_byte_for_byte(built):
    """The manifest's digest, the archive's bytes, and the file still on disk:
    three readings of the same sha256, compared pairwise. A receipt that was
    reformatted on the way in would pass a verify and fail here, which is the
    point -- the archive is evidence, and evidence is not re-typed."""
    entries = entries_of(built)
    manifest = manifest_of(built)
    listed = {f["path"]: f for f in manifest["files"]}
    assert set(listed) | {archive.MANIFEST_NAME} == set(entries)

    checked = 0
    for path, data in entries.items():
        if path == archive.MANIFEST_NAME:
            continue
        assert listed[path]["sha256"] == sha256(data), path
        assert listed[path]["bytes"] == len(data), path
        if path.startswith(archive.COHORT_DIR + "/"):
            src = EXAMPLES / Path(path).name
            assert src.read_bytes() == data, path
            assert sha256(src.read_bytes()) == listed[path]["sha256"], path
            checked += 1
    assert checked >= 12, checked


def test_the_manifest_carries_the_scope_sentence_verbatim(built):
    """Verbatim means the receipts' own words, not a restatement. Held against
    the string the roster report prints AND against the receipt file itself."""
    manifest = manifest_of(built)
    report = roster_report.build_report(EXAMPLES)
    assert manifest["scope_proves"] == report["header"]["scope_proves"]
    assert manifest["scope_does_not_prove"] == report["header"]["scope_does_not_prove"]
    assert "the score is correct" in manifest["scope_does_not_prove"]

    rc = json.loads((EXAMPLES / "11_branded_academy_cohort.receipt.json")
                    .read_text(encoding="utf-8"))
    for sentence in rc["scope"]["does_not_prove"]:
        assert sentence in manifest["scope_does_not_prove"]
    # and the README a human reads quotes the same two lines
    readme = entries_of(built)[archive.README_NAME].decode("utf-8")
    assert manifest["scope_proves"] in readme
    assert manifest["scope_does_not_prove"] in readme


def test_the_manifest_says_what_it_covers_and_covers_it(built):
    manifest = manifest_of(built)
    assert manifest["archive_version"] == archive.ARCHIVE_VERSION
    assert manifest["generated_at"].endswith("Z")
    assert manifest["manifest_covers"] == (
        f"every file in this archive except {archive.MANIFEST_NAME} itself")
    assert manifest["verdict_counts"]["receipts"] == 12
    assert len(manifest["receipts"]) == 12
    assert manifest["verification_passes"] == \
        "1 pass of at most 20 (12); every receipt was verified"


def test_the_bundled_roster_report_is_the_roster_report(built):
    """Imported, not reimplemented. The CSV in the archive is the same bytes
    `roster-report` writes for the same cohort at the same instant."""
    manifest = manifest_of(built)
    report = roster_report.build_report(EXAMPLE_TARGET,
                                        generated_at=manifest["generated_at"])
    assert entries_of(built)[archive.ROSTER_NAME].decode("utf-8") == \
        roster_report.to_csv(report)


# --------------------------------------------------------------------------
# 2. offline: extract with the network shut, verify against the bundled ledger
# --------------------------------------------------------------------------

def test_the_archive_verifies_offline_against_its_own_bundled_ledger(built, tmp_path,
                                                                     monkeypatch):
    """The product claim, exercised. Unzip into a fresh directory, cut the
    network at the socket layer, and run the real bulk verifier over the
    extracted receipts. Every one comes back `ok` with `ledger=consistent`,
    which is only possible if the ledger file it names travelled with it.

    `consistent` is the load-bearing word. A receipt whose ledger is missing
    verifies its body and reports `undetermined`; asserting only on the
    verdict would let an archive that forgot the ledger pass this test.
    """
    import socket

    dest = tmp_path / "unzipped"
    with zipfile.ZipFile(built) as z:
        z.extractall(dest)

    def no_network(*a, **kw):
        raise AssertionError("verification reached for the network")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)

    result = verify_batch.verify_batch([dest / archive.COHORT_DIR])
    assert verify_batch.exit_code(result) == 0, verify_batch.render(result)
    assert (result["verified"], result["failed"], result["undetermined"]) == (12, 0, 0)
    assert all(r["ledger"] == "consistent" for r in result["rows"]), result["rows"]
    assert len(result["rows"]) == 12


def test_the_extracted_cohort_is_flat_because_a_receipt_finds_its_ledger_beside_it(built):
    """Why `cohort/` holds receipts and ledgers together instead of sorting
    them into two folders: `verify_batch.resolve_ledger` looks for the ledger
    basename NEXT TO the receipt. Proven by asking the resolver, on the
    extracted layout, rather than by trusting the comment that says so."""
    entries = entries_of(built)
    receipt_dirs = {str(Path(n).parent) for n in entries
                    if n.endswith(".receipt.json")}
    ledger_dirs = {str(Path(n).parent) for n in entries if n.endswith(".jsonl")}
    assert receipt_dirs == ledger_dirs == {archive.COHORT_DIR}


# --------------------------------------------------------------------------
# 3. a tampered receipt is packed, with its verdict on the manifest
# --------------------------------------------------------------------------

TAMPERED = "02_oral_board_fail_partial.receipt.json"


def _tamper(target: Path) -> None:
    """One word added to one scope sentence: the smallest edit a reader would
    never catch and the digest cannot miss. Same sabotage shape as
    test_roster_report.py's, so the three modules fail the same way."""
    rc = json.loads(target.read_text(encoding="utf-8"))
    rc["scope"]["does_not_prove"][0] += " (edited)"
    target.write_text(json.dumps(rc, indent=1, ensure_ascii=False) + "\n",
                      encoding="utf-8")


def test_a_tampered_receipt_is_packed_as_a_fail_and_the_archive_still_builds(
        tmp_path):
    staged = staged_copy(tmp_path)
    _tamper(staged / TAMPERED)
    out = tmp_path / "class.zip"

    proc = run_cli("archive", staged, "--out", out)
    assert proc.returncode == 2, proc.stdout + proc.stderr     # exit code says so
    assert out.exists(), "the archive must be written even when a receipt fails"

    entries = entries_of(out)
    packed = f"{archive.COHORT_DIR}/{TAMPERED}"
    assert packed in entries, sorted(entries)
    assert entries[packed] == (staged / TAMPERED).read_bytes()

    manifest = manifest_of(out)
    assert manifest["verdict_counts"] == {"receipts": 12, "ok": 11,
                                          "FAIL": 1, "undetermined": 0}
    failed = [r for r in manifest["receipts"] if r["verdict"] == "FAIL"]
    assert len(failed) == 1 and failed[0]["file"] == packed, manifest["receipts"]
    assert "body digest mismatch" in failed[0]["reason"]
    assert failed[0]["trainee"] == "m. chen"
    assert len(manifest["receipts"]) == 12
    # and the file table still covers it, so a reader can check the bad
    # receipt's bytes against the manifest like any other file
    assert any(f["path"] == packed for f in manifest["files"])
    # the README tells the reader failures are in here rather than hiding it
    readme = entries[archive.README_NAME].decode("utf-8")
    assert "1 BROKEN" in readme


def test_an_undetermined_receipt_is_packed_too_with_exit_four(tmp_path):
    """The third verdict travels into the archive the same way. A receipt
    whose ledger is not reachable from this export is neither a pass nor an
    accusation, and it is not a reason to drop it."""
    staged = staged_copy(tmp_path)
    target = staged / "03_oral_board_reattempt.receipt.json"
    rc = json.loads(target.read_text(encoding="utf-8"))
    rc["ledger"]["path"] = "removed_from_this_export.jsonl"
    target.write_text(json.dumps(rc, indent=1, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    out = tmp_path / "class.zip"

    proc = run_cli("archive", staged, "--out", out)
    assert proc.returncode == 4, proc.stdout + proc.stderr
    manifest = manifest_of(out)
    assert manifest["verdict_counts"]["undetermined"] == 1
    und = [r for r in manifest["receipts"] if r["verdict"] == "undetermined"]
    assert len(und) == 1 and und[0]["file"].endswith("03_oral_board_reattempt.receipt.json")
    assert f"{archive.COHORT_DIR}/{target.name}" in entries_of(out)


def test_an_empty_target_is_refused_not_archived_as_a_clean_class(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    out = tmp_path / "class.zip"
    proc = run_cli("archive", empty, "--out", out)
    assert proc.returncode == 1
    assert "no receipts under" in proc.stderr
    assert not out.exists()


# --------------------------------------------------------------------------
# 4. no aggregate that implies competence
# --------------------------------------------------------------------------

def test_the_archive_carries_no_aggregate_about_scores(built):
    """The grep, over every text file in a real archive: the manifest, the
    README a stranger reads first, the bundled roster report, and every
    exhibit. The scope block denies "the score is correct"; an average, a
    rate or an ordering asserts its opposite by arithmetic."""
    entries = entries_of(built)
    for path, data in entries.items():
        if path.endswith(".receipt.json") or path.endswith(".jsonl"):
            continue                      # sealed inputs, not our sentences
        low = data.decode("utf-8").lower()
        for word in FORBIDDEN:
            assert word not in low, (path, word)


def test_no_manifest_key_is_an_aggregate(built):
    manifest = manifest_of(built)
    keys = list(manifest) + list(manifest["verdict_counts"])
    keys += list(manifest["receipts"][0]) + list(manifest["files"][0])
    for key in keys:
        # split on `_` rather than substring-matching: `generated_at` contains
        # the letters of "rate" and is not a statistic
        words = set(key.lower().split("_"))
        assert not words & {"avg", "mean", "average", "rate", "rank", "total",
                            "pct", "score", "scores"}, key
    # the only counts in the manifest are verdict counts
    assert set(manifest["verdict_counts"]) == {"receipts", "ok", "FAIL",
                                               "undetermined"}


# --------------------------------------------------------------------------
# 5. deterministic
# --------------------------------------------------------------------------

def test_the_same_cohort_archived_twice_is_the_same_bytes(tmp_path):
    """Same stamp, same input, identical files -- not just an identical
    manifest. The fixed zip timestamp is what makes this possible: without it
    every entry header carries the wall clock and two archives of one class
    differ in bytes for no reason a reader could understand."""
    a = tmp_path / "a.zip"
    b = tmp_path / "b.zip"
    archive.build_archive(EXAMPLE_TARGET, a, generated_at=STAMP)
    archive.build_archive(EXAMPLE_TARGET, b, generated_at=STAMP)
    assert a.read_bytes() == b.read_bytes()
    assert sha256(a.read_bytes()) == sha256(b.read_bytes())


def test_two_runs_differ_in_generated_at_and_in_nothing_else(tmp_path):
    a = tmp_path / "a.zip"
    b = tmp_path / "b.zip"
    m1 = archive.build_archive(EXAMPLE_TARGET, a, generated_at="2026-09-13T00:00:00Z")
    m2 = archive.build_archive(EXAMPLE_TARGET, b, generated_at="2026-09-14T09:30:00Z")
    assert m1["generated_at"] != m2["generated_at"]
    for key in m1:
        if key in ("generated_at", "files"):
            continue
        assert m1[key] == m2[key], key
    # the roster report and the README carry the stamp too, so their digests
    # move with it -- every other file in the archive is identical
    d1 = {f["path"]: f["sha256"] for f in m1["files"]}
    d2 = {f["path"]: f["sha256"] for f in m2["files"]}
    assert set(d1) == set(d2)
    differing = {p for p in d1 if d1[p] != d2[p]}
    assert differing == {archive.ROSTER_NAME, archive.README_NAME}, differing


def test_the_example_cohort_and_its_archive_are_lf_on_every_checkout():
    """examples/.gitattributes pins the cohort sources to LF (text eol=lf), so a
    Windows checkout with core.autocrlf=true and a Linux checkout read the same
    bytes, and the archive built from them is the committed one byte for byte.
    Before 2026-09-23 the committed zip held CRLF exhibits built off a Windows
    working tree and the comparison below failed on one platform or the other.
    This names that cause directly instead of leaving it to a byte diff.
    """
    crlf_sources = [p.name for p in EXAMPLES.rglob("*") if p.is_file() and b"\r\n" in p.read_bytes()]
    assert not crlf_sources, (
        "CRLF in the example cohort; examples/.gitattributes should keep these LF: "
        + ", ".join(sorted(crlf_sources)))
    crlf_entries = [n for n, b in entries_of(EXAMPLE_ARCHIVE).items() if b"\r" in b]
    assert not crlf_entries, "CR bytes in the committed example archive: " + ", ".join(crlf_entries)


def test_the_committed_example_archive_matches_a_fresh_build(tmp_path):
    """The example a buyer downloads is regenerated, not hand-assembled. If a
    change here would make the shipped archive wrong, this goes red before
    anybody opens it.

    Compared entry by entry rather than as raw zip bytes: the deflate stream
    is a property of whatever zlib built it, and holding a committed binary
    to one compressor's output would fail on a different Python for a reason
    that has nothing to do with this package. The determinism guarantee is
    the test above, which builds both sides in one process.
    """
    fresh = tmp_path / "fresh.zip"
    proc = run_cli("archive", EXAMPLE_TARGET, "--out", fresh)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    got, committed = entries_of(fresh), entries_of(EXAMPLE_ARCHIVE)
    assert set(got) == set(committed)

    stamp_new = manifest_of(fresh)["generated_at"]
    stamp_old = manifest_of(EXAMPLE_ARCHIVE)["generated_at"]
    stamped = (archive.ROSTER_NAME, archive.README_NAME)

    for path in sorted(committed):
        if path == archive.MANIFEST_NAME:
            continue
        a, b = got[path], committed[path]
        if path in stamped:                 # the clock reading, and only that
            a = a.replace(stamp_new.encode(), stamp_old.encode())
        assert a == b, path

    # the manifest, minus the clock and minus the two digests that move with
    # it: the stamp is inside the roster report and the README, so their
    # sha256 changes on every run by construction and proves nothing here
    def normalised(m):
        m = dict(m)
        m.pop("generated_at")
        m["files"] = [f for f in m["files"] if f["path"] not in stamped]
        return m

    assert normalised(manifest_of(fresh)) == normalised(manifest_of(EXAMPLE_ARCHIVE))


def test_the_summary_line_counts_files_including_the_manifest(built):
    manifest = manifest_of(built)
    line = archive.summary_line(manifest, built)
    assert line.startswith("12 receipts: 12 VERIFIED, 0 BROKEN, 0 COULD NOT LOOK")
    assert f"{len(entries_of(built))} files in {built.name}" in line
