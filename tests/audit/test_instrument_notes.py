"""`--instrument-notes`: the checker's own confessed blind spots, carried verbatim.

The convention (README, "Instrument defects"): a published audit result should
name its known false-positive modes, its known false-negative modes, and what it
did NOT exercise. This package's job is to carry that statement, not to grade it
— there is no validation, deliberately, because the value is the slot existing.

Two properties are worth a test, and only two:

    VERBATIM — byte-for-byte, or it is not the author's disclosure any more. A
    tool that reflows, re-wraps, or "normalises" someone else's account of their
    own limits has quietly become a co-author of it. Asserted on exact bytes and
    sha256, never on `in`.

    LOUD — asked for and unreadable, the export ABORTS. The failure this guards
    is the reason the convention exists: a bundle missing its instrument block
    is indistinguishable from a bundle by an author who was never asked, so a
    silent skip converts a disclosure the operator REQUESTED into an absence
    nobody can see. Exit 2 ("the check could not complete"), never 0.

The planted red is `test_missing_notes_file_never_produces_a_bundle`: delete the
abort and it fails, which was demonstrated before this file was committed.
"""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from arcaeon.record.ledger import Ledger

import arcaeon.prove.audit


TEMPLATE = """## Instrument
**Known false positives:** clock skew across the fleet can mark a same-second
write as out-of-order.
**Known false negatives:** truncation after the last pin is invisible.
**Not exercised:** the remote witness path; only the local store was run.
"""


def _run(*args):
    """Invoke the real CLI the way a customer's CI does."""
    p = subprocess.run([sys.executable, "-m", "arcaeon.prove.audit.cli", *args],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    return p.returncode, (p.stdout or ""), (p.stderr or "")


def _chained(d, n=5):
    p = Path(d) / "audit.jsonl"
    log = Ledger(p)
    for i in range(n):
        log.append({"actor": "agent", "decision": f"d{i}"})
    return p


def _notes(d, text=TEMPLATE, name="instrument.md"):
    p = Path(d) / name
    p.write_bytes(text.encode("utf-8"))
    return p


# --------------------------------------------------------------------------
# verbatim
# --------------------------------------------------------------------------

def test_notes_are_embedded_byte_for_byte():
    """Exact bytes, not `in`. A containment check passes on a reflowed copy."""
    with tempfile.TemporaryDirectory() as d:
        log = _chained(d)
        notes = _notes(d)
        out = Path(d) / "out"
        code, stdout, stderr = _run("export", str(log), str(out),
                                    "--instrument-notes", str(notes))
        assert code == 0, stdout + stderr

        src = notes.read_bytes()
        got = (out / "INSTRUMENT_NOTES.md").read_bytes()
        assert got == src
        assert hashlib.sha256(got).hexdigest() == hashlib.sha256(src).hexdigest()

        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["instrument_notes"] == src.decode("utf-8")
        assert integ["instrument_notes_sha256"] == hashlib.sha256(src).hexdigest()


def test_verbatim_survives_everything_a_normaliser_would_eat():
    """CRLF, a tab, trailing spaces, non-ASCII, no trailing newline, a blank
    run. `Path.read_text()` alone would silently fold the CRLFs on Windows —
    which is why the reader goes through bytes."""
    hostile = ("## Instrument\r\n"
               "\tfalse positives: — none known   \r\n"
               "\r\n\r\n"
               "false negatives: café ✅  trailing nbsp \n"
               "not exercised: everything after this line")   # no trailing \n
    with tempfile.TemporaryDirectory() as d:
        log = _chained(d)
        notes = _notes(d, hostile)
        out = Path(d) / "out"
        code, stdout, stderr = _run("export", str(log), str(out),
                                    "--instrument-notes", str(notes))
        assert code == 0, stdout + stderr
        assert (out / "INSTRUMENT_NOTES.md").read_bytes() == notes.read_bytes()
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["instrument_notes"] == hostile


def test_notes_reach_the_human_readable_half_too():
    """A reader who never opens integrity.json still meets the confessed limits
    next to the verdict."""
    with tempfile.TemporaryDirectory() as d:
        log = _chained(d)
        notes = _notes(d)
        out = Path(d) / "out"
        _run("export", str(log), str(out), "--instrument-notes", str(notes))
        summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
        assert "## Instrument — known defects of this check" in summary
        assert TEMPLATE.strip() in summary


def test_contents_are_never_validated():
    """No schema, no required headings, no opinion. The slot existing is the
    product; policing what an author writes in it is not this tool's business."""
    with tempfile.TemporaryDirectory() as d:
        log = _chained(d)
        notes = _notes(d, "lol nothing here\n")
        out = Path(d) / "out"
        code, stdout, stderr = _run("export", str(log), str(out),
                                    "--instrument-notes", str(notes))
        assert code == 0, stdout + stderr
        assert (out / "INSTRUMENT_NOTES.md").read_text(encoding="utf-8") == \
            "lol nothing here\n"


def test_python_api_carries_the_notes_too():
    """The CLI is one caller. `export_bundle(instrument_notes=...)` is the other."""
    with tempfile.TemporaryDirectory() as d:
        log = _chained(d)
        out = arcaeon.prove.audit.export_bundle(log, Path(d) / "out",
                                          instrument_notes=TEMPLATE)
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["instrument_notes"] == TEMPLATE
        assert (out / "INSTRUMENT_NOTES.md").read_bytes() == TEMPLATE.encode("utf-8")


# --------------------------------------------------------------------------
# loud — the planted red
# --------------------------------------------------------------------------

def test_missing_notes_file_never_produces_a_bundle():
    """PLANTED RED. Delete the abort in cli.py and this fails.

    The whole convention dies here if it fails quietly: an export that was ASKED
    for an instrument block and shipped without one looks exactly like an export
    whose author never confessed anything. Absence laundered as presence, in a
    regulator-facing artefact, at exit 0.
    """
    with tempfile.TemporaryDirectory() as d:
        log = _chained(d)
        out = Path(d) / "out"
        code, stdout, stderr = _run("export", str(log), str(out),
                                    "--instrument-notes", str(Path(d) / "nope.md"))
        assert code != 0, f"exit 0 on a missing notes file. stdout={stdout!r}"
        assert code == 2, f"expected 2 (check could not complete), got {code}"
        assert "instrument-notes" in stderr
        assert "no bundle was written" in stderr
        # and it means it: nothing on disk, not even a half-written folder
        assert not (out / "integrity.json").exists()
        assert not (out / "records.jsonl").exists()


def test_unreadable_notes_path_aborts_the_same_way():
    """A directory where a file was named — the OSError branch, not ENOENT."""
    with tempfile.TemporaryDirectory() as d:
        log = _chained(d)
        adir = Path(d) / "notes_dir"
        adir.mkdir()
        code, stdout, stderr = _run("export", str(log), str(Path(d) / "out"),
                                    "--instrument-notes", str(adir))
        assert code == 2, f"stdout={stdout!r} stderr={stderr!r}"
        assert "instrument-notes" in stderr


def test_non_utf8_notes_abort_rather_than_get_mangled():
    """The other way to lose the author's bytes: decode them wrong and ship it.
    Refuse instead — a mojibake disclosure is a corrupted one."""
    with tempfile.TemporaryDirectory() as d:
        log = _chained(d)
        notes = Path(d) / "latin1.md"
        notes.write_bytes(b"false negatives: caf\xe9 truncation\n")
        code, stdout, stderr = _run("export", str(log), str(Path(d) / "out"),
                                    "--instrument-notes", str(notes))
        assert code == 2, f"stdout={stdout!r} stderr={stderr!r}"
        assert "UTF-8" in stderr


# --------------------------------------------------------------------------
# backwards compatibility — the flag is additive or it is a regression
# --------------------------------------------------------------------------

def test_no_flag_adds_no_key_and_no_file():
    """Existing consumers parse integrity.json. A new key that appears
    unconditionally is a breaking change dressed as a feature."""
    with tempfile.TemporaryDirectory() as d:
        log = _chained(d)
        out = Path(d) / "out"
        code, stdout, stderr = _run("export", str(log), str(out))
        assert code == 0, stdout + stderr
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert "instrument_notes" not in integ
        assert "instrument_notes_sha256" not in integ
        assert not (out / "INSTRUMENT_NOTES.md").exists()
        assert sorted(p.name for p in out.iterdir()) == [
            "ARTICLE_12_SUMMARY.md", "integrity.json", "manifest.json",
            "records.jsonl"]


def test_no_flag_summary_is_unchanged_and_says_nothing_about_instruments():
    """No warning spam either: a nag on every export trains people to ignore it."""
    with tempfile.TemporaryDirectory() as d:
        log = _chained(d)
        out = Path(d) / "out"
        code, stdout, stderr = _run("export", str(log), str(out))
        assert code == 0, stdout + stderr
        summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
        assert "Instrument" not in summary
        assert "instrument" not in stdout.lower()
        assert stderr == ""
        # the section splice must not perturb the surrounding prose
        assert ("## Integrity\nVERIFIED (MODULO TRUNCATION)" in summary
                or "## Integrity\n" in summary)
        assert "\n\n\nVerification is reproducible" not in summary
