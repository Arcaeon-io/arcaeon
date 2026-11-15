"""`arcaeon start <memory folder>`: the one front door for shell agents.

One command, pointed at the folder an agent already keeps its memory in,
starts a sealed record of it: hash-chained rows, the head pinned in a local
pin file. Plain words out, no key, no network, and safe to run twice.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon.record import start
from arcaeon.record.ledger import verify_file

SRC = Path(__file__).resolve().parents[1] / "src"


@pytest.fixture
def home(monkeypatch, tmp_path):
    h = tmp_path / "arc_home"
    monkeypatch.setenv("ARCAEON_HOME", str(h))
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    monkeypatch.setattr(socket.socket, "connect",
                        lambda *a, **k: pytest.fail("network used"))
    return h


@pytest.fixture
def mem(tmp_path):
    m = tmp_path / "memory"
    (m / "notes").mkdir(parents=True)
    (m / "MEMORY.md").write_text("the user likes short answers\n", encoding="utf-8")
    (m / "notes" / "project.md").write_text("ship the front door\n", encoding="utf-8")
    return m


def _run(capsys, *argv):
    rc = cli.main(["start", *map(str, argv)])
    c = capsys.readouterr()
    return rc, c.out, c.err


def _paths(m: Path):
    d = start.record_dir(m.resolve())
    return d / start.RECORD_NAME, d / start.PINS_NAME


def _rows(record: Path):
    return [json.loads(x) for x in record.read_text(encoding="utf-8").splitlines() if x]


# --- the first run ----------------------------------------------------------------

def test_first_run_writes_one_row_and_one_pin(home, mem, capsys):
    rc, out, err = _run(capsys, mem)
    assert rc == 0, err
    record, pins = _paths(mem)
    rows = _rows(record)
    assert len(rows) == 1
    r = rows[0]
    assert r["evt"] == start.EVT_STARTED
    assert r["folder"] == str(mem.resolve())
    assert r["files"] == 2
    assert set(r["manifest"]) == {"MEMORY.md", "notes/project.md"}
    assert r["unread"] == [] and r["changed"] == [] and r["removed"] == []
    assert verify_file(record).ok is True
    pin_rows = [json.loads(x) for x in pins.read_text(encoding="utf-8").splitlines() if x]
    assert len(pin_rows) == 1 and pin_rows[0]["rows"] == 1
    assert "First look: 2 files. Written as row 1 and sealed." in out


def test_the_record_lives_outside_the_memory_folder(home, mem, capsys):
    before = sorted(p.relative_to(mem) for p in mem.rglob("*"))
    _run(capsys, mem)
    _run(capsys, mem)
    assert sorted(p.relative_to(mem) for p in mem.rglob("*")) == before
    record, _ = _paths(mem)
    assert home in record.parents


def test_output_is_plain_words(home, mem, capsys):
    _, out, err = _run(capsys, mem)
    (mem / "MEMORY.md").write_text("changed\n", encoding="utf-8")
    _, out2, err2 = _run(capsys, mem)
    text = out + err + out2 + err2
    for token in ("{", "}", "sha256", "Traceback", "chain_mismatch", chr(0x2014), chr(0x2013)):
        assert token not in text, token
    assert out.startswith("Keeping a sealed record of ")


def test_no_key_is_needed_or_read(home, mem, capsys, monkeypatch):
    monkeypatch.setenv("ARCAEON_KEY", "should-never-be-read")
    import arcaeon.remote as remote
    monkeypatch.setattr(remote, "key", lambda: pytest.fail("start read the key"))
    rc, _, err = _run(capsys, mem)
    assert rc == 0, err


# --- safe to run twice -------------------------------------------------------------

def test_second_run_with_no_change_writes_nothing(home, mem, capsys):
    _run(capsys, mem)
    record, pins = _paths(mem)
    r1, p1 = record.read_bytes(), pins.read_bytes()
    rc, out, err = _run(capsys, mem)
    assert rc == 0, err
    assert record.read_bytes() == r1 and pins.read_bytes() == p1
    assert "No change since row 1: 2 files, the same as last time. Nothing written." in out


def test_many_runs_with_no_change_stay_one_row(home, mem, capsys):
    for _ in range(5):
        assert _run(capsys, mem)[0] == 0
    assert len(_rows(_paths(mem)[0])) == 1


def test_a_relative_path_and_a_trailing_slash_find_the_same_record(home, mem, capsys, monkeypatch):
    _run(capsys, mem)
    monkeypatch.chdir(mem.parent)
    rc, out, _ = _run(capsys, "memory" + os.sep)
    assert rc == 0 and "No change since row 1" in out
    rc, out, _ = _run(capsys, "./memory")
    assert rc == 0 and "No change since row 1" in out
    assert len(list((home / "memory").iterdir())) == 1


def test_two_runs_through_the_real_command(home, mem):
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8")
    env.pop("ARCAEON_KEY", None)
    outs = []
    for _ in range(2):
        p = subprocess.run([sys.executable, "-m", "arcaeon", "start", str(mem)],
                           capture_output=True, text=True, encoding="utf-8", env=env,
                           timeout=120)
        assert p.returncode == 0, p.stderr
        outs.append(p.stdout)
    assert "Written as row 1 and sealed." in outs[0]
    assert "Nothing written." in outs[1]


# --- changes -----------------------------------------------------------------------

def test_a_change_adds_one_row_naming_what_changed(home, mem, capsys):
    _run(capsys, mem)
    (mem / "MEMORY.md").write_text("the user likes long answers\n", encoding="utf-8")
    (mem / "notes" / "new.md").write_text("new\n", encoding="utf-8")
    (mem / "notes" / "project.md").unlink()
    rc, out, err = _run(capsys, mem)
    assert rc == 0, err
    rows = _rows(_paths(mem)[0])
    assert len(rows) == 2
    r = rows[1]
    assert r["evt"] == start.EVT_CHANGED
    assert (r["added"], r["changed"], r["removed"]) == (["notes/new.md"], ["MEMORY.md"],
                                                        ["notes/project.md"])
    assert "Changed since row 1: 1 added, 1 changed, 1 removed. Written as row 2 and sealed." in out
    assert "  changed: MEMORY.md" in out
    # and the next run is quiet again
    rc, out, _ = _run(capsys, mem)
    assert rc == 0 and "No change since row 2" in out
    (mem / "MEMORY.md").write_text("again\n", encoding="utf-8")
    rc, out, _ = _run(capsys, mem)
    assert "Changed since row 2: 1 changed. Written as row 3 and sealed." in out


def test_an_empty_folder_is_recorded(home, tmp_path, capsys):
    m = tmp_path / "empty"
    m.mkdir()
    rc, out, err = _run(capsys, m)
    assert rc == 0, err
    assert "First look: 0 files." in out
    (m / "first.md").write_text("x", encoding="utf-8")
    rc, out, _ = _run(capsys, m)
    assert rc == 0 and "1 added" in out


def test_long_lists_are_cut_on_screen_but_whole_in_the_row(home, mem, capsys):
    _run(capsys, mem)
    for i in range(15):
        (mem / f"n{i:02}.md").write_text(str(i), encoding="utf-8")
    rc, out, _ = _run(capsys, mem)
    assert rc == 0
    assert ", and 5 more" in out
    assert len(_rows(_paths(mem)[0])[1]["added"]) == 15


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlinks here")
def test_a_link_is_recorded_not_followed(home, mem, tmp_path, capsys):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.md").write_text("not memory", encoding="utf-8")
    try:
        os.symlink(outside, mem / "linked")
    except (OSError, NotImplementedError):
        pytest.skip("cannot make a symlink here")
    rc, _, err = _run(capsys, mem)
    assert rc == 0, err
    manifest = _rows(_paths(mem)[0])[0]["manifest"]
    assert manifest["linked"].startswith("link:")
    assert not any(k.startswith("linked/") for k in manifest)


# --- a record that does not check out -------------------------------------------------

def test_an_edited_row_is_broken_and_nothing_is_added(home, mem, capsys):
    _run(capsys, mem)
    record, _ = _paths(mem)
    record.write_text(record.read_text(encoding="utf-8").replace('"files": 2', '"files": 3'),
                      encoding="utf-8")
    before = record.read_bytes()
    (mem / "MEMORY.md").write_text("changed\n", encoding="utf-8")
    rc, out, err = _run(capsys, mem)
    assert rc == 1
    assert err.startswith("BROKEN: the record does not check out")
    assert record.read_bytes() == before
    assert "Keep that folder as it is" in err


def test_rows_cut_off_the_end_are_broken(home, mem, capsys):
    _run(capsys, mem)
    (mem / "MEMORY.md").write_text("changed\n", encoding="utf-8")
    _run(capsys, mem)
    record, _ = _paths(mem)
    lines = record.read_text(encoding="utf-8").splitlines(True)
    record.write_text(lines[0], encoding="utf-8")
    rc, _, err = _run(capsys, mem)
    assert rc == 1
    assert "BROKEN: rows were cut off the end of the record: it holds 1, its pin says 2" in err
    assert "Nothing was added." in err


def test_a_deleted_pin_file_is_broken(home, mem, capsys):
    _run(capsys, mem)
    _paths(mem)[1].unlink()
    rc, _, err = _run(capsys, mem)
    assert rc == 1 and "pin file is gone" in err


def test_a_deleted_record_with_its_pins_left_is_broken(home, mem, capsys):
    _run(capsys, mem)
    _paths(mem)[0].unlink()
    rc, _, err = _run(capsys, mem)
    assert rc == 1 and "the record is gone" in err


def test_moving_the_broken_record_aside_starts_fresh(home, mem, capsys):
    _run(capsys, mem)
    record, _ = _paths(mem)
    record.write_text("not json\n", encoding="utf-8")
    assert _run(capsys, mem)[0] == 1
    record.parent.rename(record.parent.with_name("kept-as-evidence"))
    rc, out, _ = _run(capsys, mem)
    assert rc == 0 and "First look" in out


def test_the_printed_check_command_verifies(home, mem, capsys):
    _, out, _ = _run(capsys, mem)
    line = next(x for x in out.splitlines() if x.startswith("Anyone can check it: "))
    argv = line.split("Anyone can check it: ", 1)[1].split()
    assert argv[:2] == ["arcaeon", "verify"]
    rc = cli.main(argv[1:])
    report = capsys.readouterr().out
    assert rc == 0, report
    assert '"verdict": "VERIFIED"' in report


# --- what it refuses ----------------------------------------------------------------

def test_no_folder_is_usage(home, capsys):
    rc, _, err = _run(capsys)
    assert rc == 2 and err.startswith("usage: arcaeon start")


def test_a_missing_folder_is_usage(home, tmp_path, capsys):
    rc, _, err = _run(capsys, tmp_path / "nope")
    assert rc == 2 and "no such folder" in err
    assert not (home / "memory").exists()


def test_a_file_is_not_a_folder(home, mem, capsys):
    rc, _, err = _run(capsys, mem / "MEMORY.md")
    assert rc == 2 and "not a folder" in err


def test_the_home_folder_itself_is_refused(home, monkeypatch, tmp_path, capsys):
    fake_home = tmp_path / "me"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    rc, _, err = _run(capsys, fake_home)
    assert rc == 2 and "not a memory folder" in err


def test_an_unknown_option_is_usage(home, mem, capsys):
    rc, _, err = _run(capsys, mem, "--force")
    assert rc == 2 and "unknown option" in err


def test_too_many_files_is_usage_and_writes_nothing(home, mem, capsys, monkeypatch):
    monkeypatch.setattr(start, "MAX_FILES", 1)
    rc, _, err = _run(capsys, mem)
    assert rc == 2 and "more than 1 files" in err
    assert not _paths(mem)[0].exists()


def test_help_is_exit_0(home, capsys):
    rc, out, _ = _run(capsys, "--help")
    assert rc == 0 and out.startswith("usage: arcaeon start <memory folder>")


# --- could not look ------------------------------------------------------------------

@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs a file this user cannot read")
def test_an_unreadable_file_is_could_not_look_and_named(home, mem, capsys):
    locked = mem / "locked.md"
    locked.write_text("x", encoding="utf-8")
    locked.chmod(0)
    try:
        rc, out, err = _run(capsys, mem)
        assert rc == 3
        assert "COULD NOT LOOK: 1 file could not be read" in err
        assert "locked.md" in err
        row = _rows(_paths(mem)[0])[0]
        assert row["unread"] == ["locked.md"] and "MEMORY.md" in row["manifest"]
        # the same unreadable file again is no change, still COULD NOT LOOK
        rc, out, _ = _run(capsys, mem)
        assert rc == 3 and "Nothing written." in out
    finally:
        locked.chmod(0o600)


def test_an_unreadable_file_through_a_stub(home, mem, capsys, monkeypatch):
    real = start._sha256_file

    def fake(p):
        if p.name == "project.md":
            raise PermissionError(13, "denied", str(p))
        return real(p)
    monkeypatch.setattr(start, "_sha256_file", fake)
    rc, _, err = _run(capsys, mem)
    assert rc == 3 and "notes/project.md" in err
    row = _rows(_paths(mem)[0])[0]
    assert row["unread"] == ["notes/project.md"]
    assert "notes/project.md" not in row["manifest"]
    # once readable again it is added, not left out
    monkeypatch.setattr(start, "_sha256_file", real)
    rc, out, _ = _run(capsys, mem)
    assert rc == 0 and "1 added" in out


def test_the_record_folder_inside_the_memory_folder_is_left_out(monkeypatch, mem, capsys):
    monkeypatch.setenv("ARCAEON_HOME", str(mem / ".arcaeon"))
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    _run(capsys, mem)
    rc, out, _ = _run(capsys, mem)
    assert rc == 0 and "No change since row 1" in out


# --- the front door ----------------------------------------------------------------------

def test_start_is_listed_first_in_help():
    text = cli.help_text()
    record = text.split("Record:\n", 1)[1]
    assert record.lstrip().startswith("start ")


def test_start_is_journaled_by_path_hash_only(home, mem, capsys):
    _run(capsys, mem)
    lines = (home / "activity.jsonl").read_text(encoding="utf-8").splitlines()
    last = json.loads(lines[-1])
    assert last["verb"] == "start" and last["exit"] == 0
    assert str(mem) not in lines[-1] and "memory" not in lines[-1]


def test_a_same_length_rewrite_is_broken(home, mem, capsys):
    """Every row rewritten with its chain recomputed, the same row count: the
    chain alone verifies, and the pin is what catches it."""
    from arcaeon.record.ledger import Ledger
    _run(capsys, mem)
    record, _ = _paths(mem)
    row = _rows(record)[0]
    row["manifest"]["MEMORY.md"] = "0" * 64
    for k in ("chain", "ts"):
        row.pop(k)
    record.unlink()
    Ledger(record).append(row)
    assert verify_file(record).ok is True
    rc, _, err = _run(capsys, mem)
    assert rc == 1
    assert err.startswith("BROKEN: the record was rewritten: its row 1 is not the row its pin")


def test_an_unreadable_record_is_could_not_look_not_empty(home, mem, capsys, monkeypatch):
    _run(capsys, mem)
    record, _ = _paths(mem)
    before = record.read_bytes()
    import arcaeon.record.ledger as ledger

    class Unread:
        ok, rows, verified_scope, first_break = None, 0, "unreadable", None
    monkeypatch.setattr(ledger, "verify_file", lambda *a, **k: Unread())
    rc, _, err = _run(capsys, mem)
    assert rc == 3 and err.startswith("COULD NOT LOOK: the record could not be read")
    assert record.read_bytes() == before


def test_an_empty_record_file_with_no_pins_starts(home, mem, capsys):
    record, _ = _paths(mem)
    record.parent.mkdir(parents=True)
    record.write_text("", encoding="utf-8")
    rc, out, _ = _run(capsys, mem)
    assert rc == 0 and "First look" in out
