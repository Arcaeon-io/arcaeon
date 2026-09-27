"""`arcaeon demo` (K116): VERIFIED, one word changed, BROKEN on line 1, exit 0.
No network: socket connections fail the test."""
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from arcaeon import demo

SRC = Path(__file__).resolve().parents[1] / "src"


@pytest.fixture
def no_net(monkeypatch, tmp_path):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arc_home"))
    monkeypatch.setattr(socket.socket, "connect",
                        lambda *a, **k: pytest.fail("network used"))


def test_story_ends_on_the_broken_line_and_exits_0(no_net, capsys):
    assert demo.main([]) == 0
    lines = capsys.readouterr().out.rstrip("\n").splitlines()
    assert lines[-1] == "BROKEN: line 1: chain mismatch"
    assert "Check the record: VERIFIED, 2 rows, every link holds." in lines
    assert lines.index("Check the record: VERIFIED, 2 rows, every link holds.") < len(lines) - 1


def test_story_is_plain_words(no_net, capsys):
    demo.main([])
    out = capsys.readouterr().out
    for word in ("chain_mismatch", "sha256", "{", "Traceback", "—", "–"):
        assert word not in out
    assert "20 dollars becomes 200 dollars" in out


def test_nothing_left_behind(no_net, monkeypatch, tmp_path):
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    assert demo.main([]) == 0
    assert list(scratch.iterdir()) == []


def test_a_demo_that_did_not_break_exits_1(no_net, monkeypatch, capsys):
    monkeypatch.setattr(demo, "NEW", demo.OLD)   # the edit changes nothing
    assert demo.main([]) == 1
    assert capsys.readouterr().out.rstrip().splitlines()[-1].startswith("VERIFIED")


def test_usage(no_net, capsys):
    assert demo.main(["extra"]) == 2
    assert demo.main(["--help"]) == 0
    assert "usage: arcaeon demo" in capsys.readouterr().out


def test_front_door_prints_the_same_story(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8",
               ARCAEON_HOME=str(tmp_path / "arc_home"))
    p = subprocess.run([sys.executable, "-m", "arcaeon", "demo"], env=env, cwd=tmp_path,
                       capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert p.returncode == 0, p.stderr
    assert p.stdout.rstrip().splitlines()[-1] == "BROKEN: line 1: chain mismatch"
