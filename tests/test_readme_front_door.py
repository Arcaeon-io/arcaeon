"""The README's "Start here: three lines" block works exactly as written.

The block is read out of README.md, not copied here, so the test and the
README cannot drift apart. Line 1 (`pip install arcaeon`) needs the network
and PyPI, so it is checked as text; lines 2 and 3 are run as written, in
bash, in an empty folder with an empty home, against this checkout's
`arcaeon` (a two-line stand-in on PATH that runs `python -m arcaeon`).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HEADING = "## Start here: three lines"


def _block() -> list[str]:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert HEADING in text, "the README lost its front door"
    sec = text.split(HEADING, 1)[1]
    m = re.search(r"```bash\n(.*?)```", sec, re.S)
    assert m, "no bash block under the front door heading"
    return m.group(1).splitlines()


def test_the_front_door_is_the_first_section():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    first = re.search(r"^## .*$", text, re.M).group(0)
    assert first == HEADING


def test_the_guide_is_three_lines_install_first():
    lines = _block()
    assert len(lines) == 3, lines
    assert lines[0] == "pip install arcaeon"
    assert lines[1].startswith("arcaeon log ")
    for line in lines:
        assert "—" not in line and "–" not in line


@pytest.mark.skipif(shutil.which("bash") is None or os.name == "nt", reason="needs bash")
def test_lines_two_and_three_run_as_written(tmp_path):
    home, work, bindir = tmp_path / "home", tmp_path / "work", tmp_path / "bin"
    for d in (home, work, bindir):
        d.mkdir()
    shim = bindir / "arcaeon"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" -m arcaeon "$@"\n', encoding="utf-8")
    shim.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("ARCAEON_")}
    env.update(HOME=str(home), PATH=str(bindir) + os.pathsep + env.get("PATH", ""),
               PYTHONPATH=str(ROOT / "src"))
    script = "\n".join(_block()[1:]) + "\n"
    cp = subprocess.run(["bash", "-e", "-c", script], cwd=work, env=env,
                        capture_output=True, text=True, timeout=120)
    assert cp.returncode == 0, cp.stderr
    out = cp.stdout.splitlines()
    chain = out[0].strip()
    assert re.fullmatch(r"[0-9a-f]{32}", chain), out
    row = json.loads(out[1])
    assert row["action"] == "started" and row["chain"] == chain
    note = json.loads(out[2])
    assert note["verb"] == "log" and note["exit"] == 0
    assert (work / "agent.jsonl").is_file()
    assert (home / ".arcaeon" / "activity.jsonl").is_file()
