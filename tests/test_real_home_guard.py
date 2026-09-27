"""The suite never writes to the real home (K14xR).

The root conftest points ARCAEON_HOME and MCP_VET_AUDIT_LEDGER at a throwaway
session home before any test runs, re-points them for every test that finds
them gone or naming the real place, and measures the real ~/.arcaeon and
~/.mcp_vet at the start and the end of the session: any change fails the
session by name. These tests hold the parts of that guard.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _under(child: str, parent: Path) -> bool:
    try:
        Path(child).resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def test_every_test_runs_with_both_homes_away_from_the_real_one(real_home_guard):
    g = real_home_guard
    assert not _under(os.environ["ARCAEON_HOME"], g.real_home / ".arcaeon")
    assert not _under(os.environ["MCP_VET_AUDIT_LEDGER"], g.real_home / ".mcp_vet")


def test_the_fixture_steps_in_only_when_the_home_is_gone_or_real(real_home_guard, tmp_path):
    g = real_home_guard
    real = g.real_home / ".arcaeon"
    assert g.is_real(None, real) and g.is_real("", real)
    assert g.is_real(str(real), real)
    assert not g.is_real(str(tmp_path / "own_home"), real)


def test_a_subprocess_journals_into_the_session_home_not_the_real_one(real_home_guard):
    g = real_home_guard
    before = g.snapshot(g.watch)
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    p = subprocess.run([sys.executable, "-m", "arcaeon", "version"], env=env, cwd=ROOT,
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    journal = Path(os.environ["ARCAEON_HOME"]) / "activity.jsonl"
    assert journal.is_file() and '"verb":"version"' in journal.read_text(encoding="utf-8")
    real_journal = str(g.real_home / ".arcaeon" / "activity.jsonl")
    assert before.get(real_journal) == g.snapshot(g.watch).get(real_journal)


def test_snapshot_and_changes_name_every_kind_of_change(real_home_guard, tmp_path):
    g = real_home_guard
    a, b = tmp_path / ".arcaeon", tmp_path / ".mcp_vet"
    a.mkdir()
    (a / "activity.jsonl").write_bytes(b"one\n")
    (a / "gone.txt").write_bytes(b"x")
    before = g.snapshot([a, b])
    assert before == {str(a / "activity.jsonl"): 4, str(a / "gone.txt"): 1}
    (a / "activity.jsonl").write_bytes(b"one\ntwo\n")
    (a / "gone.txt").unlink()
    b.mkdir()
    (b / "audit.jsonl").write_bytes(b"row\n")
    changed = g.changes(before, g.snapshot([a, b]))
    assert changed == [f"{a / 'activity.jsonl'} (4 -> 8 bytes)", f"{a / 'gone.txt'} (removed)",
                       f"{b / 'audit.jsonl'} (new, 4 bytes)"]
    assert g.changes(before, before) == []


def test_a_session_that_writes_to_the_watched_home_fails_by_name(tmp_path):
    """End to end in a scratch project: a conftest that copies the guard's
    end check, a test that writes into the watched dir, and the session exits 1
    naming the file."""
    proj = tmp_path / "proj"
    proj.mkdir()
    watched = tmp_path / "fakehome" / ".arcaeon"
    watched.mkdir(parents=True)
    src = (ROOT / "conftest.py").read_text(encoding="utf-8")
    start = src.index("def home_snapshot(")
    end = src.index("def _is_real(")
    (proj / "conftest.py").write_text(
        "import os\nfrom pathlib import Path\n" + src[start:end] +
        f"WATCH = [Path({str(watched)!r})]\nBEFORE = home_snapshot(WATCH)\n\n\n"
        "def pytest_sessionfinish(session, exitstatus):\n"
        "    changed = home_changes(BEFORE, home_snapshot(WATCH))\n"
        "    if changed:\n"
        "        print('REAL HOME WRITTEN: ' + '; '.join(changed))\n"
        "        session.exitstatus = 1\n", encoding="utf-8")
    (proj / "test_writes.py").write_text(
        "from pathlib import Path\n\n\ndef test_it():\n"
        f"    Path({str(watched / 'activity.jsonl')!r}).write_text('x', encoding='utf-8')\n",
        encoding="utf-8")
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                        str(proj)], cwd=proj, capture_output=True, text=True, timeout=120)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "REAL HOME WRITTEN" in p.stdout and "activity.jsonl (new, 1 bytes)" in p.stdout
