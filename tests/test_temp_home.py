"""Every test runs with the HOME itself pointed at tmp (A11).

The root conftest's `_temp_home` fixture points HOME, USERPROFILE,
HOMEDRIVE/HOMEPATH at a fresh folder under pytest's tmp for every test, so
Path.home() and os.path.expanduser("~") never name the real home. That covers
code that has no env override of its own (the ballot pin ledger defaults to
~/.arcaeon/ballot_pin_ledger.jsonl) and code a test runs with ARCAEON_HOME
unset. The real home's ~/.arcaeon is only read here (listing and mtimes),
never written.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _under(child, parent) -> bool:
    try:
        Path(child).resolve().relative_to(Path(parent).resolve())
        return True
    except ValueError:
        return False


def _listing(d: Path) -> dict:
    """{relative path: mtime_ns} for every entry under d; read-only."""
    if not d.is_dir():
        return {}
    return {str(p.relative_to(d)): p.stat().st_mtime_ns for p in d.rglob("*")}


def test_home_and_tilde_point_under_tmp(real_home_guard, tmp_path_factory):
    base = tmp_path_factory.getbasetemp()
    assert _under(Path.home(), base), Path.home()
    assert _under(os.path.expanduser("~"), base)
    assert _under(os.path.expanduser("~/.arcaeon"), base)
    assert Path.home().resolve() != real_home_guard.real_home.resolve()


def test_a_cli_run_with_no_arcaeon_home_lands_in_tmp_not_the_real_home(
        real_home_guard, monkeypatch):
    real = real_home_guard.real_home / ".arcaeon"
    before = _listing(real)
    monkeypatch.delenv("ARCAEON_HOME", raising=False)
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)
    from arcaeon import cli
    assert cli.main(["version"]) == 0
    journal = Path.home() / ".arcaeon" / "activity.jsonl"
    assert journal.is_file() and '"verb":"version"' in journal.read_text(encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "ARCAEON_HOME"}
    env["PYTHONPATH"] = str(ROOT / "src")
    p = subprocess.run([sys.executable, "-m", "arcaeon", "version"], env=env, cwd=ROOT,
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    rows = journal.read_text(encoding="utf-8").count('"verb":"version"')
    assert rows == 2, "the subprocess journal did not land in the tmp home"
    assert _listing(real) == before


def test_a_subprocess_under_the_tmp_home_keeps_the_real_user_site():
    """The home swap must not hide `pip install --user` packages from a child,
    even one whose PYTHONPATH is replaced (as tools/sync_verbs_usage.py does)."""
    import site
    if not (site.ENABLE_USER_SITE and os.path.isdir(site.getusersitepackages())):
        import pytest
        pytest.skip("no user site-packages in this interpreter")
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    p = subprocess.run([sys.executable, "-c", "import site; print(site.getusersitepackages())"],
                       env=env, cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    assert os.path.normcase(p.stdout.strip()) == os.path.normcase(site.getusersitepackages())


def test_the_ballot_pin_ledger_default_follows_the_tmp_home(real_home_guard, monkeypatch):
    from arcaeon.record.receipt import ballot
    monkeypatch.delenv(ballot.PIN_LEDGER_ENV, raising=False)
    target = ballot.pin_ledger_path()
    assert target == Path.home() / ".arcaeon" / "ballot_pin_ledger.jsonl"
    assert ballot.DEFAULT_PIN_LEDGER == target  # the old public name still works
    assert not _under(target, real_home_guard.real_home / ".arcaeon")
