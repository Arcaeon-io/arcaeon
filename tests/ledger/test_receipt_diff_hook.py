# SPDX-License-Identifier: MIT
"""test_receipt_diff_hook.py -- tests for hooks/receipt_diff.py.

Every test runs against a REAL git repo built in tmp_path (git init, real
commits) rather than a mocked one -- the whole point of this hook is
`git diff --cached` and `git rev-list --count`, and a fake would test our
assumptions about git instead of git itself.

THE TEST THAT MATTERS MOST is `test_bypassed_commit_is_labelled_not_silent`:
it reproduces the exact `--no-verify` scenario the hook exists to catch --
hook runs, commit lands, a SECOND commit lands with the hook skipped, hook
runs again -- and asserts the gap is not just non-zero but carries the
literal "N commit(s) since the last receipted diff" wording, so a human
reading stderr sees the gap rather than a quiet, clean-looking run.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("receipt_diff", _HERE / "hooks" / "receipt_diff.py")
receipt_diff = importlib.util.module_from_spec(_spec)
sys.modules["receipt_diff"] = receipt_diff
_spec.loader.exec_module(receipt_diff)


def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"git {args} failed: {r.stderr}"
    return r.stdout.strip()


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "Test")
    return root


def _write_and_stage(repo: Path, name: str, content: str) -> None:
    (repo / name).write_text(content, encoding="utf-8")
    _git(repo, "add", name)


def _commit(repo: Path, msg: str, *, no_verify: bool = False) -> str:
    args = ["commit", "-m", msg]
    if no_verify:
        args.append("--no-verify")
    _git(repo, *args)
    return _git(repo, "rev-parse", "HEAD")


# ---------------------------------------------------------------------------
# basic mint behavior
# ---------------------------------------------------------------------------

def test_nothing_staged_is_skipped_not_minted(repo: Path):
    result = receipt_diff.mint_receipt(repo)
    assert result == {"minted": False, "skipped": "nothing staged"}
    assert not receipt_diff.ledger_path(repo).exists()


def test_first_ever_receipt_on_empty_repo_history(repo: Path):
    """No commits exist yet (unborn HEAD) and no prior ledger row: this is
    the 'first_receipt' state, not 'clean' and not 'gap' -- there is nothing
    yet to be clean or gapped relative to."""
    _write_and_stage(repo, "a.txt", "hello\n")
    result = receipt_diff.mint_receipt(repo)
    assert result["minted"] is True
    assert result["gap"] == {"status": "first_receipt", "gap_commits": 0}
    ledger = list(receipt_diff.Ledger(receipt_diff.ledger_path(repo)))
    assert len(ledger) == 1
    row = ledger[0]
    assert row["kind"] == "staged-diff"
    assert row["extra"]["parent_head"] is None
    assert row["scope"]["proves"] and row["scope"]["does_not_prove"]
    assert any("no-verify" in s for s in row["scope"]["does_not_prove"])
    assert any("reviewed" in s for s in row["scope"]["does_not_prove"])


def test_scope_never_overclaims_review_or_bypass_immunity(repo: Path):
    """The scope wording is the product; pin its exact honesty here so an
    edit that softens it fails loudly."""
    _write_and_stage(repo, "a.txt", "hello\n")
    result = receipt_diff.mint_receipt(repo)
    scope = list(receipt_diff.Ledger(receipt_diff.ledger_path(repo)))[0]["scope"]
    proves = " ".join(scope["proves"])
    does_not = " ".join(scope["does_not_prove"])
    assert "existed" in proves and "hashed" in proves
    assert "reviewed by anyone" in does_not
    assert "ended up in the resulting commit" in does_not
    assert "bypassed" in does_not


def test_clean_run_after_one_normal_commit(repo: Path):
    """Hook fires, commit lands normally (no bypass), hook fires again: the
    gap between the two hook runs must read 'clean', not a false positive."""
    _write_and_stage(repo, "a.txt", "one\n")
    r1 = receipt_diff.mint_receipt(repo)
    assert r1["gap"]["status"] == "first_receipt"
    _commit(repo, "commit 1")

    _write_and_stage(repo, "b.txt", "two\n")
    r2 = receipt_diff.mint_receipt(repo)
    assert r2["minted"] is True
    assert r2["gap"] == {"status": "clean", "gap_commits": 0}


# ---------------------------------------------------------------------------
# THE case that matters: --no-verify must be labelled, never silently clean
# ---------------------------------------------------------------------------

def test_bypassed_commit_is_labelled_not_silent(repo: Path):
    # commit 1: hook runs, then the commit lands normally
    _write_and_stage(repo, "a.txt", "one\n")
    r1 = receipt_diff.mint_receipt(repo)
    assert r1["minted"] is True
    _commit(repo, "commit 1")

    # commit 2: made with the hook SKIPPED (the --no-verify scenario)
    _write_and_stage(repo, "b.txt", "two\n")
    _commit(repo, "commit 2 (bypassed)", no_verify=True)

    # commit 3: hook fires again for the first time since the bypass
    _write_and_stage(repo, "c.txt", "three\n")
    r3 = receipt_diff.mint_receipt(repo)

    assert r3["minted"] is True
    gap = r3["gap"]
    assert gap["status"] == "gap"
    assert gap["gap_commits"] == 1
    assert gap["message"] == "1 commit(s) since the last receipted diff"

    # and the label is persisted in the ledger row too, not just returned in memory
    rows = list(receipt_diff.Ledger(receipt_diff.ledger_path(repo)))
    assert len(rows) == 2  # commit-1's row and commit-3's row; commit-2 minted nothing
    assert rows[-1]["extra"]["gap"]["gap_commits"] == 1


def test_two_bypassed_commits_count_both(repo: Path):
    _write_and_stage(repo, "a.txt", "one\n")
    receipt_diff.mint_receipt(repo)
    _commit(repo, "commit 1")

    _write_and_stage(repo, "b.txt", "two\n")
    _commit(repo, "bypass 1", no_verify=True)
    _write_and_stage(repo, "c.txt", "three\n")
    _commit(repo, "bypass 2", no_verify=True)

    _write_and_stage(repo, "d.txt", "four\n")
    result = receipt_diff.mint_receipt(repo)
    assert result["gap"] == {"status": "gap", "gap_commits": 2,
                             "message": "2 commit(s) since the last receipted diff"}


def test_hook_adopted_mid_history_is_a_gap_not_a_clean_start(repo: Path):
    """Adopting this hook on a repo with pre-existing, un-receipted commits
    must not silently read as 'clean' -- there is no prior receipt to be
    clean relative to, and the existing history is real, un-witnessed gap."""
    _write_and_stage(repo, "a.txt", "pre-existing\n")
    _commit(repo, "pre-existing commit, no hook")

    _write_and_stage(repo, "b.txt", "first hooked change\n")
    result = receipt_diff.mint_receipt(repo)
    assert result["gap"]["status"] == "gap"
    assert result["gap"]["gap_commits"] == 1
    assert "no prior receipt in this ledger" in result["gap"]["message"]


# ---------------------------------------------------------------------------
# never blocks the commit, even on failure
# ---------------------------------------------------------------------------

def test_main_never_returns_nonzero_when_git_diff_fails(repo: Path, monkeypatch):
    _write_and_stage(repo, "a.txt", "one\n")

    def _boom(*a, **k):
        raise receipt_diff.GitError("simulated failure")
    monkeypatch.setattr(receipt_diff, "get_staged_diff_bytes", _boom)
    monkeypatch.chdir(repo)
    assert receipt_diff.main([]) == 0
    assert not receipt_diff.ledger_path(repo).exists()


def test_main_never_returns_nonzero_when_ledger_append_fails(repo: Path, monkeypatch):
    _write_and_stage(repo, "a.txt", "one\n")

    class _BoomLedger:
        def __init__(self, path):
            pass

        def append(self, body):
            raise OSError("disk full, simulated")

        def __iter__(self):
            return iter(())

    monkeypatch.setattr(receipt_diff, "Ledger", _BoomLedger)
    monkeypatch.chdir(repo)
    assert receipt_diff.main([]) == 0


def test_main_outside_a_git_repo_does_not_raise(tmp_path: Path, monkeypatch):
    outside = tmp_path / "not_a_repo"
    outside.mkdir()
    monkeypatch.chdir(outside)
    assert receipt_diff.main([]) == 0


def test_main_prints_the_gap_message_to_stderr(repo: Path, monkeypatch, capsys):
    _write_and_stage(repo, "a.txt", "one\n")
    monkeypatch.chdir(repo)
    receipt_diff.main([])
    _commit(repo, "commit 1")

    _write_and_stage(repo, "b.txt", "two\n")
    _commit(repo, "bypass", no_verify=True)

    _write_and_stage(repo, "c.txt", "three\n")
    receipt_diff.main([])
    err = capsys.readouterr().err
    assert "1 commit(s) since the last receipted diff" in err
