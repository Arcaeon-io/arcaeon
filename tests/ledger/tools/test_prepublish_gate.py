# SPDX-License-Identifier: MIT
"""tools/prepublish_gate.py: the portable release gate.

Every repo here is a fake built under tmp_path: a pyproject.toml, a package
dir, a CHANGELOG.md, and a dist/ holding a wheel written with zipfile plus an
sdist that is only a correctly-named file (the gate never opens the sdist).
HEAD commit time is monkeypatched except in the one test that runs real git.

The two PLANTED RED tests exist because a gate that has never been seen
refusing anything is a gate that might pass everything. Each plants one real
defect (a wrong version, a wheel older than HEAD) and asserts FAIL, by name.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("prepublish_gate", _HERE / "prepublish_gate.py")
gate = importlib.util.module_from_spec(_spec)
sys.modules["prepublish_gate"] = gate
_spec.loader.exec_module(gate)

PKG = "fake_pkg"
VER = "0.7.5"
HEAD = 1_700_000_000  # a fixed HEAD commit time, seconds since the epoch


def _write_wheel(path: Path, version: str, *, with_init: bool = True, meta_version: str | None = None) -> None:
    with zipfile.ZipFile(path, "w") as z:
        if with_init:
            z.writestr(f"{PKG}/__init__.py", f'__version__ = "{version}"\n')
        z.writestr(f"{PKG}-{version}.dist-info/METADATA",
                   f"Metadata-Version: 2.1\nName: {PKG}\nVersion: {meta_version or version}\n")


def _make_repo(root: Path, *, version: str = VER, init_version: str | None = VER,
               changelog_heading: str | None = f"## {VER} - 2026-09-05: a fix",
               wheel_mtime: int = HEAD + 60) -> Path:
    """A minimal, correct repo at `version`. Every argument is one knob a test
    turns to plant exactly one defect."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text(
        f'[build-system]\nrequires = ["hatchling"]\n\n[project]\nname = "fake-pkg"\nversion = "{version}"\n',
        encoding="utf-8")
    pkg = root / PKG
    pkg.mkdir(exist_ok=True)
    body = f'__version__ = "{init_version}"\n' if init_version is not None else "# no version attribute here\n"
    (pkg / "__init__.py").write_text(body, encoding="utf-8")
    (root / "CHANGELOG.md").write_text(
        "# Changelog\n\n" + (changelog_heading + "\n\ntext\n" if changelog_heading else "## 0.0.1\n\nold\n"),
        encoding="utf-8")
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    whl = dist / f"{PKG}-{version}-py3-none-any.whl"
    _write_wheel(whl, version)
    sdist = dist / f"{PKG}-{version}.tar.gz"
    sdist.write_bytes(b"not a real tarball; the gate only checks the name")
    os.utime(whl, (wheel_mtime, wheel_mtime))
    os.utime(sdist, (wheel_mtime - 4, wheel_mtime - 4))
    return root


@pytest.fixture
def fixed_head(monkeypatch):
    monkeypatch.setattr(gate, "_head_commit_time", lambda repo: HEAD)
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    # The synthetic repos these tests build are directories, not git trees, so
    # the provenance check (added 2026-09-06) correctly reports FAIL on every
    # one of them and would drown every other assertion in this file. Stub it
    # where it is not the thing under test. It is NOT stubbed in the four
    # dedicated provenance tests at the bottom, which call the real function
    # and pin both of its directions -- so the check cannot rot behind this.
    monkeypatch.setattr(gate, "check_provenance",
                        lambda repo: (gate.PASS, "stubbed: not under test here"))


def _verdicts(result: dict) -> dict:
    return {k: v["verdict"] for k, v in result["checks"].items()}


# --- the clean case -----------------------------------------------------------

def test_clean_repo_passes_every_check(tmp_path, fixed_head):
    repo = _make_repo(tmp_path / "r")
    result = gate.run_gate(repo, VER)
    assert set(_verdicts(result).values()) == {gate.PASS}, result
    assert result["summary"] == "GATE PASS"
    assert result["exit_code"] == 0


# --- PLANTED RED: the gate must refuse these ----------------------------------

def test_PLANTED_RED_wrong_version_fails_not_passes(tmp_path, fixed_head):
    # Repo is entirely 0.7.5; we ask the gate to bless 0.7.6. pyproject and
    # __init__ disagree with --version, and dist/ has no 0.7.6 artefacts at all.
    repo = _make_repo(tmp_path / "r")
    result = gate.run_gate(repo, "0.7.6")
    v = _verdicts(result)
    assert v["version-agreement"] == gate.FAIL
    assert "pyproject.toml says '0.7.5'" in result["checks"]["version-agreement"]["reason"]
    assert v["dist-membership"] == gate.FAIL
    assert result["exit_code"] == 1
    assert result["summary"].startswith("GATE FAIL (")


def test_PLANTED_RED_stale_wheel_fails_not_passes(tmp_path, fixed_head):
    # The wheel was built 1000s BEFORE the HEAD commit: it cannot contain HEAD.
    repo = _make_repo(tmp_path / "r", wheel_mtime=HEAD - 1000)
    result = gate.run_gate(repo, VER)
    c = result["checks"]["staleness"]
    assert c["verdict"] == gate.FAIL
    assert "wheel predates HEAD" in c["reason"]
    assert result["exit_code"] == 1
    assert result["summary"] == "GATE FAIL (1)"


# --- UNVERIFIABLE is a third verdict, never a pass ----------------------------

def test_missing_dunder_version_is_unverifiable_not_pass(tmp_path, fixed_head):
    repo = _make_repo(tmp_path / "r", init_version=None)
    result = gate.run_gate(repo, VER)
    c = result["checks"]["version-agreement"]
    assert c["verdict"] == gate.UNVERIFIABLE
    assert "no __version__" in c["reason"]
    assert result["exit_code"] == 2
    assert result["summary"] == "GATE UNVERIFIABLE (1)"


def test_git_unavailable_is_unverifiable_not_pass(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)

    def _no_git(*a, **k):
        raise FileNotFoundError("git")

    monkeypatch.setattr(gate.subprocess, "run", _no_git)
    repo = _make_repo(tmp_path / "r")
    result = gate.run_gate(repo, VER)
    assert result["checks"]["staleness"]["verdict"] == gate.UNVERIFIABLE
    assert result["exit_code"] == 2


def test_fail_outranks_unverifiable_in_exit_code(tmp_path, fixed_head):
    # Missing __version__ (UNVERIFIABLE) plus a stale wheel (FAIL): exit 1, not 2.
    repo = _make_repo(tmp_path / "r", init_version=None, wheel_mtime=HEAD - 5)
    result = gate.run_gate(repo, VER)
    assert result["exit_code"] == 1
    assert result["summary"] == "GATE FAIL (1)"


# --- dist membership ------------------------------------------------------------

def test_newer_artifact_from_another_version_fails(tmp_path, fixed_head):
    repo = _make_repo(tmp_path / "r")
    stray = repo / "dist" / f"{PKG}-0.7.6-py3-none-any.whl"
    _write_wheel(stray, "0.7.6")
    os.utime(stray, (HEAD + 500, HEAD + 500))
    result = gate.run_gate(repo, VER)
    c = result["checks"]["dist-membership"]
    assert c["verdict"] == gate.FAIL
    assert "0.7.6" in c["reason"]


def test_older_stray_is_named_but_does_not_fail(tmp_path, fixed_head):
    repo = _make_repo(tmp_path / "r")
    stray = repo / "dist" / f"{PKG}-0.7.4.tar.gz"
    stray.write_bytes(b"old")
    os.utime(stray, (HEAD - 9000, HEAD - 9000))
    result = gate.run_gate(repo, VER)
    c = result["checks"]["dist-membership"]
    assert c["verdict"] == gate.PASS
    assert "0.7.4" in c["reason"]


def test_missing_sdist_fails(tmp_path, fixed_head):
    repo = _make_repo(tmp_path / "r")
    (repo / "dist" / f"{PKG}-{VER}.tar.gz").unlink()
    result = gate.run_gate(repo, VER)
    assert result["checks"]["dist-membership"]["verdict"] == gate.FAIL
    assert "no sdist" in result["checks"]["dist-membership"]["reason"]


def test_no_dist_dir_is_unverifiable(tmp_path, fixed_head):
    repo = _make_repo(tmp_path / "r")
    shutil.rmtree(repo / "dist")
    result = gate.run_gate(repo, VER)
    v = _verdicts(result)
    assert v["dist-membership"] == gate.UNVERIFIABLE
    assert v["staleness"] == gate.UNVERIFIABLE
    assert v["wheel-contents"] == gate.UNVERIFIABLE
    assert result["exit_code"] == 2


# --- wheel contents ---------------------------------------------------------------

def test_wheel_metadata_version_mismatch_fails(tmp_path, fixed_head):
    # Filename says 0.7.5, METADATA inside says 0.7.4. The filename is the lie.
    repo = _make_repo(tmp_path / "r")
    whl = repo / "dist" / f"{PKG}-{VER}-py3-none-any.whl"
    _write_wheel(whl, VER, meta_version="0.7.4")
    os.utime(whl, (HEAD + 60, HEAD + 60))
    c = gate.run_gate(repo, VER)["checks"]["wheel-contents"]
    assert c["verdict"] == gate.FAIL
    assert "METADATA Version: is '0.7.4'" in c["reason"]


def test_wheel_without_package_init_fails(tmp_path, fixed_head):
    repo = _make_repo(tmp_path / "r")
    whl = repo / "dist" / f"{PKG}-{VER}-py3-none-any.whl"
    _write_wheel(whl, VER, with_init=False)
    os.utime(whl, (HEAD + 60, HEAD + 60))
    c = gate.run_gate(repo, VER)["checks"]["wheel-contents"]
    assert c["verdict"] == gate.FAIL
    assert f"{PKG}/__init__.py missing" in c["reason"]


# --- changelog heading forms ------------------------------------------------------

@pytest.mark.parametrize("heading", [f"## {VER}", f"## [{VER}]", f"## v{VER}", f"## {VER} - 2026-09-05", f"### [{VER}] - date"])
def test_changelog_heading_forms_accepted(tmp_path, fixed_head, heading):
    repo = _make_repo(tmp_path / "r", changelog_heading=heading)
    assert gate.run_gate(repo, VER)["checks"]["version-agreement"]["verdict"] == gate.PASS


def test_changelog_without_heading_fails(tmp_path, fixed_head):
    repo = _make_repo(tmp_path / "r", changelog_heading=None)
    c = gate.run_gate(repo, VER)["checks"]["version-agreement"]
    assert c["verdict"] == gate.FAIL
    assert "CHANGELOG.md has no heading" in c["reason"]


def test_changelog_heading_for_a_longer_version_does_not_match(tmp_path, fixed_head):
    # 0.7.50 must not satisfy a gate asked about 0.7.5.
    repo = _make_repo(tmp_path / "r", changelog_heading="## 0.7.50 - later")
    assert gate.run_gate(repo, VER)["checks"]["version-agreement"]["verdict"] == gate.FAIL


# --- tag agreement (CI only) ----------------------------------------------------

def test_tag_mismatch_fails_in_ci(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "_head_commit_time", lambda repo: HEAD)
    monkeypatch.setenv("GITHUB_REF_NAME", "v0.7.4")
    repo = _make_repo(tmp_path / "r")
    c = gate.run_gate(repo, VER)["checks"]["tag-agreement"]
    assert c["verdict"] == gate.FAIL
    assert "v0.7.4 != v0.7.5" in c["reason"]


def test_tag_match_passes_and_branch_ref_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "_head_commit_time", lambda repo: HEAD)
    repo = _make_repo(tmp_path / "r")
    monkeypatch.setenv("GITHUB_REF_NAME", f"v{VER}")
    assert gate.run_gate(repo, VER)["checks"]["tag-agreement"]["verdict"] == gate.PASS
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    assert gate.run_gate(repo, VER)["checks"]["tag-agreement"]["verdict"] == gate.PASS


# --- CLI surface ------------------------------------------------------------------

def test_cli_prints_one_line_per_check_and_summary(tmp_path, fixed_head, capsys):
    repo = _make_repo(tmp_path / "r")
    code = gate.main(["--repo", str(repo), "--version", f"v{VER}"])  # leading v is stripped
    out = capsys.readouterr().out.splitlines()
    assert code == 0
    # Six since 2026-09-06: provenance joined the five. Asserting the count and
    # not just the summary is deliberate -- it is how a check that silently
    # stopped being registered would show up here.
    assert sum(line.startswith("[PASS] ") for line in out) == 6, out
    assert out[-1] == "GATE PASS"


def test_cli_json_and_dist_override(tmp_path, fixed_head, capsys):
    import json
    repo = _make_repo(tmp_path / "r")
    elsewhere = tmp_path / "artefacts"
    shutil.move(str(repo / "dist"), str(elsewhere))
    code = gate.main(["--repo", str(repo), "--version", VER, "--dist", str(elsewhere), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["summary"] == "GATE PASS"
    assert Path(payload["dist"]) == elsewhere.resolve()


def test_missing_repo_path_exits_2(tmp_path, capsys):
    assert gate.main(["--repo", str(tmp_path / "nope"), "--version", VER]) == 2


# --- one run against real git ------------------------------------------------------

@pytest.mark.skipif(shutil.which("git") is None, reason="git not on PATH")
def test_real_git_head_time_orders_wheel_correctly(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    repo = _make_repo(tmp_path / "r")
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@x"}
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=env)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True, env=env)
    head = gate._head_commit_time(repo)
    assert isinstance(head, int)
    whl = repo / "dist" / f"{PKG}-{VER}-py3-none-any.whl"
    os.utime(whl, (head + 30, head + 30))
    assert gate.run_gate(repo, VER)["checks"]["staleness"]["verdict"] == gate.PASS
    os.utime(whl, (head - 30, head - 30))
    assert gate.run_gate(repo, VER)["checks"]["staleness"]["verdict"] == gate.FAIL


# --- provenance: absent repository is a FAIL, not merely unverifiable -------
# 2026-09-06. arcaeon-recall was published to PyPI from a directory that was
# not a git repository. The distinction pinned here is the whole point of the
# check: "git is not installed" means the tool could not look (UNVERIFIABLE),
# while "there is no repository" means the artifact cannot answer what changed
# (FAIL). Collapsing those two into one verdict is how this shipped.

def test_untracked_directory_fails_rather_than_unverifiable(tmp_path):
    repo = tmp_path / "untracked"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname="x"\nversion="0.1.0"\n', encoding="utf-8")
    verdict, reason = gate.check_provenance(repo)
    assert verdict == gate.FAIL, (verdict, reason)
    assert "no git repository" in reason


def test_missing_git_binary_is_unverifiable_not_fail(tmp_path, monkeypatch):
    def _no_git(*a, **k):
        raise FileNotFoundError("git")
    monkeypatch.setattr(gate.subprocess, "run", _no_git)
    verdict, reason = gate.check_provenance(tmp_path)
    assert verdict == gate.UNVERIFIABLE, (verdict, reason)
    assert "could not look" in reason


def test_tracked_repo_with_a_commit_passes(tmp_path):
    import subprocess
    repo = tmp_path / "tracked"
    repo.mkdir()
    (repo / "f.txt").write_text("x", encoding="utf-8")
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    import os
    e = dict(os.environ); e.update(env)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=e)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, env=e)
    subprocess.run(["git", "commit", "-q", "-m", "first"], cwd=repo, check=True, env=e)
    verdict, reason = gate.check_provenance(repo)
    assert verdict == gate.PASS, (verdict, reason)
    assert "tracked" in reason


def test_repo_with_zero_commits_fails(tmp_path):
    import os
    import subprocess
    repo = tmp_path / "empty"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=dict(os.environ))
    verdict, reason = gate.check_provenance(repo)
    assert verdict == gate.FAIL, (verdict, reason)
    assert "no commits" in reason
