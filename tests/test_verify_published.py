"""L1-06: the post-publish verify gate (tools/verify_published.py) and the
L1-03 version guard (tools/release_guard.py), offline.

The "index" in these tests is a local directory and the pip runner is a fake
that copies from it. Nothing here touches the network.
"""
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VER = "0.11.0rc1"
WHEEL = f"arcaeon-{VER}-py3-none-any.whl"
SDIST = f"arcaeon-{VER}.tar.gz"


def _load(name):
    if not (ROOT / "tools" / f"{name}.py").is_file():
        return None  # each test then fails on its own, not the whole file at collection
    spec = importlib.util.spec_from_file_location(f"{name}_under_test", ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vp = _load("verify_published")
rg = _load("release_guard")


@pytest.fixture
def dist(tmp_path):
    d = tmp_path / "dist"
    d.mkdir()
    (d / WHEEL).write_bytes(b"wheel bytes")
    (d / SDIST).write_bytes(b"sdist bytes")
    return d


@pytest.fixture
def manifest(dist):
    return vp.build_manifest(dist, VER)


def _copy(src_dir, dest):
    dest.mkdir(parents=True, exist_ok=True)
    for p in src_dir.iterdir():
        shutil.copy2(p, dest / p.name)
    return dest


# --- manifest ----------------------------------------------------------------

def test_manifest_records_sha256_of_every_dist_file(dist, manifest):
    assert manifest["version"] == VER
    assert manifest["name"] == "arcaeon"
    assert manifest["files"] == {
        WHEEL: hashlib.sha256(b"wheel bytes").hexdigest(),
        SDIST: hashlib.sha256(b"sdist bytes").hexdigest(),
    }


def test_manifest_refuses_an_empty_dist(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(ValueError):
        vp.build_manifest(tmp_path / "empty", VER)


def test_manifest_cli_writes_json(dist, tmp_path):
    out = tmp_path / "m.json"
    rc = vp.main(["manifest", str(dist), "--version", VER, "--out", str(out)])
    assert rc == 0
    assert json.loads(out.read_text(encoding="utf-8"))["files"][WHEEL]


# --- compare -----------------------------------------------------------------

def test_compare_match_is_verified(dist, manifest, tmp_path):
    verdict, problems = vp.compare(manifest, _copy(dist, tmp_path / "dl"))
    assert verdict == "VERIFIED" and problems == []


def test_compare_mismatch_is_broken(dist, manifest, tmp_path):
    dl = _copy(dist, tmp_path / "dl")
    (dl / WHEEL).write_bytes(b"something else")
    verdict, problems = vp.compare(manifest, dl)
    assert verdict == "BROKEN"
    assert any("MISMATCH" in p and WHEEL in p for p in problems)


def test_compare_missing_file_fails(dist, manifest, tmp_path):
    dl = _copy(dist, tmp_path / "dl")
    (dl / SDIST).unlink()
    verdict, problems = vp.compare(manifest, dl)
    assert verdict == "COULD NOT LOOK"
    assert any("MISSING" in p and SDIST in p for p in problems)


def test_compare_extra_file_is_broken(dist, manifest, tmp_path):
    dl = _copy(dist, tmp_path / "dl")
    (dl / f"arcaeon-{VER}-cp312-cp312-win_amd64.whl").write_bytes(b"not ours")
    verdict, problems = vp.compare(manifest, dl)
    assert verdict == "BROKEN"
    assert any("EXTRA" in p for p in problems)


def test_compare_mismatch_beats_missing(dist, manifest, tmp_path):
    dl = _copy(dist, tmp_path / "dl")
    (dl / SDIST).unlink()
    (dl / WHEEL).write_bytes(b"tampered")
    assert vp.compare(manifest, dl)[0] == "BROKEN"


def test_compare_cli_exit_codes(dist, manifest, tmp_path):
    m = tmp_path / "m.json"
    m.write_text(json.dumps(manifest), encoding="utf-8")
    dl = _copy(dist, tmp_path / "dl")
    assert vp.main(["compare", "--manifest", str(m), "--download-dir", str(dl)]) == 0
    (dl / WHEEL).write_bytes(b"x")
    assert vp.main(["compare", "--manifest", str(m), "--download-dir", str(dl)]) == 1
    (dl / WHEEL).unlink()
    (dl / SDIST).unlink()
    assert vp.main(["compare", "--manifest", str(m), "--download-dir", str(dl)]) == 2


# --- fetch (fake index, fake pip) ----------------------------------------------

class FakePip:
    """Stands in for `python -m pip download`. Serves files from a local
    directory once `ready_after` calls have been made (the index catching up)."""

    def __init__(self, index_dir, ready_after=0):
        self.index_dir = index_dir
        self.ready_after = ready_after
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        assert "download" in cmd and "--no-deps" in cmd
        dest = Path(cmd[cmd.index("--dest") + 1])
        if len(self.calls) <= self.ready_after:
            return subprocess.CompletedProcess(cmd, 1, "", "No matching distribution")
        want_wheel = "--only-binary=:all:" in cmd
        dest.mkdir(parents=True, exist_ok=True)
        for p in self.index_dir.iterdir():
            if p.name.endswith(".whl") == want_wheel:
                shutil.copy2(p, dest / p.name)
        return subprocess.CompletedProcess(cmd, 0, "", "")


def test_fetch_downloads_both_kinds_and_verifies(dist, manifest, tmp_path):
    pip = FakePip(dist)
    verdict, problems = vp.fetch(manifest, "https://index.invalid/simple/", tmp_path / "dl",
                                 attempts=3, wait=0, runner=pip, sleep=lambda s: None)
    assert verdict == "VERIFIED", problems
    assert len(pip.calls) == 2
    for cmd in pip.calls:
        assert cmd[cmd.index("--index-url") + 1] == "https://index.invalid/simple/"
        assert f"arcaeon=={VER}" in cmd
    assert any("--no-binary=:all:" in c for c in pip.calls)


def test_fetch_retries_while_the_index_catches_up(dist, manifest, tmp_path):
    pip = FakePip(dist, ready_after=3)
    slept = []
    verdict, _ = vp.fetch(manifest, "https://index.invalid/simple/", tmp_path / "dl",
                          attempts=5, wait=7, runner=pip, sleep=slept.append)
    assert verdict == "VERIFIED"
    assert slept and all(s == 7 for s in slept)


def test_fetch_is_bounded_and_reports_could_not_look(dist, manifest, tmp_path):
    pip = FakePip(dist, ready_after=10_000)
    slept = []
    verdict, problems = vp.fetch(manifest, "https://index.invalid/simple/", tmp_path / "dl",
                                 attempts=4, wait=1, runner=pip, sleep=slept.append)
    assert verdict == "COULD NOT LOOK"
    assert len(slept) == 3, "sleep between attempts, not after the last"
    assert any("MISSING" in p for p in problems)


def test_fetch_detects_a_tampered_index(dist, manifest, tmp_path):
    index = _copy(dist, tmp_path / "index")
    (index / SDIST).write_bytes(b"swapped on the index")
    verdict, problems = vp.fetch(manifest, "https://index.invalid/simple/", tmp_path / "dl",
                                 attempts=2, wait=0, runner=FakePip(index), sleep=lambda s: None)
    assert verdict == "BROKEN"
    assert any("MISMATCH" in p and SDIST in p for p in problems)


def test_fetch_starts_from_an_empty_download_dir(dist, manifest, tmp_path):
    dl = tmp_path / "dl"
    dl.mkdir()
    (dl / "stale-arcaeon-0.0.1.tar.gz").write_bytes(b"old")
    with pytest.raises(ValueError):
        vp.fetch(manifest, "https://index.invalid/simple/", dl, attempts=1, wait=0,
                 runner=FakePip(dist), sleep=lambda s: None)


# --- version guard ----------------------------------------------------------------

def test_guard_accepts_matching_tag():
    assert rg.check("0.11.0", "0.11.0", ref_type="tag", ref_name="v0.11.0", target="pypi") == []


@pytest.mark.parametrize("pyproject,pkg,ref_name", [
    ("0.11.0", "0.11.0", "v0.11.1"),     # tag disagrees
    ("0.11.0", "0.10.0", "v0.11.0"),     # __version__ disagrees
    ("0.11.0", "0.11.0", "0.11.0"),      # tag without the v
])
def test_guard_refuses_any_disagreement(pyproject, pkg, ref_name):
    assert rg.check(pyproject, pkg, ref_type="tag", ref_name=ref_name, target="pypi")


def test_guard_refuses_real_pypi_from_a_branch():
    assert rg.check("0.11.0", "0.11.0", ref_type="branch", ref_name="main", target="pypi")


def test_guard_allows_testpypi_from_a_branch():
    assert rg.check("0.11.0rc1", "0.11.0rc1", ref_type="branch", ref_name="main",
                    target="testpypi") == []


def test_guard_refuses_an_unknown_target():
    assert rg.check("0.11.0", "0.11.0", ref_type="tag", ref_name="v0.11.0", target="prod")


def test_guard_reads_this_repo_and_versions_agree():
    assert rg.read_pyproject_version(ROOT) == rg.read_package_version(ROOT)


def test_guard_cli_prints_the_version_on_success(capsys):
    v = rg.read_pyproject_version(ROOT)
    rc = rg.main(["--ref-type", "tag", "--ref-name", f"v{v}", "--target", "pypi", "--root", str(ROOT)])
    assert rc == 0
    assert capsys.readouterr().out.strip() == v


def test_guard_cli_refuses_with_exit_1(capsys):
    rc = rg.main(["--ref-type", "tag", "--ref-name", "v99.0.0", "--target", "pypi", "--root", str(ROOT)])
    assert rc == 1
    assert capsys.readouterr().out.strip() == ""
