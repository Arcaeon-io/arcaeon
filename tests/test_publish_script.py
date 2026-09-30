"""tools/publish.py: the dry run passes steps 1 to 7 for real (git state faked,
so the test runs on any branch with any working tree), the upload step never
runs for real, and --upload without --i-mean-it exits 2 before anything runs.

Nothing here uploads: every test that could reach twine replaces publish._run.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from _load import load_module

ROOT = Path(__file__).resolve().parents[1]
FAKE_TIP = "f" * 40
FAKE_TOKEN = "pypi-NOT-A-REAL-TOKEN-0123456789"


@pytest.fixture()
def publish(monkeypatch, tmp_path):
    mod = load_module("publish_under_test", ROOT / "tools" / "publish.py")
    for name in ("PYPI_TOKEN", "TESTPYPI_TOKEN", "TWINE_USERNAME", "TWINE_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(mod, "git_state", lambda: ("main", FAKE_TIP, ""))
    # no test reaches PyPI: the plan's "already there?" lookup says no by default
    monkeypatch.setattr(mod, "index_has", lambda name, version, test_pypi=False: False)
    return mod


def _args(tmp_path, *extra):
    return ["--dist", str(tmp_path / "dist"), "--env-file", str(tmp_path / "no.env"), *extra]


@pytest.mark.slow   # ~80s: real builds and a real release check (B046)
def test_dry_run_steps_1_to_6_pass_and_upload_is_only_planned(publish, tmp_path, monkeypatch, capsys):
    seen = {}

    def fake_upload(ctx):
        seen["upload"] = ctx.upload
        seen["version"] = ctx.version
        seen["main"] = [p.name for p in ctx.main_artifacts]
        seen["shims"] = len(ctx.shim_wheels)
        return ""

    monkeypatch.setattr(publish, "step_upload", fake_upload)
    # B041: with no test key, B and C run STUBBED, which blocks once the paid
    # path differs from the last release. This test is about publish's flow,
    # not about what changed since the tag, so it names HEAD as the base.
    monkeypatch.setenv("ARCAEON_RC_PAID_BASE", "HEAD")
    rc = publish.main(_args(tmp_path))
    out = capsys.readouterr().out
    assert rc == 0, out
    for n in range(1, 8):
        assert f"✓ {n}/8 " in out, out
    assert "✗" not in out
    assert FAKE_TIP in out
    assert "VERIFIED then BROKEN" in out
    assert "release check from an empty house: A PASS, B " in out
    assert seen["upload"] is False
    assert sorted(seen["main"]) == sorted([f"arcaeon-{seen['version']}-py3-none-any.whl",
                                           f"arcaeon-{seen['version']}.tar.gz"])
    assert seen["shims"] == 13
    assert (tmp_path / "dist" / "shims").is_dir()


def test_step1_stops_on_a_dirty_tree_or_the_wrong_branch(publish, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(publish, "git_state", lambda: ("main", FAKE_TIP, " M README.md"))
    assert publish.main(_args(tmp_path)) == 1
    monkeypatch.setattr(publish, "git_state", lambda: ("feature", FAKE_TIP, ""))
    assert publish.main(_args(tmp_path)) == 1
    out = capsys.readouterr().out
    assert "✗ 1/8 git: tree not clean" in out
    assert "✗ 1/8 git: on 'feature', not 'main'" in out
    assert "2/8" not in out


def _no_subprocess(monkeypatch, publish):
    calls = []

    def boom(cmd, **kw):
        calls.append([str(c) for c in cmd])
        raise AssertionError(f"nothing should run: {cmd}")

    monkeypatch.setattr(publish, "_run", boom)
    monkeypatch.setattr(publish.subprocess, "run", boom)
    return calls


def test_upload_without_i_mean_it_exits_2_and_never_calls_twine(publish, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PYPI_TOKEN", FAKE_TOKEN)
    calls = _no_subprocess(monkeypatch, publish)
    assert publish.main(_args(tmp_path, "--upload")) == 2
    assert calls == []
    out = capsys.readouterr().out
    assert "refused" in out and FAKE_TOKEN not in out


def test_upload_without_the_token_exits_2(publish, tmp_path, monkeypatch, capsys):
    calls = _no_subprocess(monkeypatch, publish)
    assert publish.main(_args(tmp_path, "--upload", "--i-mean-it")) == 2
    monkeypatch.setenv("PYPI_TOKEN", FAKE_TOKEN)  # the wrong token for TestPyPI
    assert publish.main(_args(tmp_path, "--upload", "--i-mean-it", "--test-pypi")) == 2
    assert calls == []
    out = capsys.readouterr().out
    assert "PYPI_TOKEN is not set" in out and "TESTPYPI_TOKEN is not set" in out


def test_upload_off_main_exits_2(publish, tmp_path, monkeypatch):
    monkeypatch.setenv("PYPI_TOKEN", FAKE_TOKEN)
    calls = _no_subprocess(monkeypatch, publish)
    assert publish.main(_args(tmp_path, "--upload", "--i-mean-it", "--branch", "x")) == 2
    assert calls == []


def test_token_read_from_env_file_by_name(publish, tmp_path):
    env = tmp_path / ".env"
    env.write_text(f'OTHER=1\nTESTPYPI_TOKEN="{FAKE_TOKEN}"\n', encoding="utf-8")
    assert publish.credential("TESTPYPI_TOKEN", env) == FAKE_TOKEN
    assert publish.credential("PYPI_TOKEN", env) is None


def test_upload_order_and_token_only_in_subprocess_env(publish, tmp_path, monkeypatch, capsys):
    """With every subprocess mocked: main package, then the poll, then the shims.
    The token rides in env only: never in argv, never on stdout."""
    monkeypatch.setenv("PYPI_TOKEN", FAKE_TOKEN)
    monkeypatch.setattr(publish, "STEPS", [])
    monkeypatch.setattr(publish, "POLL_EVERY", 0)
    calls = []

    class P:
        def __init__(self, rc=0):
            self.returncode, self.stdout, self.stderr = rc, "", ""

    polls = {"n": 0}

    def fake_run(cmd, **kw):
        argv = [str(c) for c in cmd]
        calls.append((argv, kw.get("env") or {}))
        if "download" in argv:
            polls["n"] += 1
            return P(0 if polls["n"] >= 2 else 1)
        return P(0)

    monkeypatch.setattr(publish, "_run", fake_run)
    monkeypatch.setattr(publish.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("real subprocess")))
    dist = tmp_path / "dist"
    orig = publish.Ctx.__init__

    def init(self, a):
        orig(self, a)
        self.version = "0.9.1"
        self.main_artifacts = [dist / "arcaeon-0.9.1-py3-none-any.whl", dist / "arcaeon-0.9.1.tar.gz"]
        self.shim_wheels = [dist / "shims" / f"s{i}-0.1-py3-none-any.whl" for i in range(13)]

    monkeypatch.setattr(publish.Ctx, "__init__", init)
    assert publish.main(_args(tmp_path, "--upload", "--i-mean-it")) == 0
    kinds = []
    for argv, env in calls:
        assert FAKE_TOKEN not in " ".join(argv)
        if "twine" in argv:
            assert env["TWINE_USERNAME"] == "__token__" and env["TWINE_PASSWORD"] == FAKE_TOKEN
            assert "https://upload.pypi.org/legacy/" in argv
            kinds.append("shims" if any("shims" in x for x in argv) else "main")
        else:
            assert "TWINE_PASSWORD" not in env
            kinds.append("poll")
    assert kinds == ["main", "poll", "poll", "shims"]
    out = capsys.readouterr().out
    assert FAKE_TOKEN not in out
    assert "packageArguments" in out and "site.py build" in out


# --- B050: the plan skips shims whose exact version the index already serves ---------

def _plan_ctx(publish, tmp_path, monkeypatch, *extra):
    dist = tmp_path / "dist"
    a = publish.parse(_args(tmp_path, *extra))
    ctx = publish.Ctx(a)
    ctx.version = "0.9.2"
    ctx.main_artifacts = [dist / "arcaeon-0.9.2-py3-none-any.whl", dist / "arcaeon-0.9.2.tar.gz"]
    ctx.shim_wheels = [dist / "shims" / "arcaeon_ledger-0.8.2-py3-none-any.whl",
                       dist / "shims" / "arcaeon_once-0.2.5-py3-none-any.whl",
                       dist / "shims" / "mcp_vet-0.0.19-py3-none-any.whl"]
    return ctx


def test_wheel_name_version_normalizes_for_the_index(publish):
    assert publish._wheel_name_version(Path("arcaeon_ledger-0.8.2-py3-none-any.whl")) ==         ("arcaeon-ledger", "0.8.2")


def test_dry_run_plan_skips_shims_already_on_pypi(publish, tmp_path, monkeypatch, capsys):
    asked = []

    def has(name, version, test_pypi=False):
        asked.append((name, version, test_pypi))
        return {"arcaeon-ledger": True, "arcaeon-once": False, "mcp-vet": None}[name]

    monkeypatch.setattr(publish, "index_has", has)
    _no_subprocess(monkeypatch, publish)
    publish.step_upload(_plan_ctx(publish, tmp_path, monkeypatch))
    out = capsys.readouterr().out
    assert asked == [("arcaeon-ledger", "0.8.2", False), ("arcaeon-once", "0.2.5", False),
                     ("mcp-vet", "0.0.19", False)]
    iii = next(x for x in out.splitlines() if "iii." in x)
    assert "arcaeon_ledger-0.8.2" not in iii
    assert "arcaeon_once-0.2.5" in iii and "mcp_vet-0.0.19" in iii and "(2 wheels)" in iii
    assert "skipped, already on PyPI (exact version): arcaeon-ledger==0.8.2" in out
    assert "COULD NOT LOOK on PyPI, kept in the upload: mcp-vet==0.0.19" in out


def test_dry_run_plan_says_so_when_every_shim_is_already_there(publish, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(publish, "index_has", lambda n, v, t=False: True)
    _no_subprocess(monkeypatch, publish)
    publish.step_upload(_plan_ctx(publish, tmp_path, monkeypatch, "--test-pypi"))
    out = capsys.readouterr().out
    assert "iii. no shim upload: every shim's exact version is already on TestPyPI" in out
    assert "twine upload" in out.split("iii.")[0]      # the main package is still planned


def test_upload_sends_only_the_shims_not_already_there(publish, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PYPI_TOKEN", FAKE_TOKEN)
    monkeypatch.setattr(publish, "index_has", lambda n, v, t=False: n == "arcaeon-ledger")
    sent = []

    class P:
        returncode, stdout, stderr = 0, "", ""

    monkeypatch.setattr(publish, "_run", lambda cmd, **kw: sent.append([str(c) for c in cmd]) or P())
    ctx = _plan_ctx(publish, tmp_path, monkeypatch, "--upload", "--i-mean-it")
    publish.step_upload(ctx)
    shim_call = [c for c in sent if "twine" in c and any("shims" in x for x in c)]
    assert len(shim_call) == 1
    names = [Path(x).name for x in shim_call[0] if x.endswith(".whl")]
    assert names == ["arcaeon_once-0.2.5-py3-none-any.whl", "mcp_vet-0.0.19-py3-none-any.whl"]
    assert "1 skipped (already on PyPI)" in capsys.readouterr().out


def test_index_has_reads_the_status_only(monkeypatch):
    import urllib.error
    mod = load_module("publish_index_has", ROOT / "tools" / "publish.py")
    seen = []

    class R:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake(req, timeout=0):
        seen.append((req.full_url, req.get_method()))
        if "missing" in req.full_url:
            raise urllib.error.HTTPError(req.full_url, 404, "nf", {}, None)
        if "down" in req.full_url:
            raise urllib.error.URLError("offline")
        return R()

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake)
    assert mod.index_has("arcaeon-ledger", "0.8.1") is True
    assert mod.index_has("missing", "1") is False
    assert mod.index_has("down", "1") is None
    assert mod.index_has("arcaeon-ledger", "0.8.1", test_pypi=True) is True
    assert seen[0] == ("https://pypi.org/pypi/arcaeon-ledger/0.8.1/json", "GET")
    assert seen[-1][0].startswith("https://test.pypi.org/pypi/")
