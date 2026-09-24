"""tools/publish.py: the dry run passes steps 1 to 6 for real (git state faked,
so the test runs on any branch with any working tree), the upload step never
runs for real, and --upload without --i-mean-it exits 2 before anything runs.

Nothing here uploads: every test that could reach twine replaces publish._run.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FAKE_TIP = "f" * 40
FAKE_TOKEN = "pypi-NOT-A-REAL-TOKEN-0123456789"


@pytest.fixture()
def publish(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location("publish_under_test", ROOT / "tools" / "publish.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name in ("PYPI_TOKEN", "TESTPYPI_TOKEN", "TWINE_USERNAME", "TWINE_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(mod, "git_state", lambda: ("main", FAKE_TIP, ""))
    return mod


def _args(tmp_path, *extra):
    return ["--dist", str(tmp_path / "dist"), "--env-file", str(tmp_path / "no.env"), *extra]


def test_dry_run_steps_1_to_6_pass_and_upload_is_only_planned(publish, tmp_path, monkeypatch, capsys):
    seen = {}

    def fake_upload(ctx):
        seen["upload"] = ctx.upload
        seen["version"] = ctx.version
        seen["main"] = [p.name for p in ctx.main_artifacts]
        seen["shims"] = len(ctx.shim_wheels)
        return ""

    monkeypatch.setattr(publish, "step_upload", fake_upload)
    rc = publish.main(_args(tmp_path))
    out = capsys.readouterr().out
    assert rc == 0, out
    for n in range(1, 7):
        assert f"✓ {n}/7 " in out, out
    assert "✗" not in out
    assert FAKE_TIP in out
    assert "VERIFIED then BROKEN" in out
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
    assert "✗ 1/7 git: tree not clean" in out
    assert "✗ 1/7 git: on 'feature', not 'main'" in out
    assert "2/7" not in out


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
        self.version = "0.9.0"
        self.main_artifacts = [dist / "arcaeon-0.9.0-py3-none-any.whl", dist / "arcaeon-0.9.0.tar.gz"]
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
