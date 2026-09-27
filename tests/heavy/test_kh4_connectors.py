"""KH4: the connector installer across all eight clients, end to end.

For each OS shape (fake Windows, macOS and Linux homes) and each of the eight
clients in the catalog, this runs `arcaeon connect` through its real CLI entry
and proves:

    golden      `--list`, the print of every client, and a full write, check,
                write-again, undo, check transcript match tests/heavy/kh4_golden/
                <os>.txt (UPDATE_GOLDEN=1 rewrites them)
    round trip  write, check, undo for every file-writing client, starting from
                a config that already holds two other servers plus a top-level
                key, and again from a home where the file is not there at all;
                after undo the fake home is byte-identical (every file's bytes
                and every directory), and the other servers keep their exact
                original text and line endings
    no file     chatgpt and generic-http refuse --write, --check and --undo
                with exit 2 and change nothing; chatgpt says the deploy line
    refusal     a path the client's docs did not state is refused without
                --path (COULD NOT LOOK, exit 3, path_unconfirmed, nothing
                written) and goes through with it
    real        `arcaeon connect claude-code --write --path <scratch>/.mcp.json`
                as a real subprocess, undo, byte-identical; then, if the claude
                CLI is on PATH, `claude mcp list` and `claude mcp get arcaeon`
                read the entry back from the scratch project (skipped otherwise)

The OS shape is chosen by patching catalog.current_os, which is the only thing
the CLI asks. The Windows shape is only exercised on a Windows host (a
backslash path is a file NAME elsewhere); the two POSIX shapes run anywhere.

Home safety: HOME, USERPROFILE, APPDATA, LOCALAPPDATA and XDG_CONFIG_HOME point
at a guard folder in tmp_path that must never be created; ARCAEON_CONNECT_HOME
points at a per-test fake home; the claude CLI gets its own CLAUDE_CONFIG_DIR in
tmp_path. Nothing here writes to the real home. Stdlib only, no network.
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

from arcaeon.connect import catalog as C
from arcaeon.connect import cli
from arcaeon.connect import write as W

HERE = Path(__file__).resolve().parent
SRC = str(HERE.parents[1] / "src")
GOLDEN = HERE / "kh4_golden"
ON_WINDOWS = sys.platform.startswith("win")

#: Display homes for the path-only goldens (nothing is read or written there).
DISPLAY_HOME = {"windows": r"C:\Users\kh4", "macos": "/Users/kh4", "linux": "/fake/kh4"}
FILE_CLIENTS = [e.name for e in C.CATALOG if e.writes_file]
NO_FILE_CLIENTS = [e.name for e in C.CATALOG if not e.writes_file]
OS_SHAPES = [pytest.param(o, marks=pytest.mark.skipif(
    o == "windows" and not ON_WINDOWS, reason="a Windows-shape path is only a path on Windows"))
    for o in C.OSES]

#: A config that already holds two other servers and one other top-level key.
#: KEY becomes the client's key. The Windows shape is seeded with CRLF.
SEED = ('{\n'
        '  "theme": "dark",\n'
        '  "KEY": {\n'
        '    "filesystem": {"command": "npx", "args": ["-y", "@kh4/fs", "/data"]},\n'
        '    "search": {\n'
        '      "command": "search-server",\n'
        '      "env": {"LEVEL": "2"}\n'
        '    }\n'
        '  }\n'
        '}\n')
OTHER_SPANS = ('"filesystem": {"command": "npx", "args": ["-y", "@kh4/fs", "/data"]}',
               '"search": {\n      "command": "search-server",\n      "env": {"LEVEL": "2"}\n    }')


def _seed_for(entry: C.Entry, os_name: str) -> bytes:
    text = SEED.replace("KEY", entry.key)
    if os_name == "windows":
        text = text.replace("\n", "\r\n")
    return text.encode("utf-8")


@pytest.fixture(autouse=True)
def _no_real_home(tmp_path, monkeypatch):
    guard = tmp_path / "not-a-real-home"
    for var in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(var, str(guard))
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arcaeon-home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv(C.HOME_ENV, raising=False)
    yield guard
    assert not guard.exists(), "something resolved a home variable and wrote there"


@pytest.fixture
def uvx_pinned(monkeypatch):
    """The uvx launch form, and a `uvx` that resolves: the same on any machine."""
    fake = {"uv": "/fake/bin/uv", "uvx": "/fake/bin/uvx"}
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: fake.get(name))


def _as_os(monkeypatch, os_name: str) -> None:
    monkeypatch.setattr(C, "current_os", lambda: os_name)


def _fake_home(tmp_path: Path, monkeypatch, os_name: str) -> Path:
    home = tmp_path / f"home-{os_name}"
    home.mkdir()
    monkeypatch.setenv(C.HOME_ENV, str(home) if os_name == "windows" else home.as_posix())
    return home


def _snapshot(root: Path) -> dict:
    """Every file's bytes and every directory under root."""
    return {p.relative_to(root).as_posix(): (p.read_bytes() if p.is_file() else "dir")
            for p in sorted(root.rglob("*"))}


def _run(capsys, *argv) -> tuple[int, str, str]:
    rc = cli.main(list(argv))
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def _needs_path(entry: C.Entry, os_name: str) -> bool:
    return not C.confirmed_for(entry, os_name)


def _target(entry: C.Entry, os_name: str) -> Path:
    return Path(C.config_path(entry, os_name))


def _action(capsys, entry, os_name, action, *extra) -> tuple[int, str, str]:
    path = (("--path", str(_target(entry, os_name)))
            if _needs_path(entry, os_name) else ())
    return _run(capsys, entry.name, action, *path, *extra)


# --- goldens ------------------------------------------------------------------------

def _normalize(out: str, home: Path, arcaeon_home: Path) -> str:
    out = out.replace(str(arcaeon_home / "serve.token"), "<ARCAEON_HOME>/serve.token")
    out = out.replace("\\", "/").replace(home.as_posix(), "<HOME>")
    return re.sub(r"arcaeon-bak-\d{8}T\d{12}Z(-\d{3})?", "arcaeon-bak-<STAMP>", out)


def _golden_text(capsys, monkeypatch, tmp_path, os_name) -> str:
    arcaeon_home = tmp_path / "arcaeon-home"
    parts = []
    monkeypatch.setenv(C.HOME_ENV, DISPLAY_HOME[os_name])
    rc, out, _ = _run(capsys, "--list")
    assert rc == 0
    parts.append(f"## --list, home {DISPLAY_HOME[os_name]}\n{out}")
    for name in C.names():
        rc, out, _ = _run(capsys, name)
        assert rc == 0
        out = out.replace(str(arcaeon_home / "serve.token"), "<ARCAEON_HOME>/serve.token")
        parts.append(f"## connect {name}\n{out}")
    home = _fake_home(tmp_path, monkeypatch, os_name)
    for name in FILE_CLIENTS:
        e = C.get(name)
        target = _target(e, os_name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(_seed_for(e, os_name))
        lines = [f"## round trip {name}"
                 + ("  (--path: the docs did not state this path)" if _needs_path(e, os_name)
                    else "")]
        for step in ("--write", "--check", "--write", "--undo", "--check"):
            rc, out, _ = _action(capsys, e, os_name, step)
            lines.append(f"$ connect {name} {step}  -> exit {rc}\n{out.rstrip()}")
            if step == "--write" and len(lines) == 2:
                text = target.read_bytes().decode("utf-8").replace("\r\n", "<CRLF>\n")
                lines.append("file after --write:\n" + text.rstrip("\n"))
        parts.append(_normalize("\n".join(lines) + "\n", home, arcaeon_home))
    return "\n".join(parts)


@pytest.mark.parametrize("os_name", OS_SHAPES)
def test_golden_per_os(capsys, monkeypatch, tmp_path, uvx_pinned, os_name):
    _as_os(monkeypatch, os_name)
    got = _golden_text(capsys, monkeypatch, tmp_path, os_name)
    f = GOLDEN / f"{os_name}.txt"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        f.parent.mkdir(exist_ok=True)
        f.write_text(got, encoding="utf-8", newline="\n")
    assert f.is_file(), f"{f} missing; UPDATE_GOLDEN=1 writes it"
    assert got == f.read_text(encoding="utf-8"), f"{f.name} differs; UPDATE_GOLDEN=1 rewrites"


def test_golden_list_has_eight_rows(capsys, monkeypatch):
    monkeypatch.setenv(C.HOME_ENV, DISPLAY_HOME["linux"])
    _as_os(monkeypatch, "linux")
    rc, out, _ = _run(capsys, "--list")
    rows = [ln for ln in out.splitlines()[1:] if ln.split()[0] in C.names()]
    assert rc == 0 and len(rows) == 8 == len(C.names())


# --- the round trip for every client on every OS shape --------------------------------

@pytest.mark.parametrize("name", FILE_CLIENTS)
@pytest.mark.parametrize("os_name", OS_SHAPES)
def test_round_trip_keeps_other_servers(capsys, monkeypatch, tmp_path, os_name, name):
    _as_os(monkeypatch, os_name)
    home = _fake_home(tmp_path, monkeypatch, os_name)
    e = C.get(name)
    target = _target(e, os_name)
    assert home in target.parents, f"{target} is outside the fake home"
    target.parent.mkdir(parents=True, exist_ok=True)
    seed = _seed_for(e, os_name)
    target.write_bytes(seed)
    before = _snapshot(home)

    rc, out, _ = _action(capsys, e, os_name, "--write")
    assert rc == 0 and out.rstrip().endswith("written"), out
    after = target.read_bytes()
    doc, orig = json.loads(after), json.loads(seed)
    assert doc["theme"] == "dark"
    assert {k: v for k, v in doc[e.key].items() if k != "arcaeon"} == orig[e.key]
    assert doc[e.key]["arcaeon"] == cli.server_entry(e)
    text = after.decode("utf-8")
    eol = "\r\n" if os_name == "windows" else "\n"
    for span in OTHER_SPANS:
        assert span.replace("\n", eol) in text, f"other server text changed: {span[:20]}"
    if os_name == "windows":
        assert text.count("\n") == text.count("\r\n"), "a bare LF crept into a CRLF file"
    else:
        assert "\r" not in text
    assert len(W.backups(target)) == 1

    rc, out, _ = _action(capsys, e, os_name, "--check")
    assert rc == 0 and "state: present" in out, out
    rc, out, _ = _action(capsys, e, os_name, "--write")
    assert rc == 0 and "already there" in out and len(W.backups(target)) == 1

    rc, out, _ = _action(capsys, e, os_name, "--undo")
    assert rc == 0 and "restored:" in out and "backups left: 0" in out, out
    assert _snapshot(home) == before, "the fake home is not byte-identical after undo"
    rc, out, _ = _action(capsys, e, os_name, "--check")
    assert rc == 1 and "state: absent" in out
    assert _snapshot(home) == before, "--check changed something"


@pytest.mark.parametrize("name", FILE_CLIENTS)
@pytest.mark.parametrize("os_name", OS_SHAPES)
def test_round_trip_from_nothing(capsys, monkeypatch, tmp_path, os_name, name):
    _as_os(monkeypatch, os_name)
    home = _fake_home(tmp_path, monkeypatch, os_name)
    e = C.get(name)
    before = _snapshot(home)
    assert before == {}
    rc, out, _ = _action(capsys, e, os_name, "--write")
    assert rc == 0 and "the file was not there" in out, out
    assert json.loads(_target(e, os_name).read_bytes()) == {e.key: {"arcaeon": cli.server_entry(e)}}
    rc, out, _ = _action(capsys, e, os_name, "--check")
    assert rc == 0 and "state: present" in out
    rc, out, _ = _action(capsys, e, os_name, "--undo")
    assert rc == 0 and "removed the file" in out, out
    assert _snapshot(home) == before, "undo left a file or a directory behind"


@pytest.mark.parametrize("name", NO_FILE_CLIENTS)
@pytest.mark.parametrize("os_name", OS_SHAPES)
def test_no_file_clients_refuse_every_action(capsys, monkeypatch, tmp_path, os_name, name):
    _as_os(monkeypatch, os_name)
    home = _fake_home(tmp_path, monkeypatch, os_name)
    for step in ("--write", "--check", "--undo"):
        rc, out, err = _run(capsys, name, step)
        assert rc == 2 and out == "", (step, out, err)
        assert "nothing written" in err or "no config file to write" in err
        if name == "chatgpt":
            assert C.DEPLOY_LINE in err
    assert _snapshot(home) == {}


@pytest.mark.parametrize("os_name", OS_SHAPES)
def test_unconfirmed_path_refused_without_path(capsys, monkeypatch, tmp_path, os_name):
    _as_os(monkeypatch, os_name)
    home = _fake_home(tmp_path, monkeypatch, os_name)
    unconfirmed = [n for n in FILE_CLIENTS if _needs_path(C.get(n), os_name)]
    assert "vscode" in unconfirmed                   # the catalog marks it NO everywhere
    for name in unconfirmed:
        rc, out, _ = _run(capsys, name, "--write", "--json")
        r = json.loads(out)
        assert rc == 3 and r["reason_word"] == "path_unconfirmed" and r["written"] is False
    assert _snapshot(home) == {}


def test_check_goes_stale_when_the_command_stops_resolving(capsys, monkeypatch, tmp_path,
                                                           uvx_pinned):
    _as_os(monkeypatch, "linux")
    _fake_home(tmp_path, monkeypatch, "linux")
    e = C.get("cursor")
    assert _action(capsys, e, "linux", "--write")[0] == 0
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None)
    rc, out, _ = _action(capsys, e, "linux", "--check")
    assert rc == 1 and "state: stale" in out


# --- a real process against a scratch project, and the claude CLI's own read-back ----

def _env(tmp_path: Path) -> dict:
    env = dict(os.environ)                          # home variables already point at tmp
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    env["CLAUDE_CONFIG_DIR"] = str(tmp_path / "claude-config")
    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    env["DISABLE_TELEMETRY"] = "1"
    env["DISABLE_AUTOUPDATER"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _proc(argv, cwd, env) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=120,
                          encoding="utf-8", errors="replace")


def _scratch(tmp_path: Path) -> tuple[Path, Path, bytes]:
    proj = tmp_path / "scratch-project"
    proj.mkdir()
    mcp = proj / ".mcp.json"
    seed = b'{\n  "mcpServers": {\n    "kh4-other": {"command": "kh4-other-server"}\n  }\n}\n'
    mcp.write_bytes(seed)
    return proj, mcp, seed


def _connect(env, proj, mcp, action):
    return _proc([sys.executable, "-m", "arcaeon", "connect", "claude-code", action,
                  "--path", str(mcp)], proj, env)


def test_real_process_write_undo_on_a_scratch_project(tmp_path, monkeypatch):
    monkeypatch.setenv(C.HOME_ENV, str(tmp_path / "home-real"))
    env = _env(tmp_path)
    proj, mcp, seed = _scratch(tmp_path)
    before = _snapshot(proj)
    r = _connect(env, proj, mcp, "--write")
    assert r.returncode == 0 and "written" in r.stdout, r.stdout + r.stderr
    doc = json.loads(mcp.read_bytes())
    assert doc["mcpServers"]["kh4-other"] == {"command": "kh4-other-server"}
    assert doc["mcpServers"]["arcaeon"]["args"][-1] == "mcp"
    r = _connect(env, proj, mcp, "--check")
    assert r.returncode == 0 and "state: present" in r.stdout, r.stdout + r.stderr
    r = _connect(env, proj, mcp, "--undo")
    assert r.returncode == 0 and "restored:" in r.stdout, r.stdout + r.stderr
    assert _snapshot(proj) == before and mcp.read_bytes() == seed
    assert not (tmp_path / "home-real").exists()


CLAUDE = shutil.which("claude")


@pytest.mark.skipif(CLAUDE is None, reason="the claude CLI is not on PATH, so there is "
                                           "no `claude mcp list` to read the entry back")
def test_claude_cli_reads_the_entry_back(tmp_path, monkeypatch):
    monkeypatch.setenv(C.HOME_ENV, str(tmp_path / "home-real"))
    env = _env(tmp_path)
    proj, mcp, seed = _scratch(tmp_path)
    before = _snapshot(proj)
    r = _connect(env, proj, mcp, "--write")
    assert r.returncode == 0, r.stdout + r.stderr
    command = json.loads(mcp.read_bytes())["mcpServers"]["arcaeon"]["command"]

    lst = _proc([CLAUDE, "mcp", "list"], proj, env)
    assert lst.returncode == 0, lst.stdout + lst.stderr
    row = [ln for ln in lst.stdout.splitlines() if ln.startswith("arcaeon:")]
    assert row and command in row[0] and "arcaeon mcp" in row[0], lst.stdout
    assert any(ln.startswith("kh4-other:") for ln in lst.stdout.splitlines()), lst.stdout
    got = _proc([CLAUDE, "mcp", "get", "arcaeon"], proj, env)
    assert got.returncode == 0 and "Project config" in got.stdout, got.stdout + got.stderr

    r = _connect(env, proj, mcp, "--undo")
    assert r.returncode == 0, r.stdout + r.stderr
    assert _snapshot(proj) == before and mcp.read_bytes() == seed
    lst = _proc([CLAUDE, "mcp", "list"], proj, env)
    lines = lst.stdout.splitlines()
    assert not any(ln.startswith("arcaeon:") for ln in lines), lst.stdout
    assert any(ln.startswith("kh4-other:") for ln in lines), lst.stdout
