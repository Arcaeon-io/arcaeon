"""`arcaeon connect <client>` prints and writes nothing (K019).

Each golden file holds the output for a fake Windows, macOS and Linux home,
so it is the same on any machine: the file line's state word (exists, not
there yet, on another machine) depends on the host and is compared as
<state>, and the token path as <ARCAEON_HOME>/serve.token. UPDATE_GOLDEN=1
rewrites them.

A client in WRITE_GOLDEN (K022, K023) also carries the --write merge into a
config that already holds another server: the change list and the whole
file text, which is the same on every OS.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

import pytest

from arcaeon.connect import catalog as C
from arcaeon.connect import cli
from arcaeon.connect import write as W

GOLDEN = Path(__file__).resolve().parent / "golden"
FAKE_HOMES = (("windows", r"C:\Users\u"), ("macos", "/Users/u"), ("linux", "/fake/u"))
NOTHING = "nothing written (add --write to apply)"
WRITE_GOLDEN = ("claude-desktop", "claude-code", "cursor")
SEED = '{\n  "theme": "dark",\n  "KEY": {\n    "other": {"command": "other-server"}\n  }\n}\n'


def _write_section(name: str) -> str:
    e = C.get(name)
    new, changed = W.merge_text(SEED.replace("KEY", e.key), e.key, cli.ENTRY_NAME,
                                cli.server_entry(e))
    lines = ["## --write into a config holding one other server (every OS)"]
    lines += [f"changed: {c['key']} ({c['change']})" for c in changed]
    return "\n".join(lines) + "\n" + new


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arcaeon-home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")


def _out(capsys, *argv) -> tuple[int, str]:
    rc = cli.main(list(argv))
    return rc, capsys.readouterr().out


def _golden_text(capsys, name, arcaeon_home) -> str:
    parts = []
    for os_name, home in FAKE_HOMES:
        os.environ[C.HOME_ENV] = home
        try:
            rc, out = _out(capsys, name, "--os", os_name)
        finally:
            del os.environ[C.HOME_ENV]
        assert rc == 0
        out = out.replace(str(arcaeon_home / "serve.token"), "<ARCAEON_HOME>/serve.token")
        out = re.sub(r"(?m)^(file: .*)  \([a-z ]+\)$", r"\1  (<state>)", out)
        parts.append(f"## --os {os_name}, home {home}\n" + out)
    if name in WRITE_GOLDEN:
        parts.append(_write_section(name))
    return "\n".join(parts)


@pytest.mark.parametrize("name", C.names())
def test_golden(capsys, tmp_path, name):
    got = _golden_text(capsys, name, tmp_path / "arcaeon-home")
    f = GOLDEN / f"{name}.txt"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        f.write_text(got, encoding="utf-8", newline="\n")
    assert got == f.read_text(encoding="utf-8"), f"{f.name} differs; UPDATE_GOLDEN=1 rewrites"


@pytest.mark.parametrize("name", C.names())
def test_every_client_ends_nothing_written(capsys, name):
    rc, out = _out(capsys, name)
    assert rc == 0 and out.rstrip("\n").splitlines()[-1] == NOTHING


def _snapshot(root: Path) -> dict:
    return {str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest()
                                       if p.is_file() else "dir")
            for p in sorted(root.rglob("*"))}


def test_the_fake_home_is_byte_identical_before_and_after(capsys, tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv(C.HOME_ENV, str(home))
    cursor = Path(C.config_path(C.get("cursor")))
    cursor.parent.mkdir(parents=True)
    cursor.write_bytes(b'{"mcpServers": {"other": {"command": "x"}}}\r\n')
    (home / ".gemini").mkdir()
    (home / ".gemini" / "settings.json").write_text("{not json", encoding="utf-8")
    before = _snapshot(home)
    for name in C.names():
        for extra in ((), ("--json",)):
            rc, _ = _out(capsys, name, *extra)
            assert rc == 0
    assert _snapshot(home) == before
    rc, out = _out(capsys, "cursor")
    assert "(exists)" in out


def test_json_plan_names_the_file_and_the_merge(capsys, monkeypatch):
    monkeypatch.setenv(C.HOME_ENV, "/fake/u")
    rc, out = _out(capsys, "claude-code", "--os", "linux", "--json")
    d = json.loads(out)
    assert rc == 0 and d["written"] is False
    assert d["file"] == "/fake/u/.claude.json"
    assert d["merge"] == {"mcpServers": {"arcaeon": {"command": "arcaeon", "args": ["mcp"]}}}


def test_unconfirmed_path_says_so(capsys):
    rc, out = _out(capsys, "vscode")
    assert "confirmed: NO" in out


def test_preview_for_another_os_uses_placeholders(capsys, monkeypatch):
    monkeypatch.delenv(C.HOME_ENV, raising=False)
    other = "linux" if C.current_os() == "windows" else "windows"
    rc, out = _out(capsys, "cursor", "--os", other)
    want = "~/.cursor/mcp.json" if other == "linux" else r"%USERPROFILE%\.cursor\mcp.json"
    assert rc == 0 and want in out and "(on another machine)" in out


@pytest.mark.parametrize("argv", [[], ["nope"], ["cursor", "vscode"], ["cursor", "--os", "bsd"],
                                  ["cursor", "--frobnicate"], ["cursor", "--path", "x.json"]])
def test_bad_usage_is_exit_2(capsys, argv):
    assert cli.main(argv) == 2
