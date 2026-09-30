"""The launch form: uvx when uv resolves, the absolute interpreter otherwise (K025)."""
from __future__ import annotations

import json
import os
import shutil
import sys

import pytest

from arcaeon.connect import catalog as C
from arcaeon.connect import cli
from arcaeon.connect import write as W
from _connect import entry_for

UVX = {"command": "uvx", "args": ["--from", "arcaeon[mcp]", "arcaeon", "mcp"]}


@pytest.fixture()
def uv_present(monkeypatch):
    monkeypatch.setattr(shutil, "which",
                        lambda name, *a, **k: "/fake/bin/" + name if name in ("uv", "uvx")
                        else None)


@pytest.fixture()
def uv_absent(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None)


def test_uv_on_path_gives_uvx(uv_present):
    assert C.launch_form() == UVX
    assert cli.launch_form() == UVX


def test_no_uv_gives_the_absolute_interpreter(uv_absent):
    f = C.launch_form()
    assert f["args"] == ["-m", "arcaeon", "mcp"]
    assert os.path.isabs(f["command"])
    assert os.path.samefile(f["command"], sys.executable)


@pytest.mark.parametrize("name", [e.name for e in C.CATALOG if e.writes_file])
def test_every_file_client_uses_the_form(name, uv_present):
    e = entry_for(name)
    entry = cli.server_entry(e)
    assert {k: entry[k] for k in ("command", "args")} == UVX
    assert entry.get("type") == ("stdio" if e.key == "servers" else None)


def test_the_printed_snippet_follows_which(capsys, uv_absent):
    assert cli.main(["cursor", "--json"]) == 0
    got = json.loads(capsys.readouterr().out)["merge"]["mcpServers"]["arcaeon"]
    assert got == {"command": os.path.abspath(sys.executable), "args": ["-m", "arcaeon", "mcp"]}


def test_a_written_interpreter_form_checks_present(capsys, uv_absent):
    assert cli.main(["cursor", "--write"]) == 0
    rc = cli.main(["cursor", "--check"])
    out = capsys.readouterr().out
    assert rc == 0 and "state: present" in out            # absolute path exists


def test_a_written_uvx_form_is_stale_once_uv_is_gone(capsys, monkeypatch, uv_present):
    assert cli.main(["cursor", "--write"]) == 0
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None)
    assert W.check(C.config_path(entry_for("cursor")), "mcpServers", "arcaeon")["state"] == "stale"
    capsys.readouterr()
