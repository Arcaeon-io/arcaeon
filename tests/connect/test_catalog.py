"""The client catalog `arcaeon connect` reads (K018)."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from arcaeon.connect import catalog as C

ROOT = Path(__file__).resolve().parents[2]
CLIENTS = ["claude-desktop", "claude-code", "cursor", "windsurf", "vscode", "gemini-cli",
           "chatgpt", "generic-http"]


def test_the_eight_clients_in_order():
    assert C.names() == CLIENTS


@pytest.mark.parametrize("name", CLIENTS)
def test_every_entry_is_complete(name):
    e = C.get(name)
    assert e.transport in C.TRANSPORTS
    assert e.doc_url.startswith("https://")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", e.read_date)
    assert set(e.confirmed) == set(C.OSES)
    if e.transport == "stdio-mcp":
        assert e.key in ("mcpServers", "servers")
        assert set(e.paths) == set(C.OSES) and all(e.paths.values())
        assert e.writes_file
    else:
        assert e.key is None and not e.writes_file


def test_keys_per_client():
    keys = {e.name: e.key for e in C.CATALOG}
    assert keys["vscode"] == "servers"
    assert {keys[n] for n in CLIENTS[:6] if n != "vscode"} == {"mcpServers"}


def test_unconfirmed_paths_are_marked():
    assert C.confirmed_for(C.get("vscode"), "windows") is False
    assert C.confirmed_for(C.get("claude-desktop"), "linux") is False
    assert C.confirmed_for(C.get("claude-desktop"), "windows") is True
    assert C.confirmed_for(C.get("cursor"), "macos") is True


def test_connect_home_overrides_every_base(tmp_path, monkeypatch):
    monkeypatch.setenv(C.HOME_ENV, str(tmp_path))
    monkeypatch.setenv("APPDATA", r"C:\elsewhere")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/elsewhere")
    for e in C.CATALOG:
        p = C.config_path(e)
        if p is not None:
            assert Path(p).is_relative_to(tmp_path), (e.name, p)


def test_paths_on_a_fake_windows_and_posix_home():
    w = C.config_path(C.get("claude-desktop"), "windows", r"C:\Users\u")
    assert w == r"C:\Users\u\AppData\Roaming\Claude\claude_desktop_config.json"
    m = C.config_path(C.get("claude-desktop"), "macos", "/Users/u")
    assert m == "/Users/u/Library/Application Support/Claude/claude_desktop_config.json"
    assert C.config_path(C.get("cursor"), "linux", "/fake/u") == "/fake/u/.cursor/mcp.json"
    assert C.config_path(C.get("vscode"), "linux", "/fake/u") == "/fake/u/.config/Code/User/mcp.json"
    assert C.config_path(C.get("chatgpt"), "windows", r"C:\Users\u") is None


def _run(*args, env_extra=None):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "ARCAEON_JOURNAL": "0",
           **(env_extra or {})}
    return subprocess.run([sys.executable, "-m", "arcaeon", "connect", *args], env=env,
                          capture_output=True, text=True, timeout=60)


def test_connect_list_prints_eight_rows(tmp_path):
    p = _run("--list", env_extra={C.HOME_ENV: str(tmp_path)})
    assert p.returncode == 0, p.stderr
    lines = p.stdout.splitlines()
    assert lines[0].split()[:3] == ["client", "transport", "confirmed"]
    rows = [ln for ln in lines[1:] if ln.split() and ln.split()[0] in CLIENTS]
    assert [r.split()[0] for r in rows] == CLIENTS
    for r in rows:
        assert r.split()[2] in ("yes", "NO")
    assert "confirmed NO" in p.stdout


def test_connect_list_json(tmp_path):
    p = _run("--list", "--json", env_extra={C.HOME_ENV: str(tmp_path)})
    assert p.returncode == 0
    d = json.loads(p.stdout)
    assert [r["client"] for r in d["clients"]] == CLIENTS
    assert all(isinstance(r["confirmed"], bool) for r in d["clients"])


def test_catalog_imports_nothing_heavy():
    code = ("import sys, arcaeon.connect.catalog; "
            "print(sorted(m for m in ('mcp','cryptography','tree_sitter') if m in sys.modules))")
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": str(ROOT / "src")}, timeout=60)
    assert p.stdout.strip() == "[]"
