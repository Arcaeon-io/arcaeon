"""plugins/arcaeon (the Claude plugin bundle) agrees with the package.

- the version in plugin.json, the uvx pin in .mcp.json and every pin and
  version the plugin README names equal the version in pyproject.toml, and
  registry/server.json publishes the same one;
- the launcher pins the package exactly (a range or a bare name would be an
  unpinned launcher);
- no key is set anywhere in the bundle, so the free tools start without one;
- the marketplace entry points at this folder under the manifest's name;
- the README names every tool the server has, and names exactly the paid ones
  as the tools that need a key.

This repository has no CI workflow, so these run with the local suite.
arcaeon.mcp.server imports without the MCP SDK (the [mcp] extra loads it only
when the server is built), so the tool-name test runs on a base install too;
it skips, and says why, only if that import ever starts needing the extra.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "arcaeon"
MANIFEST = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
MCP = json.loads((PLUGIN / ".mcp.json").read_text(encoding="utf-8"))
README = (PLUGIN / "README.md").read_text(encoding="utf-8")
MARKET = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
SERVER_JSON = json.loads((ROOT / "registry" / "server.json").read_text(encoding="utf-8"))
PYPROJECT_TEXT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
# the floor is 3.10, which has no tomllib; the field is read by pattern
PY_VERSION = re.search(r'^version = "([^"]+)"', PYPROJECT_TEXT, re.M).group(1)
SERVER = MCP["mcpServers"]["arcaeon"]
PIN = re.compile(r"arcaeon\[mcp\]==([0-9][0-9A-Za-z.+-]*)")
COUNT_WORDS = {15: "Fifteen", 16: "Sixteen", 17: "Seventeen", 18: "Eighteen",
               19: "Nineteen", 20: "Twenty"}


def test_manifest_version_is_the_package_version():
    assert MANIFEST["version"] == PY_VERSION


def test_server_json_publishes_the_same_version():
    assert SERVER_JSON["version"] == PY_VERSION
    assert SERVER_JSON["packages"][0]["version"] == PY_VERSION


def test_launcher_pins_the_package_exactly():
    assert SERVER["command"] == "uvx"
    args = SERVER["args"]
    assert args[:2] == ["--from", f"arcaeon[mcp]=={PY_VERSION}"], args
    assert args[2:] == ["arcaeon", "mcp"], args


def test_every_pin_and_version_in_the_readme_is_the_package_version():
    pins = PIN.findall(README)
    assert pins, "the README should show the launch line"
    assert set(pins) == {PY_VERSION}, pins
    named = re.findall(r"(?:\bversion|`arcaeon`) ([0-9]+\.[0-9]+\.[0-9]+)", README)
    assert named and set(named) == {PY_VERSION}, named


def test_no_key_is_set_in_the_bundle():
    assert "ARCAEON_KEY" not in SERVER.get("env", {})
    assert "userConfig" not in MANIFEST


def test_ledger_lives_in_the_project_not_the_plugin_cache():
    # The bare form on purpose. Claude Code fills ${CLAUDE_PROJECT_DIR} itself
    # in a plugin's MCP env. The defaulted form ${CLAUDE_PROJECT_DIR:-.} goes
    # through ordinary variable expansion instead, where CLAUDE_PROJECT_DIR is
    # not set in Claude Code's own environment, so it comes out as "." and the
    # ledger path turns relative again (seen with a probe plugin installed in a
    # throwaway CLAUDE_CONFIG_DIR: bare -> <project>/agent.log.jsonl, defaulted
    # -> ./agent.log.jsonl).
    assert SERVER.get("env") == {
        "ARCAEON_LEDGER_LOG": "${CLAUDE_PROJECT_DIR}/agent.log.jsonl"}
    assert "${CLAUDE_PROJECT_DIR}/agent.log.jsonl" in README
    # and the README owns the two consequences: it overrides the user's own
    # setting, and the files sit in the project root
    assert "replaces any `ARCAEON_LEDGER_LOG`" in README
    assert "`.gitignore`" in README


def test_marketplace_entry_points_at_this_plugin():
    entries = [p for p in MARKET["plugins"] if p["name"] == MANIFEST["name"]]
    assert len(entries) == 1
    assert entries[0]["source"] == "./plugins/arcaeon"
    assert entries[0].get("version", PY_VERSION) == PY_VERSION


def test_readme_names_every_tool_and_the_paid_split():
    try:
        from arcaeon.mcp import server
    except ImportError as e:  # the [mcp] extra, or a part of it, is not installed
        pytest.skip(f"arcaeon.mcp.server does not import here: {e}")
    named = set(re.findall(r"`([a-z_]+)`", README))
    missing = [t for t in server.ALL_TOOLS if t not in named]
    assert not missing, f"README does not name: {missing}"
    key_part = README.split("Two tools need a key:", 1)[1].split("\n## ", 1)[0]
    in_key_part = {t for t in server.ALL_TOOLS if f"`{t}`" in key_part}
    assert in_key_part == set(server.PAID_TOOLS), in_key_part
    assert f"{COUNT_WORDS[len(server.FREE_TOOLS)]} tools are free" in README
