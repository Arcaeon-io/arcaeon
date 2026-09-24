"""The README's client-config block, checked against the package it configures.

Nobody installs this connector by reading the source. They copy the `.mcp.json`
stanza out of the README, paste it into their client, and restart it. That block
is therefore executable documentation with none of the protections executable
things get: rename the console script in `pyproject.toml` and the README goes on
confidently telling strangers to run a command that no longer exists, and the
only symptom is somebody else's client failing to start with a message about a
binary they never heard of.

So the block gets parsed, not eyeballed. Every `command` must be a console script
this package actually installs (read off `[project.scripts]`, never a second copy
kept by hand here), every flag in `args` must be one the CLI really accepts, the
`python -m` fallback must name a module that really has a `__main__`, and every
env var named in the block must be one the code really reads.

Red on drift, in this repo, before the README ships. Sibling of
`test_offers_drift.py`, same reasoning: a surface that quotes a fact needs a test
that owns the quote.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
README = HERE / "README.md"
# arcaeon merge: RE-TARGETED. The README block (a legacy fixture here, its
# client-config stanzas updated to `arcaeon mcp`) is checked against the ONE
# pyproject that ships the server now. W3 re-points README at the new docs.
PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"
PACKAGE = Path(__file__).resolve().parents[2] / "src" / "arcaeon" / "mcp"

# The interpreters a client config may name instead of the console script.
INTERPRETERS = {"python", "python3", "py", "uv", "uvx", "pipx"}


# --- what the README says ---------------------------------------------------

def _json_fences(text: str) -> list:
    """Every ```json fenced block, as (index, raw text)."""
    return [(i, m.group(1)) for i, m in
            enumerate(re.finditer(r"```json\n(.*?)```", text, re.DOTALL))]


def _client_configs() -> list:
    """The parsed blocks that configure an MCP client."""
    out = []
    for _i, raw in _json_fences(README.read_text(encoding="utf-8")):
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(doc, dict) and "mcpServers" in doc:
            out.append(doc)
    return out


def _server_entries() -> list:
    """(server_name, entry) for every server in every client-config block."""
    return [(name, entry)
            for doc in _client_configs()
            for name, entry in doc["mcpServers"].items()]


# --- what the package actually installs -------------------------------------

def _console_scripts() -> dict:
    """`[project.scripts]` from pyproject: {script_name: "module:function"}.

    Read from the file rather than from `importlib.metadata`, on purpose. The
    metadata only exists once the package is installed, and this guard has to
    fire on the workstation that just renamed the script -- which is exactly the
    moment before anything is reinstalled.
    """
    text = PYPROJECT.read_text(encoding="utf-8")
    try:
        import tomllib
        return dict(tomllib.loads(text).get("project", {}).get("scripts", {}))
    except ImportError:  # pragma: no cover - Python 3.10
        section = re.search(r"^\[project\.scripts\]\s*$(.*?)(?=^\[|\Z)",
                            text, re.MULTILINE | re.DOTALL)
        if not section:
            return {}
        return {m.group(1): m.group(2) for m in
                re.finditer(r'^\s*([\w.-]+)\s*=\s*"([^"]+)"\s*$',
                            section.group(1), re.MULTILINE)}


# --- the tests --------------------------------------------------------------

def test_the_readme_still_carries_a_client_config_block():
    """If this fails, every test below it is vacuously green."""
    configs = _client_configs()
    assert configs, "no ```json block with mcpServers left in the README"
    assert _server_entries(), "the mcpServers blocks are empty"


def test_every_json_block_in_the_readme_parses():
    """A copy-paste block with a trailing comma is a support ticket."""
    bad = []
    for i, raw in _json_fences(README.read_text(encoding="utf-8")):
        try:
            json.loads(raw)
        except json.JSONDecodeError as exc:
            bad.append((i, str(exc), raw[:120]))
    assert not bad, bad


def test_every_command_is_a_console_script_this_package_installs():
    """The load-bearing one. `"command": "arcaeon-mcp"` must match
    `[project.scripts]`, or the README is telling people to run something that
    does not get installed."""
    scripts = _console_scripts()
    assert scripts, "pyproject declares no console scripts at all"
    for name, entry in _server_entries():
        command = entry.get("command")
        assert command, f"server {name!r} has no command"
        if command in INTERPRETERS:
            continue
        assert command in scripts, (
            f"README tells clients to run {command!r} for server {name!r}, but "
            f"pip installs {sorted(scripts)}")


def test_the_console_script_target_still_exists_and_is_callable():
    """The other end of the same wire: `arcaeon-mcp = "pkg.__main__:main"` is
    only a promise until something imports it. A renamed `main` breaks the
    installed binary while every in-process test keeps passing."""
    import importlib
    for script, target in _console_scripts().items():
        module_name, _, func_name = target.partition(":")
        mod = importlib.import_module(module_name)
        fn = getattr(mod, func_name, None)
        assert callable(fn), f"{script}: {target} does not resolve to a callable"


def test_the_python_m_fallback_in_the_readme_names_a_real_module():
    """The README offers `"command": "python", "args": ["-m", "arcaeon.mcp"]`
    for clients that cannot run console scripts. That is a second install path,
    and it breaks silently if the package is renamed or loses `__main__.py`."""
    text = README.read_text(encoding="utf-8")
    hits = re.findall(r'"-m",\s*"([\w.]+)"', text)
    assert hits, "the `python -m` fallback is gone from the README"
    for module_name in set(hits):
        assert module_name == "arcaeon." + PACKAGE.name, (module_name, PACKAGE.name)
        assert (PACKAGE / "__main__.py").is_file(), (
            f"README offers `python -m {module_name}` and the package has no __main__.py")


def test_every_flag_in_the_readme_args_is_accepted_by_the_cli(tmp_path):
    """Not just "the flag is spelled in the source" -- the README's exact argv
    is handed to the real parser. `--tools` makes it return before any server
    starts, so this is a full argument-parse round trip with no stdio."""
    from arcaeon.mcp.__main__ import main

    saved = dict(os.environ)
    try:
        for name, entry in _server_entries():
            if entry.get("command") in INTERPRETERS:
                continue
            argv = [a for a in entry.get("args", [])]
            if entry.get("command") == "arcaeon" and argv[:1] == ["mcp"]:
                argv = argv[1:]          # `arcaeon mcp ...` hands the rest to the server
            # Redirect the paths the README's example names, so parsing the docs
            # never writes a ledger into the repo.
            argv = [str(tmp_path / a) if not a.startswith("-") else a for a in argv]
            assert main(argv + ["--tools"]) == 0, (name, argv)
    finally:
        os.environ.clear()
        os.environ.update(saved)


def test_every_env_var_in_the_readme_block_is_read_by_the_code():
    """A stanza that sets `ARCAEON_KEY` for a package that stopped reading it is
    a user who thinks the paid lane is switched on and gets the free-tier
    message instead."""
    source = "\n".join(p.read_text(encoding="utf-8")
                       for p in sorted(PACKAGE.glob("*.py")))
    named = {k for _n, entry in _server_entries() for k in (entry.get("env") or {})}
    assert named, "the README's example no longer sets any env var (was ARCAEON_KEY)"
    for var in named:
        assert var in source, (
            f"README's client config sets {var}, which no module under "
            f"{PACKAGE.name}/ reads")


def test_the_readme_install_line_names_the_distribution_pyproject_declares():
    """`pip install arcaeon` has to match `[project] name`."""
    text = PYPROJECT.read_text(encoding="utf-8")
    name_match = re.search(r'^name\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert name_match, f"{PYPROJECT} has no [project] name field to check against"
    dist = name_match.group(1)
    readme = README.read_text(encoding="utf-8")
    assert re.search(rf"pip install {re.escape(dist)}\b", readme), (
        f"the README's install command does not name the distribution {dist!r}")
