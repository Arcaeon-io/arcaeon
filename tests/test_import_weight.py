"""The base install is stdlib-only, and the adapter stays that way.

The adapter is a stdio proxy in front of every MCP call, so its import cost is
paid per session. The council (2026-09-23): "Lazy imports are a promise; make
them a test." Each check runs in a FRESH interpreter, because this pytest
process has long since imported mcp, cryptography and tree_sitter itself.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

tomllib = pytest.importorskip("tomllib")  # 3.11+; the metadata checks skip on 3.10

ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / "src")
HEAVY = ("mcp", "tree_sitter", "tree_sitter_typescript", "cryptography", "nacl")

_PROBE = r"""
import json, socket, sys
def _no_network(*a, **k):
    raise AssertionError("network touched at import time")
socket.socket.connect = _no_network
socket.create_connection = _no_network
import importlib
importlib.import_module(sys.argv[1])
heavy = sorted({m.split(".")[0] for m in sys.modules} & set(sys.argv[2].split(",")))
print(json.dumps({"heavy": heavy,
                  "arcaeon_modules": sorted(m for m in sys.modules if m.startswith("arcaeon"))}))
"""


def _import_in_fresh_python(module: str) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC
    p = subprocess.run([sys.executable, "-c", _PROBE, module, ",".join(HEAVY)],
                       capture_output=True, text=True, env=env, timeout=120)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout.strip().splitlines()[-1])


def test_importing_the_adapter_pulls_no_heavy_dependency():
    """THE CI test the council asked for: importing arcaeon.record.adapter must
    not import mcp, tree_sitter or cryptography."""
    out = _import_in_fresh_python("arcaeon.record.adapter")
    assert out["heavy"] == [], out["heavy"]


@pytest.mark.parametrize("module", [
    "arcaeon", "arcaeon.verdict", "arcaeon.cli", "arcaeon.record.row",
    "arcaeon.record.ledger", "arcaeon.record.adapter.proxy", "arcaeon.record.once",
    "arcaeon.record.receipt", "arcaeon.record.deal", "arcaeon.prove.reconcile", "arcaeon.prove.audit",
    "arcaeon.prove.compact", "arcaeon.prove.continuity", "arcaeon.prove.baseline",
    "arcaeon.save.dedup", "arcaeon.save.distill", "arcaeon.save.meter", "arcaeon.remote",
])
def test_base_modules_are_stdlib_only_and_offline(module):
    """Every family's front module imports without a third-party package and
    without opening a socket. (vet and mcp are the two with optional extras;
    vet's scanner is checked separately below.)"""
    out = _import_in_fresh_python(module)
    assert out["heavy"] == [], (module, out["heavy"])


def test_vet_scanner_imports_without_extras():
    """vet's [ts] and [sign] parts are imported lazily: the scanner itself runs
    on a base install."""
    out = _import_in_fresh_python("arcaeon.prove.vet.checks")
    assert out["heavy"] == [], out["heavy"]


def test_import_arcaeon_imports_nothing_else():
    out = _import_in_fresh_python("arcaeon")
    assert out["arcaeon_modules"] == ["arcaeon"], out["arcaeon_modules"]


def test_the_row_format_has_no_second_copy_in_src():
    """One spine: the chain rule, the json-c14n canonicalization and the strict
    reader are written out in arcaeon/record/row.py and nowhere else in src/."""
    needles = {
        'json.dumps({k: v for k, v in': "the chain body",
        '"sha256:json-c14n:v1:" + hashlib': "the json-c14n digest",
        'object_pairs_hook=_reject_duplicate_keys': "the strict reader",
        'class DuplicateKeyError': "the duplicate-key error",
    }
    # Deliberately WRONG recipes kept on purpose: the selftests compute a
    # drifted digest (sort_keys=False) to prove drift is caught. Not copies.
    negative_vectors = {"record/adapter/selftest.py", "record/ledger/mutation_harness.py"}
    hits = []
    for p in (ROOT / "src" / "arcaeon").rglob("*.py"):
        rel = p.relative_to(ROOT / "src" / "arcaeon").as_posix()
        if p.name == "row.py" or rel in negative_vectors:
            continue
        text = p.read_text(encoding="utf-8")
        for needle, what in needles.items():
            if needle in text:
                hits.append(f"{p.relative_to(ROOT)}: {what}")
    assert hits == [], hits


def test_base_install_declares_zero_dependencies_and_the_four_extras():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert meta["name"] == "arcaeon"
    assert meta["version"] == "0.10.0"
    assert meta["requires-python"] == ">=3.10"
    assert meta["dependencies"] == []
    extras = meta["optional-dependencies"]
    assert set(extras) == {"mcp", "ts", "sign", "all"}
    assert extras["mcp"] == ["mcp>=2.0.0,<3"]
    assert any(d.startswith("cryptography") for d in extras["sign"])
    assert all(any(d.startswith("tree-sitter") for d in extras["ts"]) for _ in [0])
    assert sorted(extras["all"]) == sorted(extras["mcp"] + extras["ts"] + extras["sign"])
    assert meta["scripts"] == {"arcaeon": "arcaeon.cli:main"}


def test_package_version_matches_pyproject():
    import arcaeon
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert arcaeon.__version__ == meta["version"]


_STDLIB_PROBE = r"""
import json, sys
before = set(sys.modules)
import importlib
importlib.import_module(sys.argv[1])
new = {m.split(".")[0] for m in set(sys.modules) - before}
third = sorted(n for n in new if n != "arcaeon" and n not in sys.stdlib_module_names)
print(json.dumps({"third_party": third,
                  "arcaeon_modules": sorted(m for m in sys.modules if m.startswith("arcaeon"))}))
"""


@pytest.mark.parametrize("module", ["arcaeon.journal", "arcaeon.status"])
def test_journal_and_status_import_stdlib_only(module):
    """B049: the journal is written on every verb and `status` reads it, so both
    stay on the standard library: every top-level module their import brings
    in, apart from arcaeon's own, is in sys.stdlib_module_names."""
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC
    p = subprocess.run([sys.executable, "-c", _STDLIB_PROBE, module],
                       capture_output=True, text=True, env=env, timeout=120)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout.strip().splitlines()[-1])
    assert out["third_party"] == [], (module, out["third_party"])
    assert module in out["arcaeon_modules"]


#: Agent frameworks the adapters wrap (and pydantic, which several of them
#: need): none may be imported by importing arcaeon. Each adapter imports its
#: framework inside the function that builds the tools.
FRAMEWORKS = ("agents", "openai", "langchain", "langchain_core", "langgraph",
              "llama_index", "crewai", "autogen", "autogen_core",
              "autogen_agentchat", "pydantic")

_PLUGIN_MODULES = ["arcaeon", "arcaeon.serve", "arcaeon.client", "arcaeon.connect",
                   "arcaeon.prove.readers", "arcaeon.adapters"] + sorted(
    "arcaeon.adapters." + p.stem
    for p in (ROOT / "src" / "arcaeon" / "adapters").glob("*.py")
    if p.stem != "__init__")


def test_every_adapter_module_is_in_the_plug_in_list():
    """K090: the list below is globbed, so a new adapter is covered the day it lands."""
    for name in ("openai_agents", "langchain", "llamaindex", "crewai", "autogen"):
        assert f"arcaeon.adapters.{name}" in _PLUGIN_MODULES


@pytest.mark.parametrize("module", _PLUGIN_MODULES)
def test_plug_in_modules_pull_in_no_framework_mcp_or_cryptography(module):
    """K090: importing the server, the client, connect, the readers and every
    adapter pulls in no agent framework, no mcp and no cryptography, and opens
    no socket."""
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC
    p = subprocess.run([sys.executable, "-c", _PROBE, module, ",".join(HEAVY + FRAMEWORKS)],
                       capture_output=True, text=True, env=env, timeout=120)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout.strip().splitlines()[-1])
    assert out["heavy"] == [], (module, out["heavy"])
    assert module in out["arcaeon_modules"]
