"""LangChain / LangGraph adapter (K086): a fake `langchain_core.tools` against
a real loopback server, plus one real-SDK test skipped when it is absent."""
from __future__ import annotations

import asyncio
import json
import sys

import pytest

from arcaeon.adapters import tool_specs


class FakeStructuredTool:
    """Records what the adapter hands StructuredTool; invoke() calls func the
    way langchain-core does for a dict args_schema (keyword arguments)."""
    def __init__(self, *, name, description, args_schema, func, coroutine=None):
        self.name, self.description = name, description
        self.args_schema, self.func, self.coroutine = args_schema, func, coroutine

    def invoke(self, tool_input: dict) -> str:
        return self.func(**tool_input)


def _load(fake_module):
    fake_module("langchain_core.tools", StructuredTool=FakeStructuredTool)
    sys.modules.pop("arcaeon.adapters.langchain", None)
    from arcaeon.adapters.langchain import arcaeon_tools
    return arcaeon_tools


def test_fake_structured_tools_run_against_a_loopback_server(served, fake_module):
    arcaeon_tools = _load(fake_module)
    tools = {t.name: t for t in arcaeon_tools(served.client)}
    specs = tool_specs()
    assert list(tools) == [s.name for s in specs]
    for s in specs:
        t = tools[s.name]
        assert isinstance(t, FakeStructuredTool)
        assert t.args_schema == s.parameters and t.description == s.description
        assert callable(t.coroutine)
    for n in (1, 2):
        assert json.loads(tools["log"].invoke({"ledger": "l.jsonl", "fields": {"n": n}}))["exit"] == 0
    r = json.loads(tools["verify"].invoke({"ledger": "l.jsonl"}))
    assert (r["verdict"], r["rows"], r["exit"]) == ("VERIFIED", 2, 0)
    r = json.loads(asyncio.run(tools["verify"].coroutine(ledger="l.jsonl", since=None)))
    assert r["exit"] == 0
    assert isinstance(json.loads(tools["status"].invoke({})), dict)
    p = served.root / "l.jsonl"
    p.write_bytes(p.read_bytes().replace(b'"n": 1', b'"n": 9'))
    r = json.loads(tools["verify"].invoke({"ledger": "l.jsonl"}))
    assert r["exit"] != 0 and r["verdict"] != "VERIFIED"


def test_unreachable_server_is_could_not_look_not_a_raise(fake_module):
    from arcaeon.client import Client
    arcaeon_tools = _load(fake_module)
    tools = {t.name: t for t in arcaeon_tools(Client(url="http://127.0.0.1:9", token="x"))}
    r = json.loads(tools["verify"].invoke({"ledger": "l.jsonl"}))
    assert r["exit"] == 3


def test_importing_the_module_does_not_import_langchain(monkeypatch):
    monkeypatch.delitem(sys.modules, "langchain_core", raising=False)
    monkeypatch.delitem(sys.modules, "langchain_core.tools", raising=False)
    sys.modules.pop("arcaeon.adapters.langchain", None)
    import arcaeon.adapters.langchain as mod
    assert "langchain_core" not in sys.modules
    import importlib.util
    if importlib.util.find_spec("langchain_core") is None:
        with pytest.raises(ImportError):
            mod.arcaeon_tools()


def test_real_langchain_builds_structured_tools():
    lc = pytest.importorskip("langchain_core.tools")
    sys.modules.pop("arcaeon.adapters.langchain", None)
    from arcaeon.adapters.langchain import arcaeon_tools
    tools = arcaeon_tools()
    assert tools and all(isinstance(t, lc.StructuredTool) for t in tools)
    assert [t.name for t in tools] == [s.name for s in tool_specs()]
