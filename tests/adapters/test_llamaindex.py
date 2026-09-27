"""LlamaIndex adapter (K087): a fake `llama_index.core.tools` against a real
loopback server, plus one real-SDK test skipped when it is absent."""
from __future__ import annotations

import asyncio
import json
import sys

import pytest

from arcaeon.adapters import tool_specs


class FakeToolMetadata:
    def __init__(self, *, name, description, fn_schema):
        self.name, self.description, self.fn_schema = name, description, fn_schema


class FakeFunctionTool:
    """Records what the adapter hands FunctionTool; call() passes keyword
    arguments to fn the way llama-index does."""
    def __init__(self, *, fn, metadata, async_fn=None):
        self.fn, self.metadata, self.async_fn = fn, metadata, async_fn

    def call(self, **kwargs) -> str:
        return self.fn(**kwargs)


def _load(fake_module):
    fake_module("llama_index.core.tools", FunctionTool=FakeFunctionTool,
                ToolMetadata=FakeToolMetadata)
    sys.modules.pop("arcaeon.adapters.llamaindex", None)
    from arcaeon.adapters.llamaindex import arcaeon_tools
    return arcaeon_tools


def test_fake_function_tools_run_against_a_loopback_server(served, fake_module, pydantic_mod):
    arcaeon_tools = _load(fake_module)
    tools = {t.metadata.name: t for t in arcaeon_tools(served.client)}
    specs = tool_specs()
    assert list(tools) == [s.name for s in specs]
    for s in specs:
        t = tools[s.name]
        assert isinstance(t, FakeFunctionTool) and callable(t.async_fn)
        assert t.metadata.description == s.description
        schema = t.metadata.fn_schema.model_json_schema()
        assert set(schema["properties"]) == set(s.parameters["properties"])
        assert set(schema.get("required", [])) == set(s.parameters.get("required", []))
    for n in (1, 2):
        assert json.loads(tools["log"].call(ledger="l.jsonl", fields={"n": n}))["exit"] == 0
    r = json.loads(tools["verify"].call(ledger="l.jsonl", since=None))
    assert (r["verdict"], r["rows"], r["exit"]) == ("VERIFIED", 2, 0)
    assert json.loads(asyncio.run(tools["verify"].async_fn(ledger="l.jsonl")))["exit"] == 0
    p = served.root / "l.jsonl"
    p.write_bytes(p.read_bytes().replace(b'"n": 1', b'"n": 9'))
    r = json.loads(tools["verify"].call(ledger="l.jsonl"))
    assert r["exit"] != 0 and r["verdict"] != "VERIFIED"


def test_importing_the_module_does_not_import_llamaindex(monkeypatch):
    monkeypatch.delitem(sys.modules, "llama_index", raising=False)
    sys.modules.pop("arcaeon.adapters.llamaindex", None)
    import arcaeon.adapters.llamaindex as mod
    assert "llama_index" not in sys.modules
    import importlib.util
    if importlib.util.find_spec("llama_index") is None:
        with pytest.raises(ImportError):
            mod.arcaeon_tools()


def test_real_llamaindex_builds_function_tools():
    li = pytest.importorskip("llama_index.core.tools")
    sys.modules.pop("arcaeon.adapters.llamaindex", None)
    from arcaeon.adapters.llamaindex import arcaeon_tools
    tools = arcaeon_tools()
    assert tools and all(isinstance(t, li.FunctionTool) for t in tools)
    assert [t.metadata.name for t in tools] == [s.name for s in tool_specs()]
