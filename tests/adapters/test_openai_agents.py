"""OpenAI Agents SDK adapter (K085): a fake `agents` module against a real
loopback server, plus one real-SDK test skipped when `agents` is absent."""
from __future__ import annotations

import asyncio
import json
import sys

import pytest

from arcaeon.adapters import tool_specs


class FakeFunctionTool:
    """Records what the adapter hands the SDK's FunctionTool."""
    def __init__(self, *, name, description, params_json_schema, on_invoke_tool,
                 strict_json_schema=True):
        self.name, self.description = name, description
        self.params_json_schema = params_json_schema
        self.on_invoke_tool = on_invoke_tool
        self.strict_json_schema = strict_json_schema


def _invoke(tool, args: str) -> dict:
    return json.loads(asyncio.run(tool.on_invoke_tool(object(), args)))


def test_fake_sdk_tools_run_against_a_loopback_server(served, fake_module):
    fake_module("agents", FunctionTool=FakeFunctionTool)
    sys.modules.pop("arcaeon.adapters.openai_agents", None)
    from arcaeon.adapters.openai_agents import arcaeon_tools
    tools = {t.name: t for t in arcaeon_tools(served.client)}
    assert list(tools) == [s.name for s in tool_specs()]
    for t in tools.values():
        assert isinstance(t, FakeFunctionTool)
        assert t.strict_json_schema is False
        assert t.params_json_schema["type"] == "object"
    for n in (1, 2):
        r = _invoke(tools["log"], json.dumps({"ledger": "l.jsonl", "fields": {"n": n}}))
        assert r["exit"] == 0
    r = _invoke(tools["verify"], '{"ledger": "l.jsonl"}')
    assert (r["verdict"], r["rows"], r["exit"]) == ("VERIFIED", 2, 0)
    assert isinstance(_invoke(tools["status"], ""), dict)
    assert _invoke(tools["verify"], "not json")["exit"] == 2
    assert _invoke(tools["verify"], "[1, 2]")["exit"] == 2
    p = served.root / "l.jsonl"
    p.write_bytes(p.read_bytes().replace(b'"n": 1', b'"n": 9'))
    r = _invoke(tools["verify"], '{"ledger": "l.jsonl"}')
    assert r["exit"] != 0 and r["verdict"] != "VERIFIED"


def test_importing_the_module_does_not_import_the_sdk(monkeypatch):
    monkeypatch.delitem(sys.modules, "agents", raising=False)
    sys.modules.pop("arcaeon.adapters.openai_agents", None)
    import arcaeon.adapters.openai_agents as mod
    assert "agents" not in sys.modules
    import importlib.util
    if importlib.util.find_spec("agents") is None:
        with pytest.raises(ImportError):
            mod.arcaeon_tools()


def test_real_sdk_builds_function_tools():
    agents = pytest.importorskip("agents")
    sys.modules.pop("arcaeon.adapters.openai_agents", None)
    from arcaeon.adapters.openai_agents import arcaeon_tools
    tools = arcaeon_tools()
    assert tools and all(isinstance(t, agents.FunctionTool) for t in tools)
    assert [t.name for t in tools] == [s.name for s in tool_specs()]
