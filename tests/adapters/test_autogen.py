"""AutoGen adapter (K089): a fake `autogen_core.tools` against a real loopback
server, plus one real-SDK test skipped when autogen-core is absent."""
from __future__ import annotations

import asyncio
import json
import sys

import pytest

from arcaeon.adapters import tool_specs


class FakeBaseTool:
    """Records the constructor arguments; run_json() validates the arguments
    against args_type (when it is a pydantic model) and awaits run(), the way
    autogen-core does."""
    def __init__(self, args_type, return_type, name, description, strict=False):
        self.args_type, self.return_type = args_type, return_type
        self.name, self.description = name, description

    async def run_json(self, args: dict, cancellation_token) -> str:
        v = getattr(self.args_type, "model_validate", None)
        return await self.run(v(args) if v else args, cancellation_token)


def _load(fake_module):
    fake_module("autogen_core.tools", BaseTool=FakeBaseTool)
    sys.modules.pop("arcaeon.adapters.autogen", None)
    from arcaeon.adapters.autogen import arcaeon_tools
    return arcaeon_tools


def _run(tool, args: dict) -> dict:
    return json.loads(asyncio.run(tool.run_json(args, None)))


def test_fake_autogen_tools_run_against_a_loopback_server(served, fake_module, pydantic_mod):
    arcaeon_tools = _load(fake_module)
    tools = {t.name: t for t in arcaeon_tools(served.client)}
    specs = tool_specs()
    assert list(tools) == [s.name for s in specs]
    for s in specs:
        t = tools[s.name]
        assert isinstance(t, FakeBaseTool) and t.return_type is str
        assert t.description == s.description
        schema = t.args_type.model_json_schema()
        assert set(schema["properties"]) == set(s.parameters["properties"])
        assert set(schema.get("required", [])) == set(s.parameters.get("required", []))
    for n in (1, 2):
        assert _run(tools["log"], {"ledger": "l.jsonl", "fields": {"n": n}})["exit"] == 0
    r = _run(tools["verify"], {"ledger": "l.jsonl"})
    assert (r["verdict"], r["rows"], r["exit"]) == ("VERIFIED", 2, 0)
    p = served.root / "l.jsonl"
    p.write_bytes(p.read_bytes().replace(b'"n": 1', b'"n": 9'))
    r = _run(tools["verify"], {"ledger": "l.jsonl"})
    assert r["exit"] != 0 and r["verdict"] != "VERIFIED"


def test_importing_the_module_does_not_import_autogen(monkeypatch):
    monkeypatch.delitem(sys.modules, "autogen_core", raising=False)
    sys.modules.pop("arcaeon.adapters.autogen", None)
    import arcaeon.adapters.autogen as mod
    assert "autogen_core" not in sys.modules
    import importlib.util
    if importlib.util.find_spec("autogen_core") is None:
        with pytest.raises(ImportError):
            mod.arcaeon_tools()


def test_real_autogen_builds_tools():
    at = pytest.importorskip("autogen_core.tools")
    sys.modules.pop("arcaeon.adapters.autogen", None)
    from arcaeon.adapters.autogen import arcaeon_tools
    tools = arcaeon_tools()
    assert tools and all(isinstance(t, at.BaseTool) for t in tools)
    assert [t.name for t in tools] == [s.name for s in tool_specs()]
