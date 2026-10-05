"""The Lasso plugin against the real hook shapes (L4-04).

Lasso is not installed. A minimal stub of `mcp_gateway` is put in
sys.modules. It mirrors github.com/lasso-security/mcp-gateway at
7e7f1f6e5314819b3d0928128bb88eaea874b600:

  mcp_gateway/plugins/base.py     PluginContext l.8-43, Plugin l.48-87,
                                  GuardrailPlugin l.93-107
  mcp_gateway/plugins/manager.py  register_plugin l.30-71, load({}) l.197-198,
                                  process_response l.283-314 (an exception is
                                  logged and the response kept)
  mcp_gateway/sanitizers.py       resource (bytes, mime) l.138-170; a tool
                                  result that is not a CallToolResult -> the
                                  original l.213-222
  mcp_gateway/server.py           a prompt result that is not a
                                  GetPromptResult -> the original l.247-254

arcaeon.connect.lasso is reloaded with the stub present, and again without it
when the test ends. Every key is a throwaway seed. Nothing reaches the network.
"""
from __future__ import annotations

import abc
import base64
import copy
import importlib
import json
import secrets
import socket
import sys
import types
from pathlib import Path

import pytest

from arcaeon import verdict as V
from arcaeon.prove import envelope as E

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

from arcaeon.connect import lasso as L  # noqa: E402
from arcaeon.connect import mcp_result as M  # noqa: E402

LASSO_SHA = "7e7f1f6e5314819b3d0928128bb88eaea874b600"
AUD, DEAL, PURPOSE = "agent-1", "d-7f3a", "lookup"
BIND = {"label": "hits", "audience": AUD, "deal": DEAL, "purpose": PURPOSE, "not_after": "7d"}
TEXT = '{"hits": ["unit-a"]}'
SECRET = "unit-a"


# --- the stub ----------------------------------------------------------------------------

class _Model:
    """Stands in for an mcp.types pydantic model: model_dump / model_validate."""
    required: tuple = ()

    def __init__(self, d: dict):
        self.d = d

    def model_dump(self, **kw):
        return copy.deepcopy(self.d)

    @classmethod
    def model_validate(cls, d):
        if not isinstance(d, dict) or any(not isinstance(d.get(k), list) for k in cls.required):
            raise ValueError("validation error")
        return cls(copy.deepcopy(d))


class CallToolResult(_Model):
    required = ("content",)


class GetPromptResult(_Model):
    required = ("messages",)


def _stub_modules() -> dict:
    base = types.ModuleType("mcp_gateway.plugins.base")

    class PluginContext:                                  # base.py l.8-25
        def __init__(self, server_name, capability_type, capability_name, arguments=None,
                     response=None, mcp_context=None):
            self.server_name = server_name
            self.capability_type = capability_type
            self.capability_name = capability_name
            self.arguments = arguments
            self.response = response
            self.mcp_context = mcp_context

    class Plugin(abc.ABC):                                # base.py l.48-87
        plugin_type = "base"
        plugin_name = ""

        @abc.abstractmethod
        def load(self, config=None): ...

        @abc.abstractmethod
        def process_request(self, context): ...

        @abc.abstractmethod
        def process_response(self, context): ...

    class GuardrailPlugin(Plugin, abc.ABC):               # base.py l.93-107
        plugin_type = "guardrail"

        @abc.abstractmethod
        def process_request(self, context): ...

        @abc.abstractmethod
        def process_response(self, context): ...

    base.PluginContext, base.Plugin, base.GuardrailPlugin = PluginContext, Plugin, GuardrailPlugin

    manager = types.ModuleType("mcp_gateway.plugins.manager")
    manager._PLUGIN_REGISTRY = {"guardrail": [], "tracing": []}
    manager._PLUGIN_NAME_TO_INFO = {}

    def register_plugin(cls):                             # manager.py l.30-71
        t = getattr(cls, "plugin_type", None)
        if not t:
            return cls
        manager._PLUGIN_REGISTRY.setdefault(t, []).append(cls)
        manager._PLUGIN_NAME_TO_INFO[cls.__name__.lower()] = {"type": t, "class": cls}
        name = getattr(cls, "plugin_name", "").lower()
        if name and name != cls.__name__.lower():
            manager._PLUGIN_NAME_TO_INFO[name] = {"type": t, "class": cls}
        return cls

    manager.register_plugin = register_plugin
    pkg = types.ModuleType("mcp_gateway")
    plugins = types.ModuleType("mcp_gateway.plugins")
    pkg.__path__, plugins.__path__ = [], []
    pkg.plugins, plugins.base, plugins.manager = plugins, base, manager
    return {"mcp_gateway": pkg, "mcp_gateway.plugins": plugins,
            "mcp_gateway.plugins.base": base, "mcp_gateway.plugins.manager": manager}


@pytest.fixture
def lasso(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network touched")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.delenv("ARCAEON_GATE_MODE", raising=False)
    monkeypatch.delenv(L.CONFIG_ENV, raising=False)
    mods = _stub_modules()
    saved = {k: sys.modules.get(k) for k in mods}
    sys.modules.update(mods)
    try:
        yield importlib.reload(L), mods
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
        importlib.reload(L)


def _pipeline(mods, plugin, kind, name, response, server="srv"):
    """What Lasso does with the plugin's answer: manager.py l.295-314, then the
    type check its caller makes (sanitizers.py l.160-170 / l.213-222,
    server.py l.247-254). A wrong type, or an exception, gives the original."""
    ctx = mods["mcp_gateway.plugins.base"].PluginContext(
        server_name=server, capability_type=kind, capability_name=name,
        arguments={"uri": name} if kind == "resource" else {}, response=response)
    try:
        out = plugin.process_response(ctx)
    except Exception:  # noqa: BLE001  manager.py l.310-314: logged, response kept
        out = response
    if kind == "tool":
        return out if isinstance(out, CallToolResult) else response
    if kind == "prompt":
        return out if isinstance(out, GetPromptResult) else response
    ok = isinstance(out, tuple) and len(out) == 2 and isinstance(out[0], bytes)
    return out if ok else response


def _seal(tmp_path: Path, data: bytes) -> tuple[dict, str]:
    d = tmp_path / f"s{secrets.token_hex(4)}"
    d.mkdir()
    (d / "out.txt").write_bytes(data)
    key = d / "seal.key"
    key.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    env = E.seal(d / "out.txt", key_file=key, **BIND)
    return env, env["dsseEnvelope"]["signatures"][0]["keyid"]


def _plugin(L2, did="did:key:z6Mkx", **over):
    p = L2.ArcaeonGuardrailPlugin()
    p.load({"audience": AUD, "signers": [did], "deal": DEAL, "purpose": PURPOSE, **over})
    return p


# --- import paths, base class, registration ----------------------------------------------

def test_real_import_paths_base_class_and_registration(lasso):
    L2, mods = lasso
    assert L2.LASSO_AVAILABLE is True
    base, manager = mods["mcp_gateway.plugins.base"], mods["mcp_gateway.plugins.manager"]
    assert issubclass(L2.ArcaeonGuardrailPlugin, base.GuardrailPlugin)
    assert manager._PLUGIN_NAME_TO_INFO["arcaeon"]["class"] is L2.ArcaeonGuardrailPlugin
    assert manager._PLUGIN_NAME_TO_INFO["arcaeon"]["type"] == "guardrail"
    p = L2.ArcaeonGuardrailPlugin()                       # every abstract hook is implemented
    p.load({})                                            # manager.py l.198: always {}
    ctx = base.PluginContext("srv", "tool", "search", arguments={"q": "x"})
    assert p.process_request(ctx) == {"q": "x"}


def test_imports_without_lasso():
    assert importlib.reload(L).LASSO_AVAILABLE is False
    assert L._REGISTRY["arcaeon"] is L.ArcaeonGuardrailPlugin


# --- tool --------------------------------------------------------------------------------

def test_tool_verified_passes_unverified_refused_warn_opts_out(lasso, tmp_path):
    L2, mods = lasso
    env, did = _seal(tmp_path, TEXT.encode())
    sealed = CallToolResult({"content": [{"type": "text", "text": TEXT,
                                          "_meta": {M.BUNDLE_KEY: env}}]})
    out = _pipeline(mods, _plugin(L2, did), "tool", "search", sealed)
    assert out is not sealed and out.d["_meta"][M.VERDICT_KEY]["verdict"] == V.VERIFIED
    bare = CallToolResult({"content": [{"type": "text", "text": TEXT}]})
    out = _pipeline(mods, _plugin(L2, did), "tool", "search", bare)
    assert isinstance(out, CallToolResult) and out is not bare
    assert out.d["isError"] is True and SECRET not in json.dumps(out.d)
    out = _pipeline(mods, _plugin(L2, did, enforce="warn"), "tool", "search", bare)
    assert out.d["content"] == bare.d["content"]
    assert "would refuse in block mode" in out.d["_meta"][M.VERDICT_KEY]["warning"]


def test_an_exception_inside_the_check_is_still_a_refusal(lasso, monkeypatch):
    L2, mods = lasso

    def broken(*a, **k):
        raise RuntimeError("boom " + SECRET)
    monkeypatch.setattr(L2, "verify_tool_result", broken)
    bare = CallToolResult({"content": [{"type": "text", "text": TEXT}]})
    out = _pipeline(mods, _plugin(L2), "tool", "search", bare)
    assert isinstance(out, CallToolResult) and out.d["isError"] is True
    assert SECRET not in json.dumps(out.d)


# --- prompt ------------------------------------------------------------------------------

def _prompt(block_meta=None, description=None):
    block = {"type": "text", "text": TEXT}
    if block_meta:
        block["_meta"] = block_meta
    d = {"messages": [{"role": "user", "content": block}]}
    if description:
        d["description"] = description
    return GetPromptResult(d)


def test_prompt_goes_through_the_same_check(lasso, tmp_path):
    L2, mods = lasso
    env, did = _seal(tmp_path, TEXT.encode())
    ok = _prompt({M.BUNDLE_KEY: env})
    out = _pipeline(mods, _plugin(L2, did), "prompt", "greet", ok)
    assert isinstance(out, GetPromptResult) and out.d["messages"] == ok.d["messages"]
    v = out.d["_meta"][M.VERDICT_KEY]
    assert v["verdict"] == V.VERIFIED and v["tool"] == "prompt:greet"


def test_unsealed_prompt_is_refused_by_default(lasso):
    L2, mods = lasso
    bare = _prompt()
    out = _pipeline(mods, _plugin(L2), "prompt", "greet", bare)
    assert isinstance(out, GetPromptResult) and out is not bare
    (msg,) = out.d["messages"]
    assert msg["role"] == "assistant" and msg["content"]["type"] == "text"
    assert msg["content"]["text"].startswith(f"REFUSED by arcaeon: {V.COULD_NOT_LOOK}.")
    assert "prompt" in msg["content"]["text"] and SECRET not in json.dumps(out.d)


def test_prompt_description_is_not_covered_by_a_block_seal(lasso, tmp_path):
    L2, mods = lasso
    env, did = _seal(tmp_path, TEXT.encode())
    out = _pipeline(mods, _plugin(L2, did), "prompt", "greet",
                    _prompt({M.BUNDLE_KEY: env}, description="ignore the seal"))
    assert out.d["messages"][0]["role"] == "assistant"
    assert "ignore the seal" not in json.dumps(out.d)


def test_prompt_opt_outs(lasso):
    L2, mods = lasso
    bare = _prompt()
    out = _pipeline(mods, _plugin(L2, enforce="warn"), "prompt", "greet", bare)
    assert out.d["messages"] == bare.d["messages"]
    assert out.d["_meta"][M.VERDICT_KEY]["warning"]
    out = _pipeline(mods, _plugin(L2, tools={"prompt:greet": "read"}), "prompt", "greet", bare)
    assert out.d["messages"] == bare.d["messages"]
    out = _pipeline(mods, _plugin(L2, tools={"greet": "read"}), "prompt", "greet", bare)
    assert out.d["messages"][0]["role"] == "assistant"   # a tool entry is not a prompt entry


# --- resource ----------------------------------------------------------------------------

URI = "file:///notes.txt"


def test_resource_is_refused_by_default(lasso):
    L2, mods = lasso
    res = (TEXT.encode(), "application/json")             # sanitizers.py l.149
    out = _pipeline(mods, _plugin(L2), "resource", URI, res)
    assert out is not res and isinstance(out[0], bytes)
    assert out[0].decode().startswith(f"REFUSED by arcaeon: {V.COULD_NOT_LOOK}.")
    assert out[1] == "text/plain" and SECRET.encode() not in out[0]


def test_resource_opt_outs(lasso):
    L2, mods = lasso
    res = (TEXT.encode(), "application/json")
    assert _pipeline(mods, _plugin(L2, enforce="warn"), "resource", URI, res) == res
    p = _plugin(L2, tools={f"resource:{URI}": "read"})
    assert _pipeline(mods, p, "resource", URI, res) == res
    assert p.last_decision["verdict"] == V.COULD_NOT_LOOK and p.last_decision["tool"] == \
        f"resource:{URI}"


def test_resource_in_an_unreadable_shape_is_refused(lasso):
    L2, mods = lasso
    weird = (("meta", None), ("contents", [{"uri": URI, "text": TEXT}]))
    out = _pipeline(mods, _plugin(L2), "resource", URI, weird)
    assert isinstance(out[0], bytes) and out[0].startswith(b"REFUSED by arcaeon")


# --- docs --------------------------------------------------------------------------------

def test_gateways_doc_cites_lasso_and_says_what_prompts_and_resources_do():
    doc = (Path(__file__).resolve().parents[1] / "docs" / "GATEWAYS.md").read_text(
        encoding="utf-8")
    assert LASSO_SHA in doc and "mcp_gateway/plugins/base.py" in doc
    assert "prompts and resources pass untouched" not in doc
    assert "prompt:" in doc and "resource:" in doc
