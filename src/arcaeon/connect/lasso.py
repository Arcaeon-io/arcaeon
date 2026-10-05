# SPDX-License-Identifier: MIT
"""arcaeon.connect.lasso: the arcaeon guardrail plugin for Lasso mcp-gateway (L4-02, L4-04).

    python -c "import sys, arcaeon.connect.lasso; from mcp_gateway.server import main; \\
               sys.exit(main())" --mcp-json-path ~/.cursor/mcp.json -p arcaeon

THE REAL HOOKS (L4-04), read from github.com/lasso-security/mcp-gateway at
7e7f1f6e5314819b3d0928128bb88eaea874b600 (1.2.1):

  * mcp_gateway/plugins/base.py: PluginContext(server_name, capability_type,
    capability_name, arguments=None, response=None, mcp_context=None) at
    l.8-25. Plugin(abc.ABC) at l.48-87 has abstract load(config=None) -> None,
    process_request(context) -> Optional[dict] (None blocks), and
    process_response(context) -> Any. GuardrailPlugin(Plugin) at l.93-107,
    with plugin_type "guardrail".
  * mcp_gateway/plugins/manager.py: register_plugin(cls) at l.30-71, keyed
    by the lower-cased class name and plugin_name. discover_plugins at
    l.74-96 imports only Lasso's own guardrails/tracing packages, so this
    module must be imported before the gateway starts, which is why the
    launcher above exists. load({}) at l.197-198: the config is always
    empty. process_response at l.283-314 catches an exception from a plugin,
    logs it and KEEPS THE RESPONSE (fail open). So nothing here may raise.
  * The response a plugin sees, and what Lasso accepts back:
      tool      types.CallToolResult; anything else -> the original
                (sanitizers.py l.192-222)
      prompt    types.GetPromptResult; anything else -> the original
                (server.py l.221-254)
      resource  (content: bytes, mime_type) with name = the URI; anything but
                a 2-tuple with bytes first -> the original
                (sanitizers.py l.138-170). gateway.py l.302-305 does not
                expose resources yet, so this path is not reachable today.
    A plugin that answers in the wrong type lets the original through, so
    every answer here is rebuilt in the type it came in.

WHAT IT DOES. Every response goes through
arcaeon.connect.mcp_result.verify_tool_result, which verifies the arcaeon
bundle under _meta["dev.arcaeon/bundle"] and applies the gate rule and the
enforce mode:

  tool      the CallToolResult itself, looked up in `tools` as
            "server/tool", then "tool"
  prompt    each message's content block, plus the description as one more
            block, which is never sealed. The lookup key is "prompt:<name>".
            A refusal is a GetPromptResult with one assistant message
            "REFUSED by arcaeon: ...".
  resource  the bytes. They carry no _meta, so they always read COULD NOT
            LOOK. The lookup key is "resource:<uri>". A refusal is
            (b"REFUSED by arcaeon: ...", "text/plain").

So prompts and resources are refused by default (default_action act), the
same as an unsealed tool. The opt-outs are the same as for tools:
`"enforce": "warn"` / ARCAEON_GATE_MODE=warn, or the name listed as `read`.
Any exception inside the check is a COULD NOT LOOK refusal, never a raise.

Lasso is not a dependency. When mcp_gateway is importable its GuardrailPlugin
and register_plugin are used. Otherwise a small local shim stands in, so this
module imports (and its tests run) without Lasso.

CONFIG (docs/GATEWAYS.md): the JSON file named by ARCAEON_GATEWAY_CONFIG,
with the dict `load` receives laid over it key by key (Lasso passes {}).
Keys: audience, signers, deal, purpose, enforce, default_action, tools.
"""
from __future__ import annotations

import base64
import copy
import os
from typing import Any

from arcaeon import verdict as V
from arcaeon.connect.mcp_result import (
    VERDICT_KEY,
    GatewayConfig,
    could_not_look_summary,
    refusal_result,
    verify_tool_result,
)

__all__ = ["ArcaeonGuardrailPlugin", "PLUGIN_NAME", "CONFIG_ENV", "LASSO_AVAILABLE"]

PLUGIN_NAME = "arcaeon"
CONFIG_ENV = "ARCAEON_GATEWAY_CONFIG"

try:  # base.py l.93 / manager.py l.30 at 7e7f1f6e
    from mcp_gateway.plugins.base import GuardrailPlugin as _Base  # type: ignore
    from mcp_gateway.plugins.manager import register_plugin as _register  # type: ignore
    LASSO_AVAILABLE = True
except ImportError:
    LASSO_AVAILABLE = False

    class _Base:  # the shim: Lasso's GuardrailPlugin hooks (base.py l.48-107)
        plugin_type = "guardrail"
        plugin_name = ""

        def load(self, config: dict | None = None) -> None:
            pass

        def process_request(self, context) -> Any:
            return getattr(context, "arguments", None)

        def process_response(self, context) -> Any:
            return getattr(context, "response", None)

    _REGISTRY: dict = {}

    def _register(cls):
        _REGISTRY[getattr(cls, "plugin_name", cls.__name__) or cls.__name__] = cls
        return cls


def _as_dict(response: Any) -> tuple[Any, Any]:
    """(dict form, the type to rebuild) for a dict or a pydantic result."""
    if isinstance(response, dict):
        return response, None
    dump = getattr(response, "model_dump", None)
    if callable(dump):
        return dump(by_alias=True, exclude_none=True), type(response)
    return response, None


def _rebuild(new: dict, kind, fallback: dict | None = None) -> Any:
    """`new` in the type the response came in. If the type will not take it,
    try `fallback`, a plain refusal without _meta, so that Lasso never gets a
    wrong type back, which would let the original through."""
    if kind is None:
        return new
    for cand in (new, fallback):
        if cand is None:
            continue
        try:
            return kind.model_validate(cand)
        except Exception:  # noqa: BLE001
            continue
    return new


def _refusal_text(summary: dict, what: str) -> str:
    word = summary.get("verdict") or V.COULD_NOT_LOOK
    return (f"REFUSED by arcaeon: {word}. {summary.get('reason') or ''} "
            f"The {what} was withheld and not shown.").strip()


def _prompt_refusal(summary: dict) -> tuple[dict, dict]:
    msg = {"role": "assistant", "content": {"type": "text",
                                            "text": _refusal_text(summary, "prompt")}}
    return {"messages": [msg], "_meta": {VERDICT_KEY: summary}}, {"messages": [msg]}


@_register
class ArcaeonGuardrailPlugin(_Base):
    """Verify-before-the-model-reads-it on every tool, prompt and resource result."""
    plugin_type = "guardrail"
    plugin_name = PLUGIN_NAME

    def __init__(self) -> None:
        self.config = GatewayConfig()
        self.last_decision: dict | None = None

    def load(self, config: dict | None = None) -> None:
        """Read the config: ARCAEON_GATEWAY_CONFIG's file, then `config` over
        it. Raises ValueError on a config it cannot read. Lasso logs that and
        leaves the plugin unloaded (manager.py l.203-207), so a config error
        means no gate, not a quiet pass. Check the gateway log."""
        merged: dict = {}
        path = os.environ.get(CONFIG_ENV)
        if path:
            from arcaeon.record.row import loads_strict
            with open(path, encoding="utf-8") as f:
                raw = loads_strict(f.read())
            if not isinstance(raw, dict):
                raise ValueError(f"{CONFIG_ENV}={path}: the config must be one JSON object")
            merged.update(raw)
        merged.update({k: v for k, v in (config or {}).items() if k in
                       ("audience", "signers", "deal", "purpose", "enforce", "default_action",
                        "tools")})
        self.config = GatewayConfig.from_dict(merged)

    def process_request(self, context) -> Any:
        return getattr(context, "arguments", None)

    def process_response(self, context) -> Any:
        response = getattr(context, "response", None)
        kind = getattr(context, "capability_type", None) or "tool"
        name = getattr(context, "capability_name", None)
        server = getattr(context, "server_name", None)
        try:
            if kind == "prompt":
                return self._prompt(response, name, server)
            if kind == "resource":
                return self._resource(response, name, server)
            return self._tool(response, name, server)       # "tool", or a kind we do not know
        except Exception as e:  # noqa: BLE001  Lasso would keep the original: never raise
            summary = could_not_look_summary(f"the check could not finish ({type(e).__name__})",
                                             "a finished check", "unreadable", where=kind)
            self.last_decision = summary
            return self._refuse(kind, response, summary)

    # --- the three kinds ---------------------------------------------------------------

    def _tool(self, response, name, server):
        data, typ = _as_dict(response)
        new, d = verify_tool_result(data, config=self.config, tool=name, server=server)
        self.last_decision = d
        plain = {"content": new.get("content"), "isError": True} if new.get("isError") else None
        return _rebuild(new, typ, plain)

    def _prompt(self, response, name, server):
        data, typ = _as_dict(response)
        pseudo: Any = None
        if isinstance(data, dict) and isinstance(data.get("messages"), list):
            blocks: list = []
            for m in data["messages"]:
                c = m.get("content") if isinstance(m, dict) else None
                blocks.extend(c if isinstance(c, list) else [c])
            desc = data.get("description")
            if isinstance(desc, str) and desc:
                blocks.append({"type": "text", "text": desc})    # no seal can cover it
            pseudo = {"content": blocks}
            if isinstance(data.get("_meta"), dict):
                pseudo["_meta"] = data["_meta"]
        _, d = verify_tool_result(pseudo, config=self.config, tool=f"prompt:{name}",
                                  server=server)
        self.last_decision = d
        if d["decision"] == "refuse":
            new, plain = _prompt_refusal(d)
            return _rebuild(new, typ, plain)
        out = copy.deepcopy(data)
        meta = out.get("_meta") if isinstance(out.get("_meta"), dict) else {}
        out["_meta"] = {**meta, VERDICT_KEY: d}
        return _rebuild(out, typ)

    def _resource(self, response, name, server):
        pseudo: Any = None
        if isinstance(response, tuple) and len(response) == 2 and \
                isinstance(response[0], (bytes, str)):
            raw = response[0].encode("utf-8") if isinstance(response[0], str) else response[0]
            pseudo = {"content": [{"type": "resource", "resource": {
                "uri": str(name), "blob": base64.b64encode(raw).decode("ascii")}}]}
        _, d = verify_tool_result(pseudo, config=self.config, tool=f"resource:{name}",
                                  server=server)
        self.last_decision = d
        if d["decision"] == "refuse":
            return self._refuse("resource", response, d)
        return response                                  # bytes carry no verdict

    def _refuse(self, kind: str, response, summary: dict):
        if kind == "resource":
            return _refusal_text(summary, "resource").encode("utf-8"), "text/plain"
        typ = type(response) if callable(getattr(response, "model_validate", None)) else None
        if kind == "prompt":
            new, plain = _prompt_refusal(summary)
            return _rebuild(new, typ, plain)
        new = refusal_result(summary)
        return _rebuild(new, typ, {"content": new["content"], "isError": True})
