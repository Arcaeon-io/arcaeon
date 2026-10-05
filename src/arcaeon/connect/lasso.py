# SPDX-License-Identifier: MIT
"""arcaeon.connect.lasso: the arcaeon guardrail plugin for Lasso mcp-gateway (L4-02).

    mcp-gateway --mcp-json-path ~/.cursor/mcp.json -p arcaeon

Lasso's mcp-gateway (MIT, Python) runs guardrail plugins around every tool
call: `load(config)` once, `process_request(context)` before the call,
`process_response(context)` after it, returning the (modified) response. This
plugin does its work in process_response: it hands the tool result to
arcaeon.connect.mcp_result.verify_tool_result, which verifies the arcaeon
bundle under _meta["dev.arcaeon/bundle"] and applies the gate rule and the
enforce mode. A refusal comes back as a normal result with isError true and a
plain REFUSED text; the tool's own output does not reach the model.
process_request passes the arguments through unchanged (there is nothing
sealed to check before the call).

Lasso is not a dependency. When mcp_gateway is importable its GuardrailPlugin
base and register_plugin decorator are used; otherwise a small local shim
stands in, so this module imports (and its tests run) without Lasso. Which
Lasso version and MCP revision the plugin was run against: none yet; it is
fixture-tested against the hook shapes Lasso's plugins README documents.

CONFIG (docs/GATEWAYS.md): the dict `load` receives, merged over the JSON file
named by ARCAEON_GATEWAY_CONFIG when that is set (the dict wins key by key).
Keys: audience, signers, deal, purpose, enforce, default_action, tools. A
tool listed in `tools` is looked up as "server/tool", then "tool"; an unlisted
tool is held to default_action, default "act" (fail closed).
"""
from __future__ import annotations

import os
from typing import Any

from arcaeon.connect.mcp_result import GatewayConfig, verify_tool_result

__all__ = ["ArcaeonGuardrailPlugin", "PLUGIN_NAME", "CONFIG_ENV", "LASSO_AVAILABLE"]

PLUGIN_NAME = "arcaeon"
CONFIG_ENV = "ARCAEON_GATEWAY_CONFIG"

try:  # pragma: no cover - only with Lasso installed
    from mcp_gateway.plugins.base import GuardrailPlugin as _Base  # type: ignore
    try:
        from mcp_gateway.plugins.manager import register_plugin as _register  # type: ignore
    except ImportError:
        from mcp_gateway.plugins.base import register_plugin as _register  # type: ignore
    LASSO_AVAILABLE = True
except ImportError:
    LASSO_AVAILABLE = False

    class _Base:  # the shim: the shape Lasso's GuardrailPlugin documents
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


def _rebuild(new: dict, kind) -> Any:
    if kind is None:
        return new
    try:
        return kind.model_validate(new)
    except Exception:  # noqa: BLE001  the dict is still the right answer
        return new


@_register
class ArcaeonGuardrailPlugin(_Base):
    """Verify-before-the-model-reads-it on every tool result."""
    plugin_type = "guardrail"
    plugin_name = PLUGIN_NAME

    def __init__(self) -> None:
        self.config = GatewayConfig()
        self.last_decision: dict | None = None

    def load(self, config: dict | None = None) -> None:
        """Read the config: ARCAEON_GATEWAY_CONFIG's file, then `config` over
        it. Raises ValueError on a config it cannot read: the gateway should
        not start with a gate it cannot run."""
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
        tool = getattr(context, "capability_name", None)
        server = getattr(context, "server_name", None)
        if getattr(context, "capability_type", "tool") not in ("tool", None):
            return response                      # prompts and resources: not a tool result
        data, kind = _as_dict(response)
        new, decision = verify_tool_result(data, config=self.config, tool=tool, server=server)
        self.last_decision = decision
        return _rebuild(new, kind)
