# SPDX-License-Identifier: MIT
"""AutoGen adapter (K089), for AutoGen 0.4 and later (autogen-core).

    from autogen_agentchat.agents import AssistantAgent
    from arcaeon.adapters.autogen import arcaeon_tools
    agent = AssistantAgent("checker", model_client=model_client, tools=arcaeon_tools())

`arcaeon_tools(client=None)` returns one `autogen_core.tools.BaseTool` per
free check route (arcaeon.adapters.tool_specs), with the route's name,
description and an args model derived from the route's JSON schema
(arcaeon.adapters._pydantic), so nothing is restated. The validated
arguments are the request body, sent through arcaeon.client on a worker
thread; the output is the server's JSON as text, so the model reads the
verdict and the integer `exit` itself. A server that cannot be reached is
COULD NOT LOOK (exit 3), returned, never raised, never a pass.

autogen-core is imported inside `arcaeon_tools`, never at this module's top,
so importing this module costs nothing without it.
"""
from __future__ import annotations

import json

__all__ = ["arcaeon_tools"]


def _tool_class(base, spec):
    """A BaseTool subclass whose run sends one request for this spec."""
    from arcaeon.adapters._pydantic import body

    def send(values: dict) -> str:
        return json.dumps(spec.call(body(values)), ensure_ascii=False)

    async def run(self, args, cancellation_token) -> str:
        import asyncio
        values = args.model_dump() if hasattr(args, "model_dump") else dict(args)
        return await asyncio.to_thread(send, values)

    return type(f"arcaeon_{spec.name}", (base,), {"run": run, "__module__": __name__})


def arcaeon_tools(client=None) -> list:
    """One AutoGen tool per free check route.

    `client`: an arcaeon.client.Client; None makes a default one (serve.json
    and serve.token) on the first call. Raises ImportError when autogen-core
    is not installed (`pip install autogen-core`)."""
    from arcaeon.adapters import missing
    try:
        from autogen_core.tools import BaseTool  # pyright: ignore[reportMissingImports]  # optional: user installs autogen-core (docs/ADAPTERS.md), not a declared extra
    except ImportError as e:
        raise missing("autogen", "autogen-core", e) from e
    from arcaeon.adapters import tool_specs
    from arcaeon.adapters._pydantic import args_model
    return [_tool_class(BaseTool, s)(args_model(s), str, s.name, s.description)
            for s in tool_specs(client)]
