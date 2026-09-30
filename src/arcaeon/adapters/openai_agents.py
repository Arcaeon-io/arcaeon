# SPDX-License-Identifier: MIT
"""OpenAI Agents SDK adapter (K085).

    from agents import Agent
    from arcaeon.adapters.openai_agents import arcaeon_tools
    agent = Agent(name="checker", tools=arcaeon_tools())

`arcaeon_tools(client=None)` returns one `agents.FunctionTool` per free check
route (arcaeon.adapters.tool_specs). Each tool's JSON arguments are sent as
the request body through arcaeon.client; its output is the server's JSON as
text, so the model reads the verdict and the integer `exit` itself. Arguments
that are not a JSON object come back as a bad-usage answer (exit 2), and a
server that cannot be reached as COULD NOT LOOK (exit 3): never an exception
the run would swallow, never a pass.

The SDK (`openai-agents`, module `agents`) is imported inside
`arcaeon_tools`, never at this module's top, so importing this module costs
nothing without it. The schemas are not strict (optional fields stay
optional), so each tool is built with `strict_json_schema=False`.
"""
from __future__ import annotations

import json

__all__ = ["arcaeon_tools"]


def _bad_args(reason: str) -> str:
    return json.dumps({"verdict": "bad usage", "exit": 2, "reason_word": "usage",
                       "reason": reason})


def _invoker(spec):
    async def on_invoke_tool(ctx, args: str) -> str:
        try:
            body = json.loads(args) if args and args.strip() else {}
        except ValueError:
            return _bad_args("the tool arguments are not JSON")
        if not isinstance(body, dict):
            return _bad_args("the tool arguments are not a JSON object")
        import asyncio
        result = await asyncio.to_thread(spec.call, body)
        return json.dumps(result, ensure_ascii=False)
    on_invoke_tool.__name__ = f"arcaeon_{spec.name}"
    return on_invoke_tool


def arcaeon_tools(client=None) -> list:
    """One Agents SDK FunctionTool per free check route.

    `client`: an arcaeon.client.Client; None makes a default one (serve.json
    and serve.token) on the first call. Raises ImportError when the SDK is not
    installed (`pip install openai-agents`)."""
    from arcaeon.adapters import missing
    try:
        from agents import FunctionTool  # pyright: ignore[reportMissingImports]  # optional: user installs openai-agents (docs/ADAPTERS.md), not a declared extra
    except ImportError as e:
        raise missing("openai_agents", "openai-agents", e) from e
    from arcaeon.adapters import tool_specs
    return [FunctionTool(name=s.name, description=s.description,
                         params_json_schema=s.parameters,
                         on_invoke_tool=_invoker(s), strict_json_schema=False)
            for s in tool_specs(client)]
