# SPDX-License-Identifier: MIT
"""LangChain / LangGraph adapter (K086).

    from arcaeon.adapters.langchain import arcaeon_tools
    tools = arcaeon_tools()
    llm.bind_tools(tools)                          # LangChain
    from langgraph.prebuilt import ToolNode
    node = ToolNode(tools)                         # LangGraph, as-is

`arcaeon_tools(client=None)` returns one `langchain_core.tools.StructuredTool`
per free check route (arcaeon.adapters.tool_specs). Each tool's
`args_schema` is the route's JSON schema itself (a dict, which langchain-core
accepts), so nothing is restated. The tool's arguments are the request body,
sent through arcaeon.client; its output is the server's JSON as text, so the
model reads the verdict and the integer `exit` itself. A server that cannot
be reached is COULD NOT LOOK (exit 3), returned, never raised, never a pass.

langchain-core is imported inside `arcaeon_tools`, never at this module's
top, so importing this module costs nothing without it.
"""
from __future__ import annotations

import json

__all__ = ["arcaeon_tools"]


def _funcs(spec):
    from arcaeon.adapters._pydantic import body

    def run(**kwargs) -> str:
        return json.dumps(spec.call(body(kwargs)), ensure_ascii=False)

    async def arun(**kwargs) -> str:
        import asyncio
        return await asyncio.to_thread(run, **kwargs)

    run.__name__ = arun.__name__ = f"arcaeon_{spec.name}"
    return run, arun


def arcaeon_tools(client=None) -> list:
    """One StructuredTool per free check route.

    `client`: an arcaeon.client.Client; None makes a default one (serve.json
    and serve.token) on the first call. Raises ImportError when langchain-core
    is not installed (`pip install langchain-core`)."""
    from arcaeon.adapters import missing
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as e:
        raise missing("langchain", "langchain-core", e) from e
    from arcaeon.adapters import tool_specs
    tools = []
    for s in tool_specs(client):
        run, arun = _funcs(s)
        tools.append(StructuredTool(name=s.name, description=s.description,
                                    args_schema=s.parameters, func=run,
                                    coroutine=arun))
    return tools
