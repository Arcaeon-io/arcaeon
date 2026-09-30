# SPDX-License-Identifier: MIT
"""LlamaIndex adapter (K087).

    from llama_index.core.agent.workflow import FunctionAgent
    from arcaeon.adapters.llamaindex import arcaeon_tools
    agent = FunctionAgent(tools=arcaeon_tools(), llm=llm)

`arcaeon_tools(client=None)` returns one `llama_index.core.tools.FunctionTool`
per free check route (arcaeon.adapters.tool_specs). Its metadata carries the
route's name and description and an `fn_schema` model derived from the
route's JSON schema (arcaeon.adapters._pydantic), so nothing is restated. The
keyword arguments are the request body, sent through arcaeon.client; the
output is the server's JSON as text, so the model reads the verdict and the
integer `exit` itself. A server that cannot be reached is COULD NOT LOOK
(exit 3), returned, never raised, never a pass.

llama-index-core is imported inside `arcaeon_tools`, never at this module's
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
    """One FunctionTool per free check route.

    `client`: an arcaeon.client.Client; None makes a default one (serve.json
    and serve.token) on the first call. Raises ImportError when
    llama-index-core is not installed (`pip install llama-index-core`)."""
    from arcaeon.adapters import missing
    try:
        from llama_index.core.tools import FunctionTool, ToolMetadata  # pyright: ignore[reportMissingImports]  # optional: user installs llama-index-core (docs/ADAPTERS.md), not a declared extra
    except ImportError as e:
        raise missing("llamaindex", "llama-index-core", e) from e
    from arcaeon.adapters import tool_specs
    from arcaeon.adapters._pydantic import args_model
    tools = []
    for s in tool_specs(client):
        run, arun = _funcs(s)
        meta = ToolMetadata(name=s.name, description=s.description,
                            fn_schema=args_model(s))
        tools.append(FunctionTool(fn=run, metadata=meta, async_fn=arun))
    return tools
