# SPDX-License-Identifier: MIT
"""CrewAI adapter (K088).

    from crewai import Agent
    from arcaeon.adapters.crewai import arcaeon_tools
    agent = Agent(role="checker", goal="...", backstory="...", tools=arcaeon_tools())

`arcaeon_tools(client=None)` returns one `crewai.tools.BaseTool` per free
check route (arcaeon.adapters.tool_specs), with the route's name,
description and an `args_schema` model derived from the route's JSON schema
(arcaeon.adapters._pydantic), so nothing is restated. The tool's keyword
arguments are the request body, sent through arcaeon.client; its output is
the server's JSON as text, so the model reads the verdict and the integer
`exit` itself. A server that cannot be reached is COULD NOT LOOK (exit 3),
returned, never raised, never a pass.

crewai is imported inside `arcaeon_tools`, never at this module's top, so
importing this module costs nothing without it.
"""
from __future__ import annotations

import json

__all__ = ["arcaeon_tools"]


def _tool_class(base, spec):
    """A BaseTool subclass whose _run sends one request for this spec."""
    from arcaeon.adapters._pydantic import body

    def _run(self, **kwargs) -> str:
        return json.dumps(spec.call(body(kwargs)), ensure_ascii=False)

    return type(f"arcaeon_{spec.name}", (base,), {"_run": _run,
                                                  "__module__": __name__})


def arcaeon_tools(client=None) -> list:
    """One CrewAI tool per free check route.

    `client`: an arcaeon.client.Client; None makes a default one (serve.json
    and serve.token) on the first call. Raises ImportError when crewai is not
    installed (`pip install crewai`)."""
    from crewai.tools import BaseTool
    from arcaeon.adapters import tool_specs
    from arcaeon.adapters._pydantic import args_model
    return [_tool_class(BaseTool, s)(name=s.name, description=s.description,
                                     args_schema=args_model(s))
            for s in tool_specs(client)]
