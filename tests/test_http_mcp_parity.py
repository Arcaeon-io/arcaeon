"""HTTP and MCP parity (K091).

Every free route `arcaeon serve` answers has an MCP tool that does the same
thing, or says in the route table why there is none (`mcp_exempt_reason`).
A named tool must be one the connector really advertises, and free there
too. The route table, the OpenAPI document and the MCP connector's tool list
are read as they are; nothing here keeps a second list.
"""
from __future__ import annotations

import pytest

from arcaeon.mcp.server import ALL_TOOLS, FREE_TOOLS, PAID_TOOLS
from arcaeon.serve import openapi
from arcaeon.serve.routes import ROUTES

FREE = [r for r in ROUTES if r.tier == "free"]


def _id(r):
    return f"{r.method} {r.path}"


def test_there_are_free_routes_to_check():
    assert len(FREE) >= 10


@pytest.mark.parametrize("route", FREE, ids=_id)
def test_every_free_route_has_an_mcp_tool_or_a_stated_reason(route):
    tool, reason = route.mcp_tool, route.mcp_exempt_reason
    assert (tool is None) != (reason is None), (_id(route), tool, reason)
    if reason is not None:
        assert isinstance(reason, str) and reason.strip(), _id(route)
    else:
        assert tool in ALL_TOOLS, (_id(route), tool)
        assert tool in FREE_TOOLS and tool not in PAID_TOOLS, (_id(route), tool)


def test_a_paid_route_names_no_free_mcp_tool():
    for r in ROUTES:
        if r.tier != "free":
            assert r.mcp_tool is None or r.mcp_tool in PAID_TOOLS, _id(r)


def test_the_openapi_document_carries_the_same_mapping():
    doc = openapi.build()
    seen = {}
    for path, ops in doc["paths"].items():
        for method, op in ops.items():
            seen[(method.upper(), path)] = op.get("x-arcaeon-mcp-tool")
    assert seen == {(r.method, r.path): r.mcp_tool for r in ROUTES}


def test_the_connector_advertises_every_named_tool():
    """With the MCP SDK installed, the tools the server actually lists include
    every tool a route names (skipped on a base install)."""
    pytest.importorskip("mcp", reason="needs the MCP SDK to list tools")
    import asyncio
    from mcp import Client
    from arcaeon.mcp.server import build_server

    async def names():
        async with Client(build_server()) as client:
            return {t.name for t in (await client.list_tools()).tools}

    listed = asyncio.run(names())
    named = {r.mcp_tool for r in ROUTES if r.mcp_tool}
    assert named <= listed, sorted(named - listed)
