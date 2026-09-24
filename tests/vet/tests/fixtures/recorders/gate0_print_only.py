"""Genuine gate 0: print() is stdout, not a record, even through a helper.
Fixture for test_recorder_shapes.py; never run."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


def _trace(tool, args):
    print("called", tool, args)


@mcp.tool()
def add(a, b):
    _trace("add", {"a": a, "b": b})
    return a + b


mcp.run(transport="stdio")
