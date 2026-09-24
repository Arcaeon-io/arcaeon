"""Genuine gate 0: a served tool that leaves nothing behind. Fixture for
test_recorder_shapes.py; never run."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


@mcp.tool()
def add(a, b):
    return a + b


mcp.run(transport="stdio")
