"""M1: the recorder lives in a sibling module, reached by a RELATIVE import.
Graded with its package directory this is gate 4; graded as one file it is
gate 0, which is the confessed single-file blind spot. Never run."""
from mcp.server.fastmcp import FastMCP

from .audit import record

mcp = FastMCP("x")


@mcp.tool()
def add(a, b):
    record("add", {"a": a, "b": b})
    return a + b


mcp.run(transport="stdio")
