"""KNOWN BLIND (confessed in grade.MCP08_REACH_BLIND_SPOTS): the recorder is
one relative import away, and this file is graded ALONE, with no package
directory. The walk cannot open `.audit`, so the server is reported at gate 0
although every call is recorded. Never run."""
from mcp.server.fastmcp import FastMCP

from .audit import record

mcp = FastMCP("x")


@mcp.tool()
def add(a, b):
    record("add", {"a": a, "b": b})
    return a + b


mcp.run(transport="stdio")
