"""KNOWN BLIND (confessed in grade.MCP08_REACH_BLIND_SPOTS): the recorder is
imported from a package OUTSIDE the graded tree (`auditlib`, a library). Even
with the package directory in hand there is no file to open, so the server is
reported at gate 0 although every call is recorded. Never run."""
from mcp.server.fastmcp import FastMCP

from auditlib import record

mcp = FastMCP("x")


@mcp.tool()
def add(a, b):
    record("add", {"a": a, "b": b})
    return a + b


mcp.run(transport="stdio")
