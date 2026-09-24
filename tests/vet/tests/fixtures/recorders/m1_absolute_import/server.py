"""M1: the recorder lives in a sibling module, reached by an ABSOLUTE import
that names the package (`from m1_absolute_import.audit import record`). The
walk anchors the package name on an ancestor of the handler's directory.
Never run."""
from mcp.server.fastmcp import FastMCP

from m1_absolute_import.audit import record

mcp = FastMCP("x")


@mcp.tool()
def add(a, b):
    record("add", {"a": a, "b": b})
    return a + b


mcp.run(transport="stdio")
